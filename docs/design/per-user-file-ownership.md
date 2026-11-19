# Design: Per-User File Ownership (Token → Unix Account)

## Problem statement

All nginx workers run as root (`user root;` in `conf.d/default.conf`), so every
file the gateway creates is owned `root:root`, and the root worker can read
**any** file in the store regardless of POSIX permissions — access control is
currently JWT-scope only. HPC sites need file operations to happen as the unix
user identified by the authenticated token (or an account mapped from it), so
that:

- files are owned by the stage-out user (POSIX perms, group-writable dirs,
  quotas, later access via the normal HPC path all keep working);
- filesystem permissions become real per-user enforcement (403 from the disk,
  not just from the token's scope).

## Codebase constraints (verified against the current image)

- Workers run as root in the current deployment (real uid 0). The intended
  future deployment is a non-root worker with `CAP_SETUID`/`CAP_SETGID` in
  its effective set — the switch sequence works identically in both cases
  (verified; see "Non-root workers with capabilities" below). Only
  `seteuid`/`setegid` are used; `setuid` is never used.
- The upload/TPC sink (`fileutil.sink_to_file`) alternates between
  **yielding** socket reads (`http.get_client_body_reader`) and file writes in
  the worker coroutine — the central scheduling constraint (below).
- `ngx.pipe` in this OpenResty 1.31.8.1 build has **no** uid/gid/groups
  options (verified: `pipe.lua` only accepts `merge_stderr`, `buffer_size`,
  `environ`, timeouts), so "spawn a child as user X" cannot be delegated to
  the pipe module.
- `luaposix` 39 is already installed and provides `getpwnam` (verified:
  returns `{pw_name, pw_uid, pw_gid, ...}` or `nil`). `setuid`/`setgid` are
  *not* exported, but LuaJIT `ffi.C` exposes libc directly (the repo already
  uses raw FFI in `cksumutil.lua`).
- After `bearer_jwt_verify` in `webdav_access.lua`, the full claims of a
  **verified** token are available: `sub`, `name` (WLCG common JWT profile:
  username or email), `scope`. Only verified tokens are ever mapped — never
  client-supplied headers.

## Kernel-level requirement (verified empirically)

Linux checks DAC at `open()` time; `read()`/`write()` on an already-open fd
are **not** re-checked against credentials. Verified in the image: a process
switching to user B cannot open a `0600` file owned by user A (EACCES), but a
process that holds an fd opened as user A can keep reading/writing it after
switching back to root. So only the *open/metadata* syscalls
(`open`, `mkdir`, `unlink`, `rename`) need the user's identity — the worker
can stream the whole upload as root over a fd it opened as the mapped user.
This keeps adler32 computation (worker-side, over the bytes it pipes) and the
raw-socket response handling completely unchanged.

## Why a naive in-worker `seteuid()` is NOT safe — and why this design is

Nginx multiplexes many concurrent requests per worker **process** as
coroutines. If a Lua coroutine switches credentials and then **yields**
(socket read, flush, timer), another coroutine (a different user's request,
gossip, TPC, a timer) runs the same process with the switched credentials:
wrong ownership, spurious permission failures, cross-user interleaving.
This kills any design where the switch window spans a yield — e.g. switching
from Lua before the sink loop, or a helper that inherits the worker's event
loop.

Two safe shapes exist:

1. **A separate process** does the switched syscalls (fork + exec helper, or
   fork + `SCM_RIGHTS` fd passing back to the root worker). Correct, but pays
   ~1–3 ms fork/exec per open, and adds a second program to audit, deploy and
   keep in sync.
2. **An in-worker C module** whose every function is one straight-line C
   sequence: `validate → setegid → seteuid → one syscall → seteuid(0) →
   setegid(0) → return`. No allocation, no sleep, no event-loop re-entry —
   so a LuaJIT coroutine **cannot yield in the middle of the call**. The
   coroutine scheduler is preempted only at yield points, and there are none
   inside a C FFI frame; the switch window is therefore atomic with respect
   to every other request in the worker. Only *effective* credentials are
   switched (and always restored), so the worker's real uid/gid stay 0 for
   its whole lifetime: there is no state to get stuck in, even if a bug
   skipped a restore, the worker can never *become* the mapped user.

This design uses (2): a ~150-line auditable C file with four exported
functions, no state, no threads, no libc facilities beyond `open`/`mkdir`/
`unlink`/`rename`/`seteuid`/`setegid`.

## Implementation

### 1. Identity mapping — `nginx/lua/usermap.lua` (new)

Called from `webdav_access.lua` immediately after `bearer_jwt_verify`
succeeds. Opt-in: when `user_mapping` is absent or empty, `resolve()`
returns nil and all file I/O keeps running as root, exactly like before.

Config (`config.json`):

```json
"user_mapping": {
  "claim": "name",
  "on_missing": "root",
  "deny_uids": [0],
  "uid_range": [1000, 60000],
  "fallback": { "uid": 65534, "gid": 65534 }
}
```

- `claim` (default `name`): the JWT claim holding the unix account name
  (the WLCG common JWT profile `name` claim is exactly this).
- `on_missing` (`root` default | `deny`): tokens without the claim run as
  root (legacy behavior, safe rollout) or are rejected.
- Guards: mapped uid in `deny_uids` (root by default) or outside
  `uid_range` → 403. No local account → 403, or the configured `fallback`
  account (e.g. `nobody`) — fallback uids pass through the same guards.
- Lookup via `posix.getpwnam`; results and denials cached in
  `lua_shared_dict usermap_cache 10m` keyed by `<claim>=<value>` (10 min
  TTL). `getpwnam` goes through NSS and may hit LDAP/NIS — cached, so a
  slow directory only costs the first request per account.
- Result: `ngx.ctx.fs_owner = {uid, gid}` (nil = root).

### 2. Privileged syscalls — `nginx/as_user.c` (new) + `nginx/lua/asuser.lua` (new)

`as_user.c` exports four functions, each a single straight-line sequence as
described above; all paths are validated to stay under the configured
storage root (a `..` path segment is rejected — defense in depth on the
existing traversal fix). The C file is compiled into `as_user.so` during the
image build (`gcc -O2 -Wall -Wextra -shared -fPIC`) and loaded by
`asuser.lua` via `ffi.load` (same FFI pattern as `cksumutil.lua`):

| Function | Used by |
|---|---|
| `as_user_mkdirp(uid, gid, root, path, mode)` | PUT/TPC parent dir creation (recursive; `EEXIST` tolerated for concurrent writers) |
| `as_user_open(uid, gid, root, path, flags, mode)` | PUT open-for-write (`0644`); `asuser.open_for_read` for the phase-2 read path |
| `as_user_unlink(uid, gid, root, path)` | DELETE |
| `as_user_rename(uid, gid, root, src, dst)` | reserved for MOVE |

`asuser.lua` wraps these: returns `(nil, errmsg, class)` on failure with
`class ∈ {forbidden, not_found, error}` mapped from `errno`
(EACCES/EPERM → `forbidden`, ENOENT → `not_found`). `write_fd`/`close_fd`
operate on the already-opened fd as root (no privilege change — the
permissions are fixed at open time).

### 3. Integration

- `fileutil.sink_to_file(file_path, reader, perfmarkers, owner)`: when
  `owner` is set, parent dirs and the file are opened via `asuser`
  (owned by the mapped user); data is then streamed by the root worker over
  the fd. The legacy root path is unchanged (including the existing
  `io.open` write-error handling, now checked properly). Third return value
  carries the error class for HTTP status mapping.
- `webdav_write_content.lua`: DELETE via `asuser.unlink` when mapped
  (EACCES → 403, ENOENT → 404, else 500); PUT sink errors map
  `forbidden` → 403, `not_found` → 404, else 500 (was: always 500).
- `webdav_tpc_content.lua` (COPY): passes `ngx.ctx.fs_owner` to the same
  sink.
- `conf.d/default.conf`: `lua_shared_dict usermap_cache 10m;`.
- `nginx.dockerfile`: builds and installs `as_user.so`.

### 4. Reads — phase split

- **Phase 1 (this change, write path only):** nginx core keeps serving
  GET/HEAD (alias + autoindex) as root. Any token with the read scope can
  still read any file — a locked-in, documented limitation (test
  `test_read_by_any_authenticated_user_phase1`).
- **Phase 2 (read path):** route GET/HEAD through `asuser.open_for_read` +
  `fstat` on the fd (metadata via `fstat` needs no privilege: the fd is
  already open); replace core `autoindex` with a listing generated as the
  mapped user (core autoindex as root is an enumeration leak — it lists
  every file in the tree to any read-scoped token). After this, read access
  is enforced by the filesystem per mapped user. Note: because root reads
  everything today, phase 2 will turn some currently-200 reads into 403 —
  that is the intent, but sites must be told.

## Group credentials

The switch sets **both** effective uid and effective gid (`setegid` before
`seteuid`), so new files are owned `uid:primary_gid` and creation in
directories group-owned by that gid succeeds. Supplementary groups (FQAN →
`setgroups` via NSS) are a documented extension: needed only for
group-writable dirs whose group is not the user's primary group. Verified
in the image that without `setgroups`, group membership stays `{gid 0 or
primary}` — fine for the common HPC layout of user-owned or
setgid-primary-group directories.

## Non-root workers with capabilities (empirically verified)

The intended future deployment runs the worker as a non-root user with the
Linux capabilities that allow changing user/groups (`CAP_SETUID`,
`CAP_SETGID`). Verified in the image (AlmaLinux 9, kernel 6.x):

- **How the worker gets the capabilities**: file capabilities on the binary
  — `setcap "cap_setuid+ep cap_setgid+ep" <nginx binary>` plus a non-root
  container user. The other mechanisms do *not* work (verified): a plain
  `execve` drops process capabilities (container `--cap-add` on the init
  process does not reach a non-root nginx), and a root master that
  `setuid()`s down to the worker uid loses them — `setuid(0→N)` **clears
  the permitted set** (the inheritable set is not merged into permitted),
  leaving the worker with zero capabilities.
- **The switch sequence is unchanged**: `setegid(G)` → `seteuid(U)` → one
  syscall → `seteuid(worker)` → `setegid(worker)` round-trips correctly
  from a non-root worker with file caps — including repeated round-trips,
  with correct file ownership. Verified end-to-end against the production
  `as_user.c` (linked, `setcap`'d, run as uid 2000): mkdirp/open/write/
  rename/unlink all OK, `stat` shows the mapped uid:gid, `..` traversal
  still rejected, and the same binary run as a non-root user *without* the
  caps fails every call with EPERM (the guard).
- **Why restore cannot wedge**: restoring to the worker's real uid/gid is
  unprivileged (target equals the real credential), so even a hypothetical
  loss of the effective cap set mid-sequence cannot block the restore. The
  kernel keeps the effective set as `effective ∩ permitted` across a
  `seteuid` between non-zero uids (observed: the caps stay effective
  across the entire round-trip).
- **Ordering**: `setegid` must precede `seteuid` and the gid restore must
  follow the uid restore — after `seteuid(U)`, further gid changes are
  subject to the mapped user's own privileges (a non-root `setgid` fails
  with EPERM — verified).
- **Behavior change to note**: with the feature disabled (no
  `user_mapping`), files are created as the *worker's own identity* — the
  worker uid under a non-root deployment, not root. Likewise
  `on_missing: "root"` means "serve as the worker's own identity" (root in
  the current deployment).

## Threat model / edge cases

- Mapping input is only ever a *verified* JWT; uid 0 is denied by default;
  uid range check blocks mapping into unexpected accounts; the fallback uid
  is subject to the same checks.
- C module: the worker must have a clean identity (uid == euid, gid ==
  egid) and `CAP_SETUID`+`CAP_SETGID` in the effective set (root passes
  trivially); otherwise every call fails with EPERM (fails closed —
  verified: a non-root process without the caps gets EPERM from every
  call); path containment check inside the C code (not just Lua);
  effective-only credentials, always restored to the captured worker
  identity.
- `getpwnam` blocking via NSS: cached (10 min TTL); cold-cache cost is one
  NSS lookup per account — bounded and acceptable.
- Parent directories must be writable by the mapped user — sites pre-create
  the store tree (group-owned, setgid); user-mode `mkdirp` turns EACCES
  into a 403 instead of silently creating a root-owned directory.
- Partial uploads are still cleaned up by the root worker (`os.remove`),
  which can always unlink (it owns the tmpfs/store root).
- AlmaLinux containers run SELinux permissive by default; MLS-aware sites
  need an SELinux context for user-created files (out of scope, note it).
- Compatibility: fully opt-in. Unconfigured sites see zero behavior change
  (verified by the existing suite + `test_feature_disabled_stays_root`).

## Testing (pytest harness)

Two dedicated containers with `user_mapping` enabled (created accounts
`testuser` uid 10001, `testuser2` uid 10002; mock IdP extended to issue
tokens with a `name` claim):

- PUT as `testuser` → 201; `stat -c %u %g` in the container shows 10001:10001;
  adler32 `Digest` header still returned.
- PUT into a nested path → all created parent dirs owned 10001.
- PUT with an unmapped `name` (no fallback) → 403, nothing created.
- PUT into a `0700` dir owned by `testuser2` → 403, nothing created.
- DELETE of a file in a foreign `0700` dir → 403, file remains; DELETE by
  the directory owner → 204.
- Fallback server: unmapped `name` → file owned by 65534 (nobody); mapped
  accounts still take precedence.
- Phase-1 read behavior locked in (any read-scoped token reads any file).
- Feature disabled (shared session server) → files still root-owned even
  when the token carries a `name` claim.

## Files touched

- `nginx/as_user.c` (new)
- `nginx/lua/asuser.lua` (new)
- `nginx/lua/usermap.lua` (new)
- `nginx/lua/config.lua` (`user_mapping` default)
- `nginx/lua/webdav_access.lua` (mapping step after verification)
- `nginx/lua/fileutil.lua` (owner-aware `sink_to_file`)
- `nginx/lua/webdav_write_content.lua`, `nginx/lua/webdav_tpc_content.lua`
  (pass `ngx.ctx.fs_owner`; errno → 403/404 mapping)
- `nginx/conf.d/default.conf` (`usermap_cache` shared dict)
- `nginx/nginx.dockerfile` (build/install `as_user.so`)
- `tests/conftest.py`, `tests/test_user_ownership.py`
