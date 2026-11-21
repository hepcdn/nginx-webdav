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

### Why not pure FFI (no compiled module)?

Mechanically, pure FFI works: `ffi.C.setegid`/`ffi.C.seteuid`/`ffi.C.open`
are the same libc calls the C module makes, and a Lua-level sequence
(verified in the image) produces correctly owned files. The C module is
not about *being able to call C* — FFI does that — it is about which side
of the language boundary the switch window lives on:

- In the C module the whole sequence is **one C frame**: a LuaJIT
  coroutine cannot yield inside a C frame, so the window is atomic with
  respect to every other request *by construction*.
- In a Lua FFI sequence the window is five separate `ffi.C` calls with
  instruction boundaries between them. Verified in this build (OpenResty
  1.31.8.1): the scheduler does **not** preempt — a 3 s no-yield FFI loop
  pinned the worker and a concurrent request only ran after the loop
  finished (the looping coroutine observed none of its side effects). So
  a carefully written FFI sequence is safe *today*.
- But that is luck, not an invariant. Anything placed between the switch
  and the restore — a yielding `ngx.*`/`lua-resty` call, a `pcall`
  boundary, or any Lua error (string handling, an FFI misuse) unwinding
  past the restore line — leaks the switched identity for the rest of the
  worker's lifetime. In the C module the restore is inside the same C
  frame, unreachable from Lua errors, so state can never leak. Likewise,
  if a future OpenResty gains signal-based preemption of running Lua
  code, the FFI window silently becomes unsafe; the C window is immune.
- The fail-closed identity/capability guard, the path-containment check
  and the negated-errno convention also live in one machine-checkable
  place instead of being re-derived and code-reviewed in Lua.

The C module's cost is one `gcc -shared` line in a build that already
compiles OpenResty, zlib and luaposix — it adds no new class of artifact
to the image.

## Implementation

### 1. Identity mapping — `nginx/lua/usermap.lua` (new)

Called from `webdav_access.lua` immediately after `bearer_jwt_verify`
succeeds. Opt-in: when `user_mapping` is absent or empty, `resolve()`
returns nil and all file I/O keeps running as root, exactly like before.

The unix account is chosen by exactly one of two mechanisms:

- **`map` (recommended): an explicit `sub` → account table.** The key is
  the verified `sub` claim — immutable and assigned by the IdP, so the
  user cannot change it — and the value is the unix account to use. Only
  listed identities are mapped; everything else follows `on_missing`.
  This also prevents the coincidence problem of claim-based lookup: an
  IAM username that merely happens to match a local account name is never
  mapped unless it is explicitly listed.
- **claim-based (no `map`):** the configured `claim` JWT claim is looked
  up with `getpwnam(3)`. The default claim is `preferred_username` — the
  WLCG profile's login name, which IAM instances treat as the account's
  username rather than a freely editable display name. The `name` claim
  must not be used: in OIDC it is the user's *display name*, which users
  can edit, so mapping it through `getpwnam` lets any user point it at a
  local account they can guess (e.g. setting the display name to
  "cmsprod").

Config (`config.json`):

```json
"user_mapping": {
  "map": {
    "https://iam.example.org/uid-12345": "alice",
    "https://iam.example.org/uid-67890": "bob"
  },
  "claim": "preferred_username",
  "on_missing": "deny",
  "deny_uids": [0],
  "uid_range": [1000, 65534],
  "fallback": { "uid": 65534, "gid": 65534 }
}
```

- `map`: see above; when present (non-empty) the `claim` setting is
  ignored and the `sub` claim is the only mapping input.
- `claim` (default `preferred_username`): only consulted without a `map`.
- `on_missing` (`deny` default | `root`): tokens that do not resolve to
  an account are rejected, or (opt-in legacy behavior) served as the
  worker's own identity. The default is `deny` because the alternative is
  dangerous with this feature enabled: a client-credentials token has no
  user claims at all, so with `root` any registered IAM client with
  storage scopes would bypass the mapping and write as root.
- Guards: mapped uid in `deny_uids` (root by default) or outside
  `uid_range` → 403. No local account → 403, or the configured `fallback`
  account (e.g. `nobody`) — fallback uids pass through the same guards,
  so a configured `uid_range` must include the fallback uid.
- Lookup via `posix.getpwnam`; results and denials cached in
  `lua_shared_dict usermap_cache 10m` keyed by `<claim>=<value>`
  (or `sub=<value>` in map mode), 10 min TTL. `getpwnam` goes through NSS
  and may hit LDAP/NIS — cached, so a slow directory only costs the first
  request per account.
- Result: `ngx.ctx.fs_owner = {uid, gid}` (nil = root).

### 2. Privileged syscalls — `nginx/as_user.c` (new) + `nginx/lua/asuser.lua` (new)

`as_user.c` exports five functions, each a single straight-line sequence as
described above; all paths are validated to stay under the configured
storage root (a `..` path segment is rejected — defense in depth on the
existing traversal fix). The C file is compiled into `as_user.so` during the
image build (`gcc -O2 -Wall -Wextra -shared -fPIC`) and loaded by
`asuser.lua` via `ffi.load` (same FFI pattern as `cksumutil.lua`).
`nginx/test_as_user.c` unit-tests the module directly (effective-uid/gid
switch, path containment, errno convention, fail-closed guard without
CAP_SETUID) and is compiled and run in the image build stage, so a
regression fails the build; the binary is also shipped to
`/usr/local/bin/test_as_user` and re-run by the pytest suite.

| Function | Used by |
|---|---|
| `as_user_mkdirp(uid, gid, root, path, mode)` | PUT/TPC parent dir creation (recursive; `EEXIST` tolerated for concurrent writers) |
| `as_user_open(uid, gid, root, path, flags, mode)` | PUT open-for-write (`0644`); `asuser.open_for_read` for the phase-2 read path |
| `as_user_unlink(uid, gid, root, path)` | DELETE |
| `as_user_rename(uid, gid, root, src, dst)` | reserved for MOVE |
| `as_user_setxattr(uid, gid, root, path, name, value, size, flags)` | adler32 checksum xattr persistence (write path + read-path backfill), so metadata writes are subject to the file's POSIX permissions |

`asuser.lua` wraps these: returns `(nil, errmsg, class)` on failure with
`class ∈ {forbidden, not_found, error}` mapped from `errno`
(EACCES/EPERM → `forbidden`, ENOENT → `not_found`). `write_fd`/`close_fd`
operate on the already-opened fd (no privilege change — the permissions
are fixed at open time). `as_user_write` loops until the whole buffer is
in: `write()` can return a short count on a regular file (typically just
before ENOSPC, or after an interrupting signal), and a short write that
is not retried would leave the adler32 xattr covering data that is not in
the file while the upload reports success. `as_user.so` is loaded lazily
on the first `asuser` call (every call site is on the mapped-owner path),
so a deployment without the library — feature disabled, or the README's
development workflow that mounts `./nginx/lua` into a prebuilt image —
never touches `ffi.load`.

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
`seteuid`), and — since the supplementary-groups review finding — drops
the worker's supplementary group list for the duration of the switched
call (`setgroups(0, NULL)`, captured on the first switch and restored on
every way out). The drop is required, not cosmetic: a root worker's group
0 is in its supplementary list, so without the drop every mapped user
could reach any group-root, group-writable path — the `chgrp 0` +
`chmod g=u` layout used by OpenShift-style storage and by this repo's own
Dockerfile. New files are owned `uid:primary_gid`; the worker's own
(unmapped) file I/O is unaffected because the list is restored after each
call. Setting the mapped user's *own* supplementary groups (FQAN →
`setgroups` via NSS) is a documented extension: it is the same
plumbing, and is only needed for group-writable dirs whose group is not
the user's primary group. Verified in the image that the drop/restore
round-trips correctly (unit test: a group-writable directory owned by the
worker's supplementary group is unreachable for the mapped user while the
switch is active, and the worker's groups are intact afterwards).

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

- Mapping input is only ever a *verified* JWT. In the recommended `map`
  mode the input is the `sub` claim (immutable, IdP-assigned) and only
  explicitly listed subs are mapped — a user cannot steer the mapping by
  editing any claim, and an IAM username that coincides with a local
  account name is not mapped by accident. In claim mode the default claim
  is `preferred_username` (the login name, not the editable display name
  `name`). Tokens that do not resolve to an account are rejected by
  default (`on_missing: "deny"`), so a claim-less client-credentials
  token cannot bypass the mapping and write as root. uid 0 is denied by
  default; the uid range check blocks mapping into unexpected accounts;
  the fallback uid is subject to the same checks.
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
- Partial uploads are cleaned up with the *mapped user's* credentials
  (`asuser.unlink`) when the feature is enabled, never by a root
  `os.remove`: with the root delete, a user who may overwrite a file but
  not unlink it (write on the file, none on its directory) could start an
  overwriting PUT, disconnect mid-transfer, and make root remove a file
  the user is not allowed to delete. The user's own `unlink` fails with
  EACCES in that case, which is the correct outcome (the file remains,
  truncated).
- AlmaLinux containers run SELinux permissive by default; MLS-aware sites
  need an SELinux context for user-created files (out of scope, note it).
- Compatibility: fully opt-in. Unconfigured sites see zero behavior change
  (verified by the existing suite + `test_feature_disabled_stays_root`).

## Testing (pytest harness)

Four dedicated containers with `user_mapping` enabled (accounts created
in each; mock IdP extended to issue tokens with `name` and
`preferred_username` claims):

- `claim: name` (strict):
  - PUT as `testuser` → 201; `stat -c %u %g` in the container shows
    10001:10001; adler32 `Digest` header still returned.
  - PUT into a nested path → all created parent dirs owned 10001.
  - PUT with an unmapped `name` (no fallback) → 403, nothing created.
  - PUT into a `0700` dir owned by `testuser2` → 403, nothing created.
  - DELETE of a file in a foreign `0700` dir → 403, file remains; DELETE
    by the directory owner → 204.
  - `name: root` → 403 (default `deny_uids`).
  - Denied lookups are cached (creating the account afterwards does not
    take effect within the TTL).
  - A mapped user cannot make a failed overwriting PUT delete a
    root-owned file it may write but not unlink: the partial file
    remains (cleanup runs as the mapped user, not root).
  - TPC COPY creates destination dir + file owned by the mapped user;
    adler32 xattr is present and matches the reported digest.
  - `test_as_user` re-run in the runtime (root + nonroot modes).
- `map` mode: a listed `sub` is mapped to the explicitly chosen account
  (PUT → 201, owned by it); an unlisted `sub` → 403; a `sub` that equals
  a local account name but is not listed → 403 (no coincidence mapping).
- Defaults (no `claim`/`on_missing` keys): the `preferred_username` claim
  selects the account (a misleading `name` claim is ignored); a token
  with no usable claim → 403 (default `on_missing: deny`).
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
