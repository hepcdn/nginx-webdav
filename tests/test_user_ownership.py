"""Tests for per-user file ownership (token -> unix account mapping).

Design: docs/design/per-user-file-ownership.md

When `user_mapping` is configured, the verified token's claim (default:
`name`, per the WLCG common JWT profile) selects the local unix account
used for file I/O, so files are created owned by that account and POSIX
permissions are enforced at open() time.
"""

import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Iterable

import httpx
import pytest

from .conftest import MockIdP, ServerInstance

WRITE_SCOPE = "openid offline_access storage.read:/ storage.create:/ storage.modify:/"

TESTUSER = (10001, 10001)
TESTUSER2 = (10002, 10002)
# Primary gid (20003) differs from the uid (10003): used to prove that the
# mapped user's group is set independently of the uid.
TESTUSER3 = (10003, 20003)


def _uid_gid(container_id: str, relpath: str) -> tuple[int, int]:
    out = subprocess.check_output(
        [
            "podman",
            "exec",
            container_id,
            "stat",
            "-c",
            "%u %g",
            f"/var/www/webdav/{relpath}",
        ]
    ).decode().strip()
    uid, gid = out.split()
    return int(uid), int(gid)


def _exists(container_id: str, relpath: str) -> bool:
    return (
        subprocess.run(
            ["podman", "exec", container_id, "test", "-e", f"/var/www/webdav/{relpath}"]
        ).returncode
        == 0
    )


def _mkdir(container_id: str, relpath: str, uid: int, gid: int, mode: str):
    subprocess.check_call(
        [
            "podman",
            "exec",
            container_id,
            "bash",
            "-c",
            f"mkdir -p /var/www/webdav/{relpath} && "
            f"chown {uid}:{gid} /var/www/webdav/{relpath} && "
            f"chmod {mode} /var/www/webdav/{relpath}",
        ],
        stdout=subprocess.DEVNULL,
    )


def _token_headers(idp: MockIdP, name: str) -> dict[str, str]:
    return {
        "Authorization": "Bearer "
        + idp.make_wlcg_token(WRITE_SCOPE, sub="user123", client_id="user123", name=name)
    }


def test_put_file_owned_by_mapped_user(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    headers = _token_headers(oidc_mock_idp, "testuser")
    headers["Want-Digest"] = "adler32"
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_file.txt",
        headers=headers,
        content=b"ownership test data",
    )
    assert r.status_code == 201, r.text
    # The adler32 digest must still be computed on the new write path
    assert r.headers.get("Digest", "").startswith("adler32="), dict(r.headers)
    assert _uid_gid(usermapped_server.container_id, "um_file.txt") == TESTUSER


def test_put_creates_directories_as_user(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    r = httpx.put(
        f"{usermapped_server.hosturl}/umdir/sub/file.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"nested",
    )
    assert r.status_code == 201, r.text
    assert _uid_gid(usermapped_server.container_id, "umdir") == TESTUSER
    assert _uid_gid(usermapped_server.container_id, "umdir/sub") == TESTUSER
    assert _uid_gid(usermapped_server.container_id, "umdir/sub/file.txt") == TESTUSER


def test_created_directories_use_mapped_group(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # testuser3 has uid 10003 but primary gid 20003: every created
    # directory (and the file) must be owned by the mapped user AND by the
    # mapped user's primary group. This proves the egid switch is
    # independent of the euid switch (a bug that set the gid to the uid,
    # or left it as the worker's gid 0, would fail here).
    r = httpx.put(
        f"{usermapped_server.hosturl}/umgrp/a/b/file.txt",
        headers=_token_headers(oidc_mock_idp, "testuser3"),
        content=b"grp",
    )
    assert r.status_code == 201, r.text
    assert _uid_gid(usermapped_server.container_id, "umgrp") == TESTUSER3
    assert _uid_gid(usermapped_server.container_id, "umgrp/a") == TESTUSER3
    assert _uid_gid(usermapped_server.container_id, "umgrp/a/b") == TESTUSER3
    assert _uid_gid(usermapped_server.container_id, "umgrp/a/b/file.txt") == TESTUSER3


def test_put_unmapped_user_rejected(usermapped_server: ServerInstance, oidc_mock_idp: MockIdP):
    # No local account named "ghostuser" and no fallback configured
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_ghost.txt",
        headers=_token_headers(oidc_mock_idp, "ghostuser"),
        content=b"ghost",
    )
    assert r.status_code == 403, r.text
    assert not _exists(usermapped_server.container_id, "um_ghost.txt")


def test_put_into_foreign_directory_rejected(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # A 0700 directory owned by testuser2: testuser must not be able to
    # create files inside it
    _mkdir(usermapped_server.container_id, "umpriv", *TESTUSER2, "700")
    r = httpx.put(
        f"{usermapped_server.hosturl}/umpriv/f.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"forbidden",
    )
    assert r.status_code == 403, r.text
    assert not _exists(usermapped_server.container_id, "umpriv/f.txt")


def test_delete_foreign_file_rejected(usermapped_server: ServerInstance, oidc_mock_idp: MockIdP):
    # testuser2 owns a 0700 directory and writes a file into it
    _mkdir(usermapped_server.container_id, "umpriv2", *TESTUSER2, "700")
    r = httpx.put(
        f"{usermapped_server.hosturl}/umpriv2/secret.txt",
        headers=_token_headers(oidc_mock_idp, "testuser2"),
        content=b"secret",
    )
    assert r.status_code == 201, r.text
    assert _uid_gid(usermapped_server.container_id, "umpriv2/secret.txt") == TESTUSER2

    # testuser cannot delete it: no write permission on the directory
    r = httpx.delete(
        f"{usermapped_server.hosturl}/umpriv2/secret.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
    )
    assert r.status_code == 403, r.text
    assert _exists(usermapped_server.container_id, "umpriv2/secret.txt")

    # testuser2 can delete it
    r = httpx.delete(
        f"{usermapped_server.hosturl}/umpriv2/secret.txt",
        headers=_token_headers(oidc_mock_idp, "testuser2"),
    )
    assert r.status_code == 204, r.text
    assert not _exists(usermapped_server.container_id, "umpriv2/secret.txt")


def test_fallback_user(
    usermapped_fallback_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # Unknown account -> fallback uid/gid (65534 = nobody)
    r = httpx.put(
        f"{usermapped_fallback_server.hosturl}/fb_ghost.txt",
        headers=_token_headers(oidc_mock_idp, "ghostuser"),
        content=b"fallback",
    )
    assert r.status_code == 201, r.text
    assert (
        _uid_gid(usermapped_fallback_server.container_id, "fb_ghost.txt")
        == (65534, 65534)
    )

    # Mapped accounts still take precedence over the fallback
    r = httpx.put(
        f"{usermapped_fallback_server.hosturl}/fb_mapped.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"mapped",
    )
    assert r.status_code == 201, r.text
    assert _uid_gid(usermapped_fallback_server.container_id, "fb_mapped.txt") == TESTUSER


def test_read_by_any_authenticated_user_phase1(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # Phase 1 limitation, locked in here: the read path is still served by
    # the (root) nginx core, so any token with the read scope can read any
    # file, regardless of its owner. The read path gets mapped ownership
    # only in phase 2.
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_read.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"readable by all for now",
    )
    assert r.status_code == 201, r.text
    r = httpx.get(
        f"{usermapped_server.hosturl}/um_read.txt",
        headers=_token_headers(oidc_mock_idp, "testuser2"),
    )
    assert r.status_code == 200, r.text
    assert r.content == b"readable by all for now"


def test_feature_disabled_stays_root(setup_server: ServerInstance, oidc_mock_idp: MockIdP):
    # The shared session server has no user_mapping configured: even a token
    # with a `name` claim performs file I/O as root (legacy behavior).
    # (testuser does not even exist in that container, which would also
    # prove it is never consulted.)
    r = httpx.put(
        f"{setup_server.hosturl}/legacy_file.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"legacy",
    )
    assert r.status_code == 201, r.text
    assert _uid_gid(setup_server.container_id, "legacy_file.txt") == (0, 0)


def test_root_account_denied_by_default(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # The server's user_mapping config has no explicit deny_uids: the
    # default {0} must still reject a token that maps to the root account,
    # otherwise a `name: root` token would silently perform all file I/O
    # (including directory creation) as root.
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_root.txt",
        headers=_token_headers(oidc_mock_idp, "root"),
        content=b"root",
    )
    assert r.status_code == 403, r.text
    assert not _exists(usermapped_server.container_id, "um_root.txt")


def test_token_without_claim_denied(
    usermapped_guards_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # on_missing=deny: a token without the claim is rejected instead of
    # silently falling back to the worker's identity (root)
    headers = {
        "Authorization": "Bearer "
        + oidc_mock_idp.make_wlcg_token(WRITE_SCOPE, sub="user123", client_id="user123")
    }
    r = httpx.put(
        f"{usermapped_guards_server.hosturl}/g_noclaim.txt",
        headers=headers,
        content=b"no claim",
    )
    assert r.status_code == 403, r.text
    assert not _exists(usermapped_guards_server.container_id, "g_noclaim.txt")


def test_uid_out_of_range_denied(
    usermapped_guards_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # testuser4 (uid 10100) is outside the configured range [10000, 10010]
    r = httpx.put(
        f"{usermapped_guards_server.hosturl}/g_range.txt",
        headers=_token_headers(oidc_mock_idp, "testuser4"),
        content=b"out of range",
    )
    assert r.status_code == 403, r.text
    assert not _exists(usermapped_guards_server.container_id, "g_range.txt")


def test_uid_in_range_allowed(
    usermapped_guards_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # testuser (uid 10001) is inside the range: the mapping applies and the
    # file is owned by the mapped user
    r = httpx.put(
        f"{usermapped_guards_server.hosturl}/g_ok.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"in range",
    )
    assert r.status_code == 201, r.text
    assert _uid_gid(usermapped_guards_server.container_id, "g_ok.txt") == TESTUSER


def test_denied_lookups_are_cached(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # First lookup misses and caches the denial (10 min TTL)...
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_cache.txt",
        headers=_token_headers(oidc_mock_idp, "ghostcache"),
        content=b"ghost",
    )
    assert r.status_code == 403, r.text
    # ...so creating the account afterwards must not take effect until the
    # cached denial expires.
    subprocess.check_call(
        [
            "podman",
            "exec",
            usermapped_server.container_id,
            "bash",
            "-c",
            "groupadd -g 10005 ghostcache_grp && "
            "useradd -u 10005 -g 10005 -d /nonexistent ghostcache",
        ],
        stdout=subprocess.DEVNULL,
    )
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_cache.txt",
        headers=_token_headers(oidc_mock_idp, "ghostcache"),
        content=b"ghost",
    )
    assert r.status_code == 403, "the cached denial must outlive the account creation"


class _TpcSourceHandler(BaseHTTPRequestHandler):
    """Minimal RFC 3230 source for TPC pull tests (local host port 8083)."""

    def do_GET(self):
        if self.path != "/hello.txt":
            self.send_response(404)
            self.end_headers()
            return
        data = b"Hello, world!"
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.send_header("Content-length", str(len(data)))
        self.send_header("Digest", "adler32=205e048a")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def tpc_source() -> Iterable[str]:
    httpd = HTTPServer(("", 8083), _TpcSourceHandler)
    thread = Thread(target=httpd.serve_forever)
    thread.start()
    yield "http://host.docker.internal:8083"
    httpd.shutdown()
    thread.join()


def test_tpc_copy_owned_by_mapped_user(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP, tpc_source: str
):
    # TPC COPY goes through the same owner-aware sink as PUT: both the
    # destination directory it creates and the file must be owned by the
    # mapped user.
    headers = _token_headers(oidc_mock_idp, "testuser")
    headers["Source"] = f"{tpc_source}/hello.txt"
    headers["TransferHeaderAuthorization"] = "Bearer opensesame"
    r = httpx.request(
        "COPY", f"{usermapped_server.hosturl}/tpcdst/tpc_um.txt", headers=headers
    )
    assert r.status_code == 202, r.text
    assert r.text.splitlines()[-1] == "success: Created", r.text
    assert _uid_gid(usermapped_server.container_id, "tpcdst") == TESTUSER
    assert _uid_gid(usermapped_server.container_id, "tpcdst/tpc_um.txt") == TESTUSER


def test_checksum_xattr_written_as_owner(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # The adler32 checksum xattr is persisted after the write; verify it is
    # present on the file and carries exactly the digest reported to the
    # client. (That it is written with the mapped user's credentials rather
    # than the root worker's is pinned down by the as_user.c unit tests:
    # the setxattr there is denied for files the mapped user cannot write.)
    r = httpx.put(
        f"{usermapped_server.hosturl}/um_xattr.txt",
        headers={**_token_headers(oidc_mock_idp, "testuser"), "Want-Digest": "adler32"},
        content=b"ownership test data",
    )
    assert r.status_code == 201, r.text
    digest = r.headers["Digest"].removeprefix("adler32=")
    out = subprocess.check_output(
        [
            "podman",
            "exec",
            usermapped_server.container_id,
            "/usr/local/openresty/luajit/bin/luajit",
            "-e",
            "\n".join(
                [
                    "local ffi = require 'ffi'",
                    "ffi.cdef[[int getxattr(const char*,const char*,void*,size_t);]]",
                    "local b = ffi.new('char[64]')",
                    "local n = ffi.C.getxattr('/var/www/webdav/um_xattr.txt',",
                    "    'user.nginx-webdav.adler32', b, 63)",
                    "if n < 0 then os.exit(1) end",
                    "print(ffi.string(b, n))",
                ]
            ),
        ]
    ).decode().strip()
    assert out == digest, f"xattr {out!r} != digest {digest!r}"


def test_put_to_broken_symlink_not_found(
    usermapped_server: ServerInstance, oidc_mock_idp: MockIdP
):
    # ENOENT on the write path maps to 404 (was: always 500 before this
    # feature): a symlinked directory component that points at a missing
    # path makes the (mapped user's) open() fail with ENOENT rather than
    # a permission error. (The target must be nested: useradd on this
    # platform honors CREATE_HOME and would create a single-component home
    # directory like /nonexistent on its own.)
    subprocess.check_call(
        [
            "podman",
            "exec",
            usermapped_server.container_id,
            "bash",
            "-c",
            "ln -s /does/not/exist /var/www/webdav/umbroken",
        ],
        stdout=subprocess.DEVNULL,
    )
    r = httpx.put(
        f"{usermapped_server.hosturl}/umbroken/f.txt",
        headers=_token_headers(oidc_mock_idp, "testuser"),
        content=b"broken",
    )
    assert r.status_code == 404, f"{r.status_code}: {r.text}"
    assert not _exists(usermapped_server.container_id, "umbroken/f.txt")


def test_c_module_unit_tests(usermapped_server: ServerInstance):
    # Re-run the as_user.c unit tests (shipped in the image) in the running
    # runtime: the root mode proves the effective-uid/gid switch, path
    # containment and the errno convention; the nonroot mode proves the
    # fail-closed guard for workers without CAP_SETUID/CAP_SETGID.
    for mode in ("root", "nonroot"):
        r = subprocess.run(
            [
                "podman",
                "exec",
                usermapped_server.container_id,
                "/usr/local/bin/test_as_user",
                mode,
            ],
            capture_output=True,
        )
        assert r.returncode == 0, f"{mode} mode failed:\n{r.stdout.decode()}"
        assert b"0 failures" in r.stdout
