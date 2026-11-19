"""Tests for per-user file ownership (token -> unix account mapping).

Design: docs/design/per-user-file-ownership.md

When `user_mapping` is configured, the verified token's claim (default:
`name`, per the WLCG common JWT profile) selects the local unix account
used for file I/O, so files are created owned by that account and POSIX
permissions are enforced at open() time.
"""

import subprocess

import httpx

from .conftest import MockIdP, ServerInstance

WRITE_SCOPE = "openid offline_access storage.read:/ storage.create:/ storage.modify:/"

TESTUSER = (10001, 10001)
TESTUSER2 = (10002, 10002)


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
