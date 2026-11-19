"""Regression tests for the bulk-fixes branch.

Each test targets one of the issues fixed on this branch:

- #82  sink_to_file must not crash when a disk write fails
- #85  xattr helpers: setxattr error reporting, ENODATA, second xattr location
- #86  DEBUG=true must not add a stray server block on port 80
- #92  DELETE must refuse directories, including the storage root
- #89  /redirect must answer 404 (not 500) and must not match /redirectfoo
- #100 the image must not ship libuv-devel, and .upload must not be listed
"""
import subprocess

import httpx

from .util import assert_status


def _podman_exec(container_id: str, *cmd: str) -> str:
    """Run a command in the test container and return its stdout."""
    return subprocess.check_output(
        ["podman", "exec", "-i", container_id, *cmd], text=True
    )


def test_put_disk_full_is_clean_error(
    nginx_server: str,
    setup_server,
    wlcg_create_header: dict[str, str],
):
    # The storage tmpfs is 100M. Fill it so that a large PUT fails mid-write
    # (issue #82).
    fill = "/var/www/webdav/.fill.bin"
    target = "/var/www/webdav/diskfull.bin"
    _podman_exec(
        setup_server.container_id,
        "dd", "if=/dev/zero", f"of={fill}", "bs=1M", "count=95", "status=none",
    )
    try:
        body = (b"x" * (1024 * 1024) for _ in range(30))
        try:
            response = httpx.put(
                f"{nginx_server}/diskfull.bin",
                headers=wlcg_create_header,
                content=body,
                timeout=httpx.Timeout(60.0),
            )
            # If the client gets a response, it must be a proper error, not
            # an nginx error page or a partial success
            assert response.status_code == 500, response.text
            assert "failed to write" in response.text
        except httpx.HTTPError as e:
            # The client can be reset while the server stops reading the
            # body; the server-side state below is the real assertion
            print(f"client-side error during disk-full PUT: {e!r}")

        # The partial file must have been cleaned up by the error path.
        # Pre-fix the handler crashed on file:close() of nil (the write
        # result overwrote the file handle) and left the partial file in
        # place, visible in directory listings
        listing = _podman_exec(setup_server.container_id, "ls", "/var/www/webdav")
        assert "diskfull.bin" not in listing.split(), (
            "partial file left behind after disk-full PUT"
        )
    finally:
        _podman_exec(setup_server.container_id, "rm", "-f", fill)
        _podman_exec(setup_server.container_id, "rm", "-f", target)


