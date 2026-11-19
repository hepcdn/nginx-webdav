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


def test_cksumutil_xattr_helpers(setup_server):
    # Unit-check the xattr helpers directly in the test container (issue
    # #85). Pre-fix code reports a missing xattr as an error, never reports
    # setxattr failures, and never reads the second xattr location.
    script = r"""
package.path = "/etc/nginx/lua/?.lua;" .. package.path
package.loaded["config"] = {data = {}}
local c = require("cksumutil")
local path = "/tmp/.xattr_unit_test.txt"
local f = assert(io.open(path, "w"))
f:write("hello xattr")
f:close()
local ok, err = pcall(function()
    -- a missing xattr is not an error
    local e1, v1 = c.getxattr(path, "user.nginx-webdav.adler32")
    assert(e1 == nil and v1 == nil,
        "missing xattr reported as error: " .. tostring(e1))
    -- a setxattr failure must be reported
    local e2 = c.setxattr("/nonexistent/.xattr_unit_target", "user.x", "y")
    assert(type(e2) == "string" and e2:find("Error"),
        "setxattr failure not reported: " .. tostring(e2))
    -- check_adler32 must find a value stored only in the second location
    assert(c.setxattr(path, "user.nginx-webdav.adler32", "cafebabe") == nil)
    local e3, v3 = c.check_adler32(path)
    assert(e3 == nil and v3 == "cafebabe",
        "second xattr location not checked: " .. tostring(e3) .. " " .. tostring(v3))
end)
os.remove(path)
assert(ok, "xattr helper unit test failed: " .. tostring(err))
print("XATTR_OK")
"""
    out = _podman_exec(setup_server.container_id, "luajit", "-e", script)
    assert "XATTR_OK" in out


