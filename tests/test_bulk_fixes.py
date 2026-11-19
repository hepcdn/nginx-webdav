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


def test_debug_mode_no_stray_server(setup_server):
    # The test server runs with DEBUG=true (issue #86): the generated
    # site.conf must contain exactly one server block, and there must be no
    # listener on port 80 inside the container
    conf = _podman_exec(
        setup_server.container_id, "cat", "/etc/nginx/conf.d/site.conf"
    )
    assert conf.count("server {") == 1, conf
    assert "lua_code_cache off;" in conf

    # With lua_code_cache off, modules are re-required on every request, so
    # the config must self-load on require; the health endpoint proves the
    # loaded values are in use (-1 is the pre-config default)
    base = setup_server.hosturl.rsplit("/webdav", 1)[0]
    response = httpx.get(f"{base}/webdav_health")
    assert_status(response, httpx.codes.OK)
    assert "OK -1" not in response.text

    tcp = _podman_exec(
        setup_server.container_id, "cat", "/proc/net/tcp", "/proc/net/tcp6"
    )
    listening = set()
    for line in tcp.splitlines():
        parts = line.split()
        # /proc/net/tcp rows: sl local_address rem_address st ...
        if len(parts) >= 4 and parts[3] == "0A":  # 0A = LISTEN
            listening.add(int(parts[1].rsplit(":", 1)[1], 16))
    assert 80 not in listening, f"unexpected listener on port 80: {sorted(listening)}"


def test_delete_directory_refused(
    nginx_server: str,
    setup_server,
    wlcg_modify_header: dict[str, str],
):
    # Recursive collection deletion is not implemented, so DELETE on a
    # directory must be refused rather than silently removing it (issue #92)
    _podman_exec(
        setup_server.container_id, "mkdir", "-p", "/var/www/webdav/test_del_dir"
    )
    response = httpx.delete(
        f"{nginx_server}/test_del_dir/", headers=wlcg_modify_header
    )
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "cannot delete a directory" in response.text
    listing = _podman_exec(setup_server.container_id, "ls", "/var/www/webdav")
    assert "test_del_dir" in listing.split()

    # The storage root is protected as well
    response = httpx.delete(f"{nginx_server}/", headers=wlcg_modify_header)
    assert_status(response, httpx.codes.FORBIDDEN)

    # Plain files can still be deleted
    path = f"{nginx_server}/test_del_file.txt"
    response = httpx.put(
        path, headers=wlcg_modify_header, content="delete me"
    )
    assert_status(response, httpx.codes.CREATED)
    response = httpx.delete(path, headers=wlcg_modify_header)
    assert_status(response, httpx.codes.NO_CONTENT)
    _podman_exec(
        setup_server.container_id, "rmdir", "/var/www/webdav/test_del_dir"
    )


