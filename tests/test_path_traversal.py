"""Security regression tests for path construction from the request.

fileutil.get_request_local_path() used to build the filesystem path from
ngx.var.request_uri -- the original request line, *including the query
string*. Since the kernel resolves `..` components in the resulting path,
a client could escape the storage directory with a traversal in the query
string, e.g.

    PUT /webdav/f?../../../../etc/pwned   -> wrote /etc/pwned

These tests verify that the query string is ignored when mapping the
request onto the filesystem, and that encoded paths are resolved
consistently between writes (Lua) and reads (static module).
"""

import subprocess

import httpx

from .util import assert_status

# A run of `..` that, if resolved, would climb out of /var/www/webdav
TRAVERSAL_QUERY = "?../../../../../../etc/pwned"


def _container_exec(setup_server, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["podman", "exec", setup_server.container_id, *args],
        capture_output=True,
        text=True,
    )


def test_put_query_string_traversal(
    nginx_server: str,
    setup_server,
    wlcg_create_header: dict[str, str],
):
    """A PUT whose query string contains traversal must not escape the
    storage directory: the file must be stored at the path only, and
    nothing may be written outside /var/www/webdav."""
    data = "Hello, world!" * 1000
    path = "/test_trav.txt"

    response = httpx.put(
        f"{nginx_server}{path}{TRAVERSAL_QUERY}",
        headers=wlcg_create_header,
        content=data,
    )
    assert_status(response, httpx.codes.CREATED)

    # The file must be readable back at the plain path
    response = httpx.get(f"{nginx_server}{path}", headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data

    # Nothing may have been written outside the storage directory
    assert _container_exec(setup_server, "ls", "/etc/pwned").returncode != 0
    assert _container_exec(setup_server, "ls", "/var/pwned").returncode != 0

    # The old code created junk entries with '?' in their names
    result = _container_exec(
        setup_server, "sh", "-c", "ls -A /var/www/webdav | grep -F '?' | grep -F -v hello"
    )
    assert result.stdout.strip() == ""


def test_delete_query_string_traversal(
    nginx_server: str,
    setup_server,
    wlcg_create_header: dict[str, str],
    wlcg_modify_header: dict[str, str],
):
    """A DELETE whose query string contains traversal must only affect the
    file at the path, not anything outside the storage directory."""
    data = "Hello, world!" * 1000
    path = "/test_trav_del.txt"

    response = httpx.put(
        f"{nginx_server}{path}", headers=wlcg_create_header, content=data
    )
    assert_status(response, httpx.codes.CREATED)

    response = httpx.delete(
        f"{nginx_server}{path}{TRAVERSAL_QUERY}", headers=wlcg_modify_header
    )
    assert_status(response, httpx.codes.NO_CONTENT)

    # The traversal target must be untouched
    result = _container_exec(setup_server, "sh", "-c", "head -c 1 /etc/passwd")
    assert result.returncode == 0

    # And the file at the path is gone
    response = httpx.get(f"{nginx_server}{path}", headers=wlcg_create_header)
    assert_status(response, httpx.codes.NOT_FOUND)


def test_encoded_path_consistent(
    nginx_server: str,
    setup_server,
    wlcg_create_header: dict[str, str],
):
    """A PUT and a GET of the same URL must hit the same file: percent
    encoding is decoded for both the write (Lua) and the read (static
    module)."""
    data = "Hello, world!" * 1000
    path = "/enc%20file.txt"

    response = httpx.put(f"{nginx_server}{path}", headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)

    response = httpx.get(f"{nginx_server}{path}", headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data

    # The file must exist on disk under its decoded name
    assert (
        _container_exec(
            setup_server, "sh", "-c", '[ -f "/var/www/webdav/enc file.txt" ]'
        ).returncode
        == 0
    )

    # And a file with the literal (undecoded) name must NOT exist
    assert (
        _container_exec(
            setup_server, "sh", "-c", '[ ! -f "/var/www/webdav/enc%20file.txt" ]'
        ).returncode
        == 0
    )

    response = httpx.delete(f"{nginx_server}{path}", headers=wlcg_create_header)
    assert_status(response, httpx.codes.NO_CONTENT)
