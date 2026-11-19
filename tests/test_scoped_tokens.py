"""Tests for fine-grained (directory-scoped) WLCG tokens.

Tokens scoped to a directory (e.g. storage.read:/scoped/) must only grant
access to that directory and everything below it.
"""

import httpx

from .util import assert_status


def test_scoped_create(
    nginx_server: str,
    wlcg_scoped_create_header: dict[str, str],
):
    in_scope = f"{nginx_server}/scoped/in_scope.txt"
    out_of_scope = f"{nginx_server}/outside.txt"
    # Boundary case: /scoped_outside.txt is NOT under /scoped/
    sibling = f"{nginx_server}/scoped_outside.txt"
    data = "Hello, world!" * 100

    # Create within the granted prefix
    response = httpx.put(in_scope, headers=wlcg_scoped_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)

    # Create outside the granted prefix
    response = httpx.put(out_of_scope, headers=wlcg_scoped_create_header, content=data)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to create" in response.text

    # Create at a sibling path that merely shares the string prefix
    response = httpx.put(sibling, headers=wlcg_scoped_create_header, content=data)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to create" in response.text

    # Nothing was created outside the prefix
    assert not (httpx.get(out_of_scope, headers=wlcg_scoped_create_header).status_code == httpx.codes.OK)


def test_scoped_read(
    nginx_server: str,
    wlcg_scoped_create_header: dict[str, str],
    wlcg_scoped_read_header: dict[str, str],
    wlcg_read_header: dict[str, str],
    wlcg_create_header: dict[str, str],
):
    in_scope = f"{nginx_server}/scoped/read.txt"
    out_of_scope = f"{nginx_server}/other.txt"
    data = "Hello, world!" * 100

    # Seed a file inside the prefix (and one outside, with a root token)
    response = httpx.put(in_scope, headers=wlcg_scoped_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    response = httpx.put(out_of_scope, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)

    # Read within the granted prefix
    response = httpx.get(in_scope, headers=wlcg_scoped_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data

    # Read outside the granted prefix is denied (even though the file exists)
    response = httpx.get(out_of_scope, headers=wlcg_scoped_read_header)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to read" in response.text

    # A root-scoped read token still reads everything
    response = httpx.get(in_scope, headers=wlcg_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data
    response = httpx.get(out_of_scope, headers=wlcg_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data


def test_scoped_modify(
    nginx_server: str,
    wlcg_scoped_create_header: dict[str, str],
    wlcg_scoped_modify_header: dict[str, str],
    wlcg_read_header: dict[str, str],
    wlcg_create_header: dict[str, str],
):
    in_scope = f"{nginx_server}/scoped/modify.txt"
    out_of_scope = f"{nginx_server}/nomodify.txt"
    data = "Hello, world!" * 100

    # Seed files inside and outside the prefix
    response = httpx.put(in_scope, headers=wlcg_scoped_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    response = httpx.put(out_of_scope, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)

    # Overwrite within the granted prefix
    response = httpx.put(
        in_scope, headers=wlcg_scoped_modify_header, content=data + "more"
    )
    assert_status(response, httpx.codes.NO_CONTENT)

    # Overwrite outside the granted prefix is denied
    response = httpx.put(
        out_of_scope, headers=wlcg_scoped_modify_header, content=data + "more"
    )
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    # Delete within the granted prefix
    response = httpx.delete(in_scope, headers=wlcg_scoped_modify_header)
    assert_status(response, httpx.codes.NO_CONTENT)

    # Delete outside the granted prefix is denied
    response = httpx.delete(out_of_scope, headers=wlcg_scoped_modify_header)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    # File outside the prefix is still there (root token can verify)
    response = httpx.get(out_of_scope, headers=wlcg_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data
