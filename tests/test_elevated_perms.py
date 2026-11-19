"""Tests for elevated token sub IDs (site admins).

Tokens whose "sub" claim is listed in the elevated_sub_ids configuration
bypass the WLCG scope checks.
"""

import httpx

from .util import assert_status


def test_elevated_sub_bypasses_scopes(
    nginx_server: str,
    wlcg_elevated_header: dict[str, str],
    wlcg_read_header: dict[str, str],
):
    """The elevated sub has full access despite carrying no storage scopes."""
    path = f"{nginx_server}/elevated.txt"
    data = "Hello, world!" * 100

    # Create (token has no storage.create:/ scope)
    response = httpx.put(path, headers=wlcg_elevated_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    assert response.text == "file created\n"

    # Read
    response = httpx.get(path, headers=wlcg_elevated_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data

    # Overwrite
    response = httpx.put(path, headers=wlcg_elevated_header, content=data + "more")
    assert_status(response, httpx.codes.NO_CONTENT)

    # Delete
    response = httpx.delete(path, headers=wlcg_elevated_header)
    assert_status(response, httpx.codes.NO_CONTENT)

    # Gone
    response = httpx.get(path, headers=wlcg_read_header)
    assert_status(response, httpx.codes.NOT_FOUND)


def test_non_elevated_sub_without_scopes_denied(
    nginx_server: str,
    oidc_mock_idp,
    wlcg_create_header: dict[str, str],
):
    """A sub not in elevated_sub_ids is subject to the normal scope checks."""
    path = f"{nginx_server}/nonadmin.txt"
    data = "Hello, world!" * 100

    # Token for an unlisted sub with no storage scopes
    token = oidc_mock_idp.make_wlcg_token(
        "openid offline_access", sub="not-an-admin", client_id="user123"
    )
    headers = {"Authorization": f"Bearer {token}"}

    # Seed a file with a root-scoped create token
    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)

    # Cannot read (no storage.read:/ scope, not elevated)
    response = httpx.get(path, headers=headers)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to read" in response.text

    # Cannot modify or delete
    response = httpx.put(path, headers=headers, content=data + "more")
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    response = httpx.delete(path, headers=headers)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    # File is still there
    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data
