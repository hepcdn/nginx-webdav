import httpx

from .util import assert_status


def test_appconfig(nginx_server: str):
    bare = nginx_server.removesuffix("webdav")
    response = httpx.get(f"{bare}/appconfig")
    assert_status(response, httpx.codes.OK)
    data = response.json()
    assert "public_client_id" in data
    assert data["public_client_id"] == "test_public_client_id"
