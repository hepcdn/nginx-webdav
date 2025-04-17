import zlib

import httpx

from .util import assert_status


def test_head_unauthorized(nginx_server: str):
    response = httpx.head(f"{nginx_server}/hello.txt")
    assert_status(response, httpx.codes.UNAUTHORIZED)

    response = httpx.head(
        f"{nginx_server}/hello.txt", headers={"Authorization": "Bearer blah"}
    )
    assert_status(response, httpx.codes.UNAUTHORIZED)


def test_head(nginx_server: str, wlcg_read_header: dict[str, str]):
    response = httpx.head(f"{nginx_server}/hello.txt", headers=wlcg_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.headers["Content-Length"] == "13"
    assert response.text == ""

    response = httpx.head(f"{nginx_server}/nonexistent.txt", headers=wlcg_read_header)
    assert_status(response, httpx.codes.NOT_FOUND)


def test_head_adler32(nginx_server: str, wlcg_read_header: dict[str, str]):
    headers = dict(wlcg_read_header)
    headers["Want-Digest"] = "adler32"

    # First request will compute the digest
    response = httpx.head(f"{nginx_server}/hello.txt", headers=headers)
    assert_status(response, httpx.codes.OK)
    assert response.headers["Content-Length"] == "13"
    adler32 = zlib.adler32(b"Hello, world!")
    assert response.headers["Digest"] == f"adler32={adler32:08x}"

    # Second request will read from xattr
    response = httpx.head(f"{nginx_server}/hello.txt", headers=headers)
    assert_status(response, httpx.codes.OK)
    assert response.headers["Content-Length"] == "13"
    adler32 = zlib.adler32(b"Hello, world!")
    assert response.headers["Digest"] == f"adler32={adler32:08x}"

    response = httpx.head(f"{nginx_server}/nonexistent.txt", headers=headers)
    assert_status(response, httpx.codes.NOT_FOUND)
    assert "Digest" not in response.headers