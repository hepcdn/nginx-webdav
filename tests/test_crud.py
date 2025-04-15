import zlib

import httpx

from .util import assert_status


def test_crud_file(
    nginx_server: str,
    wlcg_create_header: dict[str, str],
    wlcg_modify_header: dict[str, str],
):
    path = f"{nginx_server}/test_new.txt"
    data = "Hello, world!" * 1000

    response = httpx.put(path, content=data)
    assert_status(response, httpx.codes.UNAUTHORIZED)

    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    assert response.text == "file created\n"

    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data

    response = httpx.put(path, headers=wlcg_create_header, content=data + "plus more")
    # TODO: this should be FORBIDDEN, but allowed for wlcg_modify_header
    assert_status(response, httpx.codes.NO_CONTENT)

    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data + "plus more"

    # TODO: once the above is fixed, this should be uncommented
    # response = httpx.put(path, headers=wlcg_create_header, data=data + "with some extra data")
    # assert_status(response, httpx.codes.CREATED)

    response = httpx.delete(path, headers=wlcg_create_header)
    # TODO: this should be FORBIDDEN, but allowed for wlcg_modify_header
    assert_status(response, httpx.codes.NO_CONTENT)

    # TODO: once the above is fixed, this should be uncommented
    # response = httpx.delete(path, headers=wlcg_modify_header)
    # assert_status(response, httpx.codes.NO_CONTENT)

    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.NOT_FOUND)

    response = httpx.delete(path, headers=wlcg_modify_header)
    assert_status(response, httpx.codes.NOT_FOUND)


def test_crud_dir(
    nginx_server: str,
    wlcg_create_header: dict[str, str],
    wlcg_modify_header: dict[str, str],
):
    path = f"{nginx_server}/test_dir/"

    response = httpx.put(path)
    assert_status(response, httpx.codes.UNAUTHORIZED)

    response = httpx.put(path, headers=wlcg_create_header)
    # TODO: allow create directory with PUT or only with MKCOL?
    assert_status(response, httpx.codes.FORBIDDEN)


def test_put_chunks(
    nginx_server: str,
    wlcg_create_header: dict[str, str],
):
    path = f"{nginx_server}/test_chunks.txt"
    unit = b"Hello, world!" * 100
    n = 10
    data_gen = (unit for _ in range(n))

    response = httpx.put(path, headers=wlcg_create_header, content=data_gen)
    assert_status(response, httpx.codes.CREATED)

    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.read() == unit * n


def test_put_wantdigest(
    nginx_server: str,
    wlcg_create_header: dict[str, str],
):
    path = f"{nginx_server}/test_digest.txt"
    data = "Hello, world!" * 1000
    expected_adler32 = zlib.adler32(data.encode())

    headers = dict(wlcg_create_header)
    headers["Want-Digest"] = "adler32"
    response = httpx.put(path, headers=headers, content=data)
    assert_status(response, httpx.codes.CREATED)
    assert response.headers["Digest"] == f"adler32={expected_adler32:08x}"

    response = httpx.get(path, headers=headers)
    assert_status(response, httpx.codes.OK)
    assert response.headers["Digest"] == f"adler32={expected_adler32:08x}"


def test_put_mkdir(
    nginx_server: str,
    wlcg_create_header: dict[str, str],
):
    path = f"{nginx_server}/test_mkdir/blah.txt"
    data = "Hello, world!" * 1000

    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    assert response.text == "file created\n"

    path = f"{nginx_server}/test_mkdir/blah.txt/more.txt"
    data = "Hello, world!" * 1000

    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.INTERNAL_SERVER_ERROR)
    assert response.text == "failed to open file: /var/www/webdav/test_mkdir/blah.txt/more.txt: Not a directory\n"