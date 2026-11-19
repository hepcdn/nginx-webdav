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

    # Overwriting an existing file requires the modify scope
    response = httpx.put(path, headers=wlcg_create_header, content=data + "plus more")
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    response = httpx.put(path, headers=wlcg_modify_header, content=data + "plus more")
    assert_status(response, httpx.codes.NO_CONTENT)

    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data + "plus more"

    # Deleting requires the modify scope
    response = httpx.delete(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    response = httpx.delete(path, headers=wlcg_modify_header)
    assert_status(response, httpx.codes.NO_CONTENT)

    response = httpx.get(path, headers=wlcg_create_header)
    assert_status(response, httpx.codes.NOT_FOUND)

    response = httpx.delete(path, headers=wlcg_modify_header)
    assert_status(response, httpx.codes.NOT_FOUND)


def test_readonly_scope_cannot_write(
    nginx_server: str,
    wlcg_read_header: dict[str, str],
    wlcg_create_header: dict[str, str],
):
    """A token with only storage.read:/ must not be able to create or modify."""
    path = f"{nginx_server}/test_readonly.txt"
    data = "Hello, world!" * 100

    # Cannot create
    response = httpx.put(path, headers=wlcg_read_header, content=data)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to create" in response.text

    # Create with a create-scope token, then try modify ops with the read-only token
    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)

    # Can still read
    response = httpx.get(path, headers=wlcg_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data

    # Cannot overwrite
    response = httpx.put(path, headers=wlcg_read_header, content=data + "more")
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    # Cannot delete
    response = httpx.delete(path, headers=wlcg_read_header)
    assert_status(response, httpx.codes.FORBIDDEN)
    assert "no permission to modify" in response.text

    # File is still there
    response = httpx.get(path, headers=wlcg_read_header)
    assert_status(response, httpx.codes.OK)
    assert response.text == data


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
