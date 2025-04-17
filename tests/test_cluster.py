import time

import httpx

from tests.util import assert_status


def test_cluster_gossip(setup_cluster, hepcdn_access_header):
    """
    Test the cluster endpoint.
    """
    data = {}
    for _ in range(30):
        for server in setup_cluster:
            response = httpx.get(f"{server}gossip", headers=hepcdn_access_header)
            data[server] = response.json()

        if all(len(item) == len(setup_cluster) for item in data.values()):
            break
        time.sleep(1)

    assert data
    assert len(data) == len(setup_cluster)
    for server, items in data.items():
        print(server, items)
        assert len(items) == len(setup_cluster)
        for item in items:
            assert item.keys() == {"name", "data"}
            assert item["data"]["status"] == "alive"
            assert set(item["data"].keys()) == {
                "status",
                "epoch",
                "timestamp",
                "server_version",
            }


def test_cluster_tpc(setup_cluster, wlcg_create_header):
    assert len(setup_cluster) > 1
    server1, server2 = setup_cluster[:2]

    path = f"{server1}webdav/test_tpc.txt"
    data = "Hello, world!" * 10_000

    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    assert response.text == "file created\n"

    # TODO: have setup_cluster return client-side and server-side URLs
    src = "http://nginx-webdav-test0:8580/webdav/test_tpc.txt"
    dst = f"{server2}webdav/test_tpc.txt"

    headers = dict(wlcg_create_header)
    headers["Source"] = src
    headers["TransferHeaderAuthorization"] = headers["Authorization"]
    response = httpx.request("COPY", dst, headers=headers)
    assert response.status_code == httpx.codes.ACCEPTED
    assert response.text.strip() == "success: Created"


def test_cluster_redirect(setup_cluster, wlcg_create_header, wlcg_read_header):
    for i, server in enumerate(setup_cluster):
        path = f"{server}webdav/unique_file{i}.txt"
        data = "Hello, world!" * 10_000

        response = httpx.put(path, headers=wlcg_create_header, content=data)
        assert_status(response, httpx.codes.CREATED)
        assert response.text == "file created\n"

    for j, server in enumerate(setup_cluster):
        for i in range(len(setup_cluster)):
            response = httpx.get(
                f"{server}redirect/unique_file{i}.txt", headers=wlcg_read_header
            )
            assert_status(response, httpx.codes.TEMPORARY_REDIRECT)
            if i == j:
                assert response.headers["Location"] == f"/webdav/unique_file{i}.txt"
            else:
                assert (
                    response.headers["Location"]
                    == f"http://nginx-webdav-test{i}:858{i}/webdav/unique_file{i}.txt"
                )
