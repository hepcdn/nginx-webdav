import subprocess
import time

import httpx

from tests.util import assert_status


def test_cluster_gossip(nginx_cluster, hepcdn_access_header):
    """
    Test the cluster endpoint.
    """
    data = {}
    for _ in range(30):
        for server in nginx_cluster:
            response = httpx.get(
                f"{server.hosturl}gossip", headers=hepcdn_access_header
            )
            data[server.hosturl] = response.json()

        if all(len(item) == len(nginx_cluster) for item in data.values()):
            break
        time.sleep(1)

    assert data
    assert len(data) == len(nginx_cluster)
    for server, items in data.items():
        print(server, items)
        assert len(items) == len(nginx_cluster)
        for item in items:
            assert item.keys() == {"name", "data"}
            assert item["data"]["status"] == "alive"
            assert set(item["data"].keys()) == {
                "status",
                "epoch",
                "timestamp",
                "server_version",
                "failures",
            }


def test_cluster_tpc(nginx_cluster, wlcg_create_header):
    assert len(nginx_cluster) > 1
    server1, server2 = nginx_cluster[:2]

    path = f"{server1.hosturl}webdav/test_tpc.txt"
    data = "Hello, world!" * 10_000

    response = httpx.put(path, headers=wlcg_create_header, content=data)
    assert_status(response, httpx.codes.CREATED)
    assert response.text == "file created\n"

    # TODO: have setup_cluster return client-side and server-side URLs
    src = f"{server1.podurl}webdav/test_tpc.txt"
    dst = f"{server2.hosturl}webdav/test_tpc.txt"

    headers = dict(wlcg_create_header)
    headers["Source"] = src
    headers["TransferHeaderAuthorization"] = headers["Authorization"]
    response = httpx.request("COPY", dst, headers=headers)
    assert response.status_code == httpx.codes.ACCEPTED
    assert response.text.strip() == "success: Created"


def test_cluster_redirect(nginx_cluster, wlcg_create_header, wlcg_read_header):
    for i, server in enumerate(nginx_cluster):
        path = f"{server.hosturl}webdav/unique_file{i}.txt"
        data = "Hello, world!" * 10_000

        response = httpx.put(path, headers=wlcg_create_header, content=data)
        assert_status(response, httpx.codes.CREATED)
        assert response.text == "file created\n"

    for i, correctserver in enumerate(nginx_cluster):
        for j, server in enumerate(nginx_cluster):
            # we can't follow the redirect because the server name is only known inside the podman network
            response = httpx.get(
                f"{server.hosturl}redirect/unique_file{i}.txt", headers=wlcg_read_header
            )
            assert_status(response, httpx.codes.TEMPORARY_REDIRECT)
            if i == j:
                assert response.headers["Location"] == f"/webdav/unique_file{i}.txt"
            else:
                assert (
                    response.headers["Location"]
                    == f"{correctserver.podurl}webdav/unique_file{i}.txt"
                )


def test_cluster_drop_peer(nginx_cluster, hepcdn_access_header):
    """
    Test dropping a peer from the cluster.
    """
    server, peer, *_ = nginx_cluster
    subprocess.check_call(
        ["podman", "stop", peer.container_id], stdout=subprocess.DEVNULL
    )

    for _ in range(30):
        try:
            response = httpx.get(f"{peer.hosturl}gossip", headers=hepcdn_access_header)
        except httpx.ConnectError:
            # This is expected, as the peer is stopped
            break
    else:
        assert False, "Peer is still reachable after stopping"

    dropped = False
    for _ in range(30):
        response = httpx.get(f"{server.hosturl}gossip", headers=hepcdn_access_header)
        peerlist = {item["name"]: item for item in response.json()}
        if peer.podurl not in peerlist:
            dropped = True
            break
        time.sleep(1)

    subprocess.check_call(
        ["podman", "start", peer.container_id], stdout=subprocess.DEVNULL
    )

    assert dropped, "Peer was not dropped from the cluster"

    for _ in range(30):
        response = httpx.get(f"{server.hosturl}gossip", headers=hepcdn_access_header)
        peerlist = {item["name"]: item for item in response.json()}
        if peer.podurl in peerlist:
            dropped = False
            break
        time.sleep(1)

    assert not dropped, "Peer was not re-added to the cluster after restart"
