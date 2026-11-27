"""
Regression test: a gossip message that arrives before the ``peers``
shared-dict key has been initialized must not crash the node.

``Gossip.peers()`` is the only place that initializes the ``peers`` key
(it seeds it from ``seed_peers``). It runs on the gossip timer tick
(worker 0, after the token fetch) and when answering ``/gossip`` or
``/redirect``. If a peer's message is *processed* before any of those —
e.g. the first timer tick bailed out on a failed token fetch, or a
message arrived right after startup — ``handle_message`` ->
``update_peerdata`` -> ``add_peer`` used to index the nil ``peerstr``:

    gossip.lua:43: attempt to index local 'peerstr' (a nil value)

which turned the peer's gossip POST into a 500. ``remove_peer`` had the
same hazard when the list had been reset to nil.

This test makes the condition deterministic: the server's
``openidc_iss`` points at a closed port, so every timer tick bails out
on the token fetch before it ever calls ``Gossip.peers()``, and a huge
``gossip_delay`` guarantees no further ticks during the test. The test
then POSTs a gossip message introducing a new peer and expects a 200
with that peer in the node's view.
"""

import json
import os
import random
import socketserver
import subprocess
import time

import httpx
import pytest

from tests.conftest import ServerInstance, _remove_container
from tests.util import assert_status

CONFIG_FILE = "nginx/lua/config-gossip-init-test.json"
CONTAINER_NAME = "nginx-gossip-init-test-container"


@pytest.fixture()
def gossip_init_server(build_container: None, oidc_mock_idp):
    """A server whose gossip ``peers`` list the timer never initializes.

    ``openidc_iss`` points at a closed port (127.0.0.1:9) so the token
    fetch — and thus the ``Gossip.peers()`` call that would initialize
    the shared-dict key — always bails out; ``gossip_delay`` is huge so
    no later tick happens in-test. A dedicated config file is mounted so
    the shared ``nginx/lua/config.json`` (and any sibling container's
    bind mount of it) is never touched: in DEBUG mode config.lua
    self-loads that path on every request.
    """
    open_port = 8480
    for port in range(open_port, open_port + 100):
        try:
            socketserver.TCPServer(("", port), None)
        except IOError:
            open_port = port
            break

    config = {
        # Closed port: the node's token fetch always fails, so the first
        # timer tick returns before Gossip.peers() initializes 'peers'.
        "openidc_iss": "http://127.0.0.1:9/",
        "openidc_pubkey": oidc_mock_idp.public_key_pem,
        "openidc_client_id": "nginx1",
        "openidc_client_secret": "nginx1_secret",
        "seed_peers": "",
        "gossip_delay": 3600,
        "health_check_id": random.randint(0, 1024 * 1024 * 1024),
        "performance_marker_timeout": 2,
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

    podman_cmd = [
        "podman",
        "run",
        "-d",
        "-p",
        f"{open_port}:8080",
        "-v",
        f"./{CONFIG_FILE}:/etc/nginx/lua/config.json:ro",
        "--tmpfs",
        "/var/www/webdav:rw,size=100M,mode=1777",
        "-e",
        "DEBUG=true",
        "--name",
        CONTAINER_NAME,
        "nginx-webdav",
    ]
    container_id = subprocess.check_output(podman_cmd).decode().strip()
    try:
        started = False
        for _ in range(10):
            try:
                time.sleep(0.1)
                r = httpx.get(f"http://localhost:{open_port}/webdav_health")
                # Make sure the server that responds is the one we started
                assert str(config["health_check_id"]) in r.text
                started = True
                break
            except httpx.HTTPError as e:
                print(str(e))
                continue
        if not started:
            subprocess.check_call(["podman", "logs", container_id])
            raise RuntimeError("Container did not start")

        yield ServerInstance(
            port=open_port,
            container_id=container_id,
            podurl=f"http://{CONTAINER_NAME}:8080/webdav",
            hosturl=f"http://localhost:{open_port}/webdav",
        )
    finally:
        _remove_container(container_id)
        os.remove(CONFIG_FILE)


def test_gossip_message_before_peers_init(gossip_init_server, hepcdn_access_header):
    """A gossip POST introducing a new peer must not 500 while the
    'peers' list is still uninitialized (pre-fix: add_peer crashed with
    'attempt to index local peerstr (a nil value)')."""
    # Give the (immediate) first timer tick a moment to run and bail out
    # on the failed token fetch, so the state under test is exactly the
    # one a real peer would hit: nginx up, 'peers' never initialized.
    time.sleep(1.5)

    peer = "http://gossip-race-peer:8080/"
    message = [
        {
            "name": peer,
            "data": {
                "epoch": 1,
                "status": "alive",
                "timestamp": int(time.time()),
                "server_version": "0.0.1",
                "failures": 0,
            },
        }
    ]

    # hosturl is the /webdav root; /gossip lives at the server root
    response = httpx.post(
        f"http://localhost:{gossip_init_server.port}/gossip",
        headers=hepcdn_access_header,
        content=json.dumps(message),
    )
    assert_status(response, httpx.codes.OK)

    # The node's returned view must now contain the introduced peer.
    view = {item["name"]: item for item in response.json()}
    assert peer in view
    assert view[peer]["data"]["status"] == "alive"
    assert view[peer]["data"]["epoch"] == 1
