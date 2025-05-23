import base64
import datetime
import json
import logging
import os
import random
import socketserver
import subprocess
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Iterator
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger()


@dataclass
class MockIdP:
    public_key_pem: str
    private_key: rsa.RSAPrivateKey
    iss: str
    client_credentials: dict[str, str]

    def encode_jwt(self, payload: dict) -> str:
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def make_wlcg_token(
        self, scope: str, sub: str = "user123", client_id: str = "user123"
    ) -> str:
        """Generate a WLCG-compatible bearer token.

        See:
        https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md
        for a description of the profile.
        """
        if client_id not in self.client_credentials:
            raise ValueError(f"Unknown client_id: {client_id}")
        not_before = int(time.time())
        issued_at = not_before
        expires = not_before + 4 * 3600
        token = {
            "wlcg.ver": "1.0",
            "sub": sub,
            "aud": "https://wlcg.cern.ch/jwt/v1/any",
            "nbf": not_before,
            "scope": scope,
            "iss": self.iss,
            "exp": expires,
            "iat": issued_at,
            "jti": str(uuid.uuid4()),
            "client_id": client_id,
        }
        return self.encode_jwt(token)


@pytest.fixture(scope="session")
def oidc_mock_idp() -> Iterator[MockIdP]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    idp = MockIdP(
        public_key_pem=public_pem.decode("ascii"),
        private_key=private_key,
        iss="http://host.docker.internal:8090/",
        client_credentials={
            "user123": "user123_client_secret",
            "nginx0": "nginx0_secret",
            "nginx1": "nginx1_secret",
            "nginx2": "nginx2_secret",
        },
    )
    server_address = ("", 8090)

    class _IdPRequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/token":
                logger.debug(f"Unknown path: {self.path}")
                self.send_response(httpx.codes.NOT_FOUND)
                self.end_headers()
                return

            if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
                self.send_response(httpx.codes.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b"Unsupported content type")
                return
            self.body = self.rfile.read(int(self.headers["Content-Length"]))
            parameters = {k: v[0] for k, v in parse_qs(self.body.decode()).items()}
            if parameters.get("grant_type") != "client_credentials":
                self.send_response(httpx.codes.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b"Unsupported grant type")
                return
            scope = parameters.get("scope")
            if not scope:
                self.send_response(httpx.codes.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b"Missing scope")
                return
            if self.headers.get("Accept") != "application/json":
                self.send_response(httpx.codes.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b"Unsupported accept type")
                return
            if not self.headers.get("Authorization").startswith("Basic "):
                self.send_response(httpx.codes.UNAUTHORIZED)
                self.end_headers()
                self.wfile.write(b"Missing or invalid authorization header")
                return
            username, password = (
                base64.b64decode(self.headers["Authorization"].removeprefix("Basic "))
                .decode()
                .split(":")
            )
            if username not in idp.client_credentials:
                self.send_response(httpx.codes.UNAUTHORIZED)
                self.end_headers()
                return
            if password != idp.client_credentials[username]:
                self.send_response(httpx.codes.UNAUTHORIZED)
                self.end_headers()
                return

            self.send_response(httpx.codes.OK)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            token = idp.make_wlcg_token(scope, sub=username, client_id=username)
            response = json.dumps(
                {
                    "token_type": "Bearer",
                    "expires_in": 4 * 3600,
                    "access_token": token,
                    "scope": scope,
                }
            )
            self.wfile.write(response.encode())

    httpd = HTTPServer(server_address, _IdPRequestHandler)
    thread = Thread(target=httpd.serve_forever)
    thread.start()

    yield idp

    httpd.shutdown()
    thread.join()


@pytest.fixture(scope="session")
def hepcdn_access_header(oidc_mock_idp: MockIdP) -> dict[str, str]:
    """A HepCDN token with access to /gossip"""
    bt = oidc_mock_idp.make_wlcg_token("storage.read:/ hepcdn.access")
    return {"Authorization": f"Bearer {bt}"}


@pytest.fixture(scope="session")
def wlcg_read_header(oidc_mock_idp: MockIdP) -> dict[str, str]:
    """A WLCG token with read access to /

    storage.read: Read data. Only applies to “online” resources such as disk
    (as opposed to “nearline” such as tape where the stage authorization should be used in addition).
    """
    bt = oidc_mock_idp.make_wlcg_token("openid offline_access storage.read:/")
    return {"Authorization": f"Bearer {bt}"}


@pytest.fixture(scope="session")
def wlcg_create_header(oidc_mock_idp: MockIdP) -> dict[str, str]:
    """A WLCG token with create access to /

    storage.create: Upload data. This includes renaming files if the destination file does not
    already exist. This capability includes the creation of directories and subdirectories at
    the specified path, and the creation of any non-existent directories required to create the
    path itself. This authorization does not permit overwriting or deletion of stored data. The
    driving use case for a separate storage.create scope is to enable the stage-out of data from
    jobs on a worker node.

    TODO: does this include the ability to read the file after creation? For now, force it.
    """
    bt = oidc_mock_idp.make_wlcg_token(
        "openid offline_access storage.read:/ storage.create:/"
    )
    return {"Authorization": f"Bearer {bt}"}


@pytest.fixture(scope="session")
def wlcg_modify_header(oidc_mock_idp: MockIdP) -> dict[str, str]:
    """A WLCG token with modify access to /

    storage.modify: Change data. This includes renaming files, creating new files, and writing data.
    This permission includes overwriting or replacing stored data in addition to deleting or truncating
    data. This is a strict superset of storage.create.
    """
    bt = oidc_mock_idp.make_wlcg_token(
        "openid offline_access storage.read:/ storage.modify:/"
    )
    return {"Authorization": f"Bearer {bt}"}


@pytest.fixture(scope="session")
def build_container():
    # Make sure we are in the right place: one up from tests/
    assert os.getcwd() == os.path.dirname(os.path.dirname(__file__))

    # Build podman container
    subprocess.check_call(
        [
            "podman",
            "build",
            "--build-arg",
            "VERSION=0.0.0dev",
            "-t",
            "nginx-webdav",
            "nginx",
            "-f",
            "nginx/nginx.dockerfile",
        ]
    )

    yield


@dataclass
class ServerInstance:
    """A server instance for testing"""

    port: int
    "Port on which the server is running"
    container_id: str
    "Podman container ID"
    podurl: str
    "URL with hostname resolvable from the podman network"
    hosturl: str
    "URL with hostname (or IP) resolvable from the host (pytest) network"


@pytest.fixture(scope="session")
def setup_server(build_container: None, oidc_mock_idp: MockIdP):
    """A running nginx-webdav server for testing"""
    # Find an available port.
    open_port = 8280
    for port in range(open_port, open_port + 100):
        try:
            socketserver.TCPServer(("", port), None)
        except IOError:
            open_port = port
            break

    # Configure the server (see nginx/lua/config.lua for schema)
    config = {
        "openidc_iss": oidc_mock_idp.iss,
        "openidc_pubkey": oidc_mock_idp.public_key_pem,
        "openidc_client_id": "nginx1",
        "openidc_client_secret": "nginx1_secret",
        "receive_buffer_size": 4096,
        # Give the container a (hopefully) unique ID that is returned in a
        # health check so that we can verify that the service we started is the
        # same one we're connecting to
        "health_check_id": random.randint(0, 1024 * 1024 * 1024),
        "performance_marker_timeout": 2,
    }
    with open("nginx/lua/config.json", "w") as f:
        json.dump(config, f)

    # Start podman container
    podman_cmd = [
        "podman",
        "run",
        "-d",
        "-p",
        f"{open_port}:8080",
        "-v",
        "./nginx/lua/config.json:/etc/nginx/lua/config.json:ro",
        "--tmpfs",
        "/var/www/webdav:rw,size=100M,mode=1777",
        "-e",
        "DEBUG=true",
        # Set the name of the container so it will fail early if the old
        # container wasn't cleaned up
        "--name",
        "nginx-unit-test-container",
    ]
    podman_cmd.append("nginx-webdav")
    try:
        container_id = subprocess.check_output(podman_cmd).decode().strip()

        subprocess.run(
            [
                "podman",
                "exec",
                "-i",
                container_id,
                "dd",
                "of=/var/www/webdav/hello.txt",
            ],
            input=b"Hello, world!",
            stderr=subprocess.DEVNULL,
            check=True,
        )

        started = False
        for _ in range(10):
            try:
                time.sleep(0.1)
                r = httpx.get(f"http://localhost:{open_port}/webdav_health")
                # Make sure the server that responds is the one we started
                try:
                    assert str(config["health_check_id"]) in r.text
                except AssertionError:
                    subprocess.check_call(["podman", "logs", container_id])
                    raise
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
            podurl="http://nginx-unit-test-container:8080/webdav",
            hosturl=f"http://localhost:{open_port}/webdav",
        )
    finally:
        # Stop podman container and clean up
        subprocess.check_call(
            ["podman", "stop", container_id], stdout=subprocess.DEVNULL
        )
        subprocess.check_call(["podman", "rm", container_id], stdout=subprocess.DEVNULL)
        # Clean up
        os.remove("nginx/lua/config.json")


@pytest.fixture(scope="session")
def setup_cluster(build_container: None, oidc_mock_idp: MockIdP):
    nservers = 3

    # Set up config files for each server
    for i in range(nservers):
        config = {
            "seed_peers": "http://nginx-webdav-test0:8580/" if i > 0 else "",
            "openidc_iss": oidc_mock_idp.iss,
            "openidc_pubkey": oidc_mock_idp.public_key_pem,
            "gossip_delay": 1,
            "gossip_fraction": 0.5,
            "gossip_max_failures": 1,
            "gossip_timeout": 100,
            "openidc_client_id": f"nginx{i}",
            "openidc_client_secret": f"nginx{i}_secret",
            "health_check_id": random.randint(0, 1024 * 1024 * 1024),
        }
        with open(f"nginx/lua/config{i}.json", "w") as f:
            json.dump(config, f)

    # Set up a network for the containers
    subprocess.check_call(
        ["podman", "network", "create", "nginx-webdav-test"], stdout=subprocess.DEVNULL
    )

    # Start podman containers
    container_ids = []
    for i in range(nservers):
        podman_cmd = [
            "podman",
            "run",
            "-d",
            "-p",
            f"{8580 + i}:{8580 + i}",
            "--network",
            "nginx-webdav-test",
            "-v",
            f"./nginx/lua/config{i}.json:/etc/nginx/lua/config.json:ro",
            "--tmpfs",
            "/var/www/webdav:rw,size=10M,mode=1777",
            "-e",
            f"SERVER_NAME=nginx-webdav-test{i}",
            "-e",
            f"PORT={8580 + i}",
            "-e",
            "DEBUG=true",
            "--name",
            f"nginx-webdav-test{i}",
        ]
        podman_cmd.append("nginx-webdav")
        container_id = subprocess.check_output(podman_cmd).decode().strip()
        container_ids.append(container_id)

    time.sleep(1)
    yield [
        ServerInstance(
            port=8580 + i,
            container_id=container_id,
            podurl=f"http://nginx-webdav-test{i}:{8580 + i}/",
            hosturl=f"http://localhost:{8580 + i}/",
        )
        for i, container_id in enumerate(container_ids)
    ]

    # Clean up
    for i, container_id in enumerate(container_ids):
        # Dump container logs
        subprocess.check_call(["podman", "logs", container_id])

        # Stop podman container and clean up
        subprocess.check_call(
            ["podman", "stop", container_id], stdout=subprocess.DEVNULL
        )
        subprocess.check_call(["podman", "rm", container_id], stdout=subprocess.DEVNULL)
        os.remove(f"nginx/lua/config{i}.json")

    subprocess.check_call(
        ["podman", "network", "rm", "nginx-webdav-test"], stdout=subprocess.DEVNULL
    )


@pytest.fixture()
def nginx_server(setup_server: ServerInstance) -> Iterator[str]:
    """A running nginx-webdav server for testing

    It's nice to have a module-scoped fixture for the server, so we can
    reduce the number of irrelevant log messages in the test output.
    """

    pre_time = datetime.datetime.now().isoformat()
    yield setup_server.hosturl

    subprocess.check_call(
        ["podman", "logs", "--since", pre_time, setup_server.container_id]
    )


@pytest.fixture()
def nginx_cluster(setup_cluster: list[ServerInstance]):
    """A running nginx-webdav cluster for testing

    It's nice to have a module-scoped fixture for the server, so we can
    reduce the number of irrelevant log messages in the test output.
    """

    pre_time = datetime.datetime.now().isoformat()
    yield setup_cluster

    for server in setup_cluster:
        subprocess.check_call(
            ["podman", "logs", "--since", pre_time, server.container_id]
        )
