"""Tests for X.509/VOMS certificate authentication."""

import json
import os
import random
import subprocess
import time

import httpx
import pytest

# Use pre-generated test certificates from test-certs/
TEST_CERTS_DIR = os.path.join(os.path.dirname(__file__), "..", "test-certs")


@pytest.fixture(scope="module")
def voms_server():
    """Start nginx-webdav server with SSL and client certificate verification."""
    # Find available port
    open_port = 8395
    for port in range(open_port, open_port + 100):
        try:
            import socketserver
            socketserver.TCPServer(("", port), None)
        except IOError:
            open_port = port
            break

    # Remove any existing container
    subprocess.run(["podman", "rm", "-f", "nginx-voms-test-container"], capture_output=True)

    # Mount CA cert directory into container
    result = subprocess.run([
        "podman", "run", "-d",
        "-p", f"{open_port}:8080",
        "-v", f"{TEST_CERTS_DIR}:/etc/grid-security/certificates:ro",
        "--tmpfs", "/var/www/webdav:rw,size=100M,mode=1777",
        "-e", "USE_SSL=true",
        "-e", "SSL_HOST_CERT=/etc/grid-security/certificates/ca.crt",
        "-e", "SSL_HOST_KEY=/etc/grid-security/certificates/ca.key",
        "-e", "SSL_CERT_DIR=/etc/grid-security/certificates",
        "-e", "DEBUG=true",
        "--name", "nginx-voms-test-container",
        "nginx-webdav"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to start container: {result.stderr}")

    # Wait for server to start
    started = False
    for _ in range(20):
        try:
            time.sleep(0.5)
            with httpx.Client(verify=False) as client:
                r = client.get(f"https://localhost:{open_port}/webdav_health")
            started = True
            break
        except httpx.HTTPError:
            continue

    if not started:
        subprocess.check_call(["podman", "logs", "nginx-voms-test-container"])
        raise RuntimeError("VOMS test container did not start")

    # Create hello.txt for testing
    subprocess.run([
        "podman", "exec", "-i", "nginx-voms-test-container",
        "dd", "of=/var/www/webdav/hello.txt"
    ], input=b"Hello, world!", stderr=subprocess.DEVNULL, check=True)

    yield {
        "port": open_port,
        "hosturl": f"https://localhost:{open_port}/webdav",
        "ca_cert": os.path.join(TEST_CERTS_DIR, "ca.crt"),
        "user_cert": os.path.join(TEST_CERTS_DIR, "user_voms.crt"),
        "user_key": os.path.join(TEST_CERTS_DIR, "user.key"),
    }

    subprocess.check_call(["podman", "logs", "nginx-voms-test-container"])
    subprocess.check_call(["podman", "stop", "nginx-voms-test-container"], stdout=subprocess.DEVNULL)
    subprocess.check_call(["podman", "rm", "nginx-voms-test-container"], stdout=subprocess.DEVNULL)


def test_voms_cert_auth_get(voms_server):
    """Test GET request with VOMS client certificate."""
    with httpx.Client(
        verify=False,
        cert=(voms_server['user_cert'], voms_server['user_key'])
    ) as client:
        r = client.get(f"{voms_server['hosturl']}/hello.txt")
    assert r.status_code == 200
    assert r.text == "Hello, world!"


def test_voms_cert_auth_put(voms_server):
    """Test PUT request with VOMS client certificate."""
    with httpx.Client(
        verify=False,
        cert=(voms_server['user_cert'], voms_server['user_key'])
    ) as client:
        r = client.put(f"{voms_server['hosturl']}/voms_test.txt", content="VOMS test data")
    assert r.status_code == 201


def test_voms_cert_auth_delete(voms_server):
    """Test DELETE request with VOMS client certificate."""
    with httpx.Client(
        verify=False,
        cert=(voms_server['user_cert'], voms_server['user_key'])
    ) as client:
        r = client.delete(f"{voms_server['hosturl']}/voms_test.txt")
    assert r.status_code == 204


def test_no_cert_auth_fails(voms_server):
    """Test that requests without client certificate fail."""
    with httpx.Client(verify=False) as client:
        r = client.get(f"{voms_server['hosturl']}/hello.txt")
    assert r.status_code == 401