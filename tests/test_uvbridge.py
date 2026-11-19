import time

import httpx

from .util import assert_status


def _uvbridge_url(nginx_server: str) -> str:
    return nginx_server.removesuffix("webdav") + "webdav_uvbridge"


def test_uvbridge_attached(nginx_server: str):
    # The bridge is enabled in the test config (see conftest.py) and
    # must be attached in every worker; hit the endpoint a few times to
    # reach more than one worker.
    url = _uvbridge_url(nginx_server)
    for _ in range(8):
        response = httpx.get(url)
        assert_status(response, httpx.codes.OK)
        data = response.json()
        assert data["attached"] is True, data
        assert data["pump_count"] >= 0, data
        assert data["fd_wakeups"] >= 0, data
        assert data["tick_wakeups"] >= 0, data


def test_uvbridge_workload(nginx_server: str):
    # POST runs a loopback-only libuv workload in the worker that
    # handles the request: a 50ms libuv timer and a libuv TCP echo
    # server, both on the loop the bridge pumps. The worker parks for
    # 0.5s while they run, then reports: the timer must have fired
    # repeatedly and the echo round trip must have succeeded. Without
    # the bridge the libuv loop never runs and the timer stays at 0.
    url = _uvbridge_url(nginx_server)
    response = httpx.post(url, timeout=30)
    assert_status(response, httpx.codes.OK)
    data = response.json()
    assert data["ok"] is True, data
    assert data["timer_growth"] >= 5, data
    assert data["echo_ok"] is True, data


def test_uvbridge_does_not_starve_http(nginx_server: str):
    # After the workload POST, a 50ms libuv timer keeps running in one
    # of the workers. A burst of plain HTTP requests must still
    # complete promptly; without the bridge the worker would never get
    # control back (openresty/lua-nginx-module#2396).
    url = _uvbridge_url(nginx_server)
    response = httpx.post(url, timeout=30)
    assert_status(response, httpx.codes.OK)

    health = nginx_server.removesuffix("webdav") + "webdav_health"
    start = time.monotonic()
    for _ in range(20):
        r = httpx.get(health, timeout=10)
        assert r.status_code == 200
    elapsed = time.monotonic() - start
    assert elapsed < 10, f"HTTP burst took {elapsed:.1f}s"
