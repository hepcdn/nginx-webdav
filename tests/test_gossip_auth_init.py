"""
Regression tests for gossip auth initialization (PR #79, review issue 2).

The IAM capability probe (iam_probe.detect_rfc8705) performs an HTTP
request. Cosockets are disabled in init_worker_by_lua, so the probe must
not run there; it is deferred to a 0-delay timer, and the resolved mode
is cached in the gossip_data shared dict so every worker sees the same
mode.

NOTE: these tests also exercise the module require chain of
cert_auth.lua (review issue 1). They pass only once that require is
satisfied as well; until then they fail on the init_worker
module-not-found error instead of the cosocket error.
"""

import json
import subprocess
import time

import httpx

# Log lines that prove the startup sequence has run far enough to reach
# (or crash at) the gossip auth init, from either the init_worker or the
# deferred probe timer.
INIT_MARKERS = (
    "init_worker_by_lua_file error",
    "Failed to probe IAM metadata",
    "IAM does not support RFC 8705",
    "IAM supports RFC 8705",
)


def _read_logs(setup_server) -> str:
    # docker/podman logs mirror the container's stdout and stderr onto the
    # client's stdout and stderr respectively; nginx logs to stderr, so both
    # streams must be captured.
    return subprocess.check_output(
        ["podman", "logs", setup_server.container_id],
        stderr=subprocess.STDOUT,
    ).decode(errors="replace")


def _nginx_logs(setup_server, markers=INIT_MARKERS, timeout=10.0) -> str:
    """Poll the container log until one of `markers` appears.

    The log driver can lag behind the container's stderr by well over a
    second after startup, so a single read right after the health check
    is not reliable; poll until the init sequence has visibly run.
    """
    deadline = time.time() + timeout
    logs = ""
    while time.time() < deadline:
        logs = _read_logs(setup_server)
        if any(marker in logs for marker in markers):
            return logs
        time.sleep(0.25)
    return _read_logs(setup_server)


def test_init_worker_survives_gossip_auth_init(setup_server):
    """init_worker must not crash while initializing gossip auth.

    Pre-fix, gossip_auth.init() performed the IAM probe directly in
    init_worker_by_lua, where cosockets are disabled. The error aborted
    the phase before ngx.timer.every() ran, so the gossip timer was
    never created. (Pre-fix, the missing cert_auth dependencies crash
    the same phase first; see review issue 1.)
    """
    logs = _nginx_logs(setup_server)
    # The init sequence must have actually run (otherwise this test
    # passes vacuously if the server never starts).
    assert any(marker in logs for marker in INIT_MARKERS), (
        "no evidence the gossip auth init ran:\n" + logs[-2000:]
    )
    assert "init_worker_by_lua_file error" not in logs, (
        "init_worker crashed during gossip auth initialization:\n"
        + "\n".join(l for l in logs.splitlines() if "init_worker" in l)
    )


def test_iam_probe_runs_and_degrades_to_fallback(setup_server):
    """The probe must run (from a cosocket-enabled context) and, when
    the IdP exposes no metadata endpoint, degrade to fallback mode
    instead of crashing or wedging the server.

    The mock IdP only implements POST /token, so the GET on
    /.well-known/openid-configuration fails (501 or a DNS error); the
    probe must log that failure and cache "fallback" for retry.
    """
    logs = _nginx_logs(setup_server)
    assert "Failed to probe IAM metadata" in logs, (
        "the deferred IAM probe never ran; init_worker likely did not "
        "survive to schedule the timer:\n" + logs[-2000:]
    )
    # A failed probe must degrade to fallback, not be reported as a
    # successful "not supported" metadata response.
    assert "IAM does not support RFC 8705" not in logs


def test_gossip_endpoint_responds_with_auth_init(setup_server, hepcdn_access_header):
    """GET /gossip must work once gossip auth init is wired in.

    Pre-fix, every /gossip request 500ed at the top-level
    gossip_auth.init() call (the require chain failed, and in the
    content phase the probe ran on the request path). With the fix,
    init() is a cheap shared-dict lookup once the mode is resolved.
    """
    # hosturl is the /webdav root; the gossip location is at /gossip
    base = setup_server.hosturl.rsplit("/webdav", 1)[0]
    r = httpx.get(
        f"{base}/gossip",
        headers=hepcdn_access_header,
    )
    assert r.status_code == 200, f"GET /gossip -> {r.status_code}: {r.text}"
    # gossip.prepare_message() returns a JSON array of {name, data} entries
    gossip_state = json.loads(r.text)
    assert isinstance(gossip_state, list)
