#!/usr/bin/env python3
"""Authenticated HTTP helper for verify.sh (runs on host or in-cluster).

Two modes:
  host (default): talks to https://localhost:20443 (IdP) and
    https://localhost:20081..20084 (nodes) — the docker-published ports.
  IN_CLUSTER=1:   runs inside a container on the compose network (via
    `docker exec hepcdn-idp`) and talks to https://idp:8443 and
    https://node1..4:8080 directly, bypassing the host's docker-proxy.
    The host's docker port publishing intermittently refuses connections
    (ECONNREFUSED windows of minutes), while the container network is
    stable, so verify.sh prefers this mode.

Tokens are written to files (./run/tok on the host, /tok in-cluster —
the same bind-mounted directory) and read back from memory: they never
appear in any process argv, because `curl -H 'Authorization: Bearer ***'`
gets the bearer value rewritten to '***' by the terminal's credential
redaction layer in this environment (401 'invalid jwt string').
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

IN_CLUSTER = os.environ.get("IN_CLUSTER") == "1"
CA = "/ca-bundle.pem" if IN_CLUSTER else "certs/ca-bundle.pem"
TOKDIR = "/tok" if IN_CLUSTER else "run/tok"


def ctx():
    return ssl.create_default_context(cafile=CA)


def idp_host():
    return "idp:8443" if IN_CLUSTER else "localhost:20443"


def node_host(n):
    return f"node{n}:8080" if IN_CLUSTER else f"localhost:{20080 + n}"


def _tok(name):
    return open(os.path.join(TOKDIR, name)).read().strip()


def _urlopen(r, timeout, attempts=5):
    """urlopen with retries for transient connection errors."""
    last = None
    for attempt in range(attempts):
        try:
            return urllib.request.urlopen(r, context=ctx(), timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            last = e
            time.sleep(0.5)
    if last is not None:
        raise last
    raise RuntimeError("no attempt made")


def mint(tokname, scope, sub="user123"):
    os.makedirs(TOKDIR, exist_ok=True)
    req = urllib.request.Request(
        f"https://{idp_host()}/mint",
        data=urllib.parse.urlencode({"scope": scope, "sub": sub}).encode(),
        method="POST")
    with _urlopen(req, 10) as r:
        tok = r.read().decode().strip()
    with open(os.path.join(TOKDIR, tokname), "w") as f:
        f.write(tok)
    print(len(tok))
    return tok


def req(method, host, path, tok=None, headers=None, body=None, timeout=30,
        attempts=5):
    h = dict(headers or {})
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else body.encode()
    r = urllib.request.Request(
        f"https://{host}{path}", data=data, headers=h, method=method)
    try:
        with _urlopen(r, timeout, attempts) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    cmd = sys.argv[1]
    if cmd == "mint":
        mint(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4
             else "user123")
    elif cmd == "health":
        st, body = req("GET", node_host(int(sys.argv[2])), "/webdav_health",
                       timeout=5, attempts=3)
        print(body.strip() if st == 200 else f"http {st}: {body[:120]}")
        sys.exit(0 if st == 200 else 1)
    elif cmd == "gossip-count":
        st, body = req("GET", node_host(int(sys.argv[2])), "/gossip",
                       _tok(sys.argv[3]), timeout=4, attempts=3)
        if st != 200:
            print(0)
            print(f"http {st}: {body[:120]}", file=sys.stderr)
            return
        d = json.loads(body)
        print(sum(1 for p in d if p["data"]["status"] == "alive"))
    elif cmd == "gossip-view":
        st, body = req("GET", node_host(int(sys.argv[2])), "/gossip",
                       _tok(sys.argv[3]))
        if st != 200:
            print(f"http {st}: {body[:200]}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(json.loads(body), indent=2))
    elif cmd == "put":
        n, path, tokname, body = int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
        st, out = req("PUT", node_host(n), path, _tok(tokname),
                      {"Content-Type": "text/plain"}, body)
        print(st)
        if out:
            print(out[:200], file=sys.stderr)
    elif cmd == "get":
        n, path, tokname = int(sys.argv[2]), sys.argv[3], sys.argv[4]
        st, out = req("GET", node_host(n), path, _tok(tokname))
        if st != 200:
            print(f"http {st}: {out[:200]}", file=sys.stderr)
            sys.exit(1)
        print(out, end="")
    elif cmd == "copy":
        # argv: copy dst_node dst_path tokname src_url xfer_tokname
        n, path = int(sys.argv[2]), sys.argv[3]
        st, out = req("COPY", node_host(n), path, _tok(sys.argv[4]),
                      {"Source": sys.argv[5],
                       "TransferHeaderAuthorization": f"Bearer {_tok(sys.argv[6])}"})
        print(st)
        if out:
            print(out[:200], file=sys.stderr)
    else:
        sys.exit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
