#!/usr/bin/env python3
"""Simple functional tests for the mock IdP (../mock-idp/app.py).

Run against a running IdP (e.g. `docker compose up -d idp` from the project
root), then:

    python3 tests/test_idp.py            # or with a python that has `cryptography`
    IDP_URL=https://idp:8443 python3 tests/test_idp.py

Covers:
  * TLS: client verifies the IdP certificate against the test CA (certs/)
  * GET  /healthz
  * GET  /.well-known/openid-configuration (issuer + token endpoint)
  * POST /token  client_credentials: success, wrong secret, unknown client,
                 bad grant type, missing scope, missing Authorization
  * POST /mint   backdoor minting with requested scope/sub/client_id
  * token shape: 3-part JWT, RS256 header, WLCG profile claims
    (wlcg.ver, sub, aud, nbf, scope, iss, exp, iat, jti, client_id)
  * signature: RS256 signature verified against the IdP's public key
               extracted from certs/idp/cert.pem (requires `cryptography`;
               that check is skipped with a notice if the module is missing)

Exit code 0 = all checks passed.
"""

import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_FILE = os.path.join(ROOT, "certs", "ca-bundle.pem")
IDP_CERT = os.path.join(ROOT, "certs", "idp", "cert.pem")
BASE = os.environ.get("IDP_URL", "https://localhost:20443").rstrip("/")
ISSUER = "https://idp:8443/"
CLIENT_ID = "hepcdn"
CLIENT_SECRET = "hepcdn-secret"
SCOPE = "storage.read:/ hepcdn.access"

failures = []
skipped = []


def check(name, cond, detail=""):
    tag = "PASS" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def request(method, path, form=None, headers=None, basic=None):
    """Return (status, headers, body-text). TLS is verified against certs/."""
    ctx = ssl.create_default_context(cafile=CA_FILE)
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if basic is not None:
        hdrs["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def b64url_decode(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def check_token(name, token, expect_sub, expect_client_id, expect_scope):
    parts = token.split(".")
    check(f"{name}: 3-part JWT", len(parts) == 3, f"got {len(parts)} parts")
    if len(parts) != 3:
        return None
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    check(f"{name}: header alg RS256", header.get("alg") == "RS256", str(header))
    now = time.time()
    claims = {
        "wlcg.ver": "1.0",
        "sub": expect_sub,
        "aud": "https://wlcg.cern.ch/jwt/v1/any",
        "scope": expect_scope,
        "iss": ISSUER,
        "client_id": expect_client_id,
    }
    for k, want in claims.items():
        check(f"{name}: claim {k} == {want!r}", payload.get(k) == want,
              f"got {payload.get(k)!r}")
    check(f"{name}: exp in the future", payload.get("exp", 0) > now)
    check(f"{name}: iat ~ now", abs(payload.get("iat", 0) - now) < 300)
    check(f"{name}: nbf <= now", payload.get("nbf", 10**12) <= now)
    check(f"{name}: jti present", bool(payload.get("jti")))
    return payload


def verify_signature(name, token):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        skipped.append(f"{name}: signature verification (cryptography not installed)")
        return
    cert = x509.load_pem_x509_certificate(open(IDP_CERT, "rb").read())
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        check(f"{name}: IdP cert holds an RSA public key", False, type(pub).__name__)
        return
    hdr_b64, payload_b64, sig_b64 = token.split(".")
    sig = b64url_decode(sig_b64)
    try:
        pub.verify(sig, f"{hdr_b64}.{payload_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())
        check(f"{name}: RS256 signature verifies against IdP key", True)
    except Exception as e:
        check(f"{name}: RS256 signature verifies against IdP key", False, str(e))


def main():
    print(f"mock IdP tests against {BASE} (issuer {ISSUER})")
    if not os.path.exists(CA_FILE):
        print(f"missing {CA_FILE} - run ../setup.sh first", file=sys.stderr)
        return 2

    # --- health + discovery -------------------------------------------------
    st, _, body = request("GET", "/healthz")
    check("GET /healthz -> 200 'ok'", st == 200 and body.strip() == "ok", f"{st} {body!r}")

    st, hdrs, body = request("GET", "/.well-known/openid-configuration")
    check("GET /.well-known/openid-configuration -> 200 json", st == 200, str(st))
    if st == 200:
        meta = json.loads(body)
        check("discovery: issuer", meta.get("issuer") == ISSUER, str(meta.get("issuer")))
        check("discovery: token_endpoint",
              meta.get("token_endpoint") == ISSUER + "token", str(meta.get("token_endpoint")))

    # --- /token client_credentials ------------------------------------------
    st, hdrs, body = request(
        "POST", "/token",
        form={"grant_type": "client_credentials", "scope": SCOPE},
        headers={"Accept": "application/json"},
        basic=f"{CLIENT_ID}:{CLIENT_SECRET}",
    )
    check("POST /token (valid client) -> 200", st == 200, f"{st} {body!r}")
    access_token = None
    if st == 200:
        resp = json.loads(body)
        check("token response: token_type Bearer", resp.get("token_type") == "Bearer")
        check("token response: expires_in > 0", resp.get("expires_in", 0) > 0)
        check("token response: scope echoed", resp.get("scope") == SCOPE, str(resp.get("scope")))
        check("token response: no-store cache control",
              hdrs.get("Cache-Control") == "no-store", str(hdrs.get("Cache-Control")))
        access_token = resp.get("access_token", "")
        check("token response: access_token present", bool(access_token))
        if access_token:
            check_token("token", access_token, CLIENT_ID, CLIENT_ID, SCOPE)
            verify_signature("token", access_token)

    st, _, body = request(
        "POST", "/token",
        form={"grant_type": "client_credentials", "scope": SCOPE},
        headers={"Accept": "application/json"},
        basic=f"{CLIENT_ID}:wrong-secret",
    )
    check("POST /token (wrong secret) -> 401", st == 401, str(st))

    st, _, body = request(
        "POST", "/token",
        form={"grant_type": "client_credentials", "scope": SCOPE},
        headers={"Accept": "application/json"},
        basic="nosuchclient:whatever",
    )
    check("POST /token (unknown client) -> 401", st == 401, str(st))

    st, _, body = request(
        "POST", "/token",
        form={"grant_type": "password", "scope": SCOPE},
        headers={"Accept": "application/json"},
        basic=f"{CLIENT_ID}:{CLIENT_SECRET}",
    )
    check("POST /token (bad grant type) -> 400", st == 400, str(st))

    st, _, body = request(
        "POST", "/token",
        form={"grant_type": "client_credentials"},
        headers={"Accept": "application/json"},
        basic=f"{CLIENT_ID}:{CLIENT_SECRET}",
    )
    check("POST /token (missing scope) -> 400", st == 400, str(st))

    st, _, body = request(
        "POST", "/token",
        form={"grant_type": "client_credentials", "scope": SCOPE},
        headers={"Accept": "application/json"},
    )
    check("POST /token (no Authorization) -> 401", st == 401, str(st))

    # --- /mint ----------------------------------------------------------------
    st, _, body = request(
        "POST", "/mint",
        form={"scope": "openid offline_access storage.read:/ storage.create:/"},
    )
    check("POST /mint (custom scope) -> 200 raw JWT", st == 200, f"{st} {body!r}")
    mint_token = body.strip()
    if st == 200 and mint_token:
        check_token("mint", mint_token, "user123", "user123",
                    "openid offline_access storage.read:/ storage.create:/")
        verify_signature("mint", mint_token)

    st, _, body = request(
        "POST", "/mint",
        form={"scope": "storage.read:/", "sub": "alice", "client_id": "alice-app"},
    )
    if st == 200:
        check_token("mint (explicit sub/client_id)", body.strip(), "alice", "alice-app",
                    "storage.read:/")

    # --- summary ----------------------------------------------------------------
    for s in skipped:
        print(f"  [SKIP] {s}")
    if failures:
        print(f"\n{len(failures)} FAILURE(S): {failures}")
        return 1
    print(f"\nALL IDP CHECKS PASSED ({len(skipped)} skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
