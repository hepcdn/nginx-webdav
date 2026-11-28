#!/usr/bin/env python3
"""Self-contained mock OIDC identity provider for the HEPCDN test cluster.

Implements the minimal OIDC surface that hepcdn/nginx-webdav needs at
runtime:

  POST /token   - client_credentials grant with Basic client auth, exactly
                  as the nodes' gossip timer calls it
                  (openidc_iss + "token", scope "storage.read:/ hepcdn.access")
  POST /mint    - unauthenticated test backdoor: mints a WLCG-profile JWT for
                  any scope/sub so clients can get WebDAV tokens
  GET  /.well-known/openid-configuration - basic discovery metadata
  GET  /healthz - liveness

Tokens follow the WLCG common JWT profile (RS256):
  https://github.com/WLCG-AuthZ-WG/common-jwt-profile
(same claim set as MockIdP.make_wlcg_token in the repo's tests/conftest.py).
"""

import base64
import json
import os
import ssl
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PORT = int(os.environ.get("PORT", "8443"))
ISSUER = os.environ.get("ISSUER", "https://idp:8443/")
CLIENTS = {
    pair.split(":", 1)[0]: pair.split(":", 1)[1]
    for pair in os.environ.get("CLIENTS", "hepcdn:hepcdn-secret").split(",")
    if pair
}
TOKEN_TTL = 4 * 3600

with open("/certs/key.pem", "rb") as f:
    _loaded = serialization.load_pem_private_key(f.read(), password=None)
if not isinstance(_loaded, rsa.RSAPrivateKey):
    raise SystemExit("mock IdP signing key must be an RSA key (WLCG profile is RS256)")
_signing_key: rsa.RSAPrivateKey = _loaded


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_jwt(payload: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("ascii"))
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode("ascii"))
    )
    sig = _signing_key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return signing_input + "." + _b64url(sig)


def make_wlcg_token(scope: str, sub: str, client_id: str) -> str:
    now = int(time.time())
    return sign_jwt(
        {
            "wlcg.ver": "1.0",
            "sub": sub,
            "aud": "https://wlcg.cern.ch/jwt/v1/any",
            "nbf": now,
            "scope": scope,
            "iss": ISSUER,
            "exp": now + TOKEN_TTL,
            "iat": now,
            "jti": str(uuid.uuid4()),
            "client_id": client_id,
        }
    )


class IdPHandler(BaseHTTPRequestHandler):
    server_version = "MockIdP/1.0"

    def log_message(self, format, *args):  # one line per request
        print("%s %s" % (self.address_string(), format % args), flush=True)

    def _send(self, status: int, content_type: str, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if content_type == "application/json":
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_form(self):
        if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            self._send(400, "text/plain", "Unsupported content type")
            return None
        length = int(self.headers.get("Content-Length", 0))
        params = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        return params

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, "text/plain", "ok\n")
        elif self.path == "/.well-known/openid-configuration":
            meta = {
                "issuer": ISSUER,
                "token_endpoint": ISSUER + "token",
                "grant_types_supported": ["client_credentials"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }
            self._send(200, "application/json", json.dumps(meta, indent=2) + "\n")
        elif self.path in ("/", ""):
            self._send(200, "text/plain", "mock IdP for the hepcdn test cluster\n")
        else:
            self._send(404, "text/plain", "not found\n")

    def do_POST(self):
        if self.path == "/token":
            self._token()
        elif self.path == "/mint":
            self._mint()
        else:
            self._send(404, "text/plain", "not found\n")

    def _token(self):
        params = self._read_form()
        if params is None:
            return
        if params.get("grant_type") != "client_credentials":
            self._send(400, "text/plain", "Unsupported grant type")
            return
        scope = params.get("scope")
        if not scope:
            self._send(400, "text/plain", "Missing scope")
            return
        if self.headers.get("Accept") != "application/json":
            self._send(400, "text/plain", "Unsupported accept type")
            return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self._send(401, "text/plain", "Missing or invalid authorization header")
            return
        try:
            username, password = (
                base64.b64decode(auth.removeprefix("Basic ")).decode().split(":", 1)
            )
        except Exception:
            self._send(401, "text/plain", "Missing or invalid authorization header")
            return
        if CLIENTS.get(username) != password:
            self._send(401, "text/plain", "Invalid client credentials")
            return
        token = make_wlcg_token(scope, sub=username, client_id=username)
        self._send(
            200,
            "application/json",
            json.dumps(
                {
                    "token_type": "Bearer",
                    "expires_in": TOKEN_TTL,
                    "access_token": token,
                    "scope": scope,
                }
            ),
        )

    def _mint(self):
        params = self._read_form() or {}
        scope = params.get("scope", "storage.read:/")
        sub = params.get("sub", "user123")
        client_id = params.get("client_id", sub)
        token = make_wlcg_token(scope, sub=sub, client_id=client_id)
        self._send(200, "text/plain", token + "\n")


def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), IdPHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"mock IdP listening on https://0.0.0.0:{PORT}/ (issuer {ISSUER})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
