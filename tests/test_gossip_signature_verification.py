"""
Tests for gossip signature verification (PR #79, review issue 3).

Pre-fix, a receiver in RFC 8705 mode only checked that
`X-Gossip-Signature` was present and logged the claimed fingerprint —
it never verified the signature, and the sender did not send its
certificate, so there was nothing to verify against. Any client with a
valid bearer token could forge gossip.

These tests run a real server in rfc8705 mode (the rfc8705_server
fixture: an IdP that advertises
tls_client_certificate_bound_access_tokens, host certificates mounted
at /etc/grid-security, and a CA trust store) and check:

- signed gossip from a known peer is accepted and merged;
- unsigned gossip is rejected and not merged;
- a forged signature is rejected and not merged;
- a signature that does not match the presented certificate is
  rejected;
- a claimed fingerprint that does not match the certificate is
  rejected;
- a certificate that does not chain to the trusted CAs is rejected;
- the sender includes its certificate, fingerprint, a verifiable
  signature over the exact body, and still sends the bearer token
  (the /gossip access phase requires it).
"""

import base64
import hashlib
import json
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _sign(private_key, data: bytes) -> str:
    """RSA-SHA256 over the raw data, as `openssl dgst -sha256 -sign`
    and cert_auth.sign() do it."""
    return _b64(
        private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    )


def _fingerprint(cert_pem: str) -> str:
    """The 'sha256:<hex>' fingerprint over the certificate DER, as
    `openssl x509 -noout -fingerprint -sha256` computes it."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _gossip_body(peer_name: str) -> str:
    """A gossip message announcing one (fake) peer."""
    return json.dumps(
        [
            {
                "name": peer_name,
                "data": {
                    "epoch": 1,
                    "status": "alive",
                    "timestamp": int(time.time()),
                    "server_version": "test",
                    "failures": 0,
                },
            }
        ]
    )


def _base_url(server) -> str:
    # hosturl is the /webdav root; /gossip is a sibling location
    return server.hosturl.rsplit("/webdav", 1)[0]


def _bearer(rfc8705_idp) -> str:
    # The rfc8705 IdP only knows the nginx1 client
    return rfc8705_idp.make_wlcg_token(
        "storage.read:/ hepcdn.access", sub="nginx1", client_id="nginx1"
    )


def _post_gossip(server, body: str, **extra_headers) -> httpx.Response:
    # nginx discards header names containing underscores
    # (underscores_in_headers is off), so normalize to dashed names
    headers = {
        "Content-Type": "application/json",
        **{k.replace("_", "-"): v for k, v in extra_headers.items()},
    }
    return httpx.post(
        f"{_base_url(server)}/gossip",
        content=body.encode(),
        headers=headers,
    )


def _get_peer_names(server, rfc8705_idp) -> list:
    r = httpx.get(
        f"{_base_url(server)}/gossip",
        headers={"Authorization": f"Bearer {_bearer(rfc8705_idp)}"},
    )
    assert r.status_code == 200, f"GET /gossip -> {r.status_code}: {r.text}"
    return [entry["name"] for entry in json.loads(r.text)]


def test_signed_gossip_from_known_peer_accepted(
    rfc8705_server, rfc8705_idp
):
    server = rfc8705_server.server
    certs = rfc8705_server.certs
    peer = "http://trusted-peer.example:2880/"
    body = _gossip_body(peer)
    r = _post_gossip(
        server,
        body,
        Authorization=f"Bearer {_bearer(rfc8705_idp)}",
        X_Gossip_Signature=_sign(certs.host_private_key, body.encode()),
        X_Gossip_Cert=_b64(certs.hostcert_pem.encode()),
        X_Gossip_Cert_Fingerprint=_fingerprint(certs.hostcert_pem),
    )
    assert r.status_code == 200, f"signed gossip rejected: {r.text}"
    # The message must have been merged
    assert peer in _get_peer_names(server, rfc8705_idp)


def test_unsigned_gossip_rejected(rfc8705_server, rfc8705_idp):
    server = rfc8705_server.server
    peer = "http://unsigned-peer.example:2880/"
    body = _gossip_body(peer)
    r = _post_gossip(
        server,
        body,
        Authorization=f"Bearer {_bearer(rfc8705_idp)}",
    )
    assert r.status_code == 401, f"unsigned gossip accepted: {r.text}"
    assert peer not in _get_peer_names(server, rfc8705_idp)


def test_forged_signature_rejected(rfc8705_server, rfc8705_idp):
    server = rfc8705_server.server
    certs = rfc8705_server.certs
    peer = "http://forged-peer.example:2880/"
    body = _gossip_body(peer)
    r = _post_gossip(
        server,
        body,
        Authorization=f"Bearer {_bearer(rfc8705_idp)}",
        X_Gossip_Signature=_b64(b"\x00" * 256),  # not a valid signature
        X_Gossip_Cert=_b64(certs.hostcert_pem.encode()),
        X_Gossip_Cert_Fingerprint=_fingerprint(certs.hostcert_pem),
    )
    assert r.status_code == 401, f"forged signature accepted: {r.text}"
    assert peer not in _get_peer_names(server, rfc8705_idp)


def test_signature_not_matching_cert_rejected(rfc8705_server, rfc8705_idp):
    """Sign with one key but present the other peer's certificate:
    the signature must not verify against the presented cert."""
    server = rfc8705_server.server
    certs = rfc8705_server.certs
    peer = "http://mismatch-peer.example:2880/"
    body = _gossip_body(peer)
    r = _post_gossip(
        server,
        body,
        Authorization=f"Bearer {_bearer(rfc8705_idp)}",
        # Signed with the SECOND identity's key...
        X_Gossip_Signature=_sign(certs.second_private_key, body.encode()),
        # ...but presenting the HOST identity's certificate
        X_Gossip_Cert=_b64(certs.hostcert_pem.encode()),
        X_Gossip_Cert_Fingerprint=_fingerprint(certs.hostcert_pem),
    )
    assert r.status_code == 401, f"mismatched signature accepted: {r.text}"
    assert peer not in _get_peer_names(server, rfc8705_idp)


def test_claimed_fingerprint_mismatch_rejected(rfc8705_server, rfc8705_idp):
    """A valid signature for the presented cert, but a claimed
    fingerprint that belongs to a different certificate."""
    server = rfc8705_server.server
    certs = rfc8705_server.certs
    peer = "http://fp-mismatch-peer.example:2880/"
    body = _gossip_body(peer)
    r = _post_gossip(
        server,
        body,
        Authorization=f"Bearer {_bearer(rfc8705_idp)}",
        X_Gossip_Signature=_sign(certs.second_private_key, body.encode()),
        X_Gossip_Cert=_b64(certs.secondcert_pem.encode()),
        # Claim the fingerprint of the HOST cert instead of the
        # presented (second) cert
        X_Gossip_Cert_Fingerprint=_fingerprint(certs.hostcert_pem),
    )
    assert r.status_code == 401, f"fingerprint mismatch accepted: {r.text}"
    assert peer not in _get_peer_names(server, rfc8705_idp)


def test_untrusted_certificate_rejected(rfc8705_server, rfc8705_idp):
    """A valid signature by a certificate that does not chain to any
    CA in the server's trust store must be rejected."""
    server = rfc8705_server.server
    certs = rfc8705_server.certs
    peer = "http://untrusted-peer.example:2880/"
    body = _gossip_body(peer)
    r = _post_gossip(
        server,
        body,
        Authorization=f"Bearer {_bearer(rfc8705_idp)}",
        X_Gossip_Signature=_sign(certs.untrusted_private_key, body.encode()),
        X_Gossip_Cert=_b64(certs.untrustedcert_pem.encode()),
        X_Gossip_Cert_Fingerprint=_fingerprint(certs.untrustedcert_pem),
    )
    assert r.status_code == 401, f"untrusted certificate accepted: {r.text}"
    assert peer not in _get_peer_names(server, rfc8705_idp)


def test_sender_sends_cert_signature_and_bearer(rfc8705_server):
    """The container's own gossip timer must sign its messages and
    include its certificate, fingerprint, and the bearer token."""
    rfc8705 = rfc8705_server
    certs = rfc8705.certs

    # gossip_delay=1 and gossip_fraction=1.0: the capture peer should
    # be reached within a few seconds
    deadline = time.time() + 30
    while time.time() < deadline and not rfc8705.captured_gossip:
        time.sleep(0.5)
    assert rfc8705.captured_gossip, "gossip timer never reached the peer"

    req = rfc8705.captured_gossip[-1]
    h = req["headers"]

    # The body is a valid gossip message
    message = json.loads(req["body"])
    assert isinstance(message, list)

    # Our certificate is sent, and it is the mounted host cert
    assert "X-Gossip-Cert" in h, f"headers: {dict(h)}"
    presented = base64.b64decode(h["X-Gossip-Cert"])
    assert presented == certs.hostcert_pem.encode()

    # The claimed fingerprint matches the presented certificate
    assert h["X-Gossip-Cert-Fingerprint"] == _fingerprint(certs.hostcert_pem)

    # The signature verifies against the presented certificate over
    # the exact body that was sent
    presented_cert = x509.load_pem_x509_certificate(presented)
    signature = base64.b64decode(h["X-Gossip-Signature"])
    presented_cert.public_key().verify(
        signature, req["body"].encode(), padding.PKCS1v15(), hashes.SHA256()
    )

    # The bearer token is still sent alongside (the /gossip access
    # phase validates it)
    assert h["Authorization"].startswith("Bearer "), f"headers: {dict(h)}"
