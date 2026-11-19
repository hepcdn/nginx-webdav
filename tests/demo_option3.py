#!/usr/bin/env python3
"""
Demonstration of Option 3: Client-side JWT-Certificate Binding

Simulates a gossip node that:
1. Obtains a JWT from the OIDC issuer
2. Creates a binding assertion linking the JWT to its certificate
3. Signs the assertion with its certificate private key
4. Sends everything to a peer for verification
"""

import json
import time
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


# Mock OIDC issuer (simplified)
def mock_oidc_issue_token(client_id):
    """Simulate getting a JWT from CMS IAM."""
    return {
        "iss": "https://cms-auth.cern.ch/",
        "sub": client_id,
        "aud": "https://cms-auth.cern.ch/",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "client_id": client_id,
        "scope": "storage.read:/ hepcdn.access",
    }


def generate_cert_and_key(cn):
    """Generate a self-signed certificate and key for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def sign_data(private_key, data):
    """Sign data with RSA-SHA256."""
    from cryptography.hazmat.primitives.asymmetric import padding
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_signature(cert, data, signature):
    """Verify RSA-SHA256 signature."""
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        cert.public_key().verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def get_cert_fingerprint(cert):
    """Compute SHA-256 fingerprint of certificate."""
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return "sha256:" + digest.finalize().hex()


print("=" * 60)
print("Option 3: Client-side JWT-Certificate Binding Demo")
print("=" * 60)

# Step 1: Node obtains JWT from CMS IAM
print("\n[1] Node obtains JWT from CMS IAM...")
jwt_payload = mock_oidc_issue_token("hepcdn-node-1")
jwt_payload_json = json.dumps(jwt_payload)
print(f"    JWT subject: {jwt_payload['sub']}")
print(f"    JWT issuer: {jwt_payload['iss']}")
print(f"    JWT scopes: {jwt_payload['scope']}")

# Step 2: Node creates binding assertion
print("\n[2] Node creates binding assertion...")
cert, key = generate_cert_and_key("node1.example.com")
cert_fingerprint = get_cert_fingerprint(cert)
assertion = {
    "jwt_sub": jwt_payload["sub"],
    "jwt_iss": jwt_payload["iss"],
    "cert_fingerprint": cert_fingerprint,
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}
assertion_json = json.dumps(assertion)
print(f"    Assertion cert_fingerprint: {cert_fingerprint[:20]}...")
print(f"    Assertion jwt_sub: {assertion['jwt_sub']}")

# Step 3: Node signs assertion with certificate private key
print("\n[3] Node signs assertion with certificate private key...")
signature = sign_data(key, assertion_json.encode())
print(f"    Signature length: {len(signature)} bytes")

# Step 4: Node sends to peer (JWT + signed assertion + certificate)
print("\n[4] Node sends to peer: JWT + signed assertion + certificate")
print("    (simulating gossip message transmission)")

# Step 5: Peer verification
print("\n[5] Peer verification:")
print("    [a] Verifying JWT is valid...")
try:
    jwt_claims = json.loads(jwt_payload_json)
    assert jwt_claims["iss"] == "https://cms-auth.cern.ch/"
    print("        ✓ JWT issuer valid")
except Exception as e:
    print(f"        ✗ JWT validation failed: {e}")

print("    [b] Verifying assertion signature matches certificate...")
if verify_signature(cert, assertion_json.encode(), signature):
    print("        ✓ Assertion signature valid")
else:
    print("        ✗ Assertion signature invalid")

print("    [c] Checking assertion claims match JWT claims...")
assertion_claims = json.loads(assertion_json)
if assertion_claims["jwt_sub"] == jwt_claims["sub"] and \
   assertion_claims["jwt_iss"] == jwt_claims["iss"]:
    print("        ✓ JWT and assertion claims match")
else:
    print("        ✗ JWT and assertion claims mismatch")

print("    [d] Checking cert_fingerprint matches actual certificate...")
actual_fingerprint = get_cert_fingerprint(cert)
if assertion_claims["cert_fingerprint"] == actual_fingerprint:
    print("        ✓ Certificate fingerprint matches")
else:
    print("        ✗ Certificate fingerprint mismatch")

print("\n[6] Security property:")
print("    - JWT alone is useless (no private key)")
print("    - Certificate alone is useless (no JWT)")
print("    - Attacker needs BOTH JWT and private key to impersonate node")

print("\n" + "=" * 60)
print("Demo complete!")
print("=" * 60)