"""
Tests for certificate-bound gossip authentication.
Uses existing MockIdP from conftest and OpenSSL for certificate operations.
"""

import subprocess
import time
import json
import pytest
import os
import tempfile


@pytest.fixture
def ca_certs():
    """Generate mock CA and host certificates for testing."""
    import tempfile
    
    # Create temp directory for certificates
    temp_dir = tempfile.mkdtemp(prefix="mock-ca-test-")
    ca_cert_path = os.path.join(temp_dir, "ca-cert.pem")
    ca_key_path = os.path.join(temp_dir, "ca-key.pem")
    
    # Generate CA key and self-signed cert
    subprocess.run([
        "openssl", "genrsa", "-out", ca_key_path, "2048"
    ], capture_output=True, check=True)
    
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-key", ca_key_path,
        "-out", ca_cert_path, "-days", "365",
        "-subj", "/C=US/O=Mock CA/CN=Mock CA Root"
    ], capture_output=True, check=True)
    
    # Generate host certificates
    node1_cert = os.path.join(temp_dir, "node1-cert.pem")
    node1_key = os.path.join(temp_dir, "node1-key.pem")
    node1_csr = os.path.join(temp_dir, "node1.csr")
    
    subprocess.run([
        "openssl", "genrsa", "-out", node1_key, "2048"
    ], capture_output=True, check=True)
    
    subprocess.run([
        "openssl", "req", "-new", "-key", node1_key,
        "-out", node1_csr,
        "-subj", "/C=US/O=Mock Host/CN=node1.example.com"
    ], capture_output=True, check=True)
    
    subprocess.run([
        "openssl", "x509", "-req", "-in", node1_csr,
        "-CA", ca_cert_path, "-CAkey", ca_key_path,
        "-CAcreateserial", "-out", node1_cert, "-days", "365"
    ], capture_output=True, check=True)
    
    # Generate node2 cert
    node2_cert = os.path.join(temp_dir, "node2-cert.pem")
    node2_key = os.path.join(temp_dir, "node2-key.pem")
    node2_csr = os.path.join(temp_dir, "node2.csr")
    
    subprocess.run([
        "openssl", "genrsa", "-out", node2_key, "2048"
    ], capture_output=True, check=True)
    
    subprocess.run([
        "openssl", "req", "-new", "-key", node2_key,
        "-out", node2_csr,
        "-subj", "/C=US/O=Mock Host/CN=node2.example.com"
    ], capture_output=True, check=True)
    
    subprocess.run([
        "openssl", "x509", "-req", "-in", node2_csr,
        "-CA", ca_cert_path, "-CAkey", ca_key_path,
        "-CAcreateserial", "-out", node2_cert, "-days", "365"
    ], capture_output=True, check=True)
    
    yield {
        "temp_dir": temp_dir,
        "ca_cert": ca_cert_path,
        "ca_key": ca_key_path,
        "node1_cert": node1_cert,
        "node1_key": node1_key,
        "node2_cert": node2_cert,
        "node2_key": node2_key,
    }
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)


class TestCertificateBoundGossipAuth:
    """Test certificate-bound gossip authentication."""

    def test_ca_certificate_generation(self, ca_certs):
        """Test that CA certificate is generated correctly."""
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["ca_cert"],
            "-noout", "-text"
        ], capture_output=True)
        assert result.returncode == 0
        assert b"CA:TRUE" in result.stdout

    def test_host_certificate_chain(self, ca_certs):
        """Test that host certificates chain to CA."""
        result = subprocess.run([
            "openssl", "verify", "-CAfile", ca_certs["ca_cert"],
            ca_certs["node1_cert"]
        ], capture_output=True)
        assert result.returncode == 0
        assert b"OK" in result.stdout

    def test_certificate_signing(self, ca_certs):
        """Test RSA signing with host certificate."""
        test_data = "test message for signing"
        
        # Sign with node1 key
        sig_path = os.path.join(ca_certs["temp_dir"], "test.sig")
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-sign", ca_certs["node1_key"],
            "-out", sig_path
        ], input=test_data.encode(), capture_output=True)
        assert result.returncode == 0
        
        # Verify with node1 public key (extracted from cert)
        pubkey_path = os.path.join(ca_certs["temp_dir"], "node1-pub.pem")
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["node1_cert"],
            "-pubkey", "-noout"
        ], capture_output=True, check=True)
        with open(pubkey_path, "wb") as f:
            f.write(result.stdout)
        
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", pubkey_path,
            "-signature", sig_path
        ], input=test_data.encode(), capture_output=True)
        assert result.returncode == 0
        assert b"Verified OK" in result.stdout

    def test_gossip_message_signing_flow(self, ca_certs):
        """Test the complete gossip message signing flow."""
        gossip_message = json.dumps({
            "peers": [
                {"name": "node1", "epoch": 1, "status": "alive"},
                {"name": "node2", "epoch": 1, "status": "alive"}
            ]
        })
        
        # Node1 signs the message
        sig_path = os.path.join(ca_certs["temp_dir"], "gossip.sig")
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-sign", ca_certs["node1_key"],
            "-out", sig_path
        ], input=gossip_message.encode(), capture_output=True)
        assert result.returncode == 0
        
        # Node2 extracts public key and verifies the signature
        pubkey_path = os.path.join(ca_certs["temp_dir"], "node1-pub.pem")
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["node1_cert"],
            "-pubkey", "-noout"
        ], capture_output=True, check=True)
        with open(pubkey_path, "wb") as f:
            f.write(result.stdout)
        
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", pubkey_path,
            "-signature", sig_path
        ], input=gossip_message.encode(), capture_output=True)
        assert result.returncode == 0
        assert b"Verified OK" in result.stdout
        
        # Tamper with the message and verify it fails
        tampered = gossip_message + " tampered"
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", pubkey_path,
            "-signature", sig_path
        ], input=tampered.encode(), capture_output=True)
        assert result.returncode != 0
        assert b"Verification failure" in result.stdout

    def test_wrong_certificate_verification(self, ca_certs):
        """Test that wrong certificate fails verification."""
        test_data = "test data"
        
        # Sign with node1
        sig_path = os.path.join(ca_certs["temp_dir"], "wrong.sig")
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-sign", ca_certs["node1_key"],
            "-out", sig_path
        ], input=test_data.encode(), capture_output=True)
        assert result.returncode == 0
        
        # Try to verify with node2's public key - should fail
        pubkey_path = os.path.join(ca_certs["temp_dir"], "node2-pub.pem")
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["node2_cert"],
            "-pubkey", "-noout"
        ], capture_output=True, check=True)
        with open(pubkey_path, "wb") as f:
            f.write(result.stdout)
        
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", pubkey_path,
            "-signature", sig_path
        ], input=test_data.encode(), capture_output=True)
        assert result.returncode != 0

    def test_certificate_fingerprint(self, ca_certs):
        """Test computing certificate fingerprint."""
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["node1_cert"],
            "-noout", "-fingerprint", "-sha256"
        ], capture_output=True)
        assert result.returncode == 0
        # OpenSSL outputs "sha256 Fingerprint=" (lowercase) in newer versions
        assert b"Fingerprint=" in result.stdout

    def test_certificate_subject(self, ca_certs):
        """Test extracting certificate subject."""
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["node1_cert"],
            "-noout", "-subject"
        ], capture_output=True)
        assert result.returncode == 0
        assert b"CN=node1.example.com" in result.stdout

    def test_certificate_expiration(self, ca_certs):
        """Test certificate expiration checking."""
        result = subprocess.run([
            "openssl", "x509", "-in", ca_certs["node1_cert"],
            "-noout", "-checkend", "0"
        ], capture_output=True)
        assert result.returncode == 0
        # OpenSSL outputs "Certificate will not expire" in newer versions
        assert b"will not expire" in result.stdout