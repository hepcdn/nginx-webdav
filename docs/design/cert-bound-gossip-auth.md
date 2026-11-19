# Design: Certificate-Bound Gossip Authentication

## Problem Statement

The current gossip protocol implementation uses a shared JWT bearer token for authentication:

1. All nodes use the same OIDC client credentials (`openidc_client_id`/`openidc_client_secret`)
2. Tokens are sent in the `Authorization` header on every gossip request
3. Any authenticated peer can introduce new peers to the cluster

**Vulnerabilities:**

- **Sybil attacks**: A compromised node can advertise fake peers
- **Token exposure**: An attacker-controlled endpoint that joins the gossip list receives the bearer token in every gossip request
- **No per-node identity**: All nodes share the same JWT subject; can't identify or revoke individual nodes
- **Token replay**: Captured tokens can be reused indefinitely (until expiration)

## Proposed Solution

Use **certificate-bound JWT assertions** for gossip peer authentication:

1. Each node presents its IGTF host certificate during peer authentication
2. Nodes sign gossip messages with their certificate's private key
3. JWT claims are validated separately for authorization
4. Peer identity is derived from the certificate, not the JWT

This provides:
- **Unique peer identity** (from certificate subject DN)
- **Authorization claims** (from JWT scopes)
- **Binding between identity and claims** (via signed assertions)
- **No shared secrets** (each node has its own certificate/key pair)

## Architecture

### Peer Authentication Flow

1. **Initial contact**: Node A wants to gossip with Node B
2. **Challenge**: Node B sends a random nonce to Node A
3. **Signed response**: Node A signs the nonce + timestamp + JWT subject with its TLS private key, returns signature + certificate
4. **Verification**: Node B verifies:
   - Signature is valid using Node A's certificate
   - Certificate chains to IGTF root CA
   - Certificate subject matches expected peer identity
   - Timestamp is recent (replay protection)
5. **JWT validation**: Node B separately validates the JWT claims for authorization

### Gossip Message Format

Each gossip message includes:
```json
{
  "peers": [...],
  "signature": "base64(SHA256(message) signed with cert private key)",
  "cert_fingerprint": "sha256:abc123..."
}
```

### Implementation Components

1. **`cert_auth.lua`** - Certificate authentication functions
   - Load certificate/key pairs
   - Sign/verify messages
   - Validate certificate chains

2. **`gossip_auth.lua`** - Gossip-specific authentication
   - Challenge-response protocol
   - Peer identity verification
   - Token binding validation

3. **Updated `gossip.lua`** - Use cert-based auth instead of shared token
4. **Updated `gossip_content.lua`** - Verify incoming gossip signatures
5. **Updated `init_worker.lua`** - Use cert-based peer exchange

## Testing Strategy

1. **Unit tests** for cryptographic operations (signing, verification)
2. **Integration tests** with mock OIDC issuer and CA
3. **Multi-node cluster tests** verifying gossip authentication
4. **Attack simulation tests** (token replay, fake peer introduction)

## Mock Infrastructure

For testing, we'll create:
- Mock OIDC issuer (Python Flask/FastAPI service)
- Mock CA with self-signed certificates
- Test fixtures for various certificate scenarios