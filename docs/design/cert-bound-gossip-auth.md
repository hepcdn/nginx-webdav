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

Use **OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens** (RFC 8705), which is supported by the CMS IAM (INDIGO IAM v1.15.0+).

Each node presents its IGTF host certificate during mutual TLS to the IAM, which binds the issued JWT to the certificate by embedding its thumbprint. This provides:
- **Unique peer identity** (from certificate subject DN)
- **Authorization claims** (from JWT scopes)
- **Binding between identity and claims** (JWT contains certificate thumbprint)
- **No shared secrets** (each node has its own certificate/key pair)

## Architecture

### Token Request Flow (mTLS)

1. Node establishes mTLS connection to CMS IAM using its IGTF host certificate
2. Node requests JWT via `client_credentials` grant over the mTLS connection
3. CMS IAM issues JWT with certificate thumbprint embedded in `cnf` claim:
   ```json
   {
     "sub": "node1",
     "scope": "hepcdn.access",
     "cnf": {
       "x5t#S256": "m8UcWBSPNtaKN19TdR8zUHvWWOSCSX9nsa5vU6fscd0"
     }
   }
   ```

### Gossip Message Flow

1. Node signs gossip message with its certificate private key
2. Node sends gossip message + JWT + certificate to peer
3. Peer verifies:
   - JWT is valid (signature, issuer, expiration)
   - Gossip message signature matches the certificate
   - JWT `cnf.x5t#S256` thumbprint matches the certificate's actual fingerprint

### Implementation Components

1. **`cert_auth.lua`** - Certificate authentication functions
   - Load certificate/key pairs
   - Sign/verify messages
   - Compute certificate fingerprints

2. **`gossip_auth.lua`** - Gossip-specific authentication
   - JWT validation with certificate binding
   - Peer identity verification

3. **Updated `gossip.lua`** - Use cert-based auth instead of shared token
4. **Updated `gossip_content.lua`** - Verify incoming gossip signatures and JWT binding
5. **Updated `init_worker.lua`** - Use mTLS for token requests and cert-based peer exchange

## Testing Strategy

1. **Unit tests** for cryptographic operations (signing, verification)
2. **Integration tests** with mock OIDC issuer and CA
3. **Multi-node cluster tests** verifying gossip authentication
4. **Attack simulation tests** (token replay, fake peer introduction)

## Mock Infrastructure

For testing, we'll create:
- Mock OIDC issuer (Python HTTP server)
- Mock CA with self-signed certificates
- Test fixtures for various certificate scenarios