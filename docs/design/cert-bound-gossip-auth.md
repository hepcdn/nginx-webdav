# Design: Certificate-Bound Gossip Authentication (RFC 8705)

## Problem Statement

The current gossip protocol uses shared JWT bearer tokens for authentication, making it vulnerable to:
- **Sybil attacks**: A compromised node can advertise fake peers
- **Token exposure**: An attacker-controlled endpoint receives the bearer token
- **No per-node identity**: All nodes share the same JWT subject
- **Token replay**: Captured tokens can be reused until expiration

## Proposed Solution

Use **OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens** (RFC 8705), supported by INDIGO IAM v1.15.0+.

## Implementation Strategy

**Phase 1: Probe IAM Capabilities**
- On startup, probe the CMS IAM to detect RFC 8705 support
- Check for `tls_client_certificate_bound_access_tokens` in authorization server metadata
- Store result in shared memory for all workers

**Phase 2: Conditional Authentication**
- **If RFC 8705 is supported**: Use certificate-bound tokens for all peer-to-peer communication
  - Request tokens via mTLS with certificate
  - Verify `cnf.x5t#S256` claim matches peer certificate
- **If RFC 8705 is not supported**: Fall back to existing JWT token authentication
  - Use shared client_credentials grant
  - Send JWT in Authorization header (current behavior)

**Phase 3: Enforcement**
- When RFC 8705 is supported, require certificate-bound tokens for gossip
- Reject peers that don't use certificate-bound authentication
- Log warnings about insecure fallback when used

## IAM Capability Detection

Check the authorization server metadata endpoint:
```
GET /.well-known/openid-configuration
```

Look for:
```json
{
  "tls_client_certificate_bound_access_tokens": true
}
```

## Benefits

- Automatic detection and use of stronger authentication when available
- Backward compatibility with older IAM versions
- Clear security posture: strong auth when available, documented fallback otherwise