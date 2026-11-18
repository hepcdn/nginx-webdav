# X.509/VOMS Certificate Authentication Implementation Plan

## Overview

Add support for X.509 client certificate authentication with VOMS (Virtual Organization Membership Service) extension parsing as an alternative to the existing JWT-based authentication. This enables standard WLCG/HEP grid clients to authenticate to HEPCDN using their grid proxies.

## Architecture

```
Client Request
      │
      ├── Has JWT token? ──Yes──► JWT validation (existing path)
      │            │
      │           No
      │            │
      ├── Has client cert? ──No──► 401 Unauthorized
      │            │
      │           Yes
      │            │
      └── Parse X.509 cert ──► Extract VOMS extension ──► Validate FQANs ──► Map to scopes
```

## Implementation Details

### 1. Enable SSL Client Certificate Verification

Modify `nginx/docker-entrypoint.sh` to add `ssl_verify_client optional;` when `USE_SSL=true`:

```nginx
# In the SSL server block
ssl_verify_client optional;
ssl_client_certificate /etc/grid-security/certificates/ca-bundle.pem;
```

**Key nginx variables exposed to Lua:**
- `ngx.var.ssl_client_verify` — "SUCCESS" if cert validated, "FAILED" if not, "" if no cert
- `ngx.var.ssl_client_s_dn` — subject distinguished name
- `ngx.var.ssl_client_cert` — full client certificate PEM (including chain)
- `ngx.var.ssl_client_i_dn` — issuer distinguished name

### 2. Create VOMS Parsing Module

Create `nginx/lua/voms_auth.lua` to handle X.509/VOMS validation:

```lua
local voms_auth = {}

-- OID for VOMS extension
local VOMS_OID = "1.3.6.1.4.1.8005.100.100.5"

function voms_auth.validate()
    local cert_verify = ngx.var.ssl_client_verify
    if cert_verify ~= "SUCCESS" then
        return nil, "no valid client certificate"
    end
    
    local cert_pem = ngx.var.ssl_client_cert
    local subject_dn = ngx.var.ssl_client_s_dn
    
    -- Parse certificate and extract VOMS extension
    local voms_ext, err = extract_voms_extension(cert_pem)
    if not voms_ext then
        return nil, "no VOMS extension found: " .. err
    end
    
    -- Parse FQANs from VOMS extension
    local fqans, err = parse_voms_fqans(voms_ext)
    if not fqans then
        return nil, "failed to parse FQANs: " .. err
    end
    
    -- Validate proxy expiration (embedded in VOMS extension)
    local expired, err = check_voms_expiration(voms_ext)
    if expired then
        return nil, "VOMS proxy expired: " .. err
    end
    
    -- Map FQANs to HEPCDN scopes
    local scopes = fqans_to_scopes(fqans)
    
    return {
        sub = subject_dn,
        fqans = fqans,
        scopes = scopes
    }, nil
end

-- ASN.1/TLV parsing functions for VOMS extension
function extract_voms_extension(cert_pem)
    -- Decode PEM to DER
    -- Parse X.509 structure
    -- Find extension with OID 1.3.6.1.4.1.8005.100.100.5
    -- Return raw extension data
end

function parse_voms_fqans(voms_data)
    -- Parse nested TLVs in VOMS extension
    -- Extract FQAN list
    -- Return table of FQAN strings
end

function check_voms_expiration(voms_data)
    -- Extract expiration time from VOMS extension
    -- Compare with current time
    -- Return true if expired
end

function fqans_to_scopes(fqans)
    -- Map grid FQANs to HEPCDN scopes
    -- /cms → storage.read:/, storage.create:/, storage.modify:/
    -- /cms/Role=prod → additional scopes
    local scopes = ""
    for _, fqan in ipairs(fqans) do
        if string.find(fqan, "^/cms") then
            scopes = scopes .. " storage.read:/ storage.create:/ storage.modify:/ hepcdn.view hepcdn.access"
        end
    end
    return scopes
end

return voms_auth
```

### 3. Modify Authentication Scripts

Update `nginx/lua/webdav_access.lua` and `nginx/lua/hepcdn_access.lua`:

```lua
local ngx = require("ngx")
local openidc = require("resty.openidc")
local config = require("config")
local voms_auth = require("voms_auth")

-- Try JWT first
local res, err = openidc.bearer_jwt_verify({
    public_key = config.data.openidc_pubkey,
    token_signing_alg_values_expected = { "RS256" }
})

-- If JWT fails, try VOMS cert auth
if err or not res then
    res, err = voms_auth.validate()
end

if err or not res then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = 'Bearer realm=storage'
    ngx.say(err or "authentication failed")
    return ngx.exit(ngx.OK)
end

-- Use res.sub for identity, res.scope for authorization
ngx.var.oidc_user = res.sub
-- ... existing scope checks ...
```

## ASN.1 Parsing Challenge

The VOMS extension uses custom ASN.1/TLV encoding. Options for parsing:

1. **Pure Lua ASN.1 parser** — implement TLV parsing directly in `voms_auth.lua`
   - Pros: No dependencies, full control
   - Cons: Complex, error-prone

2. **Use lua-resty-x509 library** — existing OpenResty module for X.509 parsing
   - Pros: Handles PEM/DER decoding, basic certificate parsing
   - Cons: May not parse VOMS extension specifically; still need custom FQAN parsing

3. **External tool via ngx.spawn** — use `openssl` command-line tool
   - Pros: Battle-tested, handles all parsing
   - Cons: Process overhead, slower, requires openssl binary in container

**Recommendation:** Option 2 (lua-resty-x509) for certificate parsing + custom Lua for FQAN extraction from the VOMS extension raw bytes.

## Scope Mapping Strategy

Map grid FQANs to HEPCDN scopes based on WLCG common JWT profile:

| Grid FQAN | HEPCDN Scope |
|-----------|--------------|
| `/cms` | `storage.read:/` |
| `/cms/Role=NULL/Capability=NULL` | `storage.read:/` |
| `/cms/Role=prod/Capability=NULL` | `storage.read:/ storage.create:/ storage.modify:/` |
| `/cms/Role=NULL/Capability=read` | `storage.read:/` |
| `/cms/Role=NULL/Capability=write` | `storage.read:/ storage.create:/ storage.modify:/` |

## Testing

Test with the provided certificates:
- `test-melo-x509.cert` — contains both proxy cert (with VOMS extension) and user cert
- Verify FQAN extraction: should find `/cms`, `/cms/Role=NULL/Capability=NULL`, etc.
- Test both JWT and X.509 auth paths
- Test with expired proxy cert

## Files to Modify

1. `nginx/docker-entrypoint.sh` — add `ssl_verify_client optional;`
2. `nginx/lua/voms_auth.lua` — new VOMS authentication module
3. `nginx/lua/webdav_access.lua` — add VOMS fallback path
4. `nginx/lua/hepcdn_access.lua` — add VOMS fallback path
5. `nginx/lua/config.lua` — potentially add VOMS configuration options

## Configuration Options

Add to config for flexibility:

```lua
voms: {
    enabled: true,
    allowed_vos: ["cms"],
    vo_scope_map: {
        "cms": "storage.read:/ storage.create:/ storage.modify:/ hepcdn.view hepcdn.access"
    }
}
```