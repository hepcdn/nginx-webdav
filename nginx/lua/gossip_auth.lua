-- Gossip protocol authentication using certificate-bound JWT assertions
-- Implements challenge-response with certificate signature verification
-- Conditionally uses RFC 8705 if supported by IAM

local ngx = require("ngx")
local cjson = require("cjson")
local resty_http = require("resty.http")
local cert_auth = require("cert_auth")
local config = require("config")
local iam_probe = require("iam_probe")

local GossipAuth = {
    -- Cache of verified peer certificates (fingerprint -> cert)
    peer_certs = {},
    -- Whether to use RFC 8705 certificate-bound tokens
    use_rfc8705 = false,
}

--- Initialize authentication based on IAM capabilities
function GossipAuth.init()
    GossipAuth.use_rfc8705 = iam_probe.detect_rfc8705()
    if GossipAuth.use_rfc8705 then
        ngx.log(ngx.NOTICE, "Using RFC 8705 certificate-bound authentication for gossip")
    else
        ngx.log(ngx.WARN, "Using fallback JWT token authentication for gossip (insecure)")
    end
end

--- Get authentication mode
function GossipAuth.get_mode()
    return GossipAuth.use_rfc8705 and "rfc8705" or "fallback"
end

--- Sign a message with our certificate (RFC 8705 mode)
function GossipAuth.sign_message(message)
    if not GossipAuth.use_rfc8705 then
        return nil
    end
    
    local signature = cert_auth.sign(message)
    if not signature then
        ngx.log(ngx.ERR, "Failed to sign gossip message with certificate")
    end
    return signature
end

--- Verify a message signature (RFC 8705 mode)
function GossipAuth.verify_message(message, signature, cert_pem)
    if not GossipAuth.use_rfc8705 then
        return true  -- No verification in fallback mode
    end
    
    return cert_auth.verify(message, signature, cert_pem)
end

--- Get our certificate fingerprint
function GossipAuth.get_fingerprint()
    if not GossipAuth.use_rfc8705 then
        return nil
    end
    return cert_auth.get_fingerprint()
end

--- Verify JWT certificate binding (RFC 8705 mode)
function GossipAuth.verify_jwt_binding(jwt_payload, cert_fingerprint)
    if not GossipAuth.use_rfc8705 then
        return true  -- No binding check in fallback mode
    end
    
    if not jwt_payload or not jwt_payload.cnf or not jwt_payload.cnf["x5t#S256"] then
        ngx.log(ngx.WARN, "JWT missing cnf.x5t#S256 claim")
        return false
    end
    
    -- Compare JWT thumbprint with actual certificate fingerprint
    return jwt_payload.cnf["x5t#S256"] == cert_fingerprint
end

return GossipAuth