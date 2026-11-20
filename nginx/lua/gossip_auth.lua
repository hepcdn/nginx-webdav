-- Gossip protocol authentication using certificate-bound JWT assertions
-- Implements challenge-response with certificate signature verification
-- Conditionally uses RFC 8705 if supported by the IAM
--
-- The resolved mode lives in the gossip_data shared dict (see iam_probe)
-- so that all workers and phases agree on it. init() is safe to call from
-- any phase: where cosockets are unavailable (init_worker) it defers the
-- IAM probe to a 0-delay timer instead of throwing.

local ngx = require("ngx")
local cert_auth = require("cert_auth")
local iam_probe = require("iam_probe")

local GossipAuth = {
    -- Cache of verified peer certificates (fingerprint -> cert)
    peer_certs = {},
}

--- Initialize authentication based on IAM capabilities.
-- Safe in every phase: it never performs a cosocket call in a context
-- where cosockets are disabled. Where the mode is not yet resolved and
-- cosockets are unavailable, the probe is deferred to a 0-delay timer.
function GossipAuth.init()
    local dict = ngx.shared.gossip_data
    if dict:get(iam_probe.MODE_KEY) then
        return  -- mode already resolved
    end

    local ok, err = pcall(iam_probe.detect_rfc8705)
    if ok then
        return
    end

    ngx.log(ngx.WARN, "gossip_auth: cannot probe IAM in this context ("
        .. tostring(err) .. "); deferring to a timer")
    local timer, terr = ngx.timer.at(0, function(premature)
        if not premature then
            local pok, perr = pcall(iam_probe.detect_rfc8705)
            if not pok then
                ngx.log(ngx.ERR, "gossip_auth: deferred IAM probe failed: " .. tostring(perr))
            end
        end
    end)
    if not timer then
        ngx.log(ngx.ERR, "gossip_auth: failed to schedule IAM probe timer: " .. tostring(terr))
    end
end

--- Get the current authentication mode ("rfc8705" or "fallback").
-- Never blocks: returns "fallback" until the probe has resolved the mode.
function GossipAuth.get_mode()
    local mode = ngx.shared.gossip_data:get(iam_probe.MODE_KEY)
    if not mode then
        GossipAuth.init()
        mode = ngx.shared.gossip_data:get(iam_probe.MODE_KEY)
    end
    return mode or "fallback"
end

--- Sign a message with our certificate (RFC 8705 mode)
function GossipAuth.sign_message(message)
    if GossipAuth.get_mode() ~= "rfc8705" then
        return nil
    end

    local signature = cert_auth.sign(message)
    if not signature then
        ngx.log(ngx.ERR, "Failed to sign gossip message with certificate")
    end
    return signature
end

--- Verify a message signature (RFC 8705 mode)
-- The sender's certificate is verified, not just the signature:
-- a claimed fingerprint must match the certificate, and (when trust
-- anchors are configured in ca_dir) the certificate must chain to one
-- of them. A message only merges after all checks pass; verified peer
-- certificates are remembered in GossipAuth.peer_certs.
function GossipAuth.verify_message(message, signature, cert_pem, claimed_fingerprint)
    if GossipAuth.get_mode() ~= "rfc8705" then
        return true  -- No verification in fallback mode
    end
    if not cert_pem then
        ngx.log(ngx.WARN, "gossip_auth: no certificate provided for verification")
        return false
    end

    -- A claimed fingerprint must match the provided certificate
    local actual_fingerprint, err = cert_auth.fingerprint_of(cert_pem)
    if not actual_fingerprint then
        ngx.log(ngx.WARN, "gossip_auth: cannot parse sender certificate: "
            .. (err or "unknown"))
        return false
    end
    if claimed_fingerprint and claimed_fingerprint ~= actual_fingerprint then
        ngx.log(ngx.WARN, "gossip_auth: fingerprint mismatch: claimed "
            .. claimed_fingerprint .. " but certificate has "
            .. actual_fingerprint)
        return false
    end

    -- The certificate must chain to a trusted CA (when anchors exist)
    local chain_ok, cerr = cert_auth.verify_chain(cert_pem)
    if chain_ok == false then
        ngx.log(ngx.WARN, "gossip_auth: sender certificate does not chain "
            .. "to a trusted CA: " .. (cerr or "unknown"))
        return false
    end
    -- chain_ok == nil: no trust anchors configured; the signature
    -- check below still applies

    local ok, verr = cert_auth.verify(message, signature, cert_pem)
    if not ok then
        ngx.log(ngx.WARN, "gossip_auth: signature verification failed: "
            .. (verr or "bad signature"))
        return false
    end

    GossipAuth.peer_certs[actual_fingerprint] = cert_pem
    return true
end

--- Get our certificate PEM (for sending to peers in RFC 8705 mode)
function GossipAuth.get_cert()
    if GossipAuth.get_mode() ~= "rfc8705" then
        return nil
    end
    return cert_auth.get_cert()
end

--- Get our certificate fingerprint
function GossipAuth.get_fingerprint()
    if GossipAuth.get_mode() ~= "rfc8705" then
        return nil
    end
    return cert_auth.get_fingerprint()
end

--- Verify JWT certificate binding (RFC 8705 mode)
function GossipAuth.verify_jwt_binding(jwt_payload, cert_fingerprint)
    if GossipAuth.get_mode() ~= "rfc8705" then
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
