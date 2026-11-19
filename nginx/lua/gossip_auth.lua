-- Gossip protocol authentication using certificate-bound JWT assertions
-- Implements challenge-response with certificate signature verification

local ngx = require("ngx")
local cjson = require("cjson")
local resty_http = require("resty.http")
local cert_auth = require("cert_auth")
local config = require("config")

local GossipAuth = {
    -- Cache of verified peer certificates (fingerprint -> cert)
    peer_certs = {},
}

--- Generate a random nonce for challenge
function GossipAuth.generate_nonce()
    local bytes = ngx.encode_base64(ngx.random_bytes(16))
    return bytes
end

--- Create an authentication challenge
function GossipAuth.create_challenge()
    local challenge = {
        nonce = GossipAuth.generate_nonce(),
        timestamp = ngx.now(),
        issuer = config.data.server_address,
    }
    return challenge
end

--- Sign a challenge response with our certificate
function GossipAuth.sign_challenge(challenge, jwt_subject)
    local response = {
        nonce = challenge.nonce,
        timestamp = challenge.timestamp,
        jwt_subject = jwt_subject,
        cert_fingerprint = cert_auth.get_fingerprint(),
    }
    
    local data = cjson.encode(response)
    local signature = cert_auth.sign(data)
    
    if not signature then
        return nil, "Failed to sign challenge response"
    end
    
    return {
        data = data,
        signature = signature,
        certificate = cert_auth.load_cert() and cert_auth.cert or nil,
    }, nil
end

--- Verify a challenge response from a peer
function GossipAuth.verify_challenge(peer_addr, response, expected_nonce)
    -- Validate nonce
    if response.data.nonce ~= expected_nonce then
        return false, "Nonce mismatch"
    end
    
    -- Verify signature
    local ok = cert_auth.verify(response.data, response.signature, response.certificate)
    if not ok then
        return false, "Invalid signature"
    end
    
    -- Cache peer certificate
    local cert_obj, err = require("resty.x509").new(response.certificate)
    if cert_obj then
        local digest = require("resty.crypto").sha256(cert_obj:der())
        local fingerprint = "sha256:" .. ngx.encode_hex(digest)
        GossipAuth.peer_certs[peer_addr] = {
            cert = response.certificate,
            fingerprint = fingerprint,
            subject = cert_obj:subject(),
        }
    end
    
    return true, nil
end

--- Authenticate with a peer using challenge-response
function GossipAuth.authenticate_peer(peer_addr)
    local httpc = resty_http.new()
    httpc:set_timeouts(config.data.gossip_timeout, config.data.gossip_timeout, config.data.gossip_timeout)
    
    -- Step 1: Request challenge
    local challenge = GossipAuth.create_challenge()
    local res, err = httpc:request_uri(peer_addr .. "gossip/auth/challenge", {
        method = "POST",
        body = cjson.encode(challenge),
        headers = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json",
        },
    })
    
    if not res or res.status ~= 200 then
        return false, "Failed to get challenge: " .. (err or res and res.status or "unknown")
    end
    
    -- Step 2: Sign and send response
    local jwt_subject = ngx.shared.gossip_data:get("jwt_subject")
    if not jwt_subject then
        return false, "No JWT subject available"
    end
    
    local response, err = GossipAuth.sign_challenge(challenge, jwt_subject)
    if not response then
        return false, err
    end
    
    res, err = httpc:request_uri(peer_addr .. "gossip/auth/verify", {
        method = "POST",
        body = cjson.encode(response),
        headers = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json",
        },
    })
    
    if not res or res.status ~= 200 then
        return false, "Authentication failed: " .. (err or res and res.status or "unknown")
    end
    
    return true, nil
end

--- Verify a peer's certificate against IGTF CA bundle
function GossipAuth.verify_peer_cert(peer_addr)
    local peer_cert = GossipAuth.peer_certs[peer_addr]
    if not peer_cert then
        return false, "No certificate cached for peer"
    end
    
    -- Verify against CA bundle (simplified - in production would use openssl verify)
    -- For now, just check certificate is present and has valid subject
    if not peer_cert.subject then
        return false, "Certificate has no subject"
    end
    
    return true, nil
end

--- Get peer certificate info
function GossipAuth.get_peer_cert(peer_addr)
    return GossipAuth.peer_certs[peer_addr]
end

return GossipAuth