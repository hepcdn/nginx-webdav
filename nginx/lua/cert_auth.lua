-- Certificate-based authentication for gossip protocol
-- Uses IGTF host certificates for peer identity and message signing

local ngx = require("ngx")
local resty_crypto = require("resty.crypto")
local resty_x509 = require("resty.x509")

local CertAuth = {
    -- Certificate and key paths
    cert_path = "/etc/grid-security/hostcert.pem",
    key_path = "/etc/grid-security/hostkey.pem",
    ca_dir = "/etc/grid-security/certificates",
    
    -- Cached certificate
    cert = nil,
    key = nil,
    cert_fingerprint = nil,
    cert_subject = nil,
}

--- Load certificate and key from files
function CertAuth.load_cert()
    if CertAuth.cert then
        return true
    end
    
    -- Load certificate
    local f = io.open(CertAuth.cert_path, "r")
    if not f then
        ngx.log(ngx.ERR, "Failed to open certificate: " .. CertAuth.cert_path)
        return false
    end
    CertAuth.cert = f:read("*a")
    f:close()
    
    -- Load key
    f = io.open(CertAuth.key_path, "r")
    if not f then
        ngx.log(ngx.ERR, "Failed to open key: " .. CertAuth.key_path)
        return false
    end
    CertAuth.key = f:read("*a")
    f:close()
    
    -- Compute fingerprint and subject
    local ok, err = CertAuth.compute_fingerprint()
    if not ok then
        return false
    end
    
    ok, err = CertAuth.compute_subject()
    if not ok then
        return false
    end
    
    return true
end

--- Compute SHA-256 fingerprint of certificate
function CertAuth.compute_fingerprint()
    local cert_obj, err = resty_x509.new(CertAuth.cert)
    if not cert_obj then
        ngx.log(ngx.ERR, "Failed to parse certificate: " .. err)
        return false
    end
    
    local digest, err = resty_crypto.sha256(cert_obj:der())
    if not digest then
        ngx.log(ngx.ERR, "Failed to compute fingerprint: " .. err)
        return false
    end
    
    CertAuth.cert_fingerprint = "sha256:" .. ngx.encode_hex(digest)
    return true
end

--- Compute certificate subject DN
function CertAuth.compute_subject()
    local cert_obj, err = resty_x509.new(CertAuth.cert)
    if not cert_obj then
        ngx.log(ngx.ERR, "Failed to parse certificate: " .. err)
        return false
    end
    
    CertAuth.cert_subject = cert_obj:subject()
    return true
end

--- Sign data with certificate's private key
function CertAuth.sign(data)
    if not CertAuth.load_cert() then
        return nil
    end
    
    -- Use openssl via ngx for signing
    local digest, err = resty_crypto.sha256(data)
    if not digest then
        ngx.log(ngx.ERR, "Failed to compute digest for signing: " .. err)
        return nil
    end
    
    -- Sign with RSA-SHA256
    local sig, err = resty_crypto.rsa_sign(CertAuth.key, digest, "sha256")
    if not sig then
        ngx.log(ngx.ERR, "Failed to sign data: " .. err)
        return nil
    end
    
    return ngx.encode_base64(sig)
end

--- Verify signature using certificate
function CertAuth.verify(data, signature_b64, cert_pem)
    local sig, err = ngx.decode_base64(signature_b64)
    if not sig then
        ngx.log(ngx.ERR, "Failed to decode signature: " .. err)
        return false
    end
    
    local digest, err = resty_crypto.sha256(data)
    if not digest then
        ngx.log(ngx.ERR, "Failed to compute digest for verification: " .. err)
        return false
    end
    
    local ok, err = resty_crypto.rsa_verify(cert_pem, digest, sig, "sha256")
    if not ok then
        ngx.log(ngx.WARN, "Signature verification failed: " .. err)
        return false
    end
    
    return true
end

--- Get certificate fingerprint
function CertAuth.get_fingerprint()
    if not CertAuth.cert_fingerprint then
        if not CertAuth.load_cert() then
            return nil
        end
    end
    return CertAuth.cert_fingerprint
end

--- Get certificate subject
function CertAuth.get_subject()
    if not CertAuth.cert_subject then
        if not CertAuth.load_cert() then
            return nil
        end
    end
    return CertAuth.cert_subject
end

return CertAuth