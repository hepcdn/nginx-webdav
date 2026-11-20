-- Certificate-based authentication for gossip protocol
-- Uses IGTF host certificates for peer identity and message signing
--
-- Crypto is provided by lua-resty-openssl (resty.openssl.*), installed
-- explicitly by nginx.dockerfile.
--
-- Signing uses RSA-SHA256 over the RAW message:
--     pkey:sign(data, "sha256")  ==  openssl dgst -sha256 -sign key.pem
-- (OpenSSL hashes internally, so the message must not be pre-hashed.)
-- The fingerprint is the SHA-256 over the certificate DER:
--     cert:digest("sha256")      ==  openssl x509 -noout -fingerprint -sha256

local ngx = require("ngx")
local resty_openssl_pkey = require("resty.openssl.pkey")
local resty_openssl_x509 = require("resty.openssl.x509")

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

    -- Cached parsed objects (one per worker lua_State)
    cert_obj = nil,
    pkey_obj = nil,
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

    -- Parse the certificate (needed for fingerprint and subject)
    local cert_obj, err = resty_openssl_x509.new(CertAuth.cert, "PEM")
    if not cert_obj then
        ngx.log(ngx.ERR, "Failed to parse certificate: " .. err)
        return false
    end
    CertAuth.cert_obj = cert_obj

    -- Load the private key (type 'pr' fails loudly if the file holds
    -- only a public key)
    local pkey_obj, err = resty_openssl_pkey.new(CertAuth.key, {
        format = "PEM",
        type = "pr",
    })
    if not pkey_obj then
        ngx.log(ngx.ERR, "Failed to load private key: " .. err)
        return false
    end
    CertAuth.pkey_obj = pkey_obj

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
    local cert_obj = CertAuth.cert_obj
    if not cert_obj and CertAuth.cert then
        local obj, err = resty_openssl_x509.new(CertAuth.cert, "PEM")
        if not obj then
            ngx.log(ngx.ERR, "Failed to parse certificate: " .. err)
            return false
        end
        cert_obj = obj
        CertAuth.cert_obj = cert_obj
    end
    if not cert_obj then
        return false
    end

    local digest, err = cert_obj:digest("sha256")
    if not digest then
        ngx.log(ngx.ERR, "Failed to compute fingerprint: " .. err)
        return false
    end

    CertAuth.cert_fingerprint = "sha256:" .. ngx.encode_hex(digest)
    return true
end

--- Compute certificate subject DN
function CertAuth.compute_subject()
    local cert_obj = CertAuth.cert_obj
    if not cert_obj and CertAuth.cert then
        local obj, err = resty_openssl_x509.new(CertAuth.cert, "PEM")
        if not obj then
            ngx.log(ngx.ERR, "Failed to parse certificate: " .. err)
            return false
        end
        cert_obj = obj
        CertAuth.cert_obj = cert_obj
    end
    if not cert_obj then
        return false
    end

    local subject, err = cert_obj:get_subject_name()
    if not subject then
        ngx.log(ngx.ERR, "Failed to read certificate subject: "
            .. (err or "unknown error"))
        return false
    end

    CertAuth.cert_subject = tostring(subject)
    return true
end

--- Sign data with certificate's private key
function CertAuth.sign(data)
    if not CertAuth.load_cert() then
        return nil
    end

    -- RSA-SHA256 over the raw data; equivalent to
    -- `openssl dgst -sha256 -sign` (OpenSSL hashes internally, so the
    -- message must not be pre-hashed)
    local sig, err = CertAuth.pkey_obj:sign(data, "sha256")
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
        ngx.log(ngx.ERR, "Failed to decode signature: "
            .. (err or "invalid base64"))
        return false
    end

    local cert_obj, err = resty_openssl_x509.new(cert_pem, "PEM")
    if not cert_obj then
        ngx.log(ngx.WARN, "Failed to parse peer certificate: " .. err)
        return false
    end

    local pubkey, err = cert_obj:get_pubkey()
    if not pubkey then
        ngx.log(ngx.WARN, "Failed to extract peer public key: "
            .. (err or "unknown error"))
        return false
    end

    local valid, err = pubkey:verify(sig, data, "sha256")
    if valid ~= true then
        ngx.log(ngx.WARN, "Signature verification failed: "
            .. (err or "bad signature"))
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
