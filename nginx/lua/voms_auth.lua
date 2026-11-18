-- voms_auth.lua
-- X.509/VOMS certificate authentication for HEPCDN
-- Validates client certificates with VOMS extensions and maps FQANs to scopes.

local ngx = require("ngx")

local voms_auth = {}

-- VOMS extension OID
local VOMS_OID = "1.3.6.1.4.1.8005.100.100.5"

function voms_auth.validate()
    -- Check if client certificate was verified
    local cert_verify = ngx.var.ssl_client_verify
    if cert_verify ~= "SUCCESS" then
        return nil, "no valid client certificate"
    end

    local cert_pem = ngx.var.ssl_client_cert
    local subject_dn = ngx.var.ssl_client_s_dn

    if not cert_pem then
        return nil, "client certificate not available"
    end

    -- Extract just the first certificate from the chain
    local first_cert = voms_auth.extract_first_cert(cert_pem)
    if not first_cert then
        return nil, "failed to extract client certificate from chain"
    end

    -- Write cert to temp file for openssl
    local tmpfilename = "/tmp/voms_cert_" .. math.random(100000, 999999) .. ".pem"
    local tmpfile, err = io.open(tmpfilename, "w+")
    if not tmpfile then
        return nil, "failed to create temp file: " .. err
    end

    tmpfile:write(first_cert)
    tmpfile:close()

    -- Extract VOMS extension using openssl
    local fqans, err = voms_auth.extract_fqans(tmpfilename)
    os.remove(tmpfilename)

    if err then
        return nil, err
    end

    -- Map FQANs to HEPCDN scopes
    local scopes = voms_auth.fqans_to_scopes(fqans)

    return {
        sub = subject_dn,
        fqans = fqans,
        scopes = scopes
    }, nil
end

function voms_auth.extract_first_cert(cert_chain)
    -- Extract the first certificate from a PEM chain
    -- The cert chain from ngx.var.ssl_client_cert has tab-indented lines
    local start = cert_chain:find("-----BEGIN CERTIFICATE-----")
    if not start then
        return nil
    end
    
    local rest = cert_chain:sub(start)
    local end_pos = rest:find("-----END CERTIFICATE-----")
    if not end_pos then
        return nil
    end
    
    local cert = rest:sub(1, end_pos + 25) -- 25 = length of "-----END CERTIFICATE-----"
    -- Remove tab indentation from each line
    cert = cert:gsub("\t", "")
    return cert
end

function voms_auth.extract_fqans(cert_file)
    -- Use openssl to dump cert text and parse for VOMS extension
    local cmd = "openssl x509 -in " .. cert_file .. " -noout -text 2>&1 | grep -A 10 \"" .. VOMS_OID .. "\" || true"
    local pipe = io.popen(cmd, "r")
    if not pipe then
        return nil, "failed to execute openssl"
    end

    local output = pipe:read("*all")
    pipe:close()

    if not output or output == "" then
        return nil, "no VOMS extension found in certificate"
    end

    -- Parse FQANs from output
    -- Lines after the OID line contain the FQANs
    -- Format: "    ../fqan" (with leading dots from ASN.1 encoding)
    local fqans = {}
    local found_oid = false
    for line in output:gmatch("[^\r\n]+") do
        if line:find(VOMS_OID) then
            found_oid = true
        elseif found_oid and line:match("^%s+%.") then
            -- FQAN line (starts with whitespace and a dot)
            local fqan = line:gsub("^%s+", "")
            -- Handle ../ prefix (ASN.1 encoding artifact)
            fqan = fqan:gsub("^%.%./", "/")
            -- Handle ./ prefix
            fqan = fqan:gsub("^%./", "/")
            -- Stop at next extension or end of block
            if not fqan:find("/[a-z]") then
                break
            end
            table.insert(fqans, fqan)
        elseif found_oid and not line:match("^%s+") then
            -- Reached next non-indented line, stop
            break
        end
    end

    if #fqans == 0 then
        return nil, "no FQANs found in VOMS extension"
    end

    return fqans, nil
end

function voms_auth.fqans_to_scopes(fqans)
    -- Map grid FQANs to HEPCDN scopes
    -- Based on WLCG common JWT profile
    local scopes = ""
    for _, fqan in ipairs(fqans) do
        if fqan:find("^/cms") then
            -- Base CMS access
            scopes = scopes .. " storage.read:/ storage.create:/ storage.modify:/ hepcdn.view hepcdn.access"
            
            -- Role-based additional scopes
            if fqan:find("Role=prod") then
                -- Production role gets all scopes
            elseif fqan:find("Role=analysis") then
                -- Analysis role gets read and write
            end
            
            break -- One matching FQAN is sufficient
        end
    end
    return scopes
end

return voms_auth