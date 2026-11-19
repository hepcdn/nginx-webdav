-- IAM capability detection
-- Probes the CMS IAM to detect RFC 8705 (certificate-bound tokens) support

local ngx = require("ngx")
local resty_http = require("resty.http")
local cjson = require("cjson")
local config = require("config")

local IamProbe = {
    -- Cached result
    rfc8705_supported = nil,
}

--- Probe IAM for RFC 8705 support
function IamProbe.detect_rfc8705()
    if IamProbe.rfc8705_supported ~= nil then
        return IamProbe.rfc8705_supported
    end
    
    local httpc = resty_http.new()
    local res, err = httpc:request_uri(config.data.openidc_iss .. ".well-known/openid-configuration", {
        method = "GET",
        headers = {
            ["Accept"] = "application/json",
            ["User-Agent"] = "nginx-webdav/" .. config.data.server_version,
        },
    })
    
    if not res or res.status ~= 200 then
        ngx.log(ngx.WARN, "Failed to probe IAM metadata: " .. (err or (res and res.status or "unknown")))
        IamProbe.rfc8705_supported = false
        return IamProbe.rfc8705_supported
    end
    
    local metadata, err = cjson.decode(res.body)
    if not metadata then
        ngx.log(ngx.WARN, "Failed to decode IAM metadata: " .. err)
        IamProbe.rfc8705_supported = false
        return IamProbe.rfc8705_supported
    end
    
    IamProbe.rfc8705_supported = metadata.tls_client_certificate_bound_access_tokens == true
    
    if IamProbe.rfc8705_supported then
        ngx.log(ngx.NOTICE, "IAM supports RFC 8705 certificate-bound access tokens")
    else
        ngx.log(ngx.NOTICE, "IAM does not support RFC 8705, using fallback authentication")
    end
    
    return IamProbe.rfc8705_supported
end

return IamProbe