-- IAM capability detection
-- Probes the CMS IAM to detect RFC 8705 (certificate-bound tokens) support
--
-- The resolved mode ("rfc8705" or "fallback") is cached in the gossip_data
-- shared dict so that every worker and every request phase sees the same
-- mode. Module-level caches cannot be used for this: each request phase has
-- its own lua_State, and with lua_code_cache off (DEBUG mode) every
-- require() re-executes the module body.
--
-- detect_rfc8705() performs an HTTP request, so it must only be called from
-- contexts where cosockets are allowed (timer, content). init_worker_by_lua
-- must not call it directly: see gossip_auth.init(), which defers the probe
-- to a 0-delay timer when cosockets are unavailable.

local ngx = require("ngx")
local resty_http = require("resty.http")
-- cjson.safe is a separate module entry point (require("cjson") has no
-- .safe field): decode() returns nil on non-JSON instead of throwing.
local cjson = require("cjson.safe")
local config = require("config")

local IamProbe = {}

-- Shared-dict key holding the resolved mode.
IamProbe.MODE_KEY = "gossip_auth_mode"

-- A failed probe is only negative-cached for this long; a permanent
-- negative cache would pin the node to fallback mode after a transient
-- IAM outage.
local RETRY_TTL = 60

--- Resolve the gossip auth mode, probing the IAM metadata if not cached.
-- Returns "rfc8705" or "fallback".
-- Requires a cosocket-enabled context when the cache is empty; throws
-- otherwise, so callers in restricted contexts must wrap it in pcall.
function IamProbe.detect_rfc8705()
    local dict = ngx.shared.gossip_data
    local cached = dict:get(IamProbe.MODE_KEY)
    if cached then
        return cached
    end

    -- openidc_iss is conventionally a base URL that may or may not end in
    -- "/"; normalize before appending the metadata path.
    local base = (config.data.openidc_iss or ""):gsub("/+$", "")
    local httpc = resty_http.new()
    local res, err = httpc:request_uri(base .. "/.well-known/openid-configuration", {
        method = "GET",
        headers = {
            ["Accept"] = "application/json",
            ["User-Agent"] = "nginx-webdav/" .. config.data.server_version,
        },
    })

    if not res or res.status ~= 200 then
        ngx.log(ngx.WARN, "Failed to probe IAM metadata: "
            .. (err or (res and tostring(res.status) or "unknown")))
        dict:set(IamProbe.MODE_KEY, "fallback", RETRY_TTL)
        return "fallback"
    end

    -- cjson.decode throws on malformed input; a non-JSON error page from
    -- the IAM must not take the caller down.
    local metadata = cjson.decode(res.body)
    if type(metadata) ~= "table" then
        ngx.log(ngx.WARN, "IAM metadata response is not valid JSON; using fallback authentication")
        dict:set(IamProbe.MODE_KEY, "fallback", RETRY_TTL)
        return "fallback"
    end

    if metadata.tls_client_certificate_bound_access_tokens == true then
        -- The capability is static for the life of the deployment; a stable
        -- cache also keeps all workers of the node in the same mode.
        dict:set(IamProbe.MODE_KEY, "rfc8705")
        ngx.log(ngx.NOTICE, "IAM supports RFC 8705 certificate-bound access tokens")
        return "rfc8705"
    end

    ngx.log(ngx.NOTICE, "IAM does not support RFC 8705, using fallback authentication")
    dict:set(IamProbe.MODE_KEY, "fallback", RETRY_TTL)
    return "fallback"
end

return IamProbe
