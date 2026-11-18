local ngx = require("ngx")
local openidc = require("resty.openidc")
local config = require("config")
local voms_auth = require("voms_auth")

local res, err

-- Try JWT authentication first
if ngx.var.http_authorization then
    local opts = {
        public_key = config.data.openidc_pubkey,
        token_signing_alg_values_expected = { "RS256" }
    }
    res, err = openidc.bearer_jwt_verify(opts)
end

-- If JWT failed or wasn't provided, try VOMS certificate auth
if not res then
    res, err = voms_auth.validate()
end

if err or not res then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = 'Bearer realm=hepcdn'
    ngx.say(err and err or "authentication failed")
    return ngx.exit(ngx.OK)
end

-- Set the oidc_user, for use in access log
ngx.var.oidc_user = res.sub

-- Normalize scope field (VOMS auth returns 'scopes' with leading space)
local scope = res.scope or res.scopes or ""
if scope:find("^ ") then
    scope = scope:sub(2)
end

local is_read = ngx.var.request_method == "GET" or ngx.var.request_method == "HEAD"
if is_read and string.find(scope, "hepcdn.view") == nil and string.find(scope, "hepcdn.access") == nil then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("no permission to read this resource")
    return ngx.exit(ngx.OK)
end

local is_post = ngx.var.request_method == "POST"
if is_post and string.find(scope, "hepcdn.access") == nil then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("no permission to modify this resource")
    return ngx.exit(ngx.OK)
end