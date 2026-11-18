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
    ngx.header["WWW-Authenticate"] = 'Bearer realm=storage'
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

-- From https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md#capability-based-authorization-scope

-- storage.read: Read data. Only applies to "online" resources such as disk.
local is_read = ngx.var.request_method == "GET" or ngx.var.request_method == "HEAD"
if string.find(scope, "storage.read:/") == nil and is_read then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("no permission to read this resource")
    return ngx.exit(ngx.OK)
end

-- storage.create: Upload data.
local is_create = ngx.var.request_method == "PUT" or ngx.var.request_method == "COPY" or ngx.var.request_method == "MKCOL"
if string.find(scope, "storage.create:/") == nil and string.find(scope, "storage.read:/") == nil and is_create then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("no permission to create this resource")
    return ngx.exit(ngx.OK)
end

-- storage.modify: Change data.
local is_modify = ngx.var.request_method == "DELETE" or ngx.var.request_method == "MOVE"
if string.find(scope, "storage.modify:/") == nil and string.find(scope, "storage.read:/") == nil and is_modify then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("no permission to modify this resource")
    return ngx.exit(ngx.OK)
end