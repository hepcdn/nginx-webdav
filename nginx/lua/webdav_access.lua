local ngx = require("ngx")
local openidc = require("resty.openidc")
local config = require("config")
local fileutil = require("fileutil")

if not ngx.var.http_authorization then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = 'Bearer realm=storage'
    ngx.say("no authorization header provided")
    return ngx.exit(ngx.OK)
end

local opts = {
    public_key = config.data.openidc_pubkey,
    token_signing_alg_values_expected = { "RS256" }
}
-- call bearer_jwt_verify for OAuth 2.0 JWT validation
local res, err = openidc.bearer_jwt_verify(opts)

if err or not res then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say(err and err or "no access token provided")
    return ngx.exit(ngx.OK)
end

-- Set the oidc_user, for use in access log
ngx.var.oidc_user = res.sub

-- Site admins: configured token sub IDs bypass the WLCG scope checks.
-- The token itself must still be valid (verified above).
for _, elevated_sub in ipairs(config.data.elevated_sub_ids or {}) do
    if elevated_sub == res.sub then
        return
    end
end

-- From https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md#capability-based-authorization-scope
--
-- Scope entries have the form "<capability>:<path>", for example
-- "storage.read:/user/alice/". A path of "/" grants the entire tree;
-- any other path only grants that path and everything below it.

local scopes = {}
for entry in string.gmatch(res.scope or "", "%S+") do
    local capability, prefix = entry:match("^(%S+):(/.*)$")
    if capability then
        scopes[capability] = scopes[capability] or {}
        table.insert(scopes[capability], prefix)
    end
end

local function path_under(path, prefix)
    if prefix == "/" then
        return true
    end
    if path:sub(1, #prefix) ~= prefix then
        return false
    end
    -- Require a path boundary so that e.g. "storage.read:/data" does not
    -- grant access to "/data2".
    return path == prefix or prefix:sub(-1) == "/" or path:sub(#prefix + 1, #prefix + 1) == "/"
end

local function has_scope(capability, path)
    for _, prefix in ipairs(scopes[capability] or {}) do
        if path_under(path, prefix) then
            return true
        end
    end
    return false
end

local function deny(message)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(message)
    return ngx.exit(ngx.OK)
end

-- The resource path as addressed by the client (no service prefix, no query)
local function resource_path()
    local uri = ngx.var.request_uri
    local q = uri:find("?")
    if q then
        uri = uri:sub(1, q - 1)
    end
    if uri:sub(1, #config.data.uriprefix) == config.data.uriprefix then
        return uri:sub(#config.data.uriprefix + 1)
    end
    if uri:sub(1, 10) == "/redirect/" or uri == "/redirect" then
        return uri:sub(10)
    end
    return uri
end

local method = ngx.var.request_method
local path = resource_path()

-- storage.read: Read data. Only applies to “online” resources such as disk (as opposed to “nearline” such as tape where the stage authorization should be used in addition).
if method == "GET" or method == "HEAD" then
    if not has_scope("storage.read", path) then
        return deny("no permission to read this resource")
    end
    -- storage.create: Upload data. This includes renaming files if the destination file does not already exist. This capability includes the creation of directories and subdirectories at the specified path, and the creation of any non-existent directories required to create the path itself. This authorization does not permit overwriting or deletion of stored data. The driving use case for a separate storage.create scope is to enable the stage-out of data from jobs on a worker node.
elseif method == "PUT" or method == "COPY" or method == "MKCOL" then
    local file_path = fileutil.get_request_local_path()
    local metadata = fileutil.get_metadata(file_path, false)
    if method == "PUT" and metadata.exists and not metadata.is_directory then
        -- Overwriting an existing file is a modification, not a creation.
        if not has_scope("storage.modify", path) then
            return deny("no permission to modify this resource")
        end
    else
        -- storage.modify is a strict superset of storage.create
        if not (has_scope("storage.create", path) or has_scope("storage.modify", path)) then
            return deny("no permission to create this resource")
        end
    end
-- storage.modify: Change data. This includes renaming files, creating new files, and writing data. This permission includes overwriting or replacing stored data in addition to deleting or truncating data. This is a strict superset of storage.create.
elseif method == "DELETE" or method == "MOVE" then
    if not has_scope("storage.modify", path) then
        return deny("no permission to modify this resource")
    end
end

-- storage.stage: Read the data, potentially causing data to be staged from a nearline resource to an online resource. This is a superset of storage.read.
-- TODO: implement this
