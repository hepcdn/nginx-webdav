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

-- From https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md#capability-based-authorization-scope

local function has_scope(capability)
    return string.find(res.scope or "", capability, 1, true) ~= nil
end

local function deny(message)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(message)
    return ngx.exit(ngx.OK)
end

local method = ngx.var.request_method

-- storage.read: Read data. Only applies to “online” resources such as disk (as opposed to “nearline” such as tape where the stage authorization should be used in addition).
if method == "GET" or method == "HEAD" then
    if not has_scope("storage.read:/") then
        return deny("no permission to read this resource")
    end
    -- storage.create: Upload data. This includes renaming files if the destination file does not already exist. This capability includes the creation of directories and subdirectories at the specified path, and the creation of any non-existent directories required to create the path itself. This authorization does not permit overwriting or deletion of stored data. The driving use case for a separate storage.create scope is to enable the stage-out of data from jobs on a worker node.
elseif method == "PUT" or method == "COPY" or method == "MKCOL" then
    local file_path = fileutil.get_request_local_path()
    local metadata = fileutil.get_metadata(file_path, false)
    if method == "PUT" and metadata.exists and not metadata.is_directory then
        -- Overwriting an existing file is a modification, not a creation.
        if not has_scope("storage.modify:/") then
            return deny("no permission to modify this resource")
        end
    else
        -- storage.modify is a strict superset of storage.create
        if not (has_scope("storage.create:/") or has_scope("storage.modify:/")) then
            return deny("no permission to create this resource")
        end
    end
-- storage.modify: Change data. This includes renaming files, creating new files, and writing data. This permission includes overwriting or replacing stored data in addition to deleting or truncating data. This is a strict superset of storage.create.
elseif method == "DELETE" or method == "MOVE" then
    if not has_scope("storage.modify:/") then
        return deny("no permission to modify this resource")
    end
end

-- storage.stage: Read the data, potentially causing data to be staged from a nearline resource to an online resource. This is a superset of storage.read.
-- TODO: implement this
