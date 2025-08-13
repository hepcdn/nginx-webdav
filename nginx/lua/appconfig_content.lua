local config = require "config"
local cjson = require "cjson"

-- Check we have a public client ID configured
if not config.data.public_client_id or config.data.public_client_id == "" then
    local error = {reason = "public_client_id is not configured"}
    local message = cjson.encode(error)
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.header["Content-Length"] = #message
    ngx.print(message)
    return ngx.exit(ngx.OK)
end

-- Build the app configuration response
local app_config = {
    public_client_id = config.data.public_client_id
}

local message = cjson.encode(app_config)

-- Return the configuration as JSON
ngx.status = ngx.HTTP_OK
ngx.header["Content-Length"] = #message
ngx.print(message)
