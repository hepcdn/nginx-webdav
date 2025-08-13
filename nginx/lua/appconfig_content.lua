local config = require "config"
local cjson = require "cjson"

-- Check we have a public client ID configured
if not config.data.public_client_id or config.data.public_client_id == "" then
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("public_client_id is not configured")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- Build the app configuration response
local app_config = {
    public_client_id = config.data.public_client_id
}

local message = cjson.encode(app_config)

-- Return the configuration as JSON
ngx.status = ngx.HTTP_OK
ngx.header["Content-Type"] = "application/json"
ngx.header["Content-Length"] = #message
ngx.print(message)
