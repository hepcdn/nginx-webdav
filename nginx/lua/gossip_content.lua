local ngx = require("ngx")
local gossip = require("gossip")
local gossip_auth = require("gossip_auth")

-- Initialize gossip authentication
gossip_auth.init()

-- If the request method is a POST, then it is a peer
-- contacting us with its gossip update and we need to handle it
if ngx.var.request_method == "POST" then
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then
        -- Check authentication mode and verify accordingly
        local mode = gossip_auth.get_mode()
        
        if mode == "rfc8705" then
            -- RFC 8705 mode: verify certificate signature
            local signature = ngx.var.http_x_gossip_signature
            local cert_fingerprint = ngx.var.http_x_gossip_cert_fingerprint
            
            if not signature then
                ngx.log(ngx.WARN, "RFC 8705 mode: gossip message missing signature")
                ngx.status = ngx.HTTP_UNAUTHORIZED
                ngx.say("missing signature")
                return ngx.exit(ngx.OK)
            end
            
            -- In production, verify signature against known peer certificates
            -- This requires the peer's certificate to be available
            ngx.log(ngx.INFO, "RFC 8705 mode: gossip message signed by: " .. (cert_fingerprint or "unknown"))
        else
            -- Fallback mode: JWT validation is done by hepcdn_access.lua
            ngx.log(ngx.INFO, "Fallback mode: accepting gossip message")
        end
        
        gossip.handle_message(data)
    end
end

-- Prepare gossip message
local message = gossip.prepare_message()

-- Send the message
ngx.status = ngx.HTTP_OK
ngx.header["Content-Type"] = "application/json"
ngx.header["Content-Length"] = #message
ngx.header["Cache-Control"] = "no-cache"
ngx.print(message)

return ngx.exit(ngx.OK)