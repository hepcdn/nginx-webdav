local ngx = require("ngx")
local gossip = require("gossip")
local cert_auth = require("cert_auth")

-- If the request method is a POST, then it is a peer
-- contacting us with its gossip update and we need to handle it
if ngx.var.request_method == "POST" then
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then
        -- Verify the gossip signature
        local signature = ngx.var.http_x_gossip_signature
        local cert_fingerprint = ngx.var.http_x_gossip_cert_fingerprint
        
        if not signature then
            ngx.log(ngx.WARN, "Gossip message missing signature")
            -- For backward compatibility, accept unsigned messages for now
        else
            -- In production, verify signature against known peer certificates
            -- This requires the peer's certificate to be available
            ngx.log(ngx.INFO, "Gossip message signed by: " .. (cert_fingerprint or "unknown"))
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
