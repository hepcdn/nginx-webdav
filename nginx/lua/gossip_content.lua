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
            -- RFC 8705 mode: verify the sender's certificate and the
            -- signature over the exact message body before merging
            local signature = ngx.var.http_x_gossip_signature
            local cert_b64 = ngx.var.http_x_gossip_cert
            local cert_fingerprint = ngx.var.http_x_gossip_cert_fingerprint

            if not signature or not cert_b64 then
                ngx.log(ngx.WARN, "RFC 8705 mode: gossip message missing signature or certificate")
                ngx.status = ngx.HTTP_UNAUTHORIZED
                ngx.say("missing signature or certificate")
                return ngx.exit(ngx.OK)
            end

            local cert_pem, derr = ngx.decode_base64(cert_b64)
            if not cert_pem then
                ngx.log(ngx.WARN, "RFC 8705 mode: sender certificate is not valid base64")
                ngx.status = ngx.HTTP_UNAUTHORIZED
                ngx.say("invalid certificate")
                return ngx.exit(ngx.OK)
            end

            if not gossip_auth.verify_message(data, signature, cert_pem, cert_fingerprint) then
                ngx.status = ngx.HTTP_UNAUTHORIZED
                ngx.say("signature verification failed")
                return ngx.exit(ngx.OK)
            end
            ngx.log(ngx.INFO, "RFC 8705 mode: verified gossip message from "
                .. (cert_fingerprint or "unknown peer"))
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