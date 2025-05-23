local config = require("config")
local resty_http = require("resty.http")
local jwt = require("resty.jwt")
local cjson = require("cjson")
local gossip = require("gossip")

-- if file does not exist, we take the default values
config.load("/etc/nginx/lua/config.json")

-- Only one worker thread needs to manage the gossip timer
if ngx.worker.id() ~= 0 then
    return
end

if config.data.openidc_client_id == "" or config.data.openidc_client_secret == "" then
    ngx.log(ngx.ERR, "Missing openidc_client_id or openidc_client_secret from config.json, will not start cluster gossip")
    return
end
local token_userpass = config.data.openidc_client_id .. ":" .. config.data.openidc_client_secret

-- This function is called by the gossip timer
---@type function
---@param peer string
---@param message string
---@param token string
local function peer_exchange_gossip(peer, message, token)
    local httpc = resty_http.new()
    -- timeouts (connect, send, read) are in milliseconds
    httpc:set_timeouts(config.data.gossip_timeout, config.data.gossip_timeout, config.data.gossip_timeout)
    ngx.log(ngx.INFO, "Sending gossip message to ", peer)
    local res, err = httpc:request_uri(peer .. "gossip", {
        method = "POST",
        body = message,
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = #message,
            ["Authorization"] = "Bearer " .. token,
            ["Accept"] = "application/json",
            ["User-Agent"] = "nginx-webdav/" .. config.data.server_version,
        },
    })
    if not res then
        local errmsg = "Failed to send gossip message to " .. peer .. ": " .. err
        ngx.log(ngx.WARN, errmsg)
        gossip.handle_peer_error(peer, err)
        return
    end
    if res.status ~= 200 then
        local errmsg = "Failed to send gossip message to " .. peer .. ": " .. res.status
        ngx.log(ngx.WARN, errmsg)
        gossip.handle_peer_error(peer, "Response status " .. res.status)
        return
    end
    if res.body == "" then
        local errmsg = "Empty response from " .. peer
        ngx.log(ngx.WARN, errmsg)
        gossip.handle_peer_error(peer, "Empty response")
        return
    end
    gossip.handle_message(res.body)
end


-- This function is called by the gossip timer
---@type function
---@param premature boolean
---@return nil
local function worker_gossip(premature)
    if premature then
        return
    end

    local tic = ngx.now()

    -- Update our bearer token
    local token = ngx.shared.gossip_data:get("bearer_token")
    if type(token) ~= "string" then
        token = nil
    end
    if not token or jwt:load_jwt(token).payload.exp < ngx.now() + 600 then
        local httpc = resty_http.new()
        local res, err = httpc:request_uri(config.data.openidc_iss .. "token", {
            method = "POST",
            -- TODO: make the scope configurable
            body = "grant_type=client_credentials&scope=storage.read%3A%2F+hepcdn.access",
            headers = {
                ["Content-Type"] = "application/x-www-form-urlencoded",
                ["Accept"] = "application/json",
                ["Authorization"] = "Basic " .. ngx.encode_base64(token_userpass),
                ["User-Agent"] = "nginx-webdav/" .. config.data.server_version,
            },
        })

        if not res then
            ngx.log(ngx.ERR, "Failed to get token from issuer ", config.data.openidc_iss, ": ", err)
            return
        end

        if res.status ~= 200 then
            ngx.log(ngx.ERR, "Failed to get token from issuer ", config.data.openidc_iss, ": ", res.status, " ", res.body)
            return
        end

        token = cjson.decode(res.body).access_token
        ngx.shared.gossip_data:set("bearer_token", token)
    end

    -- Get the list of peers
    local peers, starting = gossip.peers()

    -- Prepare gossip message
    local message = gossip.prepare_message()

    -- Send message to random subset of peers
    local threads = {}
    for peer, _ in pairs(peers) do
        if starting or math.random() < config.data.gossip_fraction then
            local co, err = ngx.thread.spawn(peer_exchange_gossip, peer, message, token)
            if not co then
                ngx.log(ngx.ERR, "Failed to spawn thread: ", err)
            end
            table.insert(threads, co)
        end
    end

    -- Wait for all threads to finish
    for _, co in ipairs(threads) do
        local ok, err = ngx.thread.wait(co)
        if not ok then
            ngx.log(ngx.ERR, err)
        end
    end

    local toc = ngx.now()
    ngx.log(ngx.NOTICE, "Gossip took ", toc - tic, " seconds")
end


-- Start the gossip timer
local ok, err = ngx.timer.every(config.data.gossip_delay, worker_gossip)
if not ok then
    ngx.log(ngx.ERR, "failed to create worker timer: ", err)
    return
end
