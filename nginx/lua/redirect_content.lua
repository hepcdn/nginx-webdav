local ngx = require("ngx")
local resty_http = require("resty.http")
local fileutil = require("fileutil")
local config = require("config")
local gossip = require("gossip")


-- TODO: always "redirect"?
local path = ngx.var.request_uri:sub(#"/redirect" + 1)
local webdav_uri = config.data.uriprefix .. path
local stat = fileutil.get_metadata(config.data.local_path .. path, false)
if stat.exists then
    ngx.status = ngx.HTTP_TEMPORARY_REDIRECT
    -- TODO: do we want to use the full url (config.data.server_address)
    ngx.header["Location"] = webdav_uri
    ngx.exit(ngx.OK)
end

---@type function
---@param peer string Peer hostname
---@param uri string File url to check
---@param token string Bearer token for authentication
---@return {peer: string, location: string?} res Response from peer
local function peer_query_file(peer, uri, token)
    local httpc = resty_http.new()
    -- peer has trailing slash, uri has leading slash
    local location = peer .. uri:sub(2)
    ngx.log(ngx.NOTICE, "Querying location: ", location)
    local res, err = httpc:request_uri(location, {
        method = "HEAD",
        headers = {
            ["Authorization"] = "Bearer " .. token,
            ["User-Agent"] = "nginx-webdav/" .. config.data.server_version,
        },
    })
    if not res then
        ngx.log(ngx.ERR, "Failed to send file query to " .. peer .. ": " .. err)
        -- TODO: update peer status for gossip (unreachable)
        return {peer = peer, location = nil}
    end
    if res.status == ngx.HTTP_OK then
        ngx.log(ngx.NOTICE, "Found file on peer: ", peer)
        return {peer = peer, location = location}
    end
    ngx.log(ngx.NOTICE, "Did not find file on peer: ", peer, " status: ", res.status)
    return {peer = peer, location = nil}
end

-- Ask our peers if they have the file
local tic = ngx.now()
-- TODO: we could use the token that the client gives us, is that better?
local token = ngx.shared.gossip_data:get("bearer_token")
if not token then
    ngx.log(ngx.ERR, "No bearer token found in shared dict")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.exit(ngx.OK)
end
local peers, _ = gossip.peers()
---@type table<string, ngx.thread>
local threads = {}
for peer, _ in pairs(peers) do
    local co, err = ngx.thread.spawn(peer_query_file, peer, webdav_uri, token)
    if not co then
        ngx.log(ngx.ERR, "Failed to spawn thread: ", err)
    else
        threads[peer] = co
    end
end

-- Wait for first thread to finish
while next(threads) ~= nil do
    local lthreads = {}
    for _, thread in pairs(threads) do
        table.insert(lthreads, thread)
    end
    local ok, res = ngx.thread.wait(unpack(lthreads))
    if not ok then
        ngx.log(ngx.ERR, "Thread error: ", res)
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.exit(ngx.OK)
    else
        threads[res.peer] = nil
        if res.location then
            ngx.status = ngx.HTTP_TEMPORARY_REDIRECT
            ngx.header["Location"] = res.location
            ngx.exit(ngx.OK)
        end
    end
end

-- No peers have the file, return 404
ngx.status = ngx.HTTP_NOT_FOUND

local toc = ngx.now()
ngx.log(ngx.NOTICE, "Redirect took ", toc - tic, " seconds")
ngx.exit(ngx.OK)