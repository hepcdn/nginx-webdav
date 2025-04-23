local ngx = require("ngx")
local cjson = require("cjson")
local config = require("config")

local Gossip = {
}

---@class PeerData
---@field epoch integer Monotonic increasing number that is incremented by the peer
---@field status string Current server status (TODO: enum?)
---@field timestamp integer UNIX time of the last update
---@field server_version string Version of the server
---@field failures integer Number of failures to exchange gossip with this peer (from us or any other peer)


---@type function
---@return table<string, boolean> peers, boolean starting
---Return a list of the current peers, and a boolean
---indicating if this is the first time this worker is started
function Gossip.peers()
    local peerstr = ngx.shared.gossip_data:get("peers")
    local starting = false
    if not peerstr then
        peerstr = config.data.seed_peers .. ","
        ngx.shared.gossip_data:set("peers", peerstr)
        starting = true
    end
    local peers = {}
    ---@cast peerstr string
    for peer in string.gmatch(peerstr, "[^,]+") do
        peers[peer] = true
    end
    return peers, starting
end

---@type function
---@param peer string
---Add a peer to the list of peers
---No op if the peer is already in the list
function Gossip.add_peer(peer)
    local peerstr = ngx.shared.gossip_data:get("peers")
    ---@cast peerstr string
    if peerstr:find(peer, 1, true) == nil then
        ngx.shared.gossip_data:set("peers", peerstr .. peer .. ",")
    end
end

---@type function
---@param peer string
---Remove a peer from the list of peers
function Gossip.remove_peer(peer)
    local peerstr = ngx.shared.gossip_data:get("peers")
    ---@cast peerstr string
    local pos, endpos = peerstr:find(peer, 1, true)
    if not pos then
        ngx.log(ngx.WARN, "Peer " .. peer .. " not found in peerstr: " .. peerstr)
        return
    end
    -- Account for trailing comma
    endpos = endpos + 1
    local new_peerstr = peerstr:sub(1, pos - 1) .. peerstr:sub(endpos + 1)
    if new_peerstr == "" then
        -- the next call to peers() will reinitialize from the seed_peers
        ngx.shared.gossip_data:set("peers", nil)
    else
        ngx.shared.gossip_data:set("peers", new_peerstr)
    end
end

---@type function
---@param peer string
---@return PeerData peerdata
function Gossip.get_peerdata(peer)
    local epoch = ngx.shared.gossip_data:get("epoch:" .. peer)
    if not epoch then
        return {epoch = -1, status = "unknown", timestamp = 0, server_version = "unknown", failures = 0}
    end
    local status = ngx.shared.gossip_data:get("status:" .. peer)
    local timestamp = ngx.shared.gossip_data:get("timestamp:" .. peer)
    local server_version = ngx.shared.gossip_data:get("server_version:" .. peer)
    local failures = ngx.shared.gossip_data:get("failures:" .. peer)
    return {epoch = epoch, status = status, timestamp = timestamp, server_version = server_version, failures = failures}
end

---@type function
---@param peer string
---@param peerdata PeerData
function Gossip.set_peerdata(peer, peerdata)
    ngx.shared.gossip_data:set("epoch:" .. peer, peerdata.epoch)
    ngx.shared.gossip_data:set("status:" .. peer, peerdata.status)
    ngx.shared.gossip_data:set("timestamp:" .. peer, peerdata.timestamp)
    ngx.shared.gossip_data:set("server_version:" .. peer, peerdata.server_version)
    ngx.shared.gossip_data:set("failures:" .. peer, peerdata.failures)
end

---@type function
---@param peer string
---@param peerdata PeerData
function Gossip.update_peerdata(peer, peerdata)
    local current_timestamp = ngx.shared.gossip_data:get("timestamp:" .. peer)
    if current_timestamp and current_timestamp > peerdata.timestamp then
        return
    elseif current_timestamp == nil and peer ~= config.data.server_address then
        -- Check if we agree on http or https and if not we don't add the peer
        if peer:sub(0, 5) ~= config.data.server_address:sub(0, 5) then
            ngx.log(ngx.WARN, "Not adding new peer " .. peer .. " because it does not have the same security level as us")
            return
        end
        if peerdata.failures > config.data.gossip_max_failures then
            ngx.log(ngx.WARN, "Not adding new peer " .. peer .. " because it has failed " .. peerdata.failures .. " times")
            return
        end
        ngx.log(ngx.NOTICE, "Adding new peer " .. peer)
        -- Set its data first to reduce race conditions?
        Gossip.set_peerdata(peer, peerdata)
        -- Potential TODO: factor this out to a once-per-gossip update
        Gossip.add_peer(peer)
    else
        Gossip.set_peerdata(peer, peerdata)
    end
end


---@type function
---@return string message
---Prepare a message to send to peers representing our current view of the network
function Gossip.prepare_message()
    local peers, _ = Gossip.peers()

    local message = {}
    for peer,_ in pairs(peers) do
        local peerdata = Gossip.get_peerdata(peer)
        table.insert(message, {
            name = peer,
            data = peerdata,
        })
    end

    -- Update our own data
    local selfdata = Gossip.get_peerdata(config.data.server_address)
    selfdata.epoch = selfdata.epoch + 1
    selfdata.status = "alive"
    selfdata.timestamp = ngx.now()
    selfdata.server_version = config.data.server_version
    selfdata.failures = 0
    Gossip.set_peerdata(config.data.server_address, selfdata)
    table.insert(message, {
        name = config.data.server_address,
        data = selfdata,
    })

    return cjson.encode(message)
end

---@type function
---@param message string
---Handle a message received from a peer
function Gossip.handle_message(message)
    local peerdata = cjson.decode(message)
    if type(peerdata) == "table" then
        for _, peerinfo in ipairs(peerdata) do
            -- Ignore our own data
            if peerinfo.name ~= config.data.server_address then
                Gossip.update_peerdata(peerinfo.name, peerinfo.data)
            end
        end
    end
end

---@type function
---@param peer string
---@param err string
---Handle a failed gossip exchange with a peer or a failed redirect query
function Gossip.handle_peer_error(peer, err)
    local failures = ngx.shared.gossip_data:incr("failures:" .. peer, 1)
    -- This ensures our opinion of the peer will propagate to others
    -- There is a race condition here where two servers might increment the
    -- failures at the same time, but this just undercounts the failures
    ngx.shared.gossip_data:set("timestamp:" .. peer, ngx.now())
    ngx.shared.gossip_data:set("status:" .. peer, "failed: " .. err)
    if failures and failures >= config.data.gossip_max_failures then
        ngx.log(ngx.NOTICE, "Peer " .. peer .. " failed " .. failures .. " times, removing from list")
        Gossip.remove_peer(peer)
    end
end

return Gossip
