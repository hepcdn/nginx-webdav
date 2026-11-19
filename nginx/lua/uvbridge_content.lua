local config = require("config")
local cjson = require("cjson")

-- Diagnostic endpoint for the libuv bridge (see ../uvbridge.c).
-- Like /webdav_health it is unauthenticated: it only reports counters
-- and runs a loopback-only test workload.
--
-- The persistent libuv handles (a 50 ms timer and a TCP echo server)
-- are created in init_worker_by_lua, on the worker's MAIN state, which
-- is the state the bridge pumps (see uvbridge.lua). This handler never
-- creates luv handles: luv makes one loop per lua_State and request /
-- ngx.timer states are separate, so handles made here would live on a
-- different loop and die with the request.

local shared = ngx.shared.uvbridge
local uvbridge = require("uvbridge")

local function reply(status, table)
    ngx.status = status
    ngx.say(cjson.encode(table))
    return ngx.exit(status)
end

if not config.data.uvbridge_enabled then
    return reply(501, { error = "uvbridge not enabled (set uvbridge_enabled in config.json)" })
end

local attached, pumps, fd_wakeups, tick_wakeups = uvbridge.stats()
if attached ~= 1 then
    return reply(500, { error = "bridge not attached in this worker" })
end

local worker = ngx.worker.id()
local port = 18000 + worker

if ngx.var.request_method == "POST" then
    if shared:get("handles:" .. worker) == nil then
        return reply(500, { error = "workload handles not set up in this worker" })
    end

    -- The 50ms libuv timer (created in init_worker) must keep firing
    -- while this light thread parks: only the bridge can pump the
    -- main-state loop. Without the bridge the growth would be 0.
    local base = shared:get("timer_count") or 0
    ngx.sleep(0.5)
    local timer_growth = (shared:get("timer_count") or 0) - base
    local timer_ok = timer_growth >= 5 -- ~10 expected in 0.5s

    -- Echo round trip through the libuv TCP server.
    local echo_ok = false
    local echo_err
    local sock, cerr = ngx.socket.tcp()
    if sock then
        sock:settimeout(2000)
        local _, cterr = sock:connect("127.0.0.1", port)
        if cterr then
            echo_err = cterr
        else
            sock:send("uvbridge-echo\n")
            local data, rerr = sock:receive("*l")
            sock:close()
            echo_ok = (data == "uvbridge-echo")
            echo_err = rerr
        end
    else
        echo_err = cerr
    end

    return reply(200, {
        ok = timer_ok and echo_ok,
        timer_growth = timer_growth,
        timer_ok = timer_ok,
        echo_ok = echo_ok,
        echo_err = echo_err,
        port = port,
    })
end

-- GET: bridge status for this worker.
return reply(200, {
    attached = true,
    pump_count = pumps,
    fd_wakeups = fd_wakeups,
    tick_wakeups = tick_wakeups,
    timer_count = shared:get("timer_count") or 0,
    handles = shared:get("handles:" .. worker) ~= nil,
    accept_errors = shared:get("accept_errors") or 0,
    last_accept_err = shared:get("last_accept_err"),
})
