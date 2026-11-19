local config = require("config")

local _M = {}

local uv = nil
local attached = false
-- Diagnostic handles (timer + tcp echo server) on the MAIN state's loop.
-- Must be created in init_worker_by_lua: luv makes one libuv loop per
-- lua_State and the bridge pumps the loop of the state that attached.
-- ngx.timer callbacks do NOT share that state, so handles created there
-- live on a different loop and are destroyed when the callback returns.
local handles = nil

local function get_luv()
    if uv == nil then
        local ok, err = pcall(require, "luv")
        if not ok then
            return nil, err
        end
        uv = require("luv")
    end
    return uv
end

-- Start pumping this worker's luv loop from nginx's event loop.
-- Must be called from the worker's main state (init_worker_by_lua).
-- Idempotent (C side too).
function _M.attach(tick_ms)
    if attached then
        return true
    end
    local lib, err = get_luv()
    if not lib then
        return nil, err
    end
    local ok, err2 = pcall(lib.bridge_attach, tick_ms or config.data.uvbridge_tick)
    if not ok then
        return nil, err2
    end
    attached = true

    -- No worker-exit hook needed: when a worker process exits the OS
    -- closes the backend fd and the nginx-side events die with it.

    return true
end

-- Create the diagnostic libuv handles on the CURRENT state's loop.
-- Call from init_worker_by_lua, right after attach(). The 50 ms repeating
-- timer only ticks while the bridge pumps the loop, and the TCP echo
-- server only echoes while the bridge dispatches libuv I/O callbacks.
-- Handles are anchored on the module table so their __gc finalizers (which
-- close the underlying libuv handles) never run for the worker's lifetime.
function _M.setup_handles()
    if handles then
        return true
    end
    if not attached then
        return nil, "bridge not attached"
    end
    local lib, err = get_luv()
    if not lib then
        return nil, err
    end
    local shared = ngx.shared.uvbridge
    local port = 18000 + ngx.worker.id()

    -- A libuv timer: fires only if the loop is being pumped.
    local timer = lib.new_timer()
    timer:start(50, 50, function()
        shared:incr("timer_count", 1, 0)
    end)

    -- A libuv TCP echo server on loopback.
    local server = lib.new_tcp()
    local bind_err = server:bind("127.0.0.1", port)
    if bind_err ~= 0 then
        return nil, "bind: " .. tostring(bind_err)
    end
    -- luv 1.42: listen(backlog, connection_callback); when a connection is
    -- pending the callback pulls it with accept().
    server:listen(16, function()
        local aok, aerr = pcall(function()
            local client = lib.new_tcp()
            if server:accept(client) == 0 then
                -- luv's read callback is (err, data): data arrives as
                -- (nil, chunk); EOF arrives with no arguments.
                client:read_start(function(err, data)
                    if data and data ~= "" then
                        client:write(data)
                    else
                        client:close()
                    end
                end)
            else
                client:close()
            end
        end)
        if not aok then
            shared:incr("accept_errors", 1, 0)
            shared:set("last_accept_err", tostring(aerr))
        end
    end)

    handles = { timer = timer, server = server, port = port }
    -- Cross-state visibility: request/timer states get their own module
    -- instance, so expose setup via the shared dict (and the fixed port
    -- formula 18000+worker.id(), which needs no cross-state reference).
    shared:set("handles:" .. ngx.worker.id(), "yes")
    return true
end

-- Port the echo server is listening on (nil if handles not set up).
function _M.port()
    return handles and handles.port or nil
end

-- Return attached, pump_count, fd_wakeups, tick_wakeups (C-side state,
-- valid from any lua_State in the worker).
function _M.stats()
    local lib, err = get_luv()
    if not lib then
        return nil, err
    end
    return lib.bridge_stats()
end

return _M
