local sys_stat = require("posix.sys.stat")
local config = require("config")
local cksumutil = require("cksumutil")

local fileutil = {}

---@type function
---@return string
function fileutil.get_request_local_path()
    local uri = ngx.var.request_uri
    -- TODO: can we find the local path from ngx.var variables?
    return config.data.local_path .. uri:sub(#config.data.uriprefix + 1)
end

---@type function
---@param file_path string
---@param want_adler32 boolean
---@return {exists:boolean, is_directory:boolean, size:integer, adler32:string}
function fileutil.get_metadata(file_path, want_adler32)
    local stat = sys_stat.stat(file_path)

    if not stat then
        return {
            exists = false,
            -- If the file path ends with a slash, it will be a directory
            is_directory = file_path:sub(#file_path) == "/",
            size = 0,
            adler32 = "",
        }
    end

    -- TODO: owner, group, permissions

    local err = nil
    local adler32 = nil
    if want_adler32 then
        err, adler32 = cksumutil.get_adler32(file_path)
        if not adler32 then
            ngx.log(ngx.ERR, "Failed to get adler32 for " .. file_path .. " err: " .. err)
        end
    end

    return {
        exists = true,
        is_directory = sys_stat.S_ISDIR(stat.st_mode) ~= 0,
        size = stat.st_size,
        adler32 = adler32 or "",
    }
end

---@type function
---@param bytes_written integer
---@param start_time number
---@param last_transferred number
---@param now number
---@return nil
---Write a perf-marker-stream message to the client
local function write_perfmarker(bytes_written, start_time, last_transferred, now)
    ngx.say("Perf Marker")
    ngx.say("    Timestamp: ", math.floor(now))
    ngx.say("    State: Running")
    ngx.say("    State description: transfer has started")
    ngx.say("    Stripe Index: 0")
    ngx.say("    Stripe Start Time: ", math.floor(start_time))
    ngx.say("    Stripe Last Transferred: ", math.floor(last_transferred))
    ngx.say("    Stripe Transfer Time: ", math.floor(now - start_time))
    ngx.say("    Stripe Bytes Transferred: ", bytes_written)
    ngx.say("    Stripe Status: RUNNING")
    ngx.say("    Total Stripe Count: 1")
    ngx.say("End")
    -- TODO: RemoteConnections information
    local ok, err = ngx.flush(true)
    if not ok then
        ngx.log(ngx.ERR, "Failed to flush perf-marker-stream:", err)
    end
end

local EEXIST = 17
local DIRMODE = tonumber('755', 8)

---@type function
---@param path string
---@param recursive boolean?
---@return boolean? success, string? err
---Create a directory at the given path.
---If recursive is true, create parent directories as needed.
function fileutil.mkdir(path, recursive)
    if recursive then
        local parent = path:match("(.*)/")
        local stat = sys_stat.stat(parent)
        if not stat then
            local suc, err = fileutil.mkdir(parent, true)
            if not suc then
                return nil, err
            end
        end
    end
    local suc, err, errno = sys_stat.mkdir(path, DIRMODE)
    if suc == 0 then
        return true
    elseif errno == EEXIST then
        return true
    end
    return nil, err
end

---@type function
---@param file_path string
---@param reader fun(max_chunk_size:integer): string?, string
---@param perfmarkers boolean?
---@return string? err, string? adler32
---
---Reads from the reader function and writes to the file_path.
---Returns nil if successful, otherwise an error message
---Also returns the adler32 checksum of the written data
---Set perfmarkers to send text/perf-marker-stream messages to the client.
---  (if set, this function will call ngx.say to send messages and flush them)
function fileutil.sink_to_file(file_path, reader, perfmarkers)
    local directory = file_path:match("(.*)/")
    if directory then
        fileutil.mkdir(directory, true)
    end
    local file, err = io.open(file_path, "w+b")
    if not file then
        return "failed to open file: " .. err
    end

    local buffer = nil
    local bytes_written = 0
    local start_time = ngx.now()
    local last_perfmarker = start_time
    local last_transferred = start_time
    local adler_state = cksumutil.adler32_initialize()
    repeat
        buffer, err = reader(config.data.receive_buffer_size)
        if err then
            err = "failed to read from the request socket: " .. err
            goto cleanup
        end
        local now = ngx.now()
        if buffer then
            file, err = file:write(buffer)
            bytes_written = bytes_written + #buffer
            last_transferred = now
            cksumutil.adler32_increment(adler_state, buffer)
            if not file then
                err = "failed to write to the file: " .. err
                goto cleanup
            end
        end
        if perfmarkers and last_perfmarker + config.data.performance_marker_timeout <= now then
            write_perfmarker(bytes_written, start_time, last_transferred, now)
            last_perfmarker = now
        end
    until not buffer
    ::cleanup::

    local suc, exitcode = file:close()
    if not suc then
        -- This is more of an internal error
        ngx.log(ngx.ERR, "failed to close " .. file_path .. ": " .. exitcode)
        err = err or ("failed to close file: " .. exitcode)
    end

    if err then
        local rmerr
        suc, rmerr = os.remove(file_path)
        if not suc then
            ngx.log(ngx.ERR, "failed to cleanup " .. file_path .. ": " .. rmerr)
        end
        return err
    end

    local adler32 = cksumutil.adler32_to_string(adler_state)
    cksumutil.set_adler32(file_path, adler32)
    ngx.log(ngx.NOTICE, bytes_written, " total bytes written to ", file_path, " with adler32 ", adler32)
    return nil, adler32
end

return fileutil
