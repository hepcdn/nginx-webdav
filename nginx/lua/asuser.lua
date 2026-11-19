---FFI wrapper for the as_user.so C module.
---
---The C module runs a small set of filesystem operations with a mapped unix
---user's *effective* credentials and restores root before returning. Only
---open/metadata operations need the user's identity: Linux checks DAC at
---open() time, and read()/write() on an already-open fd are not re-checked,
---so the (root) worker can stream data over the returned fd.
---
---Safety in nginx (see as_user.c for the details):
---* Every C function is one straight-line sequence: validate -> setegid ->
---  seteuid -> one syscall -> seteuid(0) -> setegid(0) -> return. It never
---  allocates, sleeps or re-enters the event loop, so a LuaJIT coroutine
---  cannot yield in the middle of the call, and the worker's other in-flight
---  requests never observe switched credentials.
---* Only effective (seteuid/setegid) credentials are switched, and they are
---  always restored, so the worker keeps its real uid 0 for its whole
---  lifetime.
---
---C return convention (like a raw syscall): success value on success
---(fd >= 0, or 0), or the negated errno (-errno < 0) on failure. The error
---code is returned by the function instead of being read from
---ffi.errno, because the OpenResty LuaJIT build's ffi.errno property is
---unreliable (verified: reading it returns a builtin function, not the
---errno value).
---
---All functions take (owner, path) where owner is {uid, gid} and path is an
---absolute path under config.data.local_path. On failure they return
---(nil, errmsg, class) where class is "forbidden" (the mapped user lacks
---permission), "not_found", or "error".

local ffi = require("ffi")
local config = require("config")

ffi.cdef[[
int as_user_mkdirp(int uid, int gid, const char *root, const char *path, int mode);
int as_user_open(int uid, int gid, const char *root, const char *path, int flags, int mode);
int as_user_unlink(int uid, int gid, const char *root, const char *path);
int as_user_rename(int uid, int gid, const char *root, const char *src, const char *dst);
int as_user_write(int fd, const char *buf, int n);
int as_user_close_fd(int fd);
]]

local lib = ffi.load("/usr/local/openresty/site/lualib/as_user.so")

local asuser = {}

-- Linux open(2) flags
local O_RDONLY = 0x00
local O_WRONLY = 0x01
local O_CREAT = 0x40
local O_TRUNC = 0x200

-- LuaJIT is Lua 5.1: no 0o octal literals (see DIRMODE in fileutil.lua)
local DIRMODE = tonumber("755", 8)
local FILEMODE = tonumber("644", 8)

local EPERM = 1
local ENOENT = 2
local EACCES = 13

---@param errno integer
---@return string "forbidden" | "not_found" | "error"
local function classify(errno)
    if errno == EACCES or errno == EPERM then
        return "forbidden"
    elseif errno == ENOENT then
        return "not_found"
    end
    return "error"
end

---Recursively create the parent directories of `path` (and `path` itself)
---as the mapped user.
---@param owner {uid: integer, gid: integer}
---@param path string
---@return nil?, string? err, string? class
function asuser.mkdirp(owner, path)
    local r = lib.as_user_mkdirp(owner.uid, owner.gid, config.data.local_path, path, DIRMODE)
    if r == 0 then
        return nil
    end
    local errno = -r
    return "failed to create directory " .. path .. ": errno " .. errno, classify(errno)
end

---Open `path` for writing (create/truncate, mode 0644) as the mapped user.
---The returned fd may be written by the (root) worker: DAC was checked at
---open() time.
---@param owner {uid: integer, gid: integer}
---@param path string
---@return integer? fd, string? err, string? class
function asuser.open_for_write(owner, path)
    local r = lib.as_user_open(owner.uid, owner.gid, config.data.local_path, path,
        O_WRONLY + O_CREAT + O_TRUNC, FILEMODE)
    if r < 0 then
        local errno = -r
        return nil, "failed to open file " .. path .. ": errno " .. errno, classify(errno)
    end
    return r
end

---Open `path` for reading as the mapped user.
---@param owner {uid: integer, gid: integer}
---@param path string
---@return integer? fd, string? err, string? class
function asuser.open_for_read(owner, path)
    local r = lib.as_user_open(owner.uid, owner.gid, config.data.local_path, path,
        O_RDONLY, 0)
    if r < 0 then
        local errno = -r
        return nil, "failed to open file " .. path .. ": errno " .. errno, classify(errno)
    end
    return r
end

---Delete `path` as the mapped user.
---@param owner {uid: integer, gid: integer}
---@param path string
---@return boolean?, string? err, string? class
function asuser.unlink(owner, path)
    local r = lib.as_user_unlink(owner.uid, owner.gid, config.data.local_path, path)
    if r ~= 0 then
        local errno = -r
        return nil, "failed to delete file " .. path .. ": errno " .. errno, classify(errno)
    end
    return true
end

---Write a Lua string to a previously opened fd. No privilege change here:
---the fd was opened as the mapped user, so its permissions are already fixed.
---@param fd integer
---@param data string
---@return integer? n, string? err
function asuser.write_fd(fd, data)
    if #data == 0 then
        return 0
    end
    local fbuf = ffi.new("char[?]", #data)
    ffi.copy(fbuf, data, #data)
    local r = lib.as_user_write(fd, fbuf, #data)
    if r < 0 then
        return nil, "errno " .. (-r)
    end
    return r
end

---Close an fd previously returned by asuser.open_*.
---@param fd integer
---@return nil?, string? err
function asuser.close_fd(fd)
    local r = lib.as_user_close_fd(fd)
    if r ~= 0 then
        return nil, "errno " .. (-r)
    end
    return nil
end

return asuser
