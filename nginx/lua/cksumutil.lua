local ffi = require("ffi")
local config = require("config")
local zlib = require("zlib")

-- some lua-isms added from https://github.com/user-none/lua-hashings/

local cksumutil = {}
-- Where the adler32 checksums are stored
local adler_xattr_locations = {
  "user.XrdCks.Human.ADLER32",
  "user.nginx-webdav.adler32"
}

---@type function
---@param path string
---@return string? err, string? val
---Gets the adler32 of a file, calculating it if it doesn't exist
function cksumutil.get_adler32(path)
  local err, val = cksumutil.check_adler32(path)
  if err or val == nil then
    -- We checked and didn't see an adler32, so make one
    local get_err, get_val = cksumutil.compute_adler32(path)
    if not get_val then
      return get_err, nil
    end
    local set_err = cksumutil.set_adler32(path, get_val)
    if set_err then
      ngx.log(ngx.ERR, "Failed to set adler32 for " .. path .. " err: " .. set_err)
    end
    val = get_val
  end
  return nil, val
end

---@type function
---@param path string
---@param value string
---@return string? err
---Sets the adler32 of a file
function cksumutil.set_adler32(path, value)
  local total_err = nil
  for i=1,#adler_xattr_locations do
    local err = cksumutil.setxattr(path,
    adler_xattr_locations[i],
    value)
    if err then
      total_err = err
    end
  end
  return total_err
end


---@type function
---@return function state
---Makes a blank adler32 state
function cksumutil.adler32_initialize()
  return zlib.adler32()
end

---@type function
---@param state function
---@param buf string
---@return function state
---increments state with the value in buf
function cksumutil.adler32_increment(state, buf)
  state(buf)
  return state
end

---@type function
---@param state function
---@return string adler32
---Export adler32 state as hex string
function cksumutil.adler32_to_string(state)
  local digest = state()
  local bytes = {
    bit.band(bit.rshift(digest,24), 0xFF),
    bit.band(bit.rshift(digest,16), 0xFF),
    bit.band(bit.rshift(digest,8), 0xFF),
    bit.band(bit.rshift(digest,0), 0xFF),
  }
  local out = {}
  for i=1,#bytes do
    out[i] = string.format("%02X", bytes[i])
  end
  return string.lower(table.concat(out))
end

---@type function
---@param path string
---@return string? err, string? val
---Given a path, compute adler32 of the file
function cksumutil.compute_adler32(path)
  local adler_state = cksumutil.adler32_initialize()

  local fd, err = io.open(path, "r")
  if not fd then
    return "Failed to open " .. path .. ": " .. err, nil
  end

  repeat
    local data = fd:read(config.data.checksum_block_size)

    if data then
      adler_state = cksumutil.adler32_increment(adler_state, data)
    end
  until not data

  local suc, exitcode = fd:close()
  if not suc then
    return "Failed to close " .. path .. ": " .. exitcode, nil
  end

  return nil, cksumutil.adler32_to_string(adler_state)
end

---@type function
---@param path string
---@return string? err, string? val
---Gets the adler32 of a file from xattrs, NOT calculating if it doesn't exist
function cksumutil.check_adler32(path)
  -- xattrs to check for existing checksums
  local adler32 = nil
  for i=1,#adler_xattr_locations do
    local err, val = cksumutil.getxattr(path, adler_xattr_locations[i])
    if not err then
      return nil, val
    elseif err then
      return err, nil
    end
  end
  return nil, nil
end

-- The parts that actually call the C-level get/setxattr
-- FIXME migrate to ngx.run_worker_thread since this will block

-- Use FFI to call system-level set/getxattr calls. The FFI lib doesn't under-
-- stand void* variables, so I have to call value a const char* and not a void*
-- FIXME: Not platform-independent. Not sure how much we care
ffi.cdef[[
int setxattr(const char *path, const char *name, const char *value, size_t size,
int flags);
int getxattr(const char *path, const char *name, char *value, size_t size);
]]

---@type function
---@param path string
---@param key string
---@param value string
---@return string? err
---Sets an extended attribute on a file
function cksumutil.setxattr(path, key, value)
  local ret = ffi.C.setxattr(path, key, value, string.len(value), 0)
  if ret > 0 then
    ret = ffi.errno()
    return "Error " .. ret .. " in setxattr"
  else
    return nil
  end
end

---@type function
---@param path string
---@param key string
---@return string? err, string? value
---Gets an extended attribute from a file
function cksumutil.getxattr(path, key)
  local buflen = 1024
  local value = ffi.new("char[?]", buflen)
  local ret = ffi.C.getxattr(path, key, value, buflen)
  -- FIXME: get the C errstr
  if ret < 0 then
    ret = ffi.errno()
    -- the value doesn' exist
    local ENODATA = 63
    if ffi.errno() == ENODATA then
      -- It's not really an error if the attribute isn't there. I think nil
      -- is disctinct from "" in Lua
      return nil, nil
    else
      return "Error " .. ret .. " in getxattr", nil
    end
  else
    return nil, ffi.string(value, ret)
  end
end

return cksumutil
