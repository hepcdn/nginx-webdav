---Map a verified WLCG token to a local unix account.
---
---Only called from the access phase after bearer_jwt_verify succeeded, so
---the claims can be trusted.
---
---The feature is opt-in: if `user_mapping` is absent or empty in
---config.json, this module returns nil (no mapping) and all file I/O keeps
---running as root, exactly like before.
---
---Configuration (config.json):
---    "user_mapping": {
---        "claim": "name",                     -- JWT claim holding the unix
---                                              -- account name (WLCG common
---                                              -- JWT profile `name`)
---        "on_missing": "root",                -- "root" (default) or "deny":
---                                              -- what to do when the token
---                                              -- has no such claim ("root"
---                                              -- = serve as the worker's own
---                                              -- identity, root in the
---                                              -- current deployment)
---        "deny_uids": [0],                    -- mapped uids that are
---                                              -- rejected (root by default)
---        "uid_range": [1000, 60000],          -- optional allowed uid range
---        "fallback": {"uid": 65534, "gid": 65534}
---                                              -- optional account for tokens
---                                              -- whose name has no local
---                                              -- account
---    }
---
---Account lookups use getpwnam(3), which may contact NSS backends (LDAP)
---and block; results (and denials) are cached in the usermap_cache shared
---dict for 10 minutes.

local ngx = require("ngx")
local config = require("config")
local posix = require("posix")

local usermap = {}

local CACHE_TTL = 600 -- seconds

---@param deny_uids integer[]?
---@param uid integer
---@return boolean
local function denied_uid(deny_uids, uid)
    if not deny_uids then
        return false
    end
    for _, v in pairs(deny_uids) do
        if v == uid then
            return true
        end
    end
    return false
end

---@param range integer[]?  -- [min, max]
---@param uid integer
---@return boolean
local function uid_in_range(range, uid)
    if not range then
        return true
    end
    return uid >= range[1] and uid <= range[2]
end

---Resolve the verified token claims to a local unix account.
---@param claims table Verified JWT claims (bearer_jwt_verify result)
---@return {uid: integer, gid: integer}? owner nil means "run as root"
---@return string? err
---@return string? class "forbidden"
function usermap.resolve(claims)
    local m = config.data.user_mapping
    if not m or next(m) == nil then
        return nil -- feature disabled: legacy root behavior
    end

    local claim = m.claim or "name"
    local value = claims[claim]
    local on_missing = m.on_missing or "root"

    if not value or value == "" then
        if on_missing == "deny" then
            return nil, "token has no '" .. claim .. "' claim", "forbidden"
        end
        return nil -- legacy: serve as the worker's own identity (root today)
    end
    value = tostring(value)

    local cache = ngx.shared.usermap_cache
    local key = claim .. "=" .. value
    local hit = cache and cache:get(key)
    if hit then
        if hit == "deny" then
            return nil, "no unix account for '" .. value .. "'", "forbidden"
        end
        local uid, gid = hit:match("^(%d+):(%d+)$")
        if not uid then
            -- malformed cache entry; fall through and recompute
        else
            return { uid = tonumber(uid), gid = tonumber(gid) }
        end
    end

    local owner
    local pw = posix.getpwnam(value)
    if pw then
        owner = { uid = pw.pw_uid, gid = pw.pw_gid }
    elseif m.fallback then
        owner = { uid = m.fallback.uid, gid = m.fallback.gid }
    else
        if cache then
            cache:set(key, "deny", CACHE_TTL)
        end
        return nil, "no unix account for '" .. value .. "'", "forbidden"
    end

    -- Hard guards: never allow root (default) or uids outside the range,
    -- whether they came from getpwnam or from the fallback.
    if denied_uid(m.deny_uids, owner.uid) or not uid_in_range(m.uid_range, owner.uid) then
        if cache then
            cache:set(key, "deny", CACHE_TTL)
        end
        return nil, "mapped uid " .. owner.uid .. " is not permitted", "forbidden"
    end

    if cache then
        cache:set(key, owner.uid .. ":" .. owner.gid, CACHE_TTL)
    end
    return owner
end

return usermap
