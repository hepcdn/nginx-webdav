---Map a verified WLCG token to a local unix account.
---
---Only called from the access phase after bearer_jwt_verify succeeded, so
---the claims can be trusted.
---
---The feature is opt-in: if `user_mapping` is absent or empty in
---config.json, this module returns nil (no mapping) and all file I/O keeps
---running as root, exactly like before.
---
---The unix account is chosen by exactly one of two mechanisms:
---
---* an explicit `map` table (recommended): `{[sub value] = account name}`.
---  Only identities whose verified `sub` is listed are mapped, and each is
---  mapped to the explicitly chosen account. This is the safe default
---  posture: `sub` is immutable and assigned by the IdP, and IAM usernames
---  that merely happen to match a local account name are never mapped by
---  coincidence.
---* otherwise the `claim` JWT claim (default: `preferred_username`, the
---  WLCG profile's login name, which IAM instances treat as the account's
---  username rather than a freely editable display name) is looked up with
---  getpwnam(3). The `name` claim must NOT be used: in OIDC it is the
---  user's display name, which users can edit, so a user could point it at
---  any local account they can guess (e.g. "cmsprod").
---
---Configuration (config.json):
---    "user_mapping": {
---        -- Recommended: explicit sub -> account table. Only listed subs
---        -- are mapped; every other token follows on_missing.
---        "map": {
---            "https://iam.example.org/uid-12345": "alice",
---            "https://iam.example.org/uid-67890": "bob"
---        },
---        "claim": "preferred_username",       -- only used when there is no
---                                              -- `map`: the JWT claim holding
---                                              -- the unix account name
---                                              -- (default)
---        "on_missing": "deny",                -- "deny" (default) or "root":
---                                              -- what to do when the token
---                                              -- does not map to an account
---                                              -- ("root" = serve as the
---                                              -- worker's own identity,
---                                              -- root in the current
---                                              -- deployment)
---        "deny_uids": [0],                    -- mapped uids that are
---                                              -- rejected (root by default)
---        "uid_range": [1000, 65534],          -- optional allowed uid range
---                                              -- (default: unrestricted);
---                                              -- must include any fallback
---        "fallback": {"uid": 65534, "gid": 65534}
---                                              -- optional account for tokens
---                                              -- that do not resolve to a
---                                              -- local account
---    }
---
---With the defaults, a mis- or un-configured token is rejected (403)
---instead of silently performing file I/O as root: `on_missing` is "deny"
---and only explicitly configured identities are ever mapped.
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

    local cache = ngx.shared.usermap_cache
    local use_map = m.map ~= nil and next(m.map) ~= nil

    -- Pick the account name: from the explicit sub -> account table when
    -- one is configured (keyed on `sub`, which the user cannot change),
    -- otherwise from the configured claim (default preferred_username).
    local value
    local key
    if use_map then
        -- The sub must be explicitly listed in the map; the map value is
        -- the account name (a sub that is not listed falls through to
        -- on_missing, which is "deny" by default).
        local sub = claims.sub
        value = sub and m.map[tostring(sub)]
        key = "sub=" .. tostring(sub or "")
    else
        local claim = m.claim or "preferred_username"
        value = claims[claim]
        key = claim .. "=" .. tostring(value or "")
    end

    local on_missing = m.on_missing or "deny"
    if not value or value == "" then
        if on_missing == "deny" then
            if use_map then
                return nil, "token sub is not listed in the user map", "forbidden"
            end
            local claim = m.claim or "preferred_username"
            return nil, "token has no '" .. claim .. "' claim", "forbidden"
        end
        -- Opt-in legacy behavior: serve as the worker's own identity
        -- (root in the current deployment).
        return nil
    end
    value = tostring(value)

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
    -- whether they came from getpwnam or from the fallback. deny_uids
    -- defaults to {0}: a config that omits it must still never map to
    -- root.
    if denied_uid(m.deny_uids or { 0 }, owner.uid)
        or not uid_in_range(m.uid_range, owner.uid) then
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
