local ngx = require("ngx")
local fileutil = require("fileutil")

if ngx.status == ngx.HTTP_OK and string.lower(ngx.var.http_want_digest or "") == "adler32" then
  local path = fileutil.get_request_local_path()
  -- Backfilling a missing checksum xattr (if needed) runs as the mapped
  -- user, like the write path does; when the feature is disabled this is
  -- nil and the worker's own identity is used (legacy behavior).
  local stat = fileutil.get_metadata(path, true, ngx.ctx.fs_owner)
  ngx.header["Digest"] = "adler32=" .. stat.adler32
end
