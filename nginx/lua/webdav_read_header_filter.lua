local ngx = require("ngx")
local fileutil = require("fileutil")

if ngx.status == ngx.HTTP_OK and ngx.var.http_want_digest == "adler32" then
  local path = fileutil.get_request_local_path()
  local stat = fileutil.get_metadata(path, true)
  ngx.header["Digest"] = "adler32=" .. stat.adler32
end
