local ngx = require("ngx")
local config = require("config")
local http = require("resty.http")
local fileutil = require("fileutil")
local asuser = require("asuser")

local file_path = fileutil.get_request_local_path()
local metadata = fileutil.get_metadata(file_path, false)

if ngx.var.request_method == "DELETE" then
    if not metadata.exists then
        ngx.status = ngx.HTTP_NOT_FOUND
        ngx.say("file not found")
        return ngx.exit(ngx.OK)
    end
    local owner = ngx.ctx.fs_owner
    if owner then
        -- Root sees the file, but the mapped user may not be able to delete
        -- it (e.g. no write permission on the containing directory)
        local ok, uerr, uclass = asuser.unlink(owner, file_path)
        if not ok then
            if uclass == "forbidden" then
                ngx.status = ngx.HTTP_FORBIDDEN
            elseif uclass == "not_found" then
                ngx.status = ngx.HTTP_NOT_FOUND
            else
                ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
            end
            ngx.say(uerr)
            return ngx.exit(ngx.OK)
        end
    else
        local suc, err = os.remove(file_path)
        if not suc then
            ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
            ngx.say("failed to delete file: ", err)
            return ngx.exit(ngx.OK)
        end
    end
    ngx.status = ngx.HTTP_NO_CONTENT
    ngx.say("file deleted")
    return ngx.exit(ngx.OK)
-- TODO: implement MOVE, MKCOL?
elseif ngx.var.request_method ~= "PUT" then
    ngx.status = ngx.HTTP_NOT_ALLOWED
    ngx.say("only PUT and DELETE method is allowed to this endpoint")
    return ngx.exit(ngx.OK)
end

if metadata.is_directory then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("cannot write to a directory")
    return ngx.exit(ngx.OK)
end

-- After acquiring the raw socket, we cannot update the status
-- So set it to OK
ngx.status = 200

local sock, err = ngx.req.socket(true)
if not sock then
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("failed to get the request socket: " .. err)
    return ngx.exit(ngx.OK)
end

-- From this point on, we are in charge of sending the http response to the client
-- this is the price we pay for raw socket since the wrapped socket does not support
-- chunked body encoding

-- This allows clients to be sure the body will be accepted before committing to sending it
if ngx.var.http_expect == "100-continue" then
    sock:send("HTTP/1.1 100 Continue\r\n\r\n")
end

---@type function
---@param status integer
---@param message string?
---@param digest string?
local function exit(status, message, digest)
    local status_strings = {
        [200] = "OK",
        [201] = "Created",
        [204] = "No Content",
        [400] = "Bad Request",
        [403] = "Forbidden",
        [404] = "Not Found",
        [500] = "Internal Server Error",
    }
    local response = {
        string.format("HTTP/1.1 %d %s\r\n", status, status_strings[status]),
        "Connection: close\r\n",
    }
    if status == 204 then
        -- No Content should not have a body
        message = nil
    end
    if digest then
        table.insert(response, string.format("Digest: %s\r\n", digest))
    end
    if message then
        message = message .. "\n"
        table.insert(response, string.format("Content-Length: %d\r\n", #message))
        table.insert(response, "Content-Type: text/plain\r\n")
        table.insert(response, "\r\n")
        table.insert(response, message)
    else
        table.insert(response, "\r\n")
    end
    sock:send(response)
end

local reader = http.get_client_body_reader(nil, nil, sock)
if not reader then
    return exit(ngx.HTTP_INTERNAL_SERVER_ERROR, "failed to get the request body reader")
end

local sink_err, adler32, errclass = fileutil.sink_to_file(file_path, reader, nil, ngx.ctx.fs_owner)
if sink_err then
    if errclass == "forbidden" then
        return exit(ngx.HTTP_FORBIDDEN, sink_err)
    elseif errclass == "not_found" then
        return exit(ngx.HTTP_NOT_FOUND, sink_err)
    end
    return exit(ngx.HTTP_INTERNAL_SERVER_ERROR, sink_err)
end

local digest = nil
if string.lower(ngx.var.http_want_digest or "") == "adler32" then
    digest = string.format("adler32=%s", adler32)
end

if metadata.exists then
    return exit(ngx.HTTP_NO_CONTENT)
end

return exit(ngx.HTTP_CREATED, "file created", digest)
