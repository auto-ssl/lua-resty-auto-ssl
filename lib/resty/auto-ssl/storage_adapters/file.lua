local auto_ssl = require "resty.auto-ssl"

local _M = {}

local function file_path(key)
  return auto_ssl.dir .. "/storage/file/" .. ngx.escape_uri(key)
end

function _M.get(key)
  local file, err = io.open(file_path(key), "r")
  if err then
    return nil, err
  end

  local content = file:read("*all")
  file:close()
  return content
end

function _M.set(key, value)
  local file, err = io.open(file_path(key), "w")
  if err then
    return false, err
  end

  file:write(value)
  file:close()

  return true
end

function _M.delete(key)
  os.remove(file_path(key))
end

return _M
