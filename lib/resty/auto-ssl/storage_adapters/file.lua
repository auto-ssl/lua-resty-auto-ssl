local _M = {}

local function file_path(self, key)
  return self.options["dir"] .. "/storage/file/" .. ngx.escape_uri(key)
end

function _M.new(auto_ssl_instance)
  local options = {
    dir = auto_ssl_instance:get("dir")
  }

  return setmetatable({ options = options }, { __index = _M })
end

function _M.setup(self)
  local base_dir = self.options["dir"]
  os.execute("mkdir -p " .. base_dir .. "/storage/file")
  os.execute("chmod 700 " .. base_dir .. "/storage/file")
end

function _M.get(self, key)
  local file, err = io.open(file_path(self, key), "r")
  if err and string.find(err, "No such file") then
    return nil
  elseif err then
    return nil, err
  end

  local content = file:read("*all")
  file:close()
  return content
end

function _M.set(self, key, value, options)
  local file, err = io.open(file_path(self, key), "w")
  if err then
    return false, err
  end

  file:write(value)
  file:close()

  if options and options["exptime"] then
    ngx.timer.at(options["exptime"], function()
      local _, delete_err = _M.delete(self, key)
      if delete_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to remove file after exptime: ", delete_err)
      end
    end)
  end

  return true
end

function _M.delete(self, key)
  local ok, err = os.remove(file_path(self, key))
  if err and string.find(err, "No such file") then
    return false, nil
  elseif err then
    return false, err
  else
    return ok, err
  end
end

return _M
