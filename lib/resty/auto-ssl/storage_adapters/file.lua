local run_command = require "resty.auto-ssl.utils.run_command"

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

function _M.setup_worker(self)
  local base_dir = self.options["dir"]
  local _, _, mkdir_err = run_command("umask 0022 && mkdir -p " .. base_dir .. "/storage/file")
  if mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create storage directory: ", mkdir_err)
  end
  local _, _, chmod_err = run_command("chmod 700 " .. base_dir .. "/storage/file")
  if chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set storage directory permissions: ", chmod_err)
  end
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
    ngx.log(ngx.ERR, "FILE SET ERR: ", err)
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

function _M.keys_with_suffix(self, suffix)
  local glob = self.options["dir"] .. "/storage/file/*" .. ngx.escape_uri(suffix)

  local handle = io.popen("ls -1 " .. glob)
  local out = handle:read("*a")
  handle:close()

  local keys = {}
  for path in string.gmatch(out, "[^\r\n]+") do
    local filename = ngx.re.sub(path, ".*/", "")
    local key = ngx.unescape_uri(filename)
    table.insert(keys, key)
  end

  return keys
end

return _M
