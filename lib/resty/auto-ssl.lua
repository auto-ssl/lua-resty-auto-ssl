local _M = {}

local current_file_path = package.searchpath("resty.auto-ssl", package.path)
_M.lua_root = string.match(current_file_path, "(.*)/.*/.*/.*/.*/.*")
if string.sub(_M.lua_root, 1, 2) == "./" then
  local lfs = require "lfs"
  _M.lua_root = lfs.currentdir() .. string.sub(_M.lua_root, 2, -1)
end

function _M.new(options)
  if not options then
    options = {}
  end

  if not options["dir"] then
    options["dir"] = "/etc/resty-auto-ssl"
  end

  if not options["request_domain"] then
    options["request_domain"] = function(ssl, ssl_options) -- luacheck: ignore
      return ssl.server_name()
    end
  end

  if not options["allow_domain"] then
    options["allow_domain"] = function(domain) -- luacheck: ignore
      return false
    end
  end

  if not options["storage_adapter"] then
    options["storage_adapter"] = "resty.auto-ssl.storage_adapters.file"
  end

  if not options["ocsp_stapling_error_level"] then
    options["ocsp_stapling_error_level"] = ngx.ERR
  end

  if not options["renew_check_interval"] then
    options["renew_check_interval"] = 86400 -- 1 day
  end

  if not options["hook_server_port"] then
    options["hook_server_port"] = 8999
  end

  return setmetatable({ options = options }, { __index = _M })
end

function _M.set(self, key, value)
  self.options[key] = value
end

function _M.get(self, key)
  return self.options[key]
end

function _M.allow_domain(domain) -- luacheck: ignore
  return false
end

function _M.init(self)
  local init_master = require "resty.auto-ssl.init_master"
  init_master(self)
end

function _M.init_worker(self)
  local init_worker = require "resty.auto-ssl.init_worker"
  init_worker(self)
end

function _M.ssl_certificate(self, ssl_options)
  local ssl_certificate = require "resty.auto-ssl.ssl_certificate"
  ssl_certificate(self, ssl_options)
end

function _M.challenge_server(self)
  local server = require "resty.auto-ssl.servers.challenge"
  server(self)
end

function _M.hook_server(self)
  local server = require "resty.auto-ssl.servers.hook"
  server(self)
end

return _M
