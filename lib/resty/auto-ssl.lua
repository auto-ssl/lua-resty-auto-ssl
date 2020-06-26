-- Ensure resty.core FFI libraries are loaded to prevent potential deadlocks in
-- shdict. These are loaded by default in OpenResty 1.15.8.1+, but this will
-- ensure this library is loaded in older versions.
--
-- https://github.com/openresty/lua-nginx-module/issues/1207#issuecomment-350742782
-- https://github.com/auto-ssl/lua-resty-auto-ssl/issues/43
-- https://github.com/auto-ssl/lua-resty-auto-ssl/issues/220
require "resty.core"

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
    options["allow_domain"] = function(domain, auto_ssl, ssl_options, renewal) -- luacheck: ignore
      return false
    end
  end

  if not options["storage_adapter"] then
    options["storage_adapter"] = "resty.auto-ssl.storage_adapters.file"
  end

  if not options["json_adapter"] then
    options["json_adapter"] = "resty.auto-ssl.json_adapters.cjson"
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
  if key == "storage" then
    ngx.log(ngx.ERR, "auto-ssl: DEPRECATED: Don't use auto_ssl:set() for the 'storage' instance. Set directly with auto_ssl.storage.")
    self.storage = value
    return
  end

  self.options[key] = value
end

function _M.get(self, key)
  if key == "storage" then
    ngx.log(ngx.ERR, "auto-ssl: DEPRECATED: Don't use auto_ssl:get() for the 'storage' instance. Get directly with auto_ssl.storage.")
    return self.storage
  end

  return self.options[key]
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
