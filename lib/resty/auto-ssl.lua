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

  if not options["renewals_per_hour"] then
    options["renewals_per_hour"] = 60
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

function _M.get_failures(self, domain)
  if not ngx.shared.auto_ssl_failures then
    ngx.log(ngx.ERR, "auto-ssl: dict auto_ssl_failures could not be found. Please add it to your configuration: `lua_shared_dict auto_ssl_failures 1m;`")
    return
  end

  local string = ngx.shared.auto_ssl_failures:get("domain:" .. domain)
  if string then
    local failures, json_err = self.storage.json_adapter:decode(string)
    if json_err then
      ngx.log(ngx.ERR, json_err, domain)
    end
    if failures then
      local mt = {
        __concat = function(op1, op2)
          return tostring(op1) .. tostring(op2)
        end,
        __tostring = function(f)
          return "first: " .. f["first"] .. ", last: " .. f["last"] .. ", num: " .. f["num"]
        end
      }
      setmetatable(failures, mt)
      return failures
    end
  end
end

function _M.track_failure(self, domain)
  if not ngx.shared.auto_ssl_failures then
    return
  end

  local failures
  local string = ngx.shared.auto_ssl_failures:get("domain:" .. domain)
  if string then
    failures = self.storage.json_adapter:decode(string)
  end
  if not failures then
    failures = {}
    failures["first"] = ngx.now()
    failures["last"] = failures["first"]
    failures["num"] = 1
  else
    failures["last"] = ngx.now()
    failures["num"] = failures["num"] + 1
  end
  string = self.storage.json_adapter:encode(failures)
  ngx.shared.auto_ssl_failures:set("domain:" .. domain, string, 2592000)
end

function _M.track_success(_, domain)
  if not ngx.shared.auto_ssl_failures then
    return
  end

  ngx.shared.auto_ssl_failures:delete("domain:" .. domain)
end

return _M
