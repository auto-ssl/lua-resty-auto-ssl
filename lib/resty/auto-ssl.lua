local _M = {}

local current_file_path = package.searchpath("resty.auto-ssl", package.path)
_M.package_root = string.match(current_file_path, "(.*)/(.*)")
if string.sub(_M.package_root, 1, 2) == "./" then
  local lfs = require "lfs"
  _M.package_root = lfs.currentdir() .. string.sub(_M.package_root, 2, -1)
end

_M.dir = "/etc/resty-auto-ssl"

function _M.allow_domain(domain) -- luacheck: ignore
  return false
end

function _M.init_worker()
  local init_worker = require "resty.auto-ssl.init_worker"
  init_worker()
end

function _M.ssl_certificate()
  local ssl_certificate = require "resty.auto-ssl.ssl_certificate"
  ssl_certificate()
end

function _M.challenge_server()
  local server = require "resty.auto-ssl.servers.challenge"
  server()
end

function _M.hook_server()
  local server = require "resty.auto-ssl.servers.hook"
  server()
end


return _M
