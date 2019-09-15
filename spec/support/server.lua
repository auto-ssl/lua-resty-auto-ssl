local process = require "process"
local unistd = require "posix.unistd"
local ffi = require "ffi"
local log_tail = require "spec.support.log_tail"
local etlua = require "etlua"
local busted = require "busted"

local _M = {}

_M.nginx_process = nil
_M.nginx_error_log_tail = nil
_M.ngrok_hostname = nil

local file, err = io.open("spec/config/nginx.conf.etlua", "r")
local content = file:read("*all")
local nginx_template = etlua.compile(content)

local function kill(proc)
  local pid = proc:pid()
  local err = proc:kill()
  process.waitpid(pid)

  proc:kill(6)
  proc:kill(9)
end

local function start_ngrok()
  if not _M.ngrok_hostname then
    local child, err = process.exec("ngrok", { "http", "9080", "--log", "spec/tmp/ngrok.log", "--log-format", "logfmt", "--log-level", "debug" })

    local log = log_tail.new("spec/tmp/ngrok.log")
    local output = log:read_until("start tunnel listen.*Hostname:[a-z0-9]+.ngrok.io")
    local matches, err = ngx.re.match(output, "Hostname:([a-z0-9]+.ngrok.io)", "jo")
    _M.ngrok_hostname = matches[1]
    busted.subscribe({ "exit" }, function()
      kill(child)
    end)
  end
end

local function start_redis()
  if not _M.redis_process then
    local child, err = process.exec("redis-server", { "./spec/config/redis.conf" })

    local log = log_tail.new("spec/tmp/redis.log")
    local output = log:read_until("(now ready|Ready to accept)")

    busted.subscribe({ "exit" }, function()
      kill(child)
    end)
  end
end

function _M.start(options)
  start_ngrok()
  start_redis()

  if not options then
    options = {}
  end

  os.remove("spec/tmp/error.log")

  local file, err = io.open("spec/tmp/nginx.conf", "w")
  file:write(nginx_template(options))
  file:close()

  local nginx_process, err = process.exec("nginx", { "-p", "/app/spec/tmp", "-c", "/app/spec/tmp/nginx.conf" })
  _M.nginx_process = nginx_process

  _M.nginx_error_log_tail = log_tail.new("spec/tmp/error.log")
  local output = _M.nginx_error_log_tail:read_until("init_by_lua_block")
end

function _M.stop()
  if _M.nginx_process then
    kill(_M.nginx_process)
    _M.nginx_process = nil
  end
end

function _M.read_error_log()
  local log = log_tail.new("spec/tmp/error.log")
  return log:read()
end

return _M
