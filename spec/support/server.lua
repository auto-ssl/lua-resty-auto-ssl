local process = require "process"
local redis = require "resty.redis"
local unistd = require "posix.unistd"
local ffi = require "ffi"
local log_tail = require "spec.support.log_tail"
local handler = require 'busted.outputHandlers.base'()
local etlua = require "etlua"
local path = require "pl.path"
local file = require "pl.file"
local dir = require "pl.dir"
local busted = require "busted"

local _M = {}

_M.nginx_process = nil
_M.nginx_error_log_tail = nil
_M.ngrok_process = nil
_M.ngrok_hostname = nil
_M.redis_process = nil

_M.root_dir = path.dirname(path.dirname(path.dirname(path.abspath(debug.getinfo(1, "S").short_src))))
_M.test_dir = "/tmp/resty-auto-ssl-test"
-- _M.auto_ssl_test_dir = _M.test_dir .. "/auto-ssl"
_M.ngrok_test_dir = _M.test_dir .. "/ngrok"
_M.redis_test_dir = _M.test_dir .. "/redis"
_M.tests_test_dir = _M.test_dir .. "/tests"
_M.test_counter = 0

local nginx_template = etlua.compile(assert(file.read(_M.root_dir .. "/spec/config/nginx.conf.etlua")))
local redis_template = etlua.compile(assert(file.read(_M.root_dir .. "/spec/config/redis.conf.etlua")))

local function kill(proc)
  local pid = proc:pid()
  local err = proc:kill()
  process.waitpid(pid)

  proc:kill(6)
  proc:kill(9)
end

local function start_ngrok()
  if not _M.ngrok_hostname then
    if path.exists(_M.ngrok_test_dir) then
      assert(dir.rmtree(_M.ngrok_test_dir))
    end
    assert(dir.makepath(_M.ngrok_test_dir))
    local ngrok_process, err = process.exec("ngrok", { "http", "9080", "--log", _M.ngrok_test_dir .. "/ngrok.log", "--log-format", "logfmt", "--log-level", "debug" })
    _M.ngrok_process = ngrok_process

    local log = log_tail.new(_M.ngrok_test_dir .. "/ngrok.log")
    local output = log:read_until("start tunnel listen.*Hostname:[a-z0-9]+.ngrok.io")
    if not output then
      print(ngrok_process:stdout())
      print(ngrok_process:stderr())
      local log, err = file.read(_M.ngrok_test_dir .. "/ngrok.log")
      if log then
        print(log)
      elseif err then
        print(err)
      end

      error("ngrok did not startup as expected")
    end

    local matches, err = ngx.re.match(output, "Hostname:([a-z0-9]+.ngrok.io)", "jo")
    _M.ngrok_hostname = matches[1]
  end
end

local function start_redis()
  if not _M.redis_process then
    if path.exists(_M.redis_test_dir) then
      assert(dir.rmtree(_M.redis_test_dir))
    end
    assert(dir.makepath(_M.redis_test_dir))
    assert(file.write(_M.redis_test_dir .. "/redis.conf", redis_template({
      redis_test_dir = _M.redis_test_dir,
    })))

    local redis_process, err = process.exec("redis-server", { _M.redis_test_dir .. "/redis.conf" })
    _M.redis_process = redis_process

    local log = log_tail.new(_M.redis_test_dir .. "/redis.log")
    local output = log:read_until("(now ready|Ready to accept)")
    if not output then
      print(redis_process:stdout())
      print(redis_process:stderr())
      local log, err = file.read(_M.redis_test_dir .. "/redis.log")
      if log then
        print(log)
      elseif err then
        print(err)
      end

      local conf, err = file.read(_M.redis_test_dir .. "/redis.conf")
      if conf then
        print(conf)
      elseif err then
        print(err)
      end

      error("redis did not startup as expected")
    end
  end

  local r = redis:new()
  assert(r:connect("127.0.0.1", 9999))
  assert(r:flushall())
end

local function exit_handler()
  if _M.nginx_process then
    kill(_M.nginx_process)
  end

  if _M.ngrok_process then
    kill(_M.ngrok_process)
  end

  if _M.redis_process then
    kill(_M.redis_process)
  end
end
busted.subscribe({ "exit" }, exit_handler)

busted.subscribe({ "test", "start" }, function(element)
  _M.current_test_name = handler.getFullName(element)
end)
busted.subscribe({ "test", "end" }, function()
  _M.current_test_name = nil
end)

function _M.start(options)
  start_ngrok()
  start_redis()

  if not options then
    options = {}
  end

  --[[
  assert(dir.makepath(_M.auto_ssl_test_dir))

  local shell_blocking = require "shell-games"
  local result, err = shell_blocking.capture_combined({ "find", _M.auto_ssl_test_dir, "-mindepth", "1", "!", "-path", "*/letsencrypt", "!", "-path", "*/letsencrypt/accounts", "!", "-path", "*/letsencrypt/accounts/*", "-delete" })
  assert(not err, err)

  local result, err = shell_blocking.capture_combined({ "find", _M.auto_ssl_test_dir, "-mindepth", "1", "-mmin", "+10", "-delete" })
  assert(not err, err)
  ]]

  if not _M.started_once then
    if path.exists(_M.tests_test_dir) then
      assert(dir.rmtree(_M.tests_test_dir))
    end

    _M.started_once = true
  end

  _M.test_counter = _M.test_counter + 1
  local test_name_dir = _M.test_counter .. "-" .. (_M.current_test_name or "")
  test_name_dir = assert(ngx.re.gsub(test_name_dir, "[^0-9A-Za-z_-]", "_"))
  test_name_dir = string.sub(test_name_dir, 1, 255)
  _M.current_test_dir = _M.tests_test_dir .. "/" .. test_name_dir
  assert(dir.makepath(_M.current_test_dir .. "/auto-ssl"))

  options["root_dir"] = _M.root_dir
  -- options["auto_ssl_test_dir"] = _M.auto_ssl_test_dir
  options["current_test_dir"] = _M.current_test_dir

  assert(file.write(_M.current_test_dir .. "/nginx.conf", nginx_template(options)))

  local nginx_process, err = process.exec("nginx", { "-p", _M.current_test_dir, "-c", _M.current_test_dir .. "/nginx.conf" })
  _M.nginx_process = nginx_process

  _M.nginx_error_log_tail = log_tail.new(_M.current_test_dir .. "/error.log")
  local output = _M.nginx_error_log_tail:read_until("init_by_lua_block")
  if not output then
    print(nginx_process:stdout())
    print(nginx_process:stderr())
    local log, err = file.read(_M.current_test_dir .. "/error.log")
    if log then
      print(log)
    elseif err then
      print(err)
    end

    local conf, err = file.read(_M.current_test_dir .. "/nginx.conf")
    if conf then
      print(conf)
    elseif err then
      print(err)
    end

    error("nginx did not startup as expected")
  end
end

function _M.stop()
  if _M.nginx_process then
    kill(_M.nginx_process)
    _M.nginx_process = nil
  end
end

function _M.read_error_log()
  local log = log_tail.new(_M.current_test_dir .. "/error.log")
  return log:read()
end

return _M
