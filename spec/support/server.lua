local busted = require "busted"
local dir = require "pl.dir"
local etlua = require "etlua"
local file = require "pl.file"
local grp = require "posix.grp"
local handler = require 'busted.outputHandlers.base'()
local log_tail = require "spec.support.log_tail"
local path = require "pl.path"
local process = require "process"
local pwd = require "posix.pwd"
local redis = require "resty.redis"
local shell_blocking = require "shell-games"
local unistd = require "posix.unistd"

local _M = {}

_M.nginx_process = nil
_M.nginx_error_log_tail = nil
_M.ngrok_process = nil
_M.ngrok_hostname = nil
_M.redis_process = nil

_M.root_dir = path.dirname(path.dirname(path.dirname(path.abspath(debug.getinfo(1, "S").short_src))))
_M.dehydrated_persist_accounts_dir = _M.root_dir .. "/spec/tmp/dehydrated-accounts"
_M.test_dir = "/tmp/resty-auto-ssl-test"
_M.ngrok_test_dir = _M.test_dir .. "/ngrok"
_M.redis_test_dir = _M.test_dir .. "/redis"
_M.tests_test_dir = _M.test_dir .. "/tests"
_M.test_counter = 0
_M.nobody_user = "nobody"
_M.nobody_group = assert(grp.getgrgid(assert(pwd.getpwnam(_M.nobody_user)).pw_gid)).gr_name

local nginx_template = etlua.compile(assert(file.read(_M.root_dir .. "/spec/config/nginx.conf.etlua")))
local redis_template = etlua.compile(assert(file.read(_M.root_dir .. "/spec/config/redis.conf.etlua")))

local nginx_path = ngx.re.gsub(os.getenv("PATH"), [[[^:]+/resty-auto-ssl-test-luarocks/[^:]+:]], "")
local nginx_lua_path = ngx.re.gsub(os.getenv("LUA_PATH"), [[[^;]+/resty-auto-ssl-test-luarocks/[^;]+;]], "")
local nginx_lua_cpath = ngx.re.gsub(os.getenv("LUA_CPATH"), [[[^;]+/resty-auto-ssl-test-luarocks/[^;]+;]], "")

local function kill(proc)
  local pid = proc:pid()
  proc:kill()
  process.waitpid(pid)

  proc:kill(6)
  proc:kill(9)
end

local function start_ngrok()
  if not _M.ngrok_hostname then
    assert(dir.makepath(_M.ngrok_test_dir))
    local ngrok_process, exec_err = process.exec("ngrok", { "http", "9080", "--log", _M.ngrok_test_dir .. "/ngrok.log", "--log-format", "logfmt", "--log-level", "debug" })
    assert(not exec_err, exec_err)
    _M.ngrok_process = ngrok_process

    local log = log_tail.new(_M.ngrok_test_dir .. "/ngrok.log")
    local ok, output = log:read_until("start tunnel listen.*Hostname:[a-z0-9]+.ngrok.io")
    if not ok then
      print(ngrok_process:stdout())
      print(ngrok_process:stderr())
      local log_content, log_content_err = file.read(_M.ngrok_test_dir .. "/ngrok.log")
      if log_content then
        print(log_content)
      elseif log_content_err then
        print(log_content_err)
      end

      error("ngrok did not startup as expected")
    end

    local matches, match_err = ngx.re.match(output, "Hostname:([a-z0-9]+.ngrok.io)", "jo")
    assert(not match_err, match_err)
    _M.ngrok_hostname = matches[1]
  end
end

local function start_redis()
  if not _M.redis_process then
    assert(dir.makepath(_M.redis_test_dir))
    assert(file.write(_M.redis_test_dir .. "/redis.conf", redis_template({
      redis_test_dir = _M.redis_test_dir,
    })))

    local redis_process, err = process.exec("redis-server", { _M.redis_test_dir .. "/redis.conf" })
    _M.redis_process = redis_process

    local log = log_tail.new(_M.redis_test_dir .. "/redis.log")
    local ok = log:read_until("(now ready|Ready to accept)")
    if not ok then
      print(redis_process:stdout())
      print(redis_process:stderr())
      local log_content, log_content_err = file.read(_M.redis_test_dir .. "/redis.log")
      if log_content then
        print(log_content)
      elseif err then
        print(log_content_err)
      end

      local conf, conf_err = file.read(_M.redis_test_dir .. "/redis.conf")
      if conf then
        print(conf)
      elseif conf_err then
        print(conf_err)
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
  if not _M.started_once then
    if path.exists(_M.test_dir) then
      assert(dir.rmtree(_M.test_dir))
    end

    -- We persist the Let's Encrypt account configuration across individual
    -- test runs so that each test doesn't register it's own account and we
    -- don't hit the Let's Encrypt rate limits of 10 accounts per IP per 3
    -- hours (https://letsencrypt.org/docs/rate-limits/).
    --
    -- But we still want to ensure the normal account creation process works
    -- and creates files with the right permissions, so if the persisted
    -- account config is older than 4 hours, delete it, so the next test run
    -- perform a normal, fresh account registration.
    if path.exists(_M.dehydrated_persist_accounts_dir) then
      local persist_account_time = path.getmtime(_M.dehydrated_persist_accounts_dir)
      if persist_account_time < ngx.now() - 60 * 60 * 4 then
        assert(dir.rmtree(_M.dehydrated_persist_accounts_dir))
      end
    end

    _M.started_once = true
  end

  start_ngrok()
  start_redis()
  _M.stop_sockproc()

  if not options then
    options = {}
  end

  _M.test_counter = _M.test_counter + 1
  local test_name_dir = assert(ngx.re.gsub(_M.current_test_name or "", "[^0-9A-Za-z_-]+", "_"))
  test_name_dir = string.sub(test_name_dir, 1, 250)
  test_name_dir = test_name_dir .. "-" .. string.format("%04d", _M.test_counter)
  _M.current_test_dir = _M.tests_test_dir .. "/" .. test_name_dir
  _M.current_test_accounts_dir = _M.current_test_dir .. "/auto-ssl/letsencrypt/accounts"
  assert(dir.makepath(_M.current_test_dir .. "/auto-ssl/letsencrypt"))
  assert(unistd.chown(_M.current_test_dir .. "/auto-ssl", _M.nobody_user))

  -- If there is persisted account configuration, copy it into place for this
  -- test run. This prevents us hitting account registration rate limits if we
  -- were to register a new account on every test.
  if path.exists(_M.dehydrated_persist_accounts_dir) then
    _M.dehydrated_cached_accounts = true

    local _, cp_err = shell_blocking.capture_combined({ "cp", "-pr", _M.dehydrated_persist_accounts_dir, _M.current_test_accounts_dir })
    assert(not cp_err, cp_err)

    local _, chown_err = shell_blocking.capture_combined({ "chown", "-R", _M.nobody_user .. ":" .. _M.nobody_group, _M.current_test_accounts_dir })
    assert(not chown_err, chown_err)
  end

  options["root_dir"] = _M.root_dir
  options["current_test_dir"] = _M.current_test_dir
  options["user"] = _M.nobody_user .. " " .. _M.nobody_group

  assert(file.write(_M.current_test_dir .. "/nginx.conf", nginx_template(options)))

  local nginx_process, err = process.exec("nginx", {
    "-p", _M.current_test_dir,
    "-c", _M.current_test_dir .. "/nginx.conf",
  }, {
    ["PATH"] = nginx_path,
    ["LUA_PATH"] = nginx_lua_path,
    ["LUA_CPATH"] = nginx_lua_cpath,
  }, options["pwd"])
  _M.nginx_process = nginx_process

  _M.nginx_error_log_tail = log_tail.new(_M.current_test_dir .. "/error.log")
  local ok, output = _M.nginx_error_log_tail:read_until("init_by_lua_block")
  if not ok or (output and string.match(output, "emerg")) then
    print(nginx_process:stdout())
    print(nginx_process:stderr())
    local log_content, log_content_err = file.read(_M.current_test_dir .. "/error.log")
    if log_content then
      print(log_content)
    elseif err then
      print(log_content_err)
    end

    local conf, conf_err = file.read(_M.current_test_dir .. "/nginx.conf")
    if conf then
      print(conf)
    elseif conf_err then
      print(conf_err)
    end

    error("nginx did not startup as expected")
  end
end

function _M.stop()
  if _M.nginx_process then
    -- On shutdown, if we don't already have persisted account config, then
    -- copy the generated config into the persisted directory.
    if _M.current_test_accounts_dir and not path.exists(_M.dehydrated_persist_accounts_dir) and path.exists(_M.current_test_accounts_dir) then
      assert(dir.makepath(path.dirname(_M.dehydrated_persist_accounts_dir)))
      local _, cp_err = shell_blocking.capture_combined({ "cp", "-pr", _M.current_test_accounts_dir, _M.dehydrated_persist_accounts_dir })
      assert(not cp_err, cp_err)
    end

    kill(_M.nginx_process)
    _M.nginx_process = nil

    _M.stop_sockproc()
  end
end

function _M.read_error_log()
  local log = log_tail.new(_M.current_test_dir .. "/error.log")
  return log:read()
end

function _M.stop_sockproc()
  shell_blocking.capture_combined({ "pkill", "sockproc" })
  local _, err = shell_blocking.capture_combined({ "rm", "-f", "/tmp/shell.sock", "/tmp/auto-ssl-sockproc.pid" })
  assert(not err, err)
end

return _M
