local lock = require "resty.lock"
local shell_blocking = require "shell-games"

local _M = {}

-- Based on lua-rest-upstream-healthcheck's lock:
-- https://github.com/openresty/lua-resty-upstream-healthcheck/blob/v0.03/lib/resty/upstream/healthcheck.lua#L423-L440
--
-- This differs from resty-lock by ensuring that the task only gets executed
-- once per interval across all workers. resty-lock helps ensure multiple
-- concurrent tasks don't run (in case the task takes longer than interval).
local function get_interval_lock(name, interval)
  local key = "lock:" .. name

  -- the lock is held for the whole interval to prevent multiple
  -- worker processes from sending the test request simultaneously.
  -- here we substract the lock expiration time by 1ms to prevent
  -- a race condition with the next timer event.
  local ok, err = ngx.shared.auto_ssl:add(key, true, interval - 0.001)
  if not ok then
    if err == "exists" then
      return nil
    end
    ngx.log(ngx.ERR, "failed to add key \"", key, "\": ", err)
    return nil
  end
  return true
end

local function cleanup_stale_challenges(auto_ssl_instance)
  local storage = auto_ssl_instance.storage
  local challenges, challenges_err = storage:all_domain_challenges()
  if challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to fetch all certificate domains: ", challenges_err)
  end
  local current_time = os.time()
  for _, line in ipairs(challenges) do
    for domain, path in pairs(line) do
      local challenge,timestamp = storage:get_challenge(domain,path)
      if timestamp == nil or current_time > timestamp + 300 then
        ngx.log(ngx.INFO, "auto-ssl: delete stuck challenge ", domain,":", path)
        storage:delete_challenge(domain,path)
      end
    end
  end
end

local function do_cleanup(auto_ssl_instance)
  -- Ensure only 1 worker executes the cleanup once per interval.
  if not get_interval_lock("cleanup", auto_ssl_instance:get("cleanup_check_interval")) then
    return
  end
  local cleanup_lock, new_cleanup_lock_err = lock:new("auto_ssl_settings", { exptime = 200, timeout = 0 })
  if new_cleanup_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create cleanup lock: ", new_cleanup_lock_err)
    return
  end
  local _, lock_err = cleanup_lock:lock("cleanup")
  if cleanup_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to obtain cleanup lock: ", lock_err)
    return
  end
  local cleanup_ok, cleanup_err = pcall(cleanup_stale_challenges, auto_ssl_instance)
  if not cleanup_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run do_cleanup cycle: ", cleanup_err)
  end
  local ok, unlock_err = cleanup_lock:unlock()
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to unlock cleanup job: ", unlock_err)
  end
end

-- Call the cleanup function in an infinite loop
local function cleanup(premature, auto_ssl_instance)
  if premature then return end

  local cleanup_ok, cleanup_err = pcall(do_cleanup, auto_ssl_instance)
  if not cleanup_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run cleanup cycle: ", cleanup_err)
  end

  local timer_ok, timer_err = ngx.timer.at(auto_ssl_instance:get("cleanup_check_interval"), cleanup, auto_ssl_instance)
  if not timer_ok then
    if timer_err ~= "process exiting" then
      ngx.log(ngx.ERR, "auto-ssl: failed to create timer for cleanup job: ", timer_err)
    end
    return
  end
end

function _M.spawn(auto_ssl_instance)
  local ok, err = ngx.timer.at(auto_ssl_instance:get("cleanup_check_interval"), cleanup, auto_ssl_instance)
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to create timer for cleanup job: ", err)
    return
  end
end

return _M
