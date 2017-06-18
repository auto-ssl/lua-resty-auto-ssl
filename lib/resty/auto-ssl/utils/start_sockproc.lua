local auto_ssl = require "resty.auto-ssl"
local lock = require "resty.lock"

local function start()
  local _, set_false_err = ngx.shared.auto_ssl_settings:safe_set("sockproc_started", false)
  if set_false_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set shdict for sockproc_started: ", set_false_err)
  end

  ngx.log(ngx.NOTICE, "auto-ssl: starting sockproc")

  local exit_status = os.execute("umask 0022 && " .. auto_ssl.lua_root .. "/bin/resty-auto-ssl/start_sockproc")
  -- Lua 5.2+ returns boolean. Prior versions return status code.
  if exit_status == 0 or exit_status == true then
    local _, set_err = ngx.shared.auto_ssl_settings:safe_set("sockproc_started", true)
    if set_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to set shdict for sockproc_started: ", set_err)
    end
  else
    ngx.log(ngx.ERR, "auto-ssl: failed to start sockproc")
  end
end

return function(force)
  if ngx.shared.auto_ssl_settings:get("sockproc_started") and not force then
    return
  end

  -- Add lock to ensure only a single start command is attempted at a time.
  local start_lock, new_lock_err = lock:new("auto_ssl_settings", { exptime = 600, timeout = 0 })
  if new_lock_err then
    ngx.log(ngx.ERR, "Failed to create lock: ", new_lock_err)
    return
  end

  local _, lock_err = start_lock:lock("start_sockproc")
  if lock_err then
    return
  end

  local ok, err = pcall(start)
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run start_sockproc: ", err)
  end

  local unlock_ok, unlock_err = start_lock:unlock()
  if not unlock_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", unlock_err)
  end
end
