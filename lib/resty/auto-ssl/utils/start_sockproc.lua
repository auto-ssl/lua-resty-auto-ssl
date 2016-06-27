local auto_ssl = require "resty.auto-ssl"
local lock = require "resty.lock"

local function start()
  local exit_code = os.execute("umask 0022 && " .. auto_ssl.package_root .. "/auto-ssl/shell/start_sockproc")
  if exit_code == 0 then
    ngx.shared.auto_ssl:set("sockproc_started", true)
  else
    ngx.log(ngx.ERR, "auto-ssl: failed to start sockproc")
  end
end

return function(force)
  if ngx.shared.auto_ssl:get("sockproc_started") and not force then
    return
  end

  -- Add lock to ensure only a single start command is attempted at a time.
  local start_lock, new_lock_err = lock:new("auto_ssl", { exptime = 600, timeout = 0 })
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
