local shell = require "resty.auto-ssl.vendor.shell"
local start_sockproc = require "resty.auto-ssl.utils.start_sockproc"

return function(command)
  -- Make sure the sockproc has started before trying to execute any commands
  -- (since it's started by only a single worker in init_worker, it's possible
  -- other workers have already finished their init_worker phases before the
  -- process is actually started).
  if not ngx.shared.auto_ssl_settings:get("sockproc_started") then
    start_sockproc()

    local wait_time = 0
    local sleep_time = 0.01
    local max_time = 5
    while not ngx.shared.auto_ssl_settings:get("sockproc_started") do
      ngx.sleep(sleep_time)
      wait_time = wait_time + sleep_time

      if wait_time > max_time then
        ngx.log(ngx.ERR, "auto-ssl: sockproc did not start in expected amount of time")
        break
      end
    end
  end

  local options = { timeout = 60000 }
  local status, out, err = shell.execute(command, options)

  -- If the script fails due to a missing sockproc socket, try starting up
  -- the sockproc process again and then retry.
  if status ~= 0 and err == "no such file or directory" then
    ngx.log(ngx.ERR, "auto-ssl: sockproc unexpectedly not available, trying to restart")
    start_sockproc(true)
    status, out, err = shell.execute(command, options)
  end

  return status, out, err
end
