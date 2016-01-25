local shell = require "resty.auto-ssl.vendor.shell"
local start_sockproc = require "resty.auto-ssl.utils.start_sockproc"

return function(command)
  local status, out, err = shell.execute(command)

  -- If the script fails due to a missing sockproc socket, try starting up
  -- the sockproc process again and then retry.
  if status ~= 0 and err == "no such file or directory" then
    ngx.log(ngx.ERR, "auto-ssl: sockproc unexpectedly not available, trying to restart")
    start_sockproc()
    status, out, err = shell.execute(command)
  end

  return status, out, err
end
