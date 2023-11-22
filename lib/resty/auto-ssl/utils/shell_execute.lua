local shell = require "resty.shell"
local shell_join = require("shell-games").join

return function(args)
  local command = shell_join(args)
  local ok, stdout, stderr, reason, status =
    shell.run(command, nil, 60000)

  return {
    ok = ok,
    reason = reason,
    command = command,
    status = status,
    output = stdout,
    err = stderr
  }
end
