local shell_blocking = require "shell-games"

return function(runtime_dependencies)
  for _, bin in ipairs(runtime_dependencies) do
    local _, err = shell_blocking.capture_combined({ "command", "-v", bin })
    if(err) then
      ngx.log(ngx.ERR, "auto-ssl: `" .. bin .. "` was not found in PATH. Please install `" .. bin .. "` first.")
    end
  end
end
