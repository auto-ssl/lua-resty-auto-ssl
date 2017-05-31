local resty_random = require "resty.random"
local run_command = require "resty.auto-ssl.utils.run_command"
local str = require "resty.string"

local function check_dependencies()
  local runtime_dependencies = {
    "bash",
    "curl",
    "diff",
    "grep",
    "mktemp",
    "openssl",
    "sed",
  }
  for _, bin in ipairs(runtime_dependencies) do
    local _, _, err = run_command("command -v " .. bin)
    if(err) then
      ngx.log(ngx.ERR, "auto-ssl: `" .. bin .. "` was not found in PATH. Please install `" .. bin .. "` first.")
    end
  end
end

-- Generate a secret token used for the dehydrated bash hook script to
-- communicate with the internal HTTP API hook server.
--
-- The internal HTTP API should only be listening on a private port on
-- 127.0.0.1, so it should only be accessible internally already, but this
-- secret token is an extra precaution to ensure the server is not accidentally
-- opened up or proxied to the outside world.
local function generate_hook_sever_secret()
  if ngx.shared.auto_ssl_settings:get("hook_server:secret") then
    -- if we've already got a secret token, do not overwrite it, as this causes
    -- problems in reload-heavy envrionments.
    -- See https://github.com/GUI/lua-resty-auto-ssl/issues/66
    return
  end

  -- Generate the secret token.
  local random = resty_random.bytes(32)
  local _, set_err = ngx.shared.auto_ssl_settings:safe_set("hook_server:secret", str.to_hex(random))
  if set_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set shdict for hook_server:secret: ", set_err)
  end
end

local function generate_config(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")

  local _, _, mkdir_err = run_command("umask 0022 && mkdir -p " .. base_dir .. "/letsencrypt/conf.d")
  if mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/conf.d dir: ", mkdir_err)
  end

  local _, _, chmod_err = run_command("chmod 777 " .. base_dir .. "/letsencrypt")
  if chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt dir permissions: ", chmod_err)
  end

  -- Remove the old "config.sh" file used by dehydrated v0.2.0. Now it's
  -- moved to just "config".
  os.remove(base_dir .. "/letsencrypt/config.sh")

  local file, err = io.open(base_dir .. "/letsencrypt/config", "w")
  if err then
    ngx.log(ngx.ERR, "auto-ssl: failed to open letsencrypt config file")
  else
    file:write('# This file will be overwritten by resty-auto-ssl.\n')
    file:write('# Place any customizations in ' .. base_dir .. '/letsencrypt/conf.d\n\n')
    file:write('CONFIG_D="' .. base_dir .. '/letsencrypt/conf.d"\n')
    file:write('LOCKFILE="' .. base_dir .. '/letsencrypt/locks/lock"\n')
    file:write('WELLKNOWN="' .. base_dir .. '/letsencrypt/.acme-challenges"\n')

    local ca = auto_ssl_instance:get("ca")
    if ca then
      file:write('CA="' .. ca .. '"\n')
    end

    file:close()
  end
end

local function setup_storage(auto_ssl_instance)
  local adapter = require(auto_ssl_instance:get("storage_adapter"))
  local adapter_instance = adapter.new(auto_ssl_instance)
  if adapter_instance.setup then
    adapter_instance:setup()
  end

  local storage = require "resty.auto-ssl.storage"
  local storage_instance = storage.new(adapter_instance)
  auto_ssl_instance:set("storage", storage_instance)
end

return function(auto_ssl_instance)
  if not ngx.shared.auto_ssl_settings then
    ngx.log(ngx.ERR, "auto-ssl: dict auto_ssl_settings could not be found. Please add it to your configuration: `lua_shared_dict auto_ssl_settings 64k;`")
  end

  check_dependencies()
  generate_hook_sever_secret()
  generate_config(auto_ssl_instance)
  setup_storage(auto_ssl_instance)
end
