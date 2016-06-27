local resty_random = require "resty.random"
local run_command = require "resty.auto-ssl.utils.run_command"
local str = require "resty.string"

-- Generate a secret token used for the letsencrypt.sh bash hook script to
-- communicate with the internal HTTP API hook server.
--
-- The internal HTTP API should only be listening on a private port on
-- 127.0.0.1, so it should only be accessible internally already, but this
-- secret token is an extra precaution to ensure the server is not accidentally
-- opened up or proxied to the outside world.
local function generate_hook_sever_secret()
  -- Generate the secret token.
  local random = resty_random.bytes(32)
  ngx.shared.auto_ssl:set("hook_server:secret", str.to_hex(random))
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

  local file, err = io.open(base_dir .. "/letsencrypt/config.sh", "w")
  if err then
    ngx.log(ngx.ERR, "auto-ssl: failed to open letsencrypt config file")
  else
    file:write('# This file will be overwritten by resty-auto-ssl.\n')
    file:write('# Place any customizations in ' .. base_dir .. '/letsencrypt/conf.d\n\n')
    file:write('CONFIG_D="' .. base_dir .. '/letsencrypt/conf.d"\n')
    file:write('LOCKFILE="' .. base_dir .. '/letsencrypt/locks/lock"\n')

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
  generate_hook_sever_secret()
  generate_config(auto_ssl_instance)
  setup_storage(auto_ssl_instance)
end
