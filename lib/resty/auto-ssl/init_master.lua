require "resty.auto-ssl.utils.random_seed"
local resty_random = require "resty.random"
local shell_blocking = require "shell-games"
local str = require "resty.string"

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

local function setup_tmp_dir(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")

  local _, tmp_mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/tmp" })
  if tmp_mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create tmp dir: ", tmp_mkdir_err)
  end

  local _, tmp_chmod_err = shell_blocking.capture_combined({ "chmod", "777", base_dir .. "/tmp" })
  if tmp_chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create tmp dir permissions: ", tmp_chmod_err)
  end

end

local function setup_storage(auto_ssl_instance)
  local storage_adapter = require(auto_ssl_instance:get("storage_adapter"))
  local storage_adapter_instance = storage_adapter.new(auto_ssl_instance)
  if storage_adapter_instance.setup then
    storage_adapter_instance:setup()
  end

  local json_adapter = require(auto_ssl_instance:get("json_adapter"))
  local json_adapter_instance = json_adapter.new(auto_ssl_instance)

  local storage = require "resty.auto-ssl.storage"
  local storage_instance = storage.new({
    adapter = storage_adapter_instance,
    json_adapter = json_adapter_instance,
  })
  auto_ssl_instance.storage = storage_instance
end

local function setup_client_adapter(auto_ssl_instance)
  local client_adapter = require(auto_ssl_instance:get("client_adapter"))
  local client_adapter_instance = client_adapter.new(auto_ssl_instance)
  if client_adapter_instance.setup then
    client_adapter_instance:setup()
  end

  auto_ssl_instance.client = client_adapter_instance
end

return function(auto_ssl_instance)
  if not ngx.shared.auto_ssl_settings then
    ngx.log(ngx.ERR, "auto-ssl: dict auto_ssl_settings could not be found. Please add it to your configuration: `lua_shared_dict auto_ssl_settings 64k;`")
  end

  generate_hook_sever_secret()
  setup_tmp_dir(auto_ssl_instance)
  setup_storage(auto_ssl_instance)
  setup_client_adapter(auto_ssl_instance)
end
