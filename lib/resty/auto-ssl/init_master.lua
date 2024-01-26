require "resty.auto-ssl.utils.random_seed"
local resty_random = require "resty.random"
local shell_blocking = require "shell-games"
local str = require "resty.string"

local function check_dependencies()
  local runtime_dependencies = {
    "awk",
    "bash",
    "curl",
    "diff",
    "find",
    "grep",
    "mktemp",
    "openssl",
    "sed",
    "getent",
  }
  for _, bin in ipairs(runtime_dependencies) do
    local _, err = shell_blocking.capture_combined({ "command", "-v", bin })
    if(err) then
      ngx.log(ngx.ERR, "auto-ssl: `" .. bin .. "` was not found in PATH. Please install `" .. bin .. "` first.")
    end
  end
end

-- debian or redhat
local nobody_group = os.execute("getent group nobody")
if nobody_group then
  nobody_group = "nobody:nobody"
else
  nobody_group = "nobody:nogroup"
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

local function generate_config_letsencrypt(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")

  local _, mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/conf.d" }, { umask = "0022" })
  if mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/conf.d dir: ", mkdir_err)
  end

  local _, chmod_err = shell_blocking.capture_combined({ "chmod", "777", base_dir .. "/letsencrypt" })
  if chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt dir permissions: ", chmod_err)
  end

  local file, err = io.open(base_dir .. "/letsencrypt/config", "w")
  if err then
    ngx.log(ngx.ERR, "auto-ssl: failed to open letsencrypt config file")
  else
    file:write('# This file will be overwritten by resty-auto-ssl.\n')
    file:write('# Place any customizations in ' .. base_dir .. '/letsencrypt/conf.d/*.sh\n\n')
    file:write('CONFIG_D="' .. base_dir .. '/letsencrypt/conf.d"\n')
    file:write('LOCKFILE="' .. base_dir .. '/letsencrypt/locks/lock"\n')
    file:write('WELLKNOWN="' .. base_dir .. '/letsencrypt/.acme-challenges"\n')

    local ca = auto_ssl_instance:get("letsencrypt_ca")
    if ca then
      file:write('CA="' .. ca .. '"\n')
    end
    file:close()
  end

  local _, mkdir_challenges_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/.acme-challenges" }, { umask = "0022" })
  if mkdir_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/.acme-challenges dir: ", mkdir_challenges_err)
  end
  local _, chown_challenges_err = shell_blocking.capture_combined({ "chown", nobody_group, base_dir .. "/letsencrypt/.acme-challenges" })
  if chown_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to chown letsencrypt/.acme-challenges dir: ", chown_challenges_err)
  end
  local _, mkdir_locks_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/locks" }, { umask = "0022" })
  if mkdir_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/locks dir: ", mkdir_locks_err)
  end
  local _, chown_locks_err = shell_blocking.capture_combined({ "chown", nobody_group, base_dir .. "/letsencrypt/locks" })
  if chown_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to chown letsencrypt/locks dir: ", chown_locks_err)
  end

  -- if multi account enabled reuse main config by symlinkink
  if auto_ssl_instance:get("letsencrypt_multi_account") then
    local account_count = auto_ssl_instance:get("letsencrypt_account_count")
    for account_counter = 1, account_count do
      local account_dir = base_dir .. "/letsencrypt/accounts/" .. account_counter

      local _, mkdir_account_err = shell_blocking.capture_combined({ "mkdir", "-p", account_dir }, { umask = "0022" })
      if mkdir_account_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to create " .. account_dir .. " dir: ", mkdir_account_err)
      end

      local _, chown_account_err = shell_blocking.capture_combined({ "chown", nobody_group, account_dir })
      if chown_account_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to chown " .. account_dir .. " dir: ", chown_account_err)
      end

      local _, symlink_account_err = shell_blocking.capture_combined({ "ln", "-srf", "letsencrypt/config", account_dir .. "/" }, { chdir = base_dir })
      if symlink_account_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to symlink " .. base_dir .. "letsencrypt/config" .. " to " .. account_dir .. "/", symlink_account_err)
      end
    end
  end
end

local function generate_config_zerossl(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")

  local _, mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/zerossl/conf.d" }, { umask = "0022" })
  if mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create zerossl/conf.d dir: ", mkdir_err)
  end

  local _, chmod_err = shell_blocking.capture_combined({ "chmod", "777", base_dir .. "/zerossl" })
  if chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create zerossl dir permissions: ", chmod_err)
  end

  local file, err = io.open(base_dir .. "/zerossl/config", "w")
  if err then
    ngx.log(ngx.ERR, "auto-ssl: failed to open zerossl config file")
  else
    file:write('# This file will be overwritten by resty-auto-ssl.\n')
    file:write('# Place any customizations in ' .. base_dir .. '/zerossl/conf.d/*.sh\n\n')
    file:write('CONFIG_D="' .. base_dir .. '/zerossl/conf.d"\n')
    file:write('LOCKFILE="' .. base_dir .. '/zerossl/locks/lock"\n')
    file:write('WELLKNOWN="' .. base_dir .. '/zerossl/.acme-challenges"\n')

    local ca = auto_ssl_instance:get("zerossl_ca")
    if ca then
      file:write('CA="' .. ca .. '"\n')
    end
    file:close()
  end

  local _, mkdir_challenges_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/zerossl/.acme-challenges" }, { umask = "0022" })
  if mkdir_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create zerossl/.acme-challenges dir: ", mkdir_challenges_err)
  end
  local _, chown_challenges_err = shell_blocking.capture_combined({ "chown", nobody_group, base_dir .. "/zerossl/.acme-challenges" })
  if chown_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to chown zerossl/.acme-challenges dir: ", chown_challenges_err)
  end
  local _, mkdir_locks_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/zerossl/locks" }, { umask = "0022" })
  if mkdir_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create zerossl/locks dir: ", mkdir_locks_err)
  end
  local _, chown_locks_err = shell_blocking.capture_combined({ "chown", nobody_group, base_dir .. "/zerossl/locks" })
  if chown_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to chown zerossl/locks dir: ", chown_locks_err)
  end
end

local function generate_config(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")

  local _, tmp_mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/tmp" })
  if tmp_mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create tmp dir: ", tmp_mkdir_err)
  end

  local _, tmp_chmod_err = shell_blocking.capture_combined({ "chmod", "777", base_dir .. "/tmp" })
  if tmp_chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create tmp dir permissions: ", tmp_chmod_err)
  end

  if not auto_ssl_instance:get("letsencrypt_ca") and not auto_ssl_instance:get("zerossl_ca") then
    ngx.log(ngx.ERR, "auto-ssl: zerossl_ca and letsencrypt_ca parameters are missing!")
  end

  if auto_ssl_instance:get("letsencrypt_ca") then
    generate_config_letsencrypt(auto_ssl_instance)
  end

  if auto_ssl_instance:get("zerossl_ca") then
    generate_config_zerossl(auto_ssl_instance)
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

return function(auto_ssl_instance)
  if not ngx.shared.auto_ssl_settings then
    ngx.log(ngx.ERR, "auto-ssl: dict auto_ssl_settings could not be found. Please add it to your configuration: `lua_shared_dict auto_ssl_settings 64k;`")
  end

  check_dependencies()
  generate_hook_sever_secret()
  generate_config(auto_ssl_instance)
  setup_storage(auto_ssl_instance)
end
