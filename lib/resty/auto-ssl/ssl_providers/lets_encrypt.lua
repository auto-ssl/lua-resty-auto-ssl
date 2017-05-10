local _M = {}

local shell_execute = require "resty.auto-ssl.utils.shell_execute"

function _M.issue_cert(auto_ssl_instance, domain)
  assert(type(domain) == "string", "domain must be a string")

  local lua_root = auto_ssl_instance.lua_root
  assert(type(lua_root) == "string", "lua_root must be a string")

  local base_dir = auto_ssl_instance:get("dir")
  assert(type(base_dir) == "string", "dir must be a string")

  local hook_port = auto_ssl_instance:get("hook_server_port")
  assert(type(hook_port) == "number", "hook_port must be a number")
  assert(hook_port <= 65535, "hook_port must be below 65536")

  local hook_secret = ngx.shared.auto_ssl_settings:get("hook_server:secret")
  assert(type(hook_secret) == "string", "hook_server:secret must be a string")

  local env_vars =
    "env HOOK_SECRET=" .. hook_secret .. " " ..
    "HOOK_SERVER_PORT=" .. hook_port

  -- Run dehydrated for this domain, using our custom hooks to handle the
  -- domain validation and the issued certificates.
  --
  -- Disable dehydrated's locking, since we perform our own domain-specific
  -- locking using the storage adapter.
  local command = env_vars .. " " ..
    lua_root .. "/bin/resty-auto-ssl/dehydrated " ..
    "--cron " ..
    "--no-lock " ..
    "--domain " .. domain .. " " ..
    "--challenge http-01 " ..
    "--config " .. base_dir .. "/letsencrypt/config " ..
    "--hook " .. lua_root .. "/bin/resty-auto-ssl/letsencrypt_hooks"
  local status, out, err = shell_execute(command)
  if status ~= 0 then
    ngx.log(ngx.ERR, "auto-ssl: dehydrated failed: ", command, " status: ", status, " out: ", out, " err: ", err)
    return nil, nil, "dehydrated failure"
  end

  ngx.log(ngx.DEBUG, "auto-ssl: dehydrated output: " .. out)

  -- The result of running that command should result in the certs being
  -- populated in our storage (due to the deploy_cert hook triggering).
  local storage = auto_ssl_instance:get("storage")
  local fullchain_pem, privkey_pem = storage:get_cert(domain)

  -- If dehydrated said it succeeded, but we still don't have any certs in
  -- storage, the issue is likely that the certs have been deleted out of our
  -- storage, but still exist in dehydrated's certs directory. If this
  -- occurs, try to manually fire the deploy_cert hook again to populate our
  -- storage with dehydrated's local copies.
  if not fullchain_pem or not privkey_pem then
    ngx.log(ngx.WARN, "auto-ssl: dehydrated succeeded, but certs still missing from storage - trying to manually copy - domain: " .. domain)

    command = env_vars .. " " ..
      lua_root .. "/bin/resty-auto-ssl/letsencrypt_hooks " ..
      "deploy_cert " ..
      domain .. " " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/privkey.pem " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/cert.pem " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/fullchain.pem " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/chain.pem " ..
      math.floor(ngx.now())
    status, out, err = shell_execute(command)
    if status ~= 0 then
      ngx.log(ngx.ERR, "auto-ssl: dehydrated manual hook.sh failed: ", command, " status: ", status, " out: ", out, " err: ", err)
      return nil, nil, "dehydrated failure"
    end

    -- Try fetching again.
    fullchain_pem, privkey_pem = storage:get_cert(domain)
  end

  -- Return error if things are still unexpectedly missing.
  if not fullchain_pem or not privkey_pem then
    return nil, nil, "dehydrated succeeded, but no certs present"
  end

  return fullchain_pem, privkey_pem
end

return _M
