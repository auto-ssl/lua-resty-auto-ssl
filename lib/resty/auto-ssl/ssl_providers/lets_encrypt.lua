local _M = {}

local shell_execute = require "resty.auto-ssl.utils.shell_execute"

function _M.issue_cert(auto_ssl_instance, domain)
  assert(type(domain) == "string", "domain must be a string")

  local lua_root = auto_ssl_instance.lua_root
  assert(type(lua_root) == "string", "lua_root must be a string")

  local base_dir = auto_ssl_instance:get("dir")
  assert(type(base_dir) == "string", "dir must be a string")

  local hook_port = auto_ssl_instance:get("hook_server_port")
  local multiname = auto_ssl_instance:get("multiname_cert")
  domains = "--domain " .. domain .. " "

  local hook_port = auto_ssl_instance:get("hook_server_port")
  assert(type(hook_port) == "number", "hook_port must be a number")
  assert(hook_port <= 65535, "hook_port must be below 65536")

  local hook_secret = ngx.shared.auto_ssl_settings:get("hook_server:secret")
  assert(type(hook_secret) == "string", "hook_server:secret must be a string")

  if multiname then
    local storage = auto_ssl_instance:get("storage")
    domain_list, size = storage:get_subdomain(domain)
    domains = " "
    if domain_list then
      for _, i in pairs(domain_list) do
        domains = domains .. "--domain " .. i .. " "
      end
    else
      domains = "--domain " .. domain .. " "
    end
  end

  -- Run dehydrated for this domain, using our custom hooks to handle the
  -- domain validation and the issued certificates.
  --
  -- Disable dehydrated's locking, since we perform our own domain-specific
  -- locking using the storage adapter.
  local result, err = shell_execute({
    "env",
    "HOOK_SECRET=" .. hook_secret,
    "HOOK_SERVER_PORT=" .. hook_port,
    lua_root .. "/bin/resty-auto-ssl/dehydrated",
    "--cron",
    "--accept-terms",
    "--no-lock",
    domains,
    "--challenge", "http-01",
    "--config", base_dir .. "/letsencrypt/config",
    "--hook", lua_root .. "/bin/resty-auto-ssl/letsencrypt_hooks",
  })
  if result["status"] ~= 0 then
    ngx.log(ngx.ERR, "auto-ssl: dehydrated failed: ", result["command"], " status: ", result["status"], " out: ", result["output"], " err: ", err)
    return nil, "dehydrated failure"
  end

  ngx.log(ngx.DEBUG, "auto-ssl: dehydrated output: " .. result["output"])

  -- The result of running that command should result in the certs being
  -- populated in our storage (due to the deploy_cert hook triggering).
  local storage = auto_ssl_instance.storage
  local cert, get_cert_err = storage:get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
  end

  -- If dehydrated succeeded, but we still don't have any certs in storage, the
  -- issue might be that dehydrated succeeded and has local certs cached, but
  -- the initial attempt to deploy them and save them into storage failed (eg,
  -- storage was temporarily unavailable). If this occurs, try to manually fire
  -- the deploy_cert hook again to populate our storage with dehydrated's local
  -- copies.
  if not cert or not cert["fullchain_pem"] or not cert["privkey_pem"] then
    ngx.log(ngx.WARN, "auto-ssl: dehydrated succeeded, but certs still missing from storage - trying to manually copy - domain: " .. domain)

    result, err = shell_execute({
      "env",
      "HOOK_SECRET=" .. hook_secret,
      "HOOK_SERVER_PORT=" .. hook_port,
      lua_root .. "/bin/resty-auto-ssl/letsencrypt_hooks",
      "deploy_cert",
      domain,
      base_dir .. "/letsencrypt/certs/" .. domain .. "/privkey.pem",
      base_dir .. "/letsencrypt/certs/" .. domain .. "/cert.pem",
      base_dir .. "/letsencrypt/certs/" .. domain .. "/fullchain.pem",
      base_dir .. "/letsencrypt/certs/" .. domain .. "/chain.pem",
      math.floor(ngx.now()),
    })
    if result["status"] ~= 0 then
      ngx.log(ngx.ERR, "auto-ssl: dehydrated manual hook.sh failed: ", result["command"], " status: ", result["status"], " out: ", result["output"], " err: ", err)
      return nil, "dehydrated failure"
    end

    -- Try fetching again.
    cert, get_cert_err = storage:get_cert(domain)
    if get_cert_err then
      ngx.log(ngx.ERR, "auto-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
    end
  end

  -- Return error if things are still unexpectedly missing.
  if not cert or not cert["fullchain_pem"] or not cert["privkey_pem"] then
    return nil, "dehydrated succeeded, but no certs present"
  end

  return cert
end

return _M