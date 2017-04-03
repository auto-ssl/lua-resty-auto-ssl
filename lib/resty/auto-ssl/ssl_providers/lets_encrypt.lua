local _M = {}

local shell_execute = require "resty.auto-ssl.utils.shell_execute"

function _M.issue_cert(auto_ssl_instance, domain)
  local package_root = auto_ssl_instance.package_root
  local base_dir = auto_ssl_instance:get("dir")
  local hook_port = auto_ssl_instance:get("hook_server_port")

  assert(type(hook_port) == "number", "hook_port must be a number")
  assert(hook_port <= 65535, "hook_port must be below 65536")

  local env_vars =
    "env HOOK_SECRET=" .. ngx.shared.auto_ssl:get("hook_server:secret") .. " " ..
    "HOOK_SERVER_PORT=" .. hook_port

  -- The result of running that command should result in the certs being
  -- populated in our storage (due to the deploy_cert hook triggering).
  local storage = auto_ssl_instance:get("storage")
  local fullchain_pem, privkey_pem = storage:get_cert(domain)

  -- Run dehydrated for this domain, using our custom hooks to handle the
  -- domain validation and the issued certificates.
  --
  -- Disable dehydrated's locking, since we perform our own domain-specific
  -- locking using the storage adapter.
  local dom, z = storage:get_domains(domain)
  local d, zz = storage:get_subdomains(dom)
  function get_domain_list(domain)
    local str = ''
    for _, i in pairs(domain) do
      str = str .. "--domain " .. i .. " "
    end
    return str
  end
  if d then
    domainus = get_domain_list(d)
  else
    domainus = "--domain " .. z .. " "
  end
  local command = env_vars .. " " ..
    package_root .. "/auto-ssl/vendor/dehydrated " ..
    "--cron " ..
    "--no-lock " ..
    domainus ..
    "--challenge http-01 " ..
    "--config " .. base_dir .. "/letsencrypt/config " ..
    "--hook " .. package_root .. "/auto-ssl/shell/letsencrypt_hooks"
  local status, out, err = shell_execute(command)
  if status ~= 0 then
    ngx.log(ngx.ERR, "auto-ssl: dehydrated failed: ", command, " status: ", status, " out: ", out, " err: ", err)
    return nil, nil, "dehydrated failure"
  end

  ngx.log(ngx.DEBUG, "auto-ssl: dehydrated output: " .. out)


  -- If dehydrated said it succeeded, but we still don't have any certs in
  -- storage, the issue is likely that the certs have been deleted out of our
  -- storage, but still exist in dehydrated's certs directory. If this
  -- occurs, try to manually fire the deploy_cert hook again to populate our
  -- storage with dehydrated's local copies.
  if not fullchain_pem or not privkey_pem then
    ngx.log(ngx.WARN, "auto-ssl: dehydrated succeeded, but certs still missing from storage - trying to manually copy - domain: " .. domain)
    if d then
      for _, i in pairs(d) do
        command = env_vars .. " " ..
          package_root .. "/auto-ssl/shell/letsencrypt_hooks " ..
          "deploy_cert " ..
          i .. " " ..
          base_dir .. "/letsencrypt/certs/" .. i .. "/privkey.pem " ..
          base_dir .. "/letsencrypt/certs/" .. i .. "/cert.pem " ..
          base_dir .. "/letsencrypt/certs/" .. i .. "/fullchain.pem " ..
          base_dir .. "/letsencrypt/certs/" .. i .. "/chain.pem " ..
          math.floor(ngx.now())
        status, out, err = shell_execute(command)
        if status ~= 0 then
          ngx.log(ngx.ERR, "auto-ssl: dehydrated manual hook.sh failed: ", command, " status: ", status, " out: ", out, " err: ", err)
          return nil, nil, "dehydrated failure"
        end
      end
    else
      command = env_vars .. " " ..
        package_root .. "/auto-ssl/shell/letsencrypt_hooks " ..
        "deploy_cert " ..
        z .. " " ..
        base_dir .. "/letsencrypt/certs/" .. z .. "/privkey.pem " ..
        base_dir .. "/letsencrypt/certs/" .. z .. "/cert.pem " ..
        base_dir .. "/letsencrypt/certs/" .. z .. "/fullchain.pem " ..
        base_dir .. "/letsencrypt/certs/" .. z .. "/chain.pem " ..
        math.floor(ngx.now())
      status, out, err = shell_execute(command)
      if status ~= 0 then
        ngx.log(ngx.ERR, "auto-ssl: dehydrated manual hook.sh failed: ", command, " status: ", status, " out: ", out, " err: ", err)
        return nil, nil, "dehydrated failure"
      end
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
