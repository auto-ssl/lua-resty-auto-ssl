local _M = {}

local shell_execute = require "resty.auto-ssl.utils.shell_execute"

function _M.issue_cert(auto_ssl_instance, domain)
  local package_root = auto_ssl_instance.package_root
  local base_dir = auto_ssl_instance:get("dir")

  -- Run letsencrypt.sh for this domain, using our custom hooks to handle the
  -- domain validation and the issued certificates.
  local command = "env HOOK_SECRET=" .. ngx.shared.auto_ssl:get("hook_server:secret") .. " " ..
    package_root .. "/auto-ssl/vendor/letsencrypt.sh " ..
    "--cron " ..
    "--domain " .. domain .. " " ..
    "--challenge http-01 " ..
    "--config " .. base_dir .. "/letsencrypt/config.sh " ..
    "--hook " .. package_root .. "/auto-ssl/shell/letsencrypt_hooks"
  local status, out, err = shell_execute(command)
  if status ~= 0 then
    ngx.log(ngx.ERR, "auto-ssl: letsencrypt.sh failed: ", command, " status: ", status, " out: ", out, " err: ", err)
    return nil, nil, "letsencrypt.sh failure"
  end

  ngx.log(ngx.DEBUG, "auto-ssl: letsencrypt.sh output: " .. out)

  -- The result of running that command should result in the certs being
  -- populated in our storage (due to the deploy_cert hook triggering).
  local storage = auto_ssl_instance:get("storage")
  local fullchain_pem, privkey_pem = storage:get_cert(domain)

  -- If letsencrypt.sh said it succeeded, but we still don't have any certs in
  -- storage, the issue is likely that the certs have been deleted out of our
  -- storage, but still exist in letsencrypt.sh's certs directory. If this
  -- occurs, try to manually fire the deploy_cert hook again to populate our
  -- storage with letsencrypt.sh's local copies.
  if not fullchain_pem or not privkey_pem then
    ngx.log(ngx.WARN, "auto-ssl: letsencrypt.sh succeeded, but certs still missing from storage - trying to manually copy - domain: " .. domain)

    command = "env HOOK_SECRET=" .. ngx.shared.auto_ssl:get("hook_server:secret") .. " " ..
      package_root .. "/auto-ssl/shell/letsencrypt_hooks " ..
      "deploy_cert " ..
      domain .. " " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/privkey.pem " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/cert.pem " ..
      base_dir .. "/letsencrypt/certs/" .. domain .. "/fullchain.pem"
    status, out, err = shell_execute(command)
    if status ~= 0 then
      ngx.log(ngx.ERR, "auto-ssl: letsencrypt.sh manual hook.sh failed: ", command, " status: ", status, " out: ", out, " err: ", err)
      return nil, nil, "letsencrypt.sh failure"
    end

    -- Try fetching again.
    fullchain_pem, privkey_pem = storage:get_cert(domain)
  end

  -- Return error if things are still unexpectedly missing.
  if not fullchain_pem or not privkey_pem then
    return nil, nil, "letsencrypt.sh succeeded, but no certs present"
  end

  return fullchain_pem, privkey_pem
end

return _M
