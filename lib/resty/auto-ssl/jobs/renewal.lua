local lock = require "resty.lock"
local parse_openssl_time = require "resty.auto-ssl.utils.parse_openssl_time"
local shell_blocking = require "shell-games"
local shuffle_table = require "resty.auto-ssl.utils.shuffle_table"
local ssl_provider = require "resty.auto-ssl.ssl_providers.lets_encrypt"

local _M = {}

-- Based on lua-rest-upstream-healthcheck's lock:
-- https://github.com/openresty/lua-resty-upstream-healthcheck/blob/v0.03/lib/resty/upstream/healthcheck.lua#L423-L440
--
-- This differs from resty-lock by ensuring that the task only gets executed
-- once per interval across all workers. resty-lock helps ensure multiple
-- concurrent tasks don't run (in case the task takes long than interval).
local function get_interval_lock(name, interval)
  local key = "lock:" .. name

  -- the lock is held for the whole interval to prevent multiple
  -- worker processes from sending the test request simultaneously.
  -- here we substract the lock expiration time by 1ms to prevent
  -- a race condition with the next timer event.
  local ok, err = ngx.shared.auto_ssl:add(key, true, interval - 0.001)
  if not ok then
    if err == "exists" then
      return nil
    end
    ngx.log(ngx.ERR, "failed to add key \"", key, "\": ", err)
    return nil
  end
  return true
end

local function renew_check_cert_unlock(domain, storage, local_lock, distributed_lock_value)
  if local_lock then
    local _, local_unlock_err = local_lock:unlock()
    if local_unlock_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", local_unlock_err)
    end
  end

  if distributed_lock_value then
    local _, distributed_unlock_err = storage:issue_cert_unlock(domain, distributed_lock_value)
    if distributed_unlock_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", distributed_unlock_err)
    end
  end
end

local function renew_check_cert(auto_ssl_instance, storage, domain)
  -- Before issuing a cert, create a local lock to ensure multiple workers
  -- don't simultaneously try to register the same cert.
  local local_lock, new_local_lock_err = lock:new("auto_ssl", { exptime = 30, timeout = 30 })
  if new_local_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create lock: ", new_local_lock_err)
    return
  end
  local _, local_lock_err = local_lock:lock("issue_cert:" .. domain)
  if local_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to obtain lock: ", local_lock_err)
    return
  end

  -- Also add a lock to the configured storage adapter, which allows for a
  -- distributed lock across multiple servers (depending on the storage
  -- adapter).
  local distributed_lock_value, distributed_lock_err = storage:issue_cert_lock(domain)
  if distributed_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to obtain lock: ", distributed_lock_err)
    renew_check_cert_unlock(domain, storage, local_lock, nil)
    return
  end

  ngx.log(ngx.NOTICE, "auto-ssl: checking certificate renewals for ", domain)

  -- Fetch the current certificate.
  local cert, get_cert_err = storage:get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: renewal error fetching certificate from storage for ", domain, ": ", get_cert_err)
  end
  if not cert then
    cert = {}
  end

  if not cert["fullchain_pem"] then
    ngx.log(ngx.ERR, "auto-ssl: attempting to renew certificate for domain without certificates in storage: ", domain)
    renew_check_cert_unlock(domain, storage, local_lock, distributed_lock_value)
    return
  end

  -- While newer certs should have the expire date stored already, if an older
  -- cert doesn't have an expiry date stored yet, extract it and save it.
  if not cert["expiry"] then
    local cert_pem_path = auto_ssl_instance:get("dir") .. "/tmp/extract-expiry-" .. ngx.escape_uri(domain)
    local file, file_err = io.open(cert_pem_path, "w")
    if file_err then
      ngx.log(ngx.ERR, "auto-ssl: write expiry cert file for " .. domain .. " failed: ", file_err)
    else
      file:write(cert["fullchain_pem"])
      file:close()

      local date_result, date_err = shell_blocking.capture_combined({ "openssl", "x509", "-enddate", "-noout", "-in", cert_pem_path })
      if date_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to extract expiry date from cert: ", date_err)
      else
        local expiry, parse_err = parse_openssl_time(date_result["output"])
        if parse_err then
          ngx.log(ngx.ERR, "auto-ssl: failed to parse expiry date: ", parse_err)
        else
          cert["expiry"] = expiry

          -- Update stored certificate to include expiry information
          ngx.log(ngx.NOTICE, "auto-ssl: setting expiration date of ",  domain, " to ", cert["expiry"])
          local _, set_cert_err = storage:set_cert(domain, cert["fullchain_pem"], cert["privkey_pem"], cert["cert_pem"], cert["expiry"])
          if set_cert_err then
            ngx.log(ngx.ERR, "auto-ssl: failed to update cert: ", set_cert_err)
          end
        end
      end

      local _, remove_err = os.remove(cert_pem_path)
      if remove_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to remove expiry cert file: ", remove_err)
      end
    end
  end

  -- If expiry date is known, attempt renewal if it's within 30 days.
  if cert["expiry"] then
    local now = ngx.now()
    if now + (30 * 24 * 60 * 60) < cert["expiry"] then
      ngx.log(ngx.NOTICE, "auto-ssl: expiry date is more than 30 days out, skipping renewal: ", domain)
      renew_check_cert_unlock(domain, storage, local_lock, distributed_lock_value)
      return
    end
  end

  -- Check if domain is still allowed before renewing.
  local allow_domain = auto_ssl_instance:get("allow_domain")
  if not allow_domain(domain, auto_ssl_instance, nil, true) then
    ngx.log(ngx.NOTICE, "auto-ssl: domain not allowed, not renewing: ", domain)
    return
  end

  -- We didn't previously store the cert.pem (since it can be derived from the
  -- fullchain.pem). So for backwards compatibility, set the cert.pem value to
  -- the fullchain.pem value, since that should work for our date checking
  -- purposes.
  if not cert["cert_pem"] then
    cert["cert_pem"] = cert["fullchain_pem"]
  end

  -- Write out the cert.pem value to the location dehydrated expects it for
  -- checking.
  local dir = auto_ssl_instance:get("dir") .. "/letsencrypt/certs/" .. domain
  local _, mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", dir }, { umask = "0022" })
  if mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/certs dir: ", mkdir_err)
    renew_check_cert_unlock(domain, storage, local_lock, distributed_lock_value)
    return false, mkdir_err
  end
  local cert_pem_path = dir .. "/cert.pem"
  local file, err = io.open(cert_pem_path, "w")
  if err then
    ngx.log(ngx.ERR, "auto-ssl: write cert.pem for " .. domain .. " failed: ", err)
    renew_check_cert_unlock(domain, storage, local_lock, distributed_lock_value)
    return false, err
  end
  file:write(cert["cert_pem"])
  file:close()

  -- Trigger a normal certificate issuance attempt, which dehydrated will
  -- skip if the certificate already exists or renew if it's within the
  -- configured time for renewals.
  local _, issue_err = ssl_provider.issue_cert(auto_ssl_instance, domain)
  if issue_err then
    ngx.log(ngx.ERR, "auto-ssl: issuing renewal certificate failed: ", issue_err)

    -- Give up on renewing this certificate if we didn't manage to renew
    -- it before the expiration date
    if cert["expiry"] and cert["expiry"] < ngx.now() then
      ngx.log(ngx.WARN, "auto-ssl: existing certificate is expired, deleting: ", domain)
      storage:delete_cert(domain)
    end
  end

  renew_check_cert_unlock(domain, storage, local_lock, distributed_lock_value)
end

local function renew_all_domains(auto_ssl_instance)
  -- Loop through all known domains and check to see if they should be renewed.
  local storage = auto_ssl_instance.storage
  local domains, domains_err = storage:all_cert_domains()
  if domains_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to fetch all certificate domains: ", domains_err)
  else
    -- Randomize the renewal order so that if nginx is reloaded during renewals
    -- or rate limits are hit, the renewals are attempted in a different order
    -- each time (which may allow things to eventually succeed over multiple
    -- renewal attempts).
    shuffle_table(domains)

    for _, domain in ipairs(domains) do
      renew_check_cert(auto_ssl_instance, storage, domain)
    end
  end
end

local function do_renew(auto_ssl_instance)
  -- Ensure only 1 worker executes the renewal once per interval.
  if not get_interval_lock("renew", auto_ssl_instance:get("renew_check_interval")) then
    return
  end
  local renew_lock, new_renew_lock_err = lock:new("auto_ssl_settings", { exptime = 1800, timeout = 0 })
  if new_renew_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create lock: ", new_renew_lock_err)
    return
  end
  local _, lock_err = renew_lock:lock("renew")
  if lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to optain lock: ", lock_err)
    return
  end

  local renew_ok, renew_err = pcall(renew_all_domains, auto_ssl_instance)
  if not renew_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run do_renew cycle: ", renew_err)
  end

  local ok, unlock_err = renew_lock:unlock()
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", unlock_err)
  end
end

-- Call the renew function in an infinite loop (by default once per day).
local function renew(premature, auto_ssl_instance)
  if premature then return end

  local renew_ok, renew_err = pcall(do_renew, auto_ssl_instance)
  if not renew_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run do_renew cycle: ", renew_err)
  end

  local timer_ok, timer_err = ngx.timer.at(auto_ssl_instance:get("renew_check_interval"), renew, auto_ssl_instance)
  if not timer_ok then
    if timer_err ~= "process exiting" then
      ngx.log(ngx.ERR, "auto-ssl: failed to create timer: ", timer_err)
    end
    return
  end
end

function _M.spawn(auto_ssl_instance)
  local ok, err = ngx.timer.at(auto_ssl_instance:get("renew_check_interval"), renew, auto_ssl_instance)
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to create timer: ", err)
    return
  end
end

return _M
