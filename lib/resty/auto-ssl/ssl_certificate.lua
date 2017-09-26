local http = require "resty.http"
local lock = require "resty.lock"
local ocsp = require "ngx.ocsp"
local ssl = require "ngx.ssl"
local ssl_provider = require "resty.auto-ssl.ssl_providers.lets_encrypt"

local function convert_to_der_and_cache(domain, fullchain_pem, privkey_pem, newly_issued)
  -- Convert certificate from PEM to DER format.
  local fullchain_der, fullchain_der_err = ssl.cert_pem_to_der(fullchain_pem)
  if not fullchain_der or fullchain_der_err then
    return nil, nil, newly_issued, "failed to convert certificate chain from PEM to DER: " .. (fullchain_der_err or "")
  end

  -- Convert private key from PEM to DER format.
  local privkey_der, privkey_der_err = ssl.priv_key_pem_to_der(privkey_pem)
  if not privkey_der or privkey_der_err then
    return nil, nil, newly_issued, "failed to convert private key from PEM to DER: " .. (privkey_der_err or "")
  end

  -- Cache DER formats in memory for 1 hour (so renewals will get picked up
  -- across multiple servers).
  local _, set_fullchain_err, set_fullchain_forcible = ngx.shared.auto_ssl:set("domain:fullchain_der:" .. domain, fullchain_der, 3600)
  if set_fullchain_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set shdict cache of certificate chain for " .. domain .. ": ", set_fullchain_err)
  elseif set_fullchain_forcible then
    ngx.log(ngx.ERR, "auto-ssl: 'lua_shared_dict auto_ssl' might be too small - consider increasing its configured size (old entries were removed while adding certificate chain for " .. domain .. ")")
  end

  local _, set_privkey_err, set_privkey_forcible = ngx.shared.auto_ssl:set("domain:privkey_der:" .. domain, privkey_der, 3600)
  if set_privkey_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set shdict cache of private key for " .. domain .. ": ", set_privkey_err)
  elseif set_privkey_forcible then
    ngx.log(ngx.ERR, "auto-ssl: 'lua_shared_dict auto_ssl' might be too small - consider increasing its configured size (old entries were removed while adding private key for " .. domain .. ")")
  end

  return fullchain_der, privkey_der, newly_issued
end

local function issue_cert_unlock(domain, storage, local_lock, distributed_lock_value)
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

local function issue_cert(auto_ssl_instance, storage, domain)
  local fullchain_pem, privkey_pem, err

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
    issue_cert_unlock(domain, storage, local_lock, nil)
    return
  end

  -- After obtaining the local and distributed lock, see if the certificate
  -- has already been registered.
  fullchain_pem, privkey_pem = storage:get_cert(domain)
  if fullchain_pem and privkey_pem then
    issue_cert_unlock(domain, storage, local_lock, distributed_lock_value)
    return fullchain_pem, privkey_pem
  end

  ngx.log(ngx.NOTICE, "auto-ssl: issuing new certificate for ", domain)
  fullchain_pem, privkey_pem, err = ssl_provider.issue_cert(auto_ssl_instance, domain)
  if err then
    ngx.log(ngx.ERR, "auto-ssl: issuing new certificate failed: ", err)
  end

  issue_cert_unlock(domain, storage, local_lock, distributed_lock_value)
  return fullchain_pem, privkey_pem, err
end

local function get_cert(auto_ssl_instance, domain, ssl_options)
  -- Look for the certificate in shared memory first.
  local fullchain_der = ngx.shared.auto_ssl:get("domain:fullchain_der:" .. domain)
  local privkey_der = ngx.shared.auto_ssl:get("domain:privkey_der:" .. domain)
  if fullchain_der and privkey_der then
    return fullchain_der, privkey_der, false
  end

  -- Next, look for the certificate in permanent storage (which can be shared
  -- across servers depending on the storage).
  local storage = auto_ssl_instance:get("storage")
  local fullchain_pem, privkey_pem = storage:get_cert(domain)
  if fullchain_pem and privkey_pem then
    return convert_to_der_and_cache(domain, fullchain_pem, privkey_pem, false)
  end

  -- Finally, issue a new certificate if one hasn't been found yet.
  if ssl_options and ssl_options["generate_certs"] ~= false then
    fullchain_pem, privkey_pem = issue_cert(auto_ssl_instance, storage, domain)
    if fullchain_pem and privkey_pem then
      return convert_to_der_and_cache(domain, fullchain_pem, privkey_pem, true)
    end
  end

  -- Return an error if issuing the certificate failed.
  return nil, nil, nil, "failed to get or issue certificate"
end

local function get_ocsp_response(fullchain_der)
  -- Pull the OCSP URL to hit out of the certificate chain.
  local ocsp_url, ocsp_responder_err = ocsp.get_ocsp_responder_from_der_chain(fullchain_der)
  if not ocsp_url then
    return nil, "failed to get OCSP responder: " .. (ocsp_responder_err or "")
  end

  -- Generate the OCSP request body.
  local ocsp_req, ocsp_request_err = ocsp.create_ocsp_request(fullchain_der)
  if not ocsp_req then
    return nil, "failed to create OCSP request: " .. (ocsp_request_err or "")
  end

  -- Make the OCSP request against the OCSP server.
  local httpc = http.new()
  httpc:set_timeout(10000)
  local res, req_err = httpc:request_uri(ocsp_url, {
    method = "POST",
    body = ocsp_req,
    headers = {
      ["Content-Type"] = "application/ocsp-request",
    }
  })

  -- Perform various checks to ensure we have a valid OCSP response.
  if not res then
    return nil, "OCSP responder query failed (" .. (ocsp_url or "") .. "): " .. (req_err or "")
  end

  if res.status ~= 200 then
    return nil, "OCSP responder returns bad HTTP status code (" .. (ocsp_url or "") .. "): " .. (res.status or "")
  end

  local ocsp_resp = res.body
  if not ocsp_resp or ocsp_resp == "" then
    return nil, "OCSP responder returns bad response body (" .. (ocsp_url or "") .. "): " .. (ocsp_resp or "")
  end

  local ok, ocsp_validate_err = ocsp.validate_ocsp_response(ocsp_resp, fullchain_der)
  if not ok then
    return nil, "failed to validate OCSP response (" .. (ocsp_url or "") .. "): " .. (ocsp_validate_err or "")
  end

  return ocsp_resp
end

local function set_ocsp_stapling(domain, fullchain_der, newly_issued)
  -- Fetch the OCSP stapling response from the cache, or make the request to
  -- fetch it.
  local ocsp_resp = ngx.shared.auto_ssl:get("domain:ocsp:" .. domain)
  if not ocsp_resp then
    -- If the certificate was just issued on the current request, wait 1 second
    -- before making the initial OCSP request. Otherwise Let's Encrypt seems to
    -- return an Unauthorized response.
    if newly_issued then
      ngx.sleep(1)
    end

    local ocsp_response_err
    ocsp_resp, ocsp_response_err = get_ocsp_response(fullchain_der)
    if ocsp_response_err then
      return false, "failed to get ocsp response: " .. (ocsp_response_err or "")
    end

    -- Cache the OCSP stapling response for 1 hour (this is what nginx does by
    -- default).
    local _, set_ocsp_err, set_ocsp_forcible = ngx.shared.auto_ssl:set("domain:ocsp:" .. domain, ocsp_resp, 3600)
    if set_ocsp_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to set shdict cache of OCSP response for " .. domain .. ": ", set_ocsp_err)
    elseif set_ocsp_forcible then
      ngx.log(ngx.ERR, "auto-ssl: 'lua_shared_dict auto_ssl' might be too small - consider increasing its configured size (old entries were removed while adding OCSP response for " .. domain .. ")")
    end
  end

  -- Set the OCSP stapling response.
  local ok, ocsp_status_err = ocsp.set_ocsp_status_resp(ocsp_resp)
  if not ok then
    return false, "failed to set ocsp status resp: " .. (ocsp_status_err or "")
  end

  return true
end

local function set_cert(auto_ssl_instance, domain, fullchain_der, privkey_der, newly_issued)
  local ok, err

  -- Clear the default fallback certificates (defined in the hard-coded nginx
  -- config).
  ok, err = ssl.clear_certs()
  if not ok then
    return nil, "failed to clear existing (fallback) certificates - " .. (err or "")
  end

  -- Set OCSP stapling.
  ok, err = set_ocsp_stapling(domain, fullchain_der, newly_issued)
  if not ok then
    ngx.log(auto_ssl_instance:get("ocsp_stapling_error_level"), "auto-ssl: failed to set ocsp stapling for ", domain, " - continuing anyway - ", err)
  end

  -- Set the public certificate chain.
  ok, err = ssl.set_der_cert(fullchain_der)
  if not ok then
    return nil, "failed to set certificate - " .. (err or "")
  end

  -- Set the private key.
  ok, err = ssl.set_der_priv_key(privkey_der)
  if not ok then
    return nil, "failed to set private key - " .. (err or "")
  end
end

local function do_ssl(auto_ssl_instance, ssl_options)
  -- Determine the domain making the SSL request with SNI.
  local request_domain = auto_ssl_instance:get("request_domain")
  local domain, domain_err = request_domain(ssl, ssl_options)
  if not domain or domain_err then
    ngx.log(ngx.WARN, "auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - " .. (domain_err or ""))
    return
  end

  -- Check to ensure the domain is one we allow for handling SSL.
  local allow_domain = auto_ssl_instance:get("allow_domain")
  if not allow_domain(domain) then
    ngx.log(ngx.NOTICE, "auto-ssl: domain not allowed - using fallback - ", domain)
    return
  end

  -- Get or issue the certificate for this domain.
  local fullchain_der, privkey_der, newly_issued, get_cert_err = get_cert(auto_ssl_instance, domain, ssl_options)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: could not get certificate for ", domain, " - using fallback - ", get_cert_err)
    return
  elseif not fullchain_der or not privkey_der then
    ngx.log(ngx.ERR, "auto-ssl: certificate data unexpectedly missing for ", domain, " - using fallback")
    return
  end

  -- Set the certificate on the response.
  local _, set_cert_err = set_cert(auto_ssl_instance, domain, fullchain_der, privkey_der, newly_issued)
  if set_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set certificate for ", domain, " - using fallback - ", set_cert_err)
    return
  end
end

return function(auto_ssl_instance, ssl_options)
  local ok, err = pcall(do_ssl, auto_ssl_instance, ssl_options)
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run do_ssl: ", err)
  end
end
