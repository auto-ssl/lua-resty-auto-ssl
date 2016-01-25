local auto_ssl = require "resty.auto-ssl"
local http = require "resty.http"
local ocsp = require "ngx.ocsp"
local ssl = require "ngx.ssl"
local ssl_provider = require "resty.auto-ssl.ssl_providers.lets_encrypt"
local storage = require "resty.auto-ssl.storage"

local function convert_to_der_and_cache(domain, fullchain_pem, privkey_pem)
  -- Convert certificate from PEM to DER format.
  local fullchain_der, fullchain_der_err = ssl.cert_pem_to_der(fullchain_pem)
  if not fullchain_der or fullchain_der_err then
    return nil, nil, "failed to convert certificate chain from PEM to DER: " .. (fullchain_der_err or "")
  end

  -- Convert private key from PEM to DER format.
  local privkey_der, privkey_der_err = ssl.priv_key_pem_to_der(privkey_pem)
  if not privkey_der or privkey_der_err then
    return nil, nil, "failed to convert private key from PEM to DER: " .. (privkey_der_err or "")
  end

  -- Cache DER formats in memory.
  local _, set_fullchain_err = ngx.shared.auto_ssl:set("domain:fullchain_der:" .. domain, fullchain_der)
  if set_fullchain_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set shdict cache of certificate chain for " .. domain, set_fullchain_err)
  end

  local _, set_privkey_err = ngx.shared.auto_ssl:set("domain:privkey_der:" .. domain, privkey_der)
  if set_privkey_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set shdict cache of private key for " .. domain, set_privkey_err)
  end

  return fullchain_der, privkey_der
end

local function get_cert(domain)
  -- Look for the certificate in shared memory first.
  local fullchain_der = ngx.shared.auto_ssl:get("domain:fullchain_der:" .. domain)
  local privkey_der = ngx.shared.auto_ssl:get("domain:privkey_der:" .. domain)
  if fullchain_der and privkey_der then
    return fullchain_der, privkey_der
  end

  -- Next, look for the certificate in permanent storage (which can be shared
  -- across servers depending on the storage).
  local fullchain_pem, privkey_pem = storage.get_cert(domain)
  if fullchain_pem and privkey_pem then
    return convert_to_der_and_cache(domain, fullchain_pem, privkey_pem)
  end

  -- Finally, issue a new certificate if one hasn't been found yet.
  fullchain_pem, privkey_pem = ssl_provider.issue_cert(domain)
  if fullchain_pem and privkey_pem then
    return convert_to_der_and_cache(domain, fullchain_pem, privkey_pem)
  end

  -- Return an error if issuing the certificate failed.
  return nil, nil, "failed to get or issue certificate"
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
    return nil, "OCSP responder query failed: " .. (req_err or "")
  end

  if res.status ~= 200 then
    return nil, "OCSP responder returns bad HTTP status code " .. (res.status or "")
  end

  local ocsp_resp = res.body
  if not ocsp_resp or ocsp_resp == "" then
    return nil, "OCSP responder returns bad response body " .. (ocsp_resp or "")
  end

  local ok, ocsp_validate_err = ocsp.validate_ocsp_response(ocsp_resp, fullchain_der)
  if not ok then
    return nil, "failed to validate OCSP response " .. (ocsp_validate_err or "")
  end

  return ocsp_resp
end

local function set_ocsp_stapling(domain, fullchain_der)
  -- Fetch the OCSP stapling response from the cache, or make the request to
  -- fetch it.
  local ocsp_resp = ngx.shared.auto_ssl:get("domain:ocsp:" .. domain)
  if not ocsp_resp then
    local ocsp_response_err
    ocsp_resp, ocsp_response_err = get_ocsp_response(fullchain_der)
    if ocsp_response_err then
      return false, "failed to get ocsp response: " .. (ocsp_response_err or "")
    end

    -- Cache the OCSP stapling response for 1 hour (this is what nginx does by
    -- default).
    ngx.shared.auto_ssl:set("domain:ocsp:" .. domain, ocsp_resp, 3600)
  end

  -- Set the OCSP stapling response.
  local ok, ocsp_status_err = ocsp.set_ocsp_status_resp(ocsp_resp)
  if not ok then
    return false, "failed to set ocsp status resp: " .. (ocsp_status_err or "")
  end

  return true
end

local function set_cert(domain, fullchain_der, privkey_der)
  local ok, err

  -- Clear the default fallback certificates (defined in the hard-coded nginx
  -- config).
  ok, err = ssl.clear_certs()
  if not ok then
    return nil, "failed to clear existing (fallback) certificates - " .. (err or "")
  end

  -- Set OCSP stapling.
  ok, err = set_ocsp_stapling(domain, fullchain_der)
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to set ocsp stapling for ", domain, " - continuing anyway - ", err)
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

return function()
  -- Determine the domain making the SSL request with SNI.
  local domain, server_name_err = ssl.server_name()
  if server_name_err then
    ngx.log(ngx.ERR, "auto-ssl: could not determine domain with SNI - skipping")
    return
  end

  -- Check to ensure the domain is one we allow for handling SSL.
  if not auto_ssl.allow_domain(domain) then
    ngx.log(ngx.ERR, "auto-ssl: domain not allowed - skipping - ", domain)
    return
  end

  -- Get or issue the certificate for this domain.
  local fullchain_der, privkey_der, get_cert_err = get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: could not get certificate for ", domain, " - skipping - ", get_cert_err)
    return
  end

  -- Set the certificate on the response.
  local _, set_cert_err = set_cert(domain, fullchain_der, privkey_der)
  if set_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set certificate for ", domain, " - skipping - ", set_cert_err)
    return
  end
end
