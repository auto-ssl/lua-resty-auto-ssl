local http = require "resty.http"
local cjson = require "cjson"

-- Verify the domain name and return its result.
return function(auto_ssl_instance, domain)
  local httpc = http.new()
  local url = auto_ssl_instance:get("verification_url")

  if not url then
    return true, nil
  end

  url = url .. "d=" .. domain
  httpc:set_timeout(10000)
  local res, req_err = httpc:request_uri(url, {
    method = "GET"
  })

  if not res then
    return false, "Verification failed (" .. (url or "") .. "): " .. (req_err or "")
  end

  if res.status ~= 200 then
    return false, "Verification returns bad HTTP status code (" .. (url or "") .. "): " .. (res.status or "")
  end

  local resp = res.body
  if not resp or resp == "" then
    return false, "Verification returns bad response body (" .. (url or "") .. "): " .. (resp or "")
  end

  local data = cjson.decode(resp)
  if not data["valid"] then
    return false, "Invalid domain: " .. domain
  end
  return true, nil
end
