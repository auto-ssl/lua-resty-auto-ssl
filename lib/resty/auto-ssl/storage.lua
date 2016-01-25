local _M = {}

local cjson = require "cjson"
local adapter = require "resty.auto-ssl.storage_adapters.file"

function _M.get_challenge(domain, path)
  return adapter.get(domain .. ":challenge:" .. path)
end

function _M.set_challenge(domain, path, value)
  return adapter.set(domain .. ":challenge:" .. path, value)
end

function _M.delete_challenge(domain, path)
  return adapter.delete(domain .. ":challenge:" .. path)
end

function _M.get_cert(domain)
  local json, err = adapter.get(domain .. ":latest")
  if err then
    return nil, nil, err
  end

  local data = cjson.decode(json)
  return data["fullchain_pem"], data["privkey_pem"]
end

function _M.set_cert(domain, fullchain_pem, privkey_pem)
  -- Store the public certificate and private key as a single JSON string.
  --
  -- We use a single JSON string so that the storage adapter just has to store
  -- a single string (regardless of implementation), and we don't have to worry
  -- about race conditions with the public cert and private key being stored
  -- separately and getting out of sync.
  local data = cjson.encode({
    fullchain_pem = fullchain_pem,
    privkey_pem = privkey_pem,
  })

  -- Store the cert with the current timestamp, so the old certs are preserved
  -- in case something goes wrong.
  local time = ngx.now() * 1000
  adapter.set(domain .. ":" .. time, data)

  -- Store the cert under the "latest" alias, which is what this app will use.
  adapter.set(domain .. ":latest", data)
end

return _M
