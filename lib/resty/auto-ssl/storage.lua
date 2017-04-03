local resty_random = require "resty.random"
local str = require "resty.string"

local _M = {}

local cjson = require "cjson"

function _M.new(adapter)
  return setmetatable({ adapter = adapter }, { __index = _M })
end

function _M.get_domains(self, domain)
    function tablelength(a)
      local count = 0
      for _ in pairs(a) do count = count + 1 end
      return count
    end

    function subdomain(a)
      local x = {}
      for word in string.gmatch(a, '([^.]+)') do
          table.insert(x, word)
      end
      return x
    end

    local ar = subdomain(domain)
    local size = tablelength(ar)
    local main_domain = ar[size-1] .. "." .. ar[size]
    if size>2 then
       return main_domain, domain
    else
       return main_domain, nil
    end
end

function _M.get_subdomains(self, domain)
    function tablelength(a)
      local count = 0
      for _ in pairs(a) do count = count + 1 end
      return count
    end

    function subdomains(a)
      local x = {}
      for word in string.gmatch(a, '([^:]+)') do
          table.insert(x, word)
      end
      return x
    end
    local json, err = self.adapter:get(domain .. "main")
    if err then
       return nil, nil, err
    elseif not json then
       return nil
    end
    local data = cjson.decode(json)
    local ar = subdomains(data['subdomain'])
    local size = tablelength(ar)
    return ar, size
end

function _M.set_subdomains(self, domain, subdomain)
    local x, n, err = self.get_subdomains(self, domain)
    if err then
       local data = cjson.encode({domain=domain,
       subdomain=subdomain})
       self.adapter:set(domain .. "main", data)
    else
       for _, i in pairs(x) do 
          if i == subdomain then
              return true
          end
       end
       local sub = table.concat(x, ":")
       if nil == string.find(sub, subdomain) then
          local sub = sub .. ":" .. subdomain
          local data = cjson.encode({domain=domain,
          subdomain=sub})
          self.adapter:set(domain .. "main", data)
       end
    end
end

function _M.check_subdomain(self, domain, subdomain)
  local x, n, err = self.get_subdomains(self, domain)
  if x then
    for _, i in pairs(x) do
      if i == subdomain then
        return domain
      end
    end
  end
  return nil
end

function _M.get_challenge(self, domain, path)
  return self.adapter:get(domain .. ":challenge:" .. path)
end

function _M.set_challenge(self, domain, path, value)
  return self.adapter:set(domain .. ":challenge:" .. path, value)
end

function _M.delete_challenge(self, domain, path)
  return self.adapter:delete(domain .. ":challenge:" .. path)
end

function _M.get_cert(self, domain)
  local d, z = self.get_domains(self, domain)
  local c = self.check_subdomain(self, d, z)
  if not c then
    return nil
  end
  local json, err = self.adapter:get(d .. ":latest")
  if err then
    return nil, nil, err
  elseif not json then
    return nil
  end

  local data = cjson.decode(json)
  return data["fullchain_pem"], data["privkey_pem"], data["cert_pem"]
end

function _M.set_cert(self, domain, fullchain_pem, privkey_pem, cert_pem)
  -- Store the public certificate and private key as a single JSON string.
  --
  -- We use a single JSON string so that the storage adapter just has to store
  -- a single string (regardless of implementation), and we don't have to worry
  -- about race conditions with the public cert and private key being stored
  -- separately and getting out of sync.
  local d, z = self.get_domains(self, domain)
  local data = cjson.encode({
    fullchain_pem = fullchain_pem,
    privkey_pem = privkey_pem,
    cert_pem = cert_pem,
  })

  -- Store the cert with the current timestamp, so the old certs are preserved
  -- in case something goes wrong.
  local time = ngx.now() * 1000
  self.adapter:set(d .. ":" .. time, data)

  -- Store the cert under the "latest" alias, which is what this app will use.
  return self.adapter:set(d .. ":latest", data)
end

function _M.all_cert_domains(self)
  local keys, err = self.adapter:keys_with_suffix(":latest")
  if err then
    return nil, err
  end

  local domains = {}
  for _, key in ipairs(keys) do
    local domain = ngx.re.sub(key, ":latest$", "", "jo")
    table.insert(domains, domain)
  end

  return domains
end

-- A simplistic locking mechanism to try and ensure the app doesn't try to
-- register multiple certificates for the same domain simultaneously.
--
-- This is used in conjunction with resty-lock for local in-memory locking in
-- resty/auto-ssl/ssl_certificate.lua. However, this lock uses the configured
-- storage adapter, so it can work across multiple nginx servers if the storage
-- adapter is something like redis.
--
-- This locking algorithm isn't perfect and probably has some race conditions,
-- but in combination with resty-lock, it should prevent the vast majority of
-- double requests.
function _M.issue_cert_lock(self, domain)
  local d, z = self.get_domains(self, domain)
  local key = d .. ":issue_cert_lock"
  local lock_rand_value = str.to_hex(resty_random.bytes(32))

  -- Wait up to 30 seconds for any existing locks to be unlocked.
  local unlocked = false
  local wait_time = 0
  local sleep_time = 0.5
  local max_time = 30
  repeat
    local existing_value = self.adapter:get(key)
    if not existing_value then
      unlocked = true
    else
      ngx.sleep(sleep_time)
      wait_time = wait_time + sleep_time
    end
  until unlocked or wait_time > max_time

  -- Create a new lock.
  local ok, err = self.adapter:set(key, lock_rand_value, { exptime = 30 })
  if not ok then
    return nil, err
  else
    return lock_rand_value
  end
end

function _M.issue_cert_unlock(self, domain, lock_rand_value)
  local d, z = self.get_domains(self, domain)
  local key = d .. ":issue_cert_lock"

  -- Remove the existing lock if it matches the expected value.
  local current_value, err = self.adapter:get(key)
  if lock_rand_value == current_value then
    return self.adapter:delete(key)
  elseif current_value then
    return false, "lock does not match expected value"
  else
    return false, err
  end
end

return _M
