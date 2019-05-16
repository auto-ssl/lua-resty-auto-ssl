local resty_random = require "resty.random"
local str = require "resty.string"
local cjson = require "cjson"

local _M = {}


function _M.new(options)
  assert(options)
  assert(options["adapter"])
  assert(options["json_adapter"])

  return setmetatable(options, { __index = _M })
end

function tablelength(a)
  local count = 0
  for _ in pairs(a) do count = count + 1 end
  return count
end

function _M.get_domains(self, domain, level)
    local function subdomain(a)
      local x = {}
      for word in string.gmatch(a, '([^.]+)') do
          table.insert(x, word)
      end
      return x
    end

    local function get_name(name_list, size, level)
      if level > size then
        return nil
      end
      x = name_list[size]
      for i=1, level-1 do
        x = name_list[size-i] .. "." .. x
      end
      return x
    end

    if type(level) ~= "number" then
      level = 2
    end
    local ar = subdomain(domain)
    local size = tablelength(ar)

    local main_domain = get_name(ar, size, level)
    if main_domain then
      return main_domain, domain
    else
      return domain, nil
    end
end

function _M.get_subdomain(self, domain)
    local function subdomains(a)
      local x = {}
      if a then
        for word in string.gmatch(a, '([^:]+)') do
          table.insert(x, word)
        end
        return x
      end
      return nil
    end

    local function check_max_len(subdomain_list, size)
      local x = ((string.len(table.concat(subdomain_list, ":"))) * size) + (10 * size)
      if x > 1000 then
        return 100
      else
        return size
      end
    end

    local json, err = self.adapter:get(domain .. ":main")
    if err then
       return nil, nil, err
    elseif not json then
       return nil
    end
    local data = cjson.decode(json)
    local ar = subdomains(data['subdomain'])
    local extended = subdomains(data['extended'])
    local size = check_max_len(ar, tablelength(ar))
    return ar, size, nil, extended
end

function _M.set_subdomain(self, domain, subdomain, extended)
    local x, n, err, extended_list = self.get_subdomain(self, domain)

    local function check_extended(extended, extended_list)
      local x = nil
      if extended_list then
        x = table.concat(extended_list, ":") .. ":"
      end
      if extended then
        if x then
          x = x .. extended
        else
          x = extended
        end
      end
      return x
    end

    local function set_subdomains(subdomain, subdomain_list, err, extend)
      local function check_name(subdomain, subdomain_list)
        for _, i in pairs(subdomain_list) do
          if i == subdomain then
            return true
          end
        end
      end

      if err then
        return subdomain
      end

      local x = table.concat(subdomain_list, ":")
      if check_name(subdomain, subdomain_list) then
        return nil, true
      elseif nil == string.find(x, subdomain) and extend then
        return x
      elseif nil == string.find(x, subdomain) then
        x = x .. ":" .. subdomain
        return x
      end
    end

    local extend = check_extended(extended, extended_list)
    local subdomain_list, exists = set_subdomains(subdomain, x, err,  extend)
    if exists then
      return
    end
    if extend then
      data = cjson.encode({domain=domain,
                           subdomain=subdomain_list,
                           extended=extend})
    else
      data = cjson.encode({domain=domain,
                           subdomain=subdomain_list})
    end
    self.adapter:set(domain .. ":main", data)
end

function _M.check_subdomain(self, domain, subdomain)
  local x, n, err, extended = self.get_subdomain(self, domain)

  local function check_main(domain_list, subdomain)
    if domain_list then
      local size = tablelength(domain_list)
      for _, i in pairs(domain_list) do
        if i == subdomain then
          return domain, size
        end
      end
    end
  end

  local function check_extended(self, extended_list, subdomain)
    if extended_list then
      for _, i in pairs(extended_list) do
        domain, size = self.check_subdomain(self, i, subdomain)
        if domain then
          return domain, size
        end
      end
    end
  end

  local domain, size = check_main(x, subdomain)
  if domain then
    return domain, size
  end

  local domain, size = check_extended(self, extended, subdomain)
  if domain then
    return domain, size
  end

  if n and n>99 then
    return nil, n
  end

  return nil, nil
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
  local json, err = self.adapter:get(domain .. ":latest")
  if err then
    return nil, err
  elseif not json then
    return nil
  end

  local data, json_err = self.json_adapter:decode(json)
  if json_err then
    return nil, json_err
  end

  return data
end

function _M.set_cert(self, domain, fullchain_pem, privkey_pem, cert_pem, expiry)
  -- Store the public certificate and private key as a single JSON string.
  --
  -- We use a single JSON string so that the storage adapter just has to store
  -- a single string (regardless of implementation), and we don't have to worry
  -- about race conditions with the public cert and private key being stored
  -- separately and getting out of sync.
  local string, err = self.json_adapter:encode({
    fullchain_pem = fullchain_pem,
    privkey_pem = privkey_pem,
    cert_pem = cert_pem,
    expiry = tonumber(expiry),
  })
  if err then
    return nil, err
  end

  -- Store the cert under the "latest" alias, which is what this app will use.
  return self.adapter:set(domain .. ":latest", string)
end

function _M.delete_cert(self, domain)
  return self.adapter:delete(domain .. ":latest")
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
  local key = domain .. ":issue_cert_lock"
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
  local key = domain .. ":issue_cert_lock"

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