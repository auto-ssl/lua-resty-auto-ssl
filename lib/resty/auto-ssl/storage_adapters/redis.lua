local redis = require "resty.redis"

local _M = {}

local function prefixed_key(self, key)
  if self.options["prefix"] then
    return self.options["prefix"] .. ":" .. key
  else
    return key
  end
end

function _M.new(auto_ssl_instance)
  local options = auto_ssl_instance:get("redis") or {}

  if not options["host"] then
    options["host"] = "127.0.0.1"
  end

  if not options["port"] then
    options["port"] = 6379
  end

  return setmetatable({ options = options }, { __index = _M })
end

function _M.get_connection(self)
  local connection = ngx.ctx.auto_ssl_redis_connection
  if connection then
    return connection
  end

  connection = redis:new()
  local ok, err

  if self.options["socket"] then
    ok, err = connection:connect(self.options["socket"])
  else
    ok, err = connection:connect(self.options["host"], self.options["port"])
  end
  if not ok then
    return false, err
  end

  if self.options["auth"] then
    ok, err = connection:auth(self.options["auth"])
    if not ok then
      return false, err
    end
  end

  if self.options["db"] then
    ok, err = connection:select(self.options["db"])
    if not ok then
      return false, err
    end
  end

  ngx.ctx.auto_ssl_redis_connection = connection
  return connection
end

function _M.setup()
end

function _M.get(self, key)
  local connection, connection_err = self:get_connection()
  if connection_err then
    return nil, connection_err
  end

  local res, err = connection:get(prefixed_key(self, key))
  if res == ngx.null then
    res = nil
  end

  return res, err
end

function _M.set(self, key, value, options)
  local connection, connection_err = self:get_connection()
  if connection_err then
    return false, connection_err
  end

  key = prefixed_key(self, key)
  local ok, err = connection:set(key, value)
  if ok then
    if options and options["exptime"] then
      local _, expire_err = connection:expire(key, options["exptime"])
      if expire_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to set expire: ", expire_err)
      end
    end
  end

  return ok, err
end

function _M.delete(self, key)
  local connection, connection_err = self:get_connection()
  if connection_err then
    return false, connection_err
  end

  return connection:del(prefixed_key(self, key))
end

function _M.keys_with_suffix(self, suffix)
  local connection, connection_err = self:get_connection()
  if connection_err then
    return false, connection_err
  end

  local keys, err = connection:keys(prefixed_key(self, "*" .. suffix))

  if keys and self.options["prefix"] then
    local unprefixed_keys = {}
    -- First character past the prefix and a colon
    local offset = string.len(self.options["prefix"]) + 2

    for _, key in ipairs(keys) do
      local unprefixed = string.sub(key, offset)
      table.insert(unprefixed_keys, unprefixed)
    end

    keys = unprefixed_keys
  end

  return keys, err
end

return _M
