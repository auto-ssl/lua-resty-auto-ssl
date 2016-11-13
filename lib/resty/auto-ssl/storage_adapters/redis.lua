local redis = require "resty.redis"

local _M = {}

local function get_redis_instance(self)
  local instance = ngx.ctx.auto_ssl_redis_instance
  if instance then
    return instance
  end

  instance = redis:new()
  local ok, err

  if self.options["socket"] then
    ok, err = instance:connect(self.options["socket"])
  else
    ok, err = instance:connect(self.options["host"], self.options["port"])
  end
  if not ok then
    return false, err
  end

  if self.options["auth"] then
    ok, err = instance:auth(self.options["auth"])
    if not ok then
      return false, err
    end
  end

  ngx.ctx.auto_ssl_redis_instance = instance
  return instance
end

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

function _M.setup()
end

function _M.get(self, key)
  local redis_instance, instance_err = get_redis_instance(self)
  if instance_err then
    return nil, instance_err
  end

  local res, err = redis_instance:get(prefixed_key(self, key))
  if res == ngx.null then
    res = nil
    err = "not found"
  end

  return res, err
end

function _M.set(self, key, value, options)
  local redis_instance, instance_err = get_redis_instance(self)
  if instance_err then
    return false, instance_err
  end

  key = prefixed_key(self, key)
  local ok, err = redis_instance:set(key, value)
  if ok then
    if options and options["exptime"] then
      local _, expire_err = redis_instance:expire(key, options["exptime"])
      if expire_err then
        ngx.log(ngx.ERR, "auto-ssl: failed to set expire: ", expire_err)
      end
    end
  end

  return ok, err
end

function _M.delete(self, key)
  local redis_instance, instance_err = get_redis_instance(self)
  if instance_err then
    return false, instance_err
  end

  return redis_instance:del(prefixed_key(self, key))
end

function _M.keys_with_suffix(self, suffix)
  local redis_instance, instance_err = get_redis_instance(self)
  if instance_err then
    return false, instance_err
  end

  local keys, err = redis_instance:keys(prefixed_key(self, "*" .. suffix))

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
