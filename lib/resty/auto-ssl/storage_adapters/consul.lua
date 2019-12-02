---
-- Requisites:
--   opm get hamishforbes/lua-resty-consul

local consul = require('resty.consul')

--------------------------------------------------------------------------------
-- @todo remove this entire section after finish the heavy debugging
--       of the consul adapter (fititnt, 2019-11-28 20:21 BRT)

local dumpcache = {}

---
-- @author https://pastebin.com/A7JScXWk
-- @param data Anything that need to be dumped
-- @return string
local function dumpvar(data)
  -- cache of tables already printed, to avoid infinite recursive loops
  local tablecache = {}
  local buffer = ""
  local padder = "    "

  local function _dumpvar(d, depth)
      local t = type(d)
      local str = tostring(d)
      if (t == "table") then
          if (tablecache[str]) then
              -- table already dumped before, so we dont
              -- dump it again, just mention it
              buffer = buffer.."<"..str..">\n"
          else
              tablecache[str] = (tablecache[str] or 0) + 1
              buffer = buffer.."("..str..") {\n"
              for k, v in pairs(d) do
                  buffer = buffer..string.rep(padder, depth+1).."["..k.."] => "
                  _dumpvar(v, depth+1)
              end
              buffer = buffer..string.rep(padder, depth).."}\n"
          end
      elseif (t == "number") then
          buffer = buffer.."("..t..") "..str.."\n"
      else
          buffer = buffer.."("..t..") \""..str.."\"\n"
      end
  end
  _dumpvar(data, 0)
  return buffer
end

---
-- @author fititnt
local function dump(value, cache_uid)
  --- print(DataDumper(...), "\n---")
  -- ngx.log(ngx.ERR, DataDumper(value, varname, false, 2))
  if (cache_uid) then
    -- ngx.log(ngx.ERR, 'debug dump function', cache_uid .. os.date("%Y%m%d%H%M"))
    if (not dumpcache[cache_uid .. os.date("%Y%m%d%H%M")]) then
      dumpcache[cache_uid .. os.date("%Y%m%d%H%M")] = 1
      ngx.log(ngx.ERR, dumpvar(value))
    end
  else
    ngx.log(ngx.ERR, dumpvar(value))
  end
end

ngx.log(ngx.ERR, "\n\n\n\n\n\n\n\n\n\n---")
dump({'started', os.date("!%Y-%m-%dT%TZ")})
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

-- @module storage_adapter_consul
local _M = {}

--- Local helper function to, if options have prefix, return a prefixed key name
-- @param  self
-- @param  key The umprefixed key name
-- @return The key prefixed
local function prefixed_key(self, key)
  if self.options["prefix"] then
    -- return self.options["prefix"] .. ":" .. key
    return self.options["prefix"] .. "/" .. key
  else
    return key
  end
end

-- @TODO: Discover what to type is the return of _M.new (fititnt, 2019-11-27 22:51 BRT)

--- Returns a stored Key Value from the Consul
-- @param   auto_ssl_instance
-- @return  ????
function _M.new(auto_ssl_instance)
  local options = auto_ssl_instance:get("consul") or {}

  if not options["prefix"] then
    options["prefix"] = "lua-resty-auto-ssl"
  end

  if not options["host"] then
    options["host"] = "127.0.0.1"
  end

  if not options["port"] then
    options["port"] = 8500
  end

  if not options["connect_timeout"] then
    options["connect_timeout"] = '60s'
  end

  if not options["read_timeout"] then
    options["read_timeout"] = '60s'
  end

  if not options["ssl"] then
    options["ssl"] = false
  end

  if not options["ssl_verify"] then
    options["ssl_verify"] = true
  end

  dump({fn = '_M.new', options = options}, '_M.new')

  return setmetatable({ options = options }, { __index = _M })
end

--- Get the Consul connection, creates one if already does not exist
-- @param   self
-- @return  connection
function _M.get_connection(self)
  local connection = ngx.ctx.auto_ssl_consul_connection
  if connection then
    return connection
  end

  connection = consul:new(self.options)

  dump({fn = '_M.get_connection', connection = connection}, '_M.get_connection')

  ngx.ctx.auto_ssl_consul_connection = connection
  return connection
end

-- Note: _M.setup() on redis.lua is empty, no arguments, no return value
function _M.setup()
end

--- Returns a stored Key Value from the Consul
-- @param  self
-- @param  key   The umprefixed key name
-- @return The value of saved key (if exists)
function _M.get(self, key)
  local connection, connection_err = self:get_connection()
  local value = nil
  if connection_err then
    return nil, connection_err
  end

  -- Redis use get, Consul use get_key
  -- Redis 'res' is value or nil; Consul is a lua-resty-http response object
  local res, err = connection:get_key(prefixed_key(self, key))

  if res.status ~= 404 and res.body[1] ~= nil and res.body[1]['Value'] ~= nil then
    value = res.body[1]['Value']
  else
    dump({fn = '_M.get fail', res})
  end

  dump({fn = '_M.get', key=key, res=res, err=err, value=value}, '_M.get')

  return value, err
end

--- Store a key-value on the Consul
-- @param  self
-- @param  key      The umprefixed key name
-- @param  value    The values
-- @param  options  The values
-- @return ok       Boolean if result was ok or not
-- @return res  lua-resty-http response object. On error returns nil
-- @return err  On error returns an error message
function _M.set(self, key, value, options)
  local connection, connection_err = self:get_connection()
  local ok = false

  if connection_err then
    return false, connection_err
  end

  key = prefixed_key(self, key)

  local res, err = connection:put_key(key, value)

  if res.status == 200 then
    ok = true

    -- This expire strategy is based on file.lua and not on redis.lua and
    -- at the moment is not using Consul native way to expire keys. Since the
    -- version resty.consul v0.3.2 does not implement Expire, even if is
    -- possible to do with more RAW HTTP methods, we initialy will the ngx.timer
    -- Not ideal, but it works for and functional MVP (fititnt, 2019-11-30 22:14 BRT)
    if options and options["exptime"] then
      ngx.timer.at(options["exptime"], function()
        local _, delete_err = _M.delete(self, key)
        if delete_err then
          ngx.log(ngx.ERR, "auto-ss.lstorage_adapter.consul._M.delete: failed to remove the key from Consul after the expiretime ", delete_err)
        else
          dump({fn = '_M.set', _=_, delete_err=delete_err, 'ngx.timer worked!'})
        end
      end)
    end
  end

  dump({fn = '_M.set', ok=ok, key=key, value=value, options=options, res=res, err=err}, '_M.set')
  return ok, err
end

--- Delete a value from Consul based on the unprefixed key
-- @param  self
-- @param  key  The umprefixed key name
-- @return res  lua-resty-http response object. On error returns nil
-- @return err  On error returns an error message
function _M.delete(self, key)
  local connection, connection_err = self:get_connection()
  if connection_err then
    -- ngx.log(ngx.EMERG, '_M.delete: ', connection_err)
    ngx.log(ngx.EMERG, 'storage_adapter.consul._M.delete: connection error:', connection_err)
    return false, connection_err
  end

  -- local cjson = require "cjson"
  -- ngx.log(ngx.ERR, '_M.delete: ', connection_err)
  -- ngx.log(ngx.ERR, cjson.encode(connection_err))

  -- Redis use del, Consul uses delete_key
  return connection:delete_key(prefixed_key(self, key))
end

-- TODO: finish _M.keys_with_suffix (fititnt, 2019-27-23:01 BRT)
--- Returns a stored Key Value from the Consul
-- @param  self
-- @param  suffix   The umprefixed key name
-- @return keys     The keys
-- @return err  On error returns an error message
function _M.keys_with_suffix(self, suffix)
  local connection, connection_err = self:get_connection()
  if connection_err then
    ngx.log(ngx.EMERG, '_M.keys_with_suffix: ', connection_err)
    return false, connection_err
  end

  local keys, err = connection:list_keys(prefixed_key(self, "*" .. suffix))

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

  dump({fn = '_M.keys_with_suffix', keys = keys, err = err}, '_M.keys_with_suffix')

  return keys, err
end


return _M
