local dkjson = require "dkjson"

local _M = {}

function _M.new()
  return setmetatable({}, { __index = _M })
end

function _M.encode(_, data)
  return dkjson.encode(data)
end

function _M.decode(_, string)
  local data, _, err = dkjson.decode(string)
  return data, err
end

return _M
