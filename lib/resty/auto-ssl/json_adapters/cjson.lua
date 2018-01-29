local cjson = require "cjson.safe"

local _M = {}

function _M.new()
  return setmetatable({}, { __index = _M })
end

function _M.encode(_, data)
  return cjson.encode(data)
end

function _M.decode(_, string)
  return cjson.decode(string)
end

return _M
