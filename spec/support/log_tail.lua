local _M = {}

function _M.new(path)
  return setmetatable({ path = path, pos = 0 }, { __index = _M })
end

function _M.read(self)
  local output
  local file = io.open(self.path, "r")
  if file then
    file:seek("set", self.pos)
    output = file:read("*all")
    self.pos = file:seek("cur")
  end

  return output
end

function _M.read_until(self, regex, regex_options, timeout)
  if not regex_options then
    regex_options = "jo"
  end

  if not timeout then
    timeout = 5
  end

  local wait_time = 0
  local sleep_time = 0.5

  local output
  local match_found = false
  repeat
    local output_chunk = self:read()
    if output_chunk then
      output = (output or "") .. output_chunk

      local match, err = ngx.re.match(output_chunk, regex, regex_options)
      assert(not err, err)
      if match then
        match_found = true
      end
    end

    if not match_found then
      ngx.sleep(sleep_time)
      wait_time = wait_time + sleep_time
    end
  until match_found or wait_time > timeout

  return match_found, output
end

return _M
