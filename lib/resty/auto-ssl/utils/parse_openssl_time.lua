local floor = math.floor

local months = {
  Jan = 1,
  Feb = 2,
  Mar = 3,
  Apr = 4,
  May = 5,
  Jun = 6,
  Jul = 7,
  Aug = 8,
  Sep = 9,
  Oct = 10,
  Nov = 11,
  Dec = 12,
}

-- Parse the time strings that OpenSSL outputs via ASN1_TIME_print:
-- https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_print.html
--
-- Relevant pieces of specification:
--
-- > It will be of the format MMM DD HH:MM:SS YYYY [GMT], for example "Feb 3
-- > 00:55:52 2015 GMT"
-- > Does not print out the time zone: it either prints out "GMT" or nothing.
-- > But all certificates complying with RFC5280 et al use GMT anyway.
return function(time_str)
  local matches, match_err = ngx.re.match(time_str, [[(?<month>[A-Za-z]{3}) +(?<day>\d{1,2}) +(?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})(?:\.\d+)? +(?<year>-?\d{4})]], "jo")
  if match_err then
    return nil, match_err
  elseif not matches then
    return nil, "could not parse openssl time string: " .. (tostring(time_str) or "")
  end

  local month = months[matches["month"]]
  if not month then
    return nil, "could not parse month in openssl time string: " .. (tostring(time_str) or "")
  end

  local year = tonumber(matches["year"])
  local day = tonumber(matches["day"])
  local hour = tonumber(matches["hour"])
  local minute = tonumber(matches["minute"])
  local second = tonumber(matches["second"])

  -- Convert the parsed time into a unix epoch timestamp. Since the unix
  -- timestamp should always be returned according to UTC, we can't use Lua's
  -- "os.time", since it returns values based on local time
  -- (http://lua-users.org/lists/lua-l/2012-04/msg00557.html), and workarounds
  -- seem tricky (http://lua-users.org/lists/lua-l/2012-04/msg00588.html).
  --
  -- So instead, manually calculate the days since UTC epoch and output based
  -- on this math. The algorithm behind this is based on
  -- http://howardhinnant.github.io/date_algorithms.html#civil_from_days
  if month <= 2 then
    year = year - 1
    month = month + 9
  else
    month = month - 3
  end
  local era = floor(year / 400)
  local yoe = year - era * 400
  local doy = floor((153 * month + 2) / 5) + day - 1
  local doe = (yoe * 365) + floor(yoe / 4) - floor(yoe / 100) + doy
  local days = era * 146097 + doe - 719468

  return (days * 86400) + (hour * 3600) + (minute * 60) + second
end
