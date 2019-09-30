local parse_openssl_time = require "resty.auto-ssl.utils.parse_openssl_time"
local stdlib = require "posix.stdlib"

describe("parse_openssl_time", function()
  local orig_tz
  before_each(function()
    orig_tz = os.getenv("TZ")
  end)
  after_each(function()
    stdlib.setenv("TZ", orig_tz)
  end)

  it("parses basic openssl time", function()
    local timestamp, err = parse_openssl_time("Jun 22 00:00:00 2036 GMT")
    assert.Nil(err)
    assert.equal(2097705600, timestamp)
  end)

  it("parses single digit days", function()
    local timestamp, err = parse_openssl_time("Mar  7 12:00:00 2020 GMT")
    assert.Nil(err)
    assert.equal(1583582400, timestamp)
  end)

  it("parses prefixed output from openssl", function()
    local timestamp, err = parse_openssl_time("notAfter=Dec 17 17:55:50 2019 GMT")
    assert.Nil(err)
    assert.equal(1576605350, timestamp)
  end)

  it("parses times with milliseconds", function()
    local timestamp, err = parse_openssl_time("Jul 31 22:20:50.123 2017 GMT")
    assert.Nil(err)
    assert.equal(1501539650, timestamp)
  end)

  it("parses times with 1 fractional digit for seconds", function()
    local timestamp, err = parse_openssl_time("Jul 31 22:20:50.1 2017 GMT")
    assert.Nil(err)
    assert.equal(1501539650, timestamp)
  end)

  it("parses times without GMT suffix", function()
    local timestamp, err = parse_openssl_time("Nov 28 20:21:47 2019")
    assert.Nil(err)
    assert.equal(1574972507, timestamp)
  end)

  it("returns error for unknown data", function()
    local timestamp, err = parse_openssl_time("Bad time value")
    assert.Nil(timestamp)
    assert.equal("could not parse openssl time string: Bad time value", err)
  end)

  it("returns error for unknown month", function()
    local timestamp, err = parse_openssl_time("Abc 22 00:00:00 2036 GMT")
    assert.Nil(timestamp)
    assert.equal("could not parse month in openssl time string: Abc 22 00:00:00 2036 GMT", err)
  end)

  it("months are case sensitive", function()
    local timestamp, err = parse_openssl_time("jan 22 00:00:00 2036 GMT")
    assert.Nil(timestamp)
    assert.equal("could not parse month in openssl time string: jan 22 00:00:00 2036 GMT", err)
  end)

  it("ignores the system time zone and always outputs in UTC unix timestamps", function()
    stdlib.setenv("TZ", "Pacific/Honolulu")
    -- Sanity check to ensure "os.time" behavior is picking up the TZ that is
    -- set (which is incorrect for our purposes), and that our values differ.
    local local_time = os.time({
      year = 2036,
      month = 6,
      day = 22,
      hour = 0,
      min = 0,
      sec = 0,
    })
    assert.equal(2097741600, local_time)
    local timestamp, err = parse_openssl_time("Jun 22 00:00:00 2036 GMT")
    assert.Nil(err)
    assert.equal(2097705600, timestamp)
    assert.Not.equal(timestamp, local_time)

    stdlib.setenv("TZ", "Asia/Kolkata")
    local_time = os.time({
      year = 2036,
      month = 6,
      day = 22,
      hour = 0,
      min = 0,
      sec = 0,
    })
    assert.equal(2097685800, local_time)
    timestamp, err = parse_openssl_time("Jun 22 00:00:00 2036 GMT")
    assert.Nil(err)
    assert.equal(2097705600, timestamp)
    assert.Not.equal(timestamp, local_time)
  end)

  -- Based on the eras from
  -- http://howardhinnant.github.io/date_algorithms.html#civil_from_days, along
  -- with other boundaries (epoch, Y2038, etc).
  it("parses various historical, future, and boundary times", function()
    local timestamp, err = parse_openssl_time("Mar 1 00:00:00 -0800 GMT")
    assert.Nil(err)
    assert.equal(-87407596800, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 -0400 GMT")
    assert.Nil(err)
    assert.equal(-74784902400, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 -0400 GMT")
    assert.Nil(err)
    assert.equal(-74784816000, timestamp)

    timestamp, err = parse_openssl_time("Jan 1 00:00:00 0000 GMT")
    assert.Nil(err)
    assert.equal(-62167219200, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 0000 GMT")
    assert.Nil(err)
    assert.equal(-62162121600, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 0000 GMT")
    assert.Nil(err)
    assert.equal(-62162035200, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 0400 GMT")
    assert.Nil(err)
    assert.equal(-49539340800, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 0400 GMT")
    assert.Nil(err)
    assert.equal(-49539254400, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 0800 GMT")
    assert.Nil(err)
    assert.equal(-36916560000, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 0800 GMT")
    assert.Nil(err)
    assert.equal(-36916473600, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 1200 GMT")
    assert.Nil(err)
    assert.equal(-24293779200, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 1200 GMT")
    assert.Nil(err)
    assert.equal(-24293692800, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 1600 GMT")
    assert.Nil(err)
    assert.equal(-11670998400, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 1600 GMT")
    assert.Nil(err)
    assert.equal(-11670912000, timestamp)

    timestamp, err = parse_openssl_time("Jan 1 00:00:00 1970 GMT")
    assert.Nil(err)
    assert.equal(0, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 2000 GMT")
    assert.Nil(err)
    assert.equal(951782400, timestamp)

    timestamp, err = parse_openssl_time("Mar 1 00:00:00 2000 GMT")
    assert.Nil(err)
    assert.equal(951868800, timestamp)

    timestamp, err = parse_openssl_time("Jan 18 00:00:00 2038 GMT")
    assert.Nil(err)
    assert.equal(2147385600, timestamp)

    timestamp, err = parse_openssl_time("Jan 19 00:00:00 2038 GMT")
    assert.Nil(err)
    assert.equal(2147472000, timestamp)

    timestamp, err = parse_openssl_time("Jan 20 00:00:00 2038 GMT")
    assert.Nil(err)
    assert.equal(2147558400, timestamp)

    timestamp, err = parse_openssl_time("Feb 29 00:00:00 2400 GMT")
    assert.Nil(err)
    assert.equal(13574563200, timestamp)
  end)
end)
