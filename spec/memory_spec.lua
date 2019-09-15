local http = require "resty.http"
local cjson = require "cjson.safe"
local server = require "spec.support.server"
local redis = require "resty.redis"

describe("memory", function()
  before_each(server.stop)
  after_each(server.stop)

  it("logs when running out of memory in shared dict", function()
    server.start()

    local httpc = http.new()

    local res, err = httpc:request_uri("http://127.0.0.1:9080/fill-auto-ssl-shdict")
    assert.equal(nil, err)
    assert.equal(200, res.status)
    local data, err = cjson.decode(res.body)
    assert.equal(2, data["keys"])

    -- Ensure we can make a successful request.
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal(nil, err)

    local res, err = httpc:request({ path = "/foo" })
    assert.equal(nil, err)
    assert.equal(200, res.status)

    local body, err = res:read_body()
    assert.equal(nil, err)
    assert.equal("foo", body)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.matches("'lua_shared_dict auto_ssl' might be too small", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("can issue a new certificate after all memory is flushed", function()
    server.start()

    local httpc = http.new()

    local res, err = httpc:request_uri("http://127.0.0.1:9080/flush")
    assert.equal(nil, err)
    assert.equal(200, res.status)
    local data, err = cjson.decode(res.body)
    assert.equal(0, data["keys"])

    -- Ensure we can make a successful request.
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal(nil, err)

    local res, err = httpc:request({ path = "/foo" })
    assert.equal(nil, err)
    assert.equal(200, res.status)

    local body, err = res:read_body()
    assert.equal(nil, err)
    assert.equal("foo", body)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
