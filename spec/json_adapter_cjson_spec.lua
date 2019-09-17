local http = require "resty.http"
local cjson = require "cjson.safe"
local server = require "spec.support.server"
local redis = require "resty.redis"

describe("json adapter cjson", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues a new SSL certificate and stores it in redis", function()
    server.start({
      auto_ssl_pre_new = [[
        options["storage_adapter"] = "resty.auto-ssl.storage_adapters.redis"
        options["redis"] = {
          port = 9999,
        }
      ]],
    })

    local r = redis:new()
    local ok, err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, err)
    assert.truthy(ok)

    local res, err = r:set(server.ngrok_hostname .. ":latest", '{"invalid_json"')
    assert.equal(nil, err)

    local httpc = http.new()
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

    local r = redis:new()
    local ok, err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, err)
    assert.truthy(ok)

    local res, err = r:get(server.ngrok_hostname .. ":latest")
    assert.equal(nil, err)
    assert.string(res)

    local data, err = cjson.decode(res)
    assert.equal(nil, err)
    assert.string(data["fullchain_pem"])

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: error fetching certificate from storage for " .. server.ngrok_hostname .. ": Expected colon but found T_END at character 16", error_log, nil, true)
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
