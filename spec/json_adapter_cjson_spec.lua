local cjson = require "cjson.safe"
local http = require "resty.http"
local redis = require "resty.redis"
local server = require "spec.support.server"

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
    local connect_ok, connect_err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, connect_err)
    assert.truthy(connect_ok)

    local _, set_err = r:set(server.ngrok_hostname .. ":latest", '{"invalid_json"')
    assert.equal(nil, set_err)

    local httpc = http.new()
    local _, http_connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, http_connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal(nil, ssl_err)

    local res, request_err = httpc:request({ path = "/foo" })
    assert.equal(nil, request_err)
    assert.equal(200, res.status)

    local body, body_err = res:read_body()
    assert.equal(nil, body_err)
    assert.equal("foo", body)

    local get_res, get_err = r:get(server.ngrok_hostname .. ":latest")
    assert.equal(nil, get_err)
    assert.string(get_res)

    local data, json_err = cjson.decode(get_res)
    assert.equal(nil, json_err)
    assert.string(data["fullchain_pem"])

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: error fetching certificate from storage for " .. server.ngrok_hostname .. ": Expected colon but found T_END at character 16", error_log, nil, true)
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
