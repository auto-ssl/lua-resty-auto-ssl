local http = require "resty.http"
local cjson = require "cjson.safe"
local server = require "spec.support.server"
local redis = require "resty.redis"

describe("option generate_certs", function()
  before_each(server.stop)
  after_each(server.stop)

  it("generate_certs disables generation of new SSL certs", function()
    server.start({
      auto_ssl_http_config = [[
        server {
          listen 9444 ssl;
          ssl_certificate_by_lua_block {
            auto_ssl:ssl_certificate({
              generate_certs = false,
            })
          }

          location /foo {
            echo -n "generate_certs = false server";
          }
        }
      ]],
    })

    local httpc = http.new()

    -- Make an initial request against the "generate_certs = false" server to
    -- ensure we don't get back a valid SSL cert.
    local _, err = httpc:connect("127.0.0.1", 9444)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", err)

    -- Reconnect and try again with ssl verification disabled.
    local _, err = httpc:connect("127.0.0.1", 9444)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, false)
    assert.equal(nil, err)

    local res, err = httpc:request({ path = "/foo" })
    assert.equal(nil, err)
    assert.equal(200, res.status)

    local body, err = res:read_body()
    assert.equal(nil, err)
    assert.equal("generate_certs = false server", body)

    -- Make a request to a different server block that uses the default
    -- generate_certs value (true) and ensure that this does still generate
    -- the cert.
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

    -- Make a 3rd request back to the "generate_certs = false" server and
    -- ensure that it now returns a valid certificate (since it should still
    -- return already existing certs).
    local _, err = httpc:connect("127.0.0.1", 9444)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal(nil, err)

    local res, err = httpc:request({ path = "/foo" })
    assert.equal(nil, err)
    assert.equal(200, res.status)

    local body, err = res:read_body()
    assert.equal(nil, err)
    assert.equal("generate_certs = false server", body)

    local error_log = server.read_error_log()
    assert.matches("using fallback - did not issue certificate, because the generate_certs setting is false", error_log, nil, true)
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
