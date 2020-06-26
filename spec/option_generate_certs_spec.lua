local http = require "resty.http"
local server = require "spec.support.server"

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
    do
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal("18: self signed certificate", ssl_err)
    end

    -- Reconnect and try again with ssl verification disabled.
    do
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, false)
      assert.equal(nil, ssl_err)

      local res, request_err = httpc:request({ path = "/foo" })
      assert.equal(nil, request_err)
      assert.equal(200, res.status)

      local body, body_err = res:read_body()
      assert.equal(nil, body_err)
      assert.equal("generate_certs = false server", body)
    end

    -- Make a request to a different server block that uses the default
    -- generate_certs value (true) and ensure that this does still generate
    -- the cert.
    do
      local _, connect_err = httpc:connect("127.0.0.1", 9443)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal(nil, ssl_err)

      local res, request_err = httpc:request({ path = "/foo" })
      assert.equal(nil, request_err)
      assert.equal(200, res.status)

      local body, body_err = res:read_body()
      assert.equal(nil, body_err)
      assert.equal("foo", body)
    end

    -- Make a 3rd request back to the "generate_certs = false" server and
    -- ensure that it now returns a valid certificate (since it should still
    -- return already existing certs).
    do
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal(nil, ssl_err)

      local res, request_err = httpc:request({ path = "/foo" })
      assert.equal(nil, request_err)
      assert.equal(200, res.status)

      local body, body_err = res:read_body()
      assert.equal(nil, body_err)
      assert.equal("generate_certs = false server", body)
    end

    local error_log = server.read_error_log()
    assert.matches("using fallback - did not issue certificate, because the generate_certs setting is false", error_log, nil, true)
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
