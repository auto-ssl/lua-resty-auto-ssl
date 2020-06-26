local http = require "resty.http"
local server = require "spec.support.server"

describe("proxy", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues and renews certificates", function()
    server.start({
      auto_ssl_pre_new = [[
        options["http_proxy_options"] = {
          http_proxy = "http://127.0.0.1:9444",
          http_proxy_authorization = "Basic ZGVtbzp0ZXN0",
        }
      ]],
      auto_ssl_http_config = [[
        server {
          listen 9444;

          location / {
            content_by_lua_block {
              ngx.log(ngx.INFO, "http proxy auth: ", ngx.var.http_proxy_authorization)
            }
          }
        }
      ]],
    })

    local httpc = http.new()
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

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: issuing new certificate for " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("http proxy auth: Basic ZGVtbzp0ZXN0", error_log, nil, true)
    assert.matches("auto-ssl: failed to set ocsp stapling for " .. server.ngrok_hostname .. " - continuing anyway - failed to get ocsp response: OCSP responder returns bad response body (http://ocsp.stg-int-x1.letsencrypt.org): ,", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
