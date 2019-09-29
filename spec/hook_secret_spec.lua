local http = require "resty.http"
local server = require "spec.support.server"

describe("hook secret", function()
  before_each(server.stop)
  after_each(server.stop)

  it("writes a friendly error message when auto_ssl_settings dict is missing", function()
    server.start({
      disable_auto_ssl_settings_dict = true,
    })

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: dict auto_ssl_settings could not be found. Please add it to your configuration: `lua_shared_dict auto_ssl_settings 64k;`", error_log, nil, true)
  end)

  it("doesn't change the hook secret after reloading", function()
    server.start({
      auto_ssl_http_server_config = [[
        location /auto-ssl-init {
          content_by_lua_block {
            auto_ssl:init()
            ngx.print("init")
          }
        }
      ]],
    })

    local httpc = http.new()

    local res, err = httpc:request_uri("http://127.0.0.1:9080/hook-server-secret")
    assert.equal(nil, err)
    assert.equal(200, res.status)
    assert.string(res.body)
    assert.equal(64, string.len(res.body))
    local secret1 = res.body

    local init_res, init_err = httpc:request_uri("http://127.0.0.1:9080/auto-ssl-init")
    assert.equal(nil, init_err)
    assert.equal(200, init_res.status)
    assert.equal("init", init_res.body)

    local res2, err2 = httpc:request_uri("http://127.0.0.1:9080/hook-server-secret")
    assert.equal(nil, err2)
    assert.equal(200, res2.status)
    assert.string(res2.body)
    assert.equal(64, string.len(res2.body))
    local secret2 = res2.body

    assert.equal(secret1, secret2)

    local error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
