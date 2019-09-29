local cjson = require "cjson.safe"
local http = require "resty.http"
local server = require "spec.support.server"

describe("memory", function()
  before_each(server.stop)
  after_each(server.stop)

  it("logs when running out of memory in shared dict", function()
    server.start({
      auto_ssl_http_server_config = [[
        location /fill-auto-ssl-shdict {
          content_by_lua_block {
            local cjson = require "cjson.safe"
            local resty_random = require "resty.random"
            local str = require "resty.string"

            -- Fill the shdict with random things to simulate what happens when old
            -- data gets forced out.
            for i = 1, 15 do
              local random = resty_random.bytes(256000)
              local _, err = ngx.shared.auto_ssl:set("foobar" .. i, str.to_hex(random))
              if err then
                ngx.log(ngx.ERR, "set error: ", err)
                return ngx.exit(500)
              end
            end

            -- Ensure items are getting forced out as expected, after filling it up.
            local random = resty_random.bytes(256000)
            local _, err, forcible = ngx.shared.auto_ssl:set("foobar-force", str.to_hex(random))
            if err then
              ngx.log(ngx.ERR, "set error: ", err)
              return ngx.exit(500)
            end
            if not forcible then
              ngx.log(ngx.ERR, "set didn't force other items out of shdict, as expected")
              return ngx.exit(500)
            end

            ngx.print(cjson.encode({
              keys = #ngx.shared.auto_ssl:get_keys(),
            }))
          }
        }
      ]],
    })

    local httpc = http.new()

    local fill_res, err = httpc:request_uri("http://127.0.0.1:9080/fill-auto-ssl-shdict")
    assert.equal(nil, err)
    assert.equal(200, fill_res.status)
    local data, json_err = cjson.decode(fill_res.body)
    assert.equal(nil, json_err)
    assert.equal(2, data["keys"])

    -- Ensure we can make a successful request.
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
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.matches("'lua_shared_dict auto_ssl' might be too small", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("can issue a new certificate after all memory is flushed", function()
    server.start({
      auto_ssl_http_server_config = [[
        location /flush-auto-ssl-shdict {
          content_by_lua_block {
            local cjson = require "cjson.safe"

            -- Completely wipe certs from storage, to simulate a new registration
            -- after completely running out of memory.
            ngx.shared.auto_ssl:flush_all()

            ngx.print(cjson.encode({
              keys = #ngx.shared.auto_ssl:get_keys(),
            }))
          }
        }
      ]],
    })

    local httpc = http.new()

    local flush_res, err = httpc:request_uri("http://127.0.0.1:9080/flush-auto-ssl-shdict")
    assert.equal(nil, err)
    assert.equal(200, flush_res.status)
    local data, json_err = cjson.decode(flush_res.body)
    assert.equal(nil, json_err)
    assert.equal(0, data["keys"])

    -- Ensure we can make a successful request.
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
    assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
