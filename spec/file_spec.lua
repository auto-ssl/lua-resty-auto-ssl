local cjson = require "cjson.safe"
local http = require "resty.http"
local server = require "spec.support.server"

describe("file", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues and renews certificates", function()
    server.start({
      auto_ssl_pre_new = [[
        options["renew_check_interval"] = 1
      ]],
    })

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

    local file, err = io.open(server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest"), "r")
    assert.equal(nil, err)

    local content = file:read("*all")
    file:close()
    assert.string(content)

    local data, err = cjson.decode(content)
    assert.equal(nil, err)
    assert.string(data["fullchain_pem"])

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("issuing new certificate for", error_log, nil, true)

    -- Wait for scheduled renewals to happen (since the check interval is
    -- every 1 second).
    ngx.sleep(3)

    -- Since we don't actually expect the renewal to happen (since our cert
    -- is too new), we'll ensure that the "skipping" message gets logged (so
    -- we're at least sure that the renewal was fired.
    local error_log = server.nginx_error_log_tail:read()
    assert.matches("auto-ssl: checking certificate renewals for", error_log, nil, true)
    assert.matches("auto-ssl: expiry date is more than 30 days out", error_log, nil, true)

    -- Next, ensure that that we're still able to access things using the
    -- existing certificate even after the renewal was triggered.
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

    local error_log = server.nginx_error_log_tail:read()
    assert.Not.matches("issuing new certificate for", error_log, nil, true)

    local error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
