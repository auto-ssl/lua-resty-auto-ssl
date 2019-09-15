local http = require "resty.http"
local cjson = require "cjson.safe"
local server = require "spec.support.server"
local redis = require "resty.redis"

describe("redis", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues and renews certificates", function()
    server.start({
      auto_ssl_new_options = [[{
        storage_adapter = "resty.auto-ssl.storage_adapters.redis",
        redis = {
          port = 9999,
        },
        renew_check_interval = 1,
      }]],
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

  it("issues and renews certificates with redis storage prefix", function()
    server.start({
      auto_ssl_new_options = [[{
        storage_adapter = "resty.auto-ssl.storage_adapters.redis",
        redis = {
          port = 9999,
          prefix = "key-prefix",
        },
        renew_check_interval = 1,
      }]],
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

    local r = redis:new()
    local ok, err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, err)
    assert.truthy(ok)

    local res, err = r:get("key-prefix:" .. server.ngrok_hostname .. ":latest")
    assert.equal(nil, err)
    assert.string(res)

    local data, err = cjson.decode(res)
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

  it("allows storage in a separate redis database number", function()
    server.start({
      auto_ssl_new_options = [[{
        storage_adapter = "resty.auto-ssl.storage_adapters.redis",
        redis = {
          port = 9999,
          db = 5,
          prefix = "db-test-prefix",
        },
      }]],
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

    local r = redis:new()
    local ok, err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, err)
    assert.truthy(ok)

    local ok, err = r:select(5)
    assert.equal(nil, err)
    assert.truthy(ok)

    local res, err = r:get("db-test-prefix:" .. server.ngrok_hostname .. ":latest")
    assert.equal(nil, err)
    assert.string(res)

    local data, err = cjson.decode(res)
    assert.equal(nil, err)
    assert.string(data["fullchain_pem"])

    local error_log = server.read_error_log()
    assert.matches("issuing new certificate for", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("exposes redis connection in allow_domain callback", function()
    server.start({
      auto_ssl_new_options = [[{
        storage_adapter = "resty.auto-ssl.storage_adapters.redis",
        redis = {
          port = 9999,
        },
        allow_domain = function(domain, allow_domain_auto_ssl)
          ngx.log(ngx.INFO, "allow_domain auto_ssl: " .. type(allow_domain_auto_ssl))
          local redis = allow_domain_auto_ssl.storage.adapter:get_connection()
          ngx.log(ngx.INFO, "allow_domain redis: " .. type(redis))
          redis:set("allow_domain_redis_test", "foo")
          return false
        end,
      }]],
    })

    local httpc = http.new()
    local res, err = httpc:request_uri("https://127.0.0.1:9443/foo", {
      ssl_verify = false,
    })
    assert.equal(nil, err)
    assert.equal(200, res.status)
    assert.equal("foo", res.body)

    local r = redis:new()
    local ok, err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, err)
    assert.truthy(ok)

    local res, err = r:get("allow_domain_redis_test")
    assert.equal(nil, err)
    assert.equal("foo", res)

    local error_log = server.read_error_log()
    assert.matches("allow_domain auto_ssl: table", error_log, nil, true)
    assert.matches("allow_domain redis: table", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
