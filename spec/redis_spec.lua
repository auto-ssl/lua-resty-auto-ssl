local cjson = require "cjson.safe"
local http = require "resty.http"
local redis = require "resty.redis"
local server = require "spec.support.server"

describe("redis", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues and renews certificates", function()
    server.start({
      auto_ssl_pre_new = [[
        options["storage_adapter"] = "resty.auto-ssl.storage_adapters.redis"
        options["redis"] = {
          port = 9999,
        }
        options["renew_check_interval"] = 1
      ]],
    })

    do
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

      local r = redis:new()
      local redis_connect_ok, redis_connect_err = r:connect("127.0.0.1", 9999)
      assert.equal(nil, redis_connect_err)
      assert.truthy(redis_connect_ok)

      local get_res, get_err = r:get(server.ngrok_hostname .. ":latest")
      assert.equal(nil, get_err)
      assert.string(get_res)

      local data, json_err = cjson.decode(get_res)
      assert.equal(nil, json_err)
      assert.string(data["fullchain_pem"])

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("issuing new certificate for", error_log, nil, true)
    end

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
    do
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

      error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("issuing new certificate for", error_log, nil, true)
    end

    error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("issues and renews certificates with redis storage prefix", function()
    server.start({
      auto_ssl_pre_new = [[
        options["storage_adapter"] = "resty.auto-ssl.storage_adapters.redis"
        options["redis"] = {
          port = 9999,
          prefix = "key-prefix",
        }
        options["renew_check_interval"] = 1
      ]],
    })

    do
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

      local r = redis:new()
      local redis_connect_ok, redis_connect_err = r:connect("127.0.0.1", 9999)
      assert.equal(nil, redis_connect_err)
      assert.truthy(redis_connect_ok)

      local get_res, get_err = r:get("key-prefix:" .. server.ngrok_hostname .. ":latest")
      assert.equal(nil, get_err)
      assert.string(get_res)

      local data, json_err = cjson.decode(get_res)
      assert.equal(nil, json_err)
      assert.string(data["fullchain_pem"])

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("issuing new certificate for", error_log, nil, true)
    end

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
    do
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

      error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("issuing new certificate for", error_log, nil, true)
    end

    error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("allows storage in a separate redis database number", function()
    server.start({
      auto_ssl_pre_new = [[
        options["storage_adapter"] = "resty.auto-ssl.storage_adapters.redis"
        options["redis"] = {
          port = 9999,
          db = 5,
          prefix = "db-test-prefix",
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

    local r = redis:new()
    local redis_connect_ok, redis_connect_err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, redis_connect_err)
    assert.truthy(redis_connect_ok)

    local select_ok, select_err = r:select(5)
    assert.equal(nil, select_err)
    assert.truthy(select_ok)

    local get_res, get_err = r:get("db-test-prefix:" .. server.ngrok_hostname .. ":latest")
    assert.equal(nil, get_err)
    assert.string(get_res)

    local data, json_err = cjson.decode(get_res)
    assert.equal(nil, json_err)
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
      auto_ssl_pre_new = [[
        options["storage_adapter"] = "resty.auto-ssl.storage_adapters.redis"
        options["redis"] = {
          port = 9999,
        }
        options["allow_domain"] = function(domain, allow_domain_auto_ssl)
          ngx.log(ngx.INFO, "allow_domain auto_ssl: " .. type(allow_domain_auto_ssl))
          local redis = allow_domain_auto_ssl.storage.adapter:get_connection()
          ngx.log(ngx.INFO, "allow_domain redis: " .. type(redis))
          redis:set("allow_domain_redis_test", "foo")
          return false
        end
      ]],
    })

    local httpc = http.new()
    local res, err = httpc:request_uri("https://127.0.0.1:9443/foo", {
      ssl_verify = false,
    })
    assert.equal(nil, err)
    assert.equal(200, res.status)
    assert.equal("foo", res.body)

    local r = redis:new()
    local redis_connect_ok, connect_err = r:connect("127.0.0.1", 9999)
    assert.equal(nil, connect_err)
    assert.truthy(redis_connect_ok)

    local get_res, get_err = r:get("allow_domain_redis_test")
    assert.equal(nil, get_err)
    assert.equal("foo", get_res)

    local error_log = server.read_error_log()
    assert.matches("allow_domain auto_ssl: table", error_log, nil, true)
    assert.matches("allow_domain redis: table", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("accepts additional connect options", function()
    server.start({
      auto_ssl_pre_new = [[
        options["storage_adapter"] = "resty.auto-ssl.storage_adapters.redis"
        options["redis"] = {
          port = 9999,
          connect_options = {
            pool = { "invalid-value" },
          },
        }
      ]],
    })

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("bad argument #3 to 'connect'", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
