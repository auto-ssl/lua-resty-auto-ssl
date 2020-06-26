local cjson = require "cjson.safe"
local file = require "pl.file"
local http = require "resty.http"
local server = require "spec.support.server"

describe("renewal", function()
  before_each(server.stop)
  after_each(server.stop)

  it("calls the allow_domain callback on renewals", function()
    server.start({
      auto_ssl_pre_new = [[
        options["renew_check_interval"] = 1
        options["allow_domain"] = function(domain, auto_ssl, ssl_options, renewal)
          ngx.log(ngx.INFO, "allow_domain (renewal=" .. tostring(renewal) .. "): domain=" .. type(domain))
          ngx.log(ngx.INFO, "allow_domain (renewal=" .. tostring(renewal) .. "): auto_ssl=" .. type(auto_ssl))
          ngx.log(ngx.INFO, "allow_domain (renewal=" .. tostring(renewal) .. "): ssl_options=" .. type(ssl_options))
          ngx.log(ngx.INFO, "allow_domain (renewal=" .. tostring(renewal) .. "): renewal=" .. type(renewal))

          if renewal then
            return false
          else
            return true
          end
        end
      ]],
      auto_ssl_http_config = [[
        server {
          listen 9444 ssl;
          ssl_certificate_by_lua_block {
            auto_ssl:ssl_certificate({})
          }

          location /foo {
            echo -n "foo";
          }
        }
      ]],
    })

    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal(nil, ssl_err)

      local res, request_err = httpc:request({ path = "/foo" })
      assert.equal(nil, request_err)
      assert.equal(200, res.status)

      local body, body_err = res:read_body()
      assert.equal(nil, body_err)
      assert.equal("foo", body)

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("auto-ssl: issuing new certificate for " .. server.ngrok_hostname, error_log, nil, true)
      assert.matches("allow_domain (renewal=false): domain=string", error_log, nil, true)
      assert.matches("allow_domain (renewal=false): auto_ssl=table", error_log, nil, true)
      assert.matches("allow_domain (renewal=false): ssl_options=table", error_log, nil, true)
      assert.Not.matches("allow_domain (renewal=false): ssl_options=nil", error_log, nil, true)
      assert.matches("allow_domain (renewal=false): renewal=boolean", error_log, nil, true)
    end

    -- Wait for scheduled renewals to happen.
    ngx.sleep(3)

    -- allow_domain should not be called until it's ready to expire.
    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal(nil, ssl_err)

      local res, request_err = httpc:request({ path = "/foo" })
      assert.equal(nil, request_err)
      assert.equal(200, res.status)

      local body, body_err = res:read_body()
      assert.equal(nil, body_err)
      assert.equal("foo", body)

      local error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("auto-ssl: issuing new certificate for " .. server.ngrok_hostname, error_log, nil, true)
      assert.matches("auto-ssl: checking certificate renewals for " .. server.ngrok_hostname, error_log, nil, true)
      assert.matches("auto-ssl: expiry date is more than 30 days out, skipping renewal: " .. server.ngrok_hostname, error_log, nil, true)
      assert.Not.matches("allow_domain (renewal=true)", error_log, nil, true)
    end

    -- Alter certificate so that it's expired and up for renewal.
    local cert_path = server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest")
    local content = assert(file.read(cert_path))
    local data = assert(cjson.decode(content))
    assert.number(data["expiry"])
    data["expiry"] = 1000
    assert(file.write(cert_path, assert(cjson.encode(data))))

    -- Wait for scheduled renewals to happen.
    ngx.sleep(3)

    -- allow_domain should not be called until it's ready to expire.
    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal(nil, ssl_err)

      local res, request_err = httpc:request({ path = "/foo" })
      assert.equal(nil, request_err)
      assert.equal(200, res.status)

      local body, body_err = res:read_body()
      assert.equal(nil, body_err)
      assert.equal("foo", body)

      local error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("auto-ssl: issuing new certificate for " .. server.ngrok_hostname, error_log, nil, true)
      assert.matches("auto-ssl: checking certificate renewals for " .. server.ngrok_hostname, error_log, nil, true)
      assert.Not.matches("auto-ssl: expiry date is more than 30 days out, skipping renewal: " .. server.ngrok_hostname, error_log, nil, true)
      assert.matches("allow_domain (renewal=true): domain=string", error_log, nil, true)
      assert.matches("allow_domain (renewal=true): auto_ssl=table", error_log, nil, true)
      assert.matches("allow_domain (renewal=true): ssl_options=nil", error_log, nil, true)
      assert.Not.matches("allow_domain (renewal=true): ssl_options=table", error_log, nil, true)
      assert.matches("allow_domain (renewal=true): renewal=boolean", error_log, nil, true)
      assert.matches("auto-ssl: domain not allowed, not renewing: " .. server.ngrok_hostname, error_log, nil, true)
    end
  end)
end)
