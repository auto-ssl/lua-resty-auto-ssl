local cjson = require "cjson.safe"
local dir = require "pl.dir"
local file = require "pl.file"
local http = require "resty.http"
local pl_utils = require "pl.utils"
local server = require "spec.support.server"
local shell_blocking = require "shell-games"

describe("sanity", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues a new SSL certificate and returns existing ones", function()
    server.start()

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

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("issuing new certificate for", error_log, nil, true)
    end

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

      local error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("issuing new certificate for", error_log, nil, true)
    end

    local error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("returns the fallback SSL certificate when SNI isn't used", function()
    server.start()

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, nil, true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - ", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("disallows all domains for registration by default", function()
    server.start({
      auto_ssl_pre_new = [[
        options["allow_domain"] = nil
      ]]
    })

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: domain not allowed - using fallback - " .. server.ngrok_hostname, error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("calls the allow_domain function which can perform more complex logic", function()
    server.start({
      auto_ssl_pre_new = [[
        options["allow_domain"] = function(domain)
          ngx.log(ngx.INFO, "allow_domain called: " .. domain)
          if string.find(domain, "not-going-to-find") then
            return true
          else
            return false
          end
        end
      ]],
    })

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("allow_domain called: " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("auto-ssl: domain not allowed - using fallback - " .. server.ngrok_hostname, error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("options can also be set with the set() function after new()", function()
    server.start({
      auto_ssl_pre_new = [[
        local orig_options = options
        options = nil
      ]],
      auto_ssl_post_new = [[
        auto_ssl:set("dir", orig_options["dir"])
        auto_ssl:set("ca", orig_options["ca"])
        auto_ssl:set("allow_domain", function(domain)
          ngx.log(ngx.INFO, "allow_domain set() called: " .. domain)
          if string.find(domain, "not-going-to-find") then
            return true
          else
            return false
          end
        end)
      ]]
    })

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("allow_domain set() called: " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("auto-ssl: domain not allowed - using fallback - " .. server.ngrok_hostname, error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("returns the fallback SSL certificate when the domain is allowed and valid, but the domain challenge fails", function()
    server.start()

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, "not-ours-" .. server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: issuing new certificate for not-ours-" .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("auto-ssl: dehydrated failed", error_log, nil, true)
    assert.matches("auto-ssl: could not get certificate for not-ours-" .. server.ngrok_hostname, error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("returns the fallback SSL certificate when the domain is allowed, but not resolvable", function()
    server.start()

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, "unresolvable-sdjfklsdjf.example", true)
    assert.equal("18: self signed certificate", ssl_err)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: issuing new certificate for unresolvable-sdjfklsdjf.example", error_log, nil, true)
    assert.matches("auto-ssl: dehydrated failed", error_log, nil, true)
    assert.matches("auto-ssl: could not get certificate for unresolvable-sdjfklsdjf.example", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("allows for custom logic to control domain name to handle lack of SNI support", function()
    server.start({
      auto_ssl_pre_new = [[
        options["request_domain"] = function(ssl, ssl_options)
          local domain, err = ssl.server_name()
          if (not domain or err) and ssl_options and ssl_options["port"] then
            if ssl_options["port"] == 9444 then
              domain = "non-sni-" .. ssl_options["port"] .. ".example"
            elseif ssl_options["port"] == 9445 then
              domain = "non-sni-mismatch-" .. ssl_options["port"] .. ".example"
            elseif ssl_options["port"] == 9447 then
              domain = "non-sni-disallowed-" .. ssl_options["port"] .. ".example"
            end
          end

          return domain, err
        end
        options["allow_domain"] = function(domain, auto_ssl, ssl_options)
          if ssl_options and ssl_options["port"] == 9447 then
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
            auto_ssl:ssl_certificate({ port = 9444 })
          }
        }

        server {
          listen 9445 ssl;
          ssl_certificate_by_lua_block {
            auto_ssl:ssl_certificate({ port = 9445 })
          }
        }

        server {
          listen 9446 ssl;
          ssl_certificate_by_lua_block {
            auto_ssl:ssl_certificate({ port = 9446 })
          }
        }

        server {
          listen 9447 ssl;
          ssl_certificate_by_lua_block {
            auto_ssl:ssl_certificate({ port = 9447 })
          }
        }
      ]]
    })

    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9444)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, nil, true)
      assert.equal("18: self signed certificate", ssl_err)

      local error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - ,", error_log, nil, true)
      assert.matches("auto-ssl: issuing new certificate for non-sni-9444.example", error_log, nil, true)
      assert.matches("auto-ssl: dehydrated failed", error_log, nil, true)
      assert.matches("Name does not end in a public suffix", error_log, nil, true)
      assert.Not.matches("[alert]", error_log, nil, true)
      assert.Not.matches("[emerg]", error_log, nil, true)
    end

    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9445)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, nil, true)
      assert.equal("18: self signed certificate", ssl_err)

      local error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - ,", error_log, nil, true)
      assert.matches("auto-ssl: issuing new certificate for non-sni-mismatch-9445.example", error_log, nil, true)
      assert.matches("auto-ssl: dehydrated failed", error_log, nil, true)
      assert.matches("Name does not end in a public suffix", error_log, nil, true)
      assert.Not.matches("[alert]", error_log, nil, true)
      assert.Not.matches("[emerg]", error_log, nil, true)
    end

    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9446)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, nil, true)
      assert.equal("18: self signed certificate", ssl_err)

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - ,", error_log, nil, true)
      assert.Not.matches("auto-ssl: issuing new certificate", error_log, nil, true)
      assert.Not.matches("[error]", error_log, nil, true)
      assert.Not.matches("[alert]", error_log, nil, true)
      assert.Not.matches("[emerg]", error_log, nil, true)
    end

    do
      local httpc = http.new()
      local _, connect_err = httpc:connect("127.0.0.1", 9447)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, nil, true)
      assert.equal("18: self signed certificate", ssl_err)

      local error_log = server.nginx_error_log_tail:read()
      assert.Not.matches("auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - ,", error_log, nil, true)
      assert.matches("auto-ssl: domain not allowed - using fallback - non-sni-disallowed-9447.example", error_log, nil, true)
      assert.Not.matches("auto-ssl: issuing new certificate", error_log, nil, true)
      assert.Not.matches("[warn]", error_log, nil, true)
      assert.Not.matches("[error]", error_log, nil, true)
      assert.Not.matches("[alert]", error_log, nil, true)
      assert.Not.matches("[emerg]", error_log, nil, true)
    end
  end)

  it("deletes dehydrated temporary files after successful cert deployment", function()
    server.start()

    local result, err = shell_blocking.capture_combined({ "ls", "-1", server.current_test_dir .. "/auto-ssl/letsencrypt" })
    assert.equal(nil, err)
    assert.same({
      "accounts",
      "conf.d",
      "config",
      "locks",
    }, pl_utils.split(result["output"]))

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

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("issuing new certificate for", error_log, nil, true)

    local ls_result, ls_err = shell_blocking.capture_combined({ "ls", "-1", server.current_test_dir .. "/auto-ssl/letsencrypt" })
    assert.equal(nil, ls_err)
    assert.same({
      "accounts",
      "certs",
      "chains",
      "conf.d",
      "config",
      "locks",
    }, pl_utils.split(ls_result["output"]))

    local ls_certs_result, ls_certs_err = shell_blocking.capture_combined({ "ls", "-1", server.current_test_dir .. "/auto-ssl/letsencrypt/certs" })
    assert.equal(nil, ls_certs_err)
    assert.same({}, pl_utils.split(ls_certs_result["output"]))

    error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("retains dehydrated temporary files if cert deployment fails", function()
    server.start()

    -- Create a directory where the storage file would normally belong so
    -- that attempt to write this cert to storage will temporarily fail.
    assert(dir.makepath(server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest")))

    local ls_before_result, ls_before_err = shell_blocking.capture_combined({ "ls", "-1", server.current_test_dir .. "/auto-ssl/letsencrypt" })
    assert.equal(nil, ls_before_err)
    assert.same({
      "accounts",
      "conf.d",
      "config",
      "locks",
    }, pl_utils.split(ls_before_result["output"]))

    local httpc = http.new()

    do
      local _, connect_err = httpc:connect("127.0.0.1", 9443)
      assert.equal(nil, connect_err)

      local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
      assert.equal("18: self signed certificate", ssl_err)

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
      assert.matches("auto-ssl: failed to open file for writing:", error_log, nil, true)
      assert.matches("auto-ssl: failed to set cert", error_log, nil, true)
      assert.matches("auto-ssl: dehydrated failed", error_log, nil, true)
      assert.matches("auto-ssl: issuing new certificate failed", error_log, nil, true)
      assert.matches("auto-ssl: could not get certificate for", error_log, nil, true)
    end

    local ls_result, ls_err = shell_blocking.capture_combined({ "ls", "-1", server.current_test_dir .. "/auto-ssl/letsencrypt" })
    assert.equal(nil, ls_err)
    assert.same({
      "accounts",
      "certs",
      "chains",
      "conf.d",
      "config",
      "locks",
    }, pl_utils.split(ls_result["output"]))

    local ls_certs_result, ls_certs_err = shell_blocking.capture_combined({ "ls", "-1", server.current_test_dir .. "/auto-ssl/letsencrypt/certs" })
    assert.equal(nil, ls_certs_err)
    assert.same({
      server.ngrok_hostname,
    }, pl_utils.split(ls_certs_result["output"]))

    assert(dir.rmtree(server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest")))

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

      local error_log = server.nginx_error_log_tail:read()
      assert.matches("auto-ssl: issuing new certificate for", error_log, nil, true)
      assert.matches("Checking domain name(s) of existing cert... unchanged.", error_log, nil, true)
      assert.matches("auto-ssl: dehydrated succeeded, but certs still missing from storage - trying to manually copy", error_log, nil, true)
    end

    local error_log = server.read_error_log()
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("hook server port can be changed", function()
    server.start({
      auto_ssl_pre_new = [[
        options["hook_server_port"] = 9888
      ]],
      auto_ssl_http_config = [[
        server {
          listen 127.0.0.1:9888;
          client_body_buffer_size 128k;
          client_max_body_size 128k;
          location / {
            content_by_lua_block {
              ngx.log(ngx.INFO, "custom hook_server_port=9888")
              auto_ssl:hook_server()
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

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("auto-ssl: issuing new certificate for " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("custom hook_server_port=9888", error_log, nil, true)
  end)

  it("fills in missing expiry dates in storage from certificate expiration on renewal", function()
    server.start({
      auto_ssl_pre_new = [[
        options["renew_check_interval"] = 1
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

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("issuing new certificate for", error_log, nil, true)

    local cert_path = server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest")
    local content = assert(file.read(cert_path))
    assert.string(content)
    local data = assert(cjson.decode(content))
    local original_expiry = data["expiry"]
    assert.number(data["expiry"])

    -- Unset the expiration time.
    data["expiry"] = nil
    assert.Nil(data["expiry"])

    assert(file.write(cert_path, assert(cjson.encode(data))))

    -- Wait for scheduled renewals to happen.
    ngx.sleep(3)

    error_log = server.nginx_error_log_tail:read()
    assert.matches("auto-ssl: checking certificate renewals for " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("auto-ssl: setting expiration date of " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("auto-ssl: expiry date is more than 30 days out, skipping renewal: " .. server.ngrok_hostname, error_log, nil, true)

    content = assert(file.read(cert_path))
    assert.string(content)
    data = assert(cjson.decode(content))
    assert.number(data["expiry"])
    assert.equal(original_expiry, data["expiry"])

    error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("removes cert if expiration has expired and renewal fails", function()
    server.start({
      auto_ssl_pre_new = [[
        options["renew_check_interval"] = 1
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

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("issuing new certificate for", error_log, nil, true)

    local cert_path = server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest")
    local content = assert(file.read(cert_path))
    assert.string(content)
    local data = assert(cjson.decode(content))
    assert.number(data["expiry"])

    -- Set the expiration time to some time in the past.
    data["expiry"] = 1000

    assert(file.write(cert_path, assert(cjson.encode(data))))

    -- Wait for scheduled renewals to happen.
    ngx.sleep(3)

    error_log = server.nginx_error_log_tail:read()
    assert.matches("auto-ssl: checking certificate renewals for " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("Skipping renew!", error_log, nil, true)

    -- Since this cert renewal is still valid, it should still remain despite
    -- being marked as expired.
    content = assert(file.read(cert_path))
    assert.string(content)
    data = assert(cjson.decode(content))
    assert.number(data["expiry"])

    -- Copy the cert to an unresolvable domain to verify that failed renewals
    -- will be removed.
    local unresolvable_cert_path = server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri("unresolvable-sdjfklsdjf.example:latest")
    local _, cp_err = shell_blocking.capture_combined({ "cp", "-p", cert_path, unresolvable_cert_path })
    assert.equal(nil, cp_err)

    -- Wait for scheduled renewals to happen.
    ngx.sleep(5)

    error_log = server.nginx_error_log_tail:read()
    assert.matches("auto-ssl: checking certificate renewals for " .. server.ngrok_hostname, error_log, nil, true)
    assert.matches("Skipping renew!", error_log, nil, true)
    assert.matches("auto-ssl: checking certificate renewals for unresolvable-sdjfklsdjf.example", error_log, nil, true)
    assert.matches("Ignoring because renew was forced!", error_log, nil, true)
    assert.matches("Name does not end in a public suffix", error_log, nil, true)
    assert.matches("auto-ssl: issuing renewal certificate failed: dehydrated failure", error_log, nil, true)
    assert.matches("auto-ssl: existing certificate is expired, deleting: unresolvable-sdjfklsdjf.example", error_log, nil, true)

    -- Verify that the valid cert still remains (despite being marked as
    -- expired).
    content = assert(file.read(cert_path))
    assert.string(content)
    data = assert(cjson.decode(content))
    assert.number(data["expiry"])

    -- Verify that the failed renewal gets deleted.
    local file_content, file_err = file.read(unresolvable_cert_path)
    assert.equal(nil, file_content)
    assert.matches("No such file or directory", file_err, nil, true)

    error_log = server.read_error_log()
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("does not expose test suite libraries to test nginx server", function()
    server.start({
      auto_ssl_http_server_config = [[
        location /lib-test {
          content_by_lua_block {
            local cjson = require "cjson.safe"

            local ok, inspect = pcall(require, "inspect")
            ngx.print(cjson.encode({
              ok = ok,
              inspect = inspect,
            }))

          }
        }
      ]],
    })

    local inspect = require "inspect"
    assert.equal('"inspect"', inspect("inspect"))

    local httpc = http.new()
    local res, request_err = httpc:request_uri("http://127.0.0.1:9080/lib-test")
    assert.equal(nil, request_err)
    assert.equal(200, res.status)
    local data, err = cjson.decode(res.body)
    assert.equal(nil, err)
    assert.equal(false, data["ok"])
    assert.string(data["inspect"])
    assert.matches("not found", data["inspect"], nil, true)
  end)
end)
