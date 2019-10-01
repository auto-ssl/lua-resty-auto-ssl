local cjson = require "cjson.safe"
local file = require "pl.file"
local http = require "resty.http"
local server = require "spec.support.server"
local shell_blocking = require "shell-games"

describe("expiry", function()
  before_each(server.stop)
  after_each(server.stop)

  it("stores the expiry date on issuance", function()
    server.start()

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
    assert.matches("issuing new certificate for " .. server.ngrok_hostname, error_log, nil, true)
    assert.Not.matches("auto-ssl: checking certificate renewals for " .. server.ngrok_hostname, error_log, nil, true)
    assert.Not.matches("failed to get the expiry date", error_log, nil, true)

    local cert_path = server.current_test_dir .. "/auto-ssl/storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest")
    local content = assert(file.read(cert_path))
    assert.string(content)
    local data = assert(cjson.decode(content))
    assert.number(data["expiry"])
    assert(data["expiry"] > 0, data["expiry"] .. " is not greater than 0")
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
end)
