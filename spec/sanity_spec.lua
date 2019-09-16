local cjson = require "cjson.safe"
local http = require "resty.http"
local server = require "spec.support.server"

describe("sanity", function()
  before_each(server.stop)
  after_each(server.stop)

  it("issues a new SSL certificate and returns existing ones", function()
    server.start()

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
    assert.matches("issuing new certificate for", error_log, nil, true)

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

  it("returns the fallback SSL certificate when SNI isn't used", function()
    server.start()

    local httpc = http.new()
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, nil, true)
    assert.equal("18: self signed certificate", err)

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
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", err)

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
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", err)

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
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", err)

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
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, "not-ours-" .. server.ngrok_hostname, true)
    assert.equal("18: self signed certificate", err)

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
    local _, err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, err)

    local _, err = httpc:ssl_handshake(nil, "unresolvable-sdjfklsdjf.example", true)
    assert.equal("18: self signed certificate", err)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: issuing new certificate for unresolvable-sdjfklsdjf.example", error_log, nil, true)
    assert.matches("auto-ssl: dehydrated failed", error_log, nil, true)
    assert.matches("auto-ssl: could not get certificate for unresolvable-sdjfklsdjf.example", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
