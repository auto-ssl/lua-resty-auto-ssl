local http = require "resty.http"
local resty_random = require "resty.random"
local server = require "spec.support.server"
local str = require "resty.string"

local function get_hook_secret()
  local httpc = http.new()
  local res, err = httpc:request_uri("http://127.0.0.1:9080/hook-server-secret")
  assert.equal(nil, err)
  assert.equal(200, res.status)
  assert.string(res.body)
  assert.equal(64, string.len(res.body))

  return res.body
end

describe("hook server", function()
  before_each(server.stop)
  after_each(server.stop)

  it("without secret", function()
    server.start()

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
      method = "POST",
      body = "a=1&b=2",
      headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    assert.equal(nil, err)
    assert.equal(401, res.status)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: unauthorized access to hook server (hook secret did not match)", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("unknown path", function()
    server.start()

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:8999/foobar", {
      method = "POST",
      body = "a=1&b=2",
      headers = {
        ["X-Hook-Secret"] = get_hook_secret(),
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    assert.equal(nil, err)
    assert.equal(404, res.status)

    local error_log = server.read_error_log()
    assert.matches("auto-ssl: unknown request to hook server: /foobar", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("missing POST args", function()
    server.start()

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
      method = "POST",
      body = "foo=bar",
      headers = {
        ["X-Hook-Secret"] = get_hook_secret(),
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    assert.equal(nil, err)
    assert.equal(500, res.status)

    local error_log = server.read_error_log()
    assert.matches("assertion failed!", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("POST body execeeds allowed size", function()
    server.start()

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
      method = "POST",
      body = str.to_hex(resty_random.bytes(256000)),
      headers = {
        ["X-Hook-Secret"] = get_hook_secret(),
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    assert.equal(nil, err)
    assert.equal(413, res.status)

    local error_log = server.read_error_log()
    assert.matches("client intended to send too large body", error_log, nil, true)
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("POST body execeeds buffer size", function()
    server.start({
      hook_server = {
        client_max_body_size = "1m",
      },
    })

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
      method = "POST",
      body = str.to_hex(resty_random.bytes(256000)),
      headers = {
        ["X-Hook-Secret"] = get_hook_secret(),
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    assert.equal(nil, err)
    assert.equal(500, res.status)

    local error_log = server.read_error_log()
    assert.matches("a client request body is buffered to a temporary file", error_log, nil, true)
    if ngx.config.ngx_lua_version < 10008 then -- v0.10.8
      assert.matches("auto-ssl: failed to parse POST args: requesty body in temp file not supported", error_log, nil, true)
    else
      assert.matches("auto-ssl: failed to parse POST args: request body in temp file not supported", error_log, nil, true)
    end
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)

  it("successful deploy-challenge", function()
    server.start()

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
      method = "POST",
      body = "domain=example.com&token_filename=foo&token_value=bar",
      headers = {
        ["X-Hook-Secret"] = get_hook_secret(),
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    assert.equal(nil, err)
    assert.equal(200, res.status)
    assert.equal("", res.body)

    local challenge_res, challenge_err = httpc:request_uri("http://127.0.0.1:9080/.well-known/acme-challenge/foo", {
      headers = {
        ["Host"] = "example.com",
      },
    })
    assert.equal(nil, challenge_err)
    assert.equal(200, challenge_res.status)
    assert.equal("bar\n", challenge_res.body)

    local error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
