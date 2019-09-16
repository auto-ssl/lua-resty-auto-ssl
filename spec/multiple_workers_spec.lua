local cjson = require "cjson.safe"
local http = require "resty.http"
local server = require "spec.support.server"

local function make_http_requests()
  local httpc = http.new()

  local _, err = httpc:connect("127.0.0.1", 9443)
  assert.equal(nil, err)

  local _, err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
  assert.equal(nil, err)

  -- Make pipelined requests on this connection to test behavior across
  -- the same connection.
  local requests = {}
  for i = 1, 10 do
    table.insert(requests, {
      path = "/foo",
      headers = { ["Host"] = host },
    })
  end

  local responses, err = httpc:request_pipeline(requests)
  assert.equal(nil, err)

  for _, res in ipairs(responses) do
    assert.equal(200, res.status)

    local body, err = res:read_body()
    assert.equal(nil, err)
    assert.equal("foo", body)

    -- Keep track of the total number of successful requests across all
    -- the parallel requests.
    if res.status == 200 and body == "foo" then
      local _, err = ngx.shared.test_counts:incr("successes", 1)
      assert.equal(nil, err)
    end
  end

  local _, err = httpc:close()
  assert.equal(nil, err)
end

describe("multiple workers", function()
  it("issues a new SSL certificate when multiple nginx workers are running and concurrent requests are made", function()
    server.start({
      master_process = "on",
      worker_processes = 5,
    })

    local _, err = ngx.shared.test_counts:set("successes", 0)
    assert.equal(nil, err)

    -- Make 50 concurrent requests to see how separate connections are
    -- handled during initial registration.
    local threads = {}
    for i = 1, 50 do
      table.insert(threads, ngx.thread.spawn(make_http_requests))
    end
    for _, thread in ipairs(threads) do
      ngx.thread.wait(thread)
    end

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("issuing new certificate for", error_log, nil, true)

    -- Make some more concurrent requests after waiting for the first batch
    -- to succeed. All of these should then be dealing with the cached certs.
    local threads = {}
    for i = 1, 50 do
      table.insert(threads, ngx.thread.spawn(make_http_requests))
    end
    for _, thread in ipairs(threads) do
      ngx.thread.wait(thread)
    end

    -- Report the total number of successful requests across all the parallel
    -- requests to make sure it matches what's expected.
    assert.equal(1000, ngx.shared.test_counts:get("successes"))

    local error_log = server.nginx_error_log_tail:read()
    assert.Not.matches("issuing new certificate for", error_log, nil, true)

    local error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
