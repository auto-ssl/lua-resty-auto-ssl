local http = require "resty.http"
local server = require "spec.support.server"

local function make_http_requests()
  local httpc = http.new()

  local _, connect_err = httpc:connect("127.0.0.1", 9443)
  assert.equal(nil, connect_err)

  local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
  assert.equal(nil, ssl_err)

  -- Make pipelined requests on this connection to test behavior across
  -- the same connection.
  local requests = {}
  for _ = 1, 10 do
    table.insert(requests, {
      path = "/foo",
    })
  end

  local responses, request_err = httpc:request_pipeline(requests)
  assert.equal(nil, request_err)

  for _, res in ipairs(responses) do
    assert.equal(200, res.status)

    local body, body_err = res:read_body()
    assert.equal(nil, body_err)
    assert.equal("foo", body)

    -- Keep track of the total number of successful requests across all
    -- the parallel requests.
    if res.status == 200 and body == "foo" then
      local _, incr_err = ngx.shared.test_counts:incr("successes", 1)
      assert.equal(nil, incr_err)
    end
  end

  local _, close_err = httpc:close()
  assert.equal(nil, close_err)
end

describe("multiple workers", function()
  before_each(server.stop)
  after_each(server.stop)

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
    for _ = 1, 50 do
      table.insert(threads, ngx.thread.spawn(make_http_requests))
    end
    for _, thread in ipairs(threads) do
      ngx.thread.wait(thread)
    end

    local error_log = server.nginx_error_log_tail:read()
    assert.matches("issuing new certificate for", error_log, nil, true)

    -- Make some more concurrent requests after waiting for the first batch
    -- to succeed. All of these should then be dealing with the cached certs.
    threads = {}
    for _ = 1, 50 do
      table.insert(threads, ngx.thread.spawn(make_http_requests))
    end
    for _, thread in ipairs(threads) do
      ngx.thread.wait(thread)
    end

    -- Report the total number of successful requests across all the parallel
    -- requests to make sure it matches what's expected.
    assert.equal(1000, ngx.shared.test_counts:get("successes"))

    error_log = server.nginx_error_log_tail:read()
    assert.Not.matches("issuing new certificate for", error_log, nil, true)

    error_log = server.read_error_log()
    assert.Not.matches("[warn]", error_log, nil, true)
    assert.Not.matches("[error]", error_log, nil, true)
    assert.Not.matches("[alert]", error_log, nil, true)
    assert.Not.matches("[emerg]", error_log, nil, true)
  end)
end)
