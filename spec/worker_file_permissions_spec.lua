local cjson = require "cjson.safe"
local http = require "resty.http"
local server = require "spec.support.server"
local shell_blocking = require "shell-games"

describe("worker file permissions", function()
  it("creates file with expected permissions", function()
    server.start({
      master_process = "on",
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

    local result, err = shell_blocking.capture_combined({ "find", server.current_test_dir .. "/auto-ssl", "-printf", [[./%P %u %g %m %y\n]] })
    assert.equal(nil, err)

    local output = string.gsub(result["output"], "%s+$", "")
    local lines = {}
    for line in string.gmatch(output, "[^\n]+") do
      table.insert(lines, line)
    end
    table.sort(lines)

    assert.same({
      "./ nobody root 755 d",
      "./letsencrypt root root 777 d",
      "./letsencrypt/.acme-challenges nobody nobody 755 d",
      "./letsencrypt/accounts nobody nobody 700 d",
      "./letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK nobody nobody 700 d",
      "./letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK/account_key.pem nobody nobody 600 f",
      "./letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK/registration_info.json nobody nobody 600 f",
      "./letsencrypt/certs nobody nobody 700 d",
      "./letsencrypt/chains nobody nobody 700 d",
      "./letsencrypt/chains/0a3654cf.chain nobody nobody 600 f",
      "./letsencrypt/conf.d root root 755 d",
      "./letsencrypt/config root root 644 f",
      "./letsencrypt/locks nobody nobody 755 d",
      "./storage nobody nobody 755 d",
      "./storage/file nobody nobody 700 d",
      "./storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest") .. " nobody nobody 644 f",
      "./tmp root root 777 d",
    }, lines)
  end)
end)
