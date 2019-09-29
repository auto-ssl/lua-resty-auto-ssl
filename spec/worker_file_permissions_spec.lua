local http = require "resty.http"
local server = require "spec.support.server"
local shell_blocking = require "shell-games"

describe("worker file permissions", function()
  before_each(server.stop)
  after_each(server.stop)

  it("creates file with expected permissions", function()
    server.start({
      master_process = "on",
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

    local result, shell_err = shell_blocking.capture_combined({ "find", server.current_test_dir .. "/auto-ssl", "-printf", [[./%P %u %g %m %y\n]] })
    assert.equal(nil, shell_err)

    local output = string.gsub(result["output"], "%s+$", "")
    local lines = {}
    for line in string.gmatch(output, "[^\n]+") do
      table.insert(lines, line)
    end
    table.sort(lines)

    assert.same({
      "./ nobody root 755 d",
      "./letsencrypt root root 777 d",
      "./letsencrypt/.acme-challenges " .. server.nobody_user .. " " .. server.nobody_group .. " 755 d",
      "./letsencrypt/accounts " .. server.nobody_user .. " " .. server.nobody_group .. " 700 d",
      "./letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK " .. server.nobody_user .. " " .. server.nobody_group .. " 700 d",
      "./letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK/account_key.pem " .. server.nobody_user .. " " .. server.nobody_group .. " 600 f",
      "./letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK/registration_info.json " .. server.nobody_user .. " " .. server.nobody_group .. " 600 f",
      "./letsencrypt/certs " .. server.nobody_user .. " " .. server.nobody_group .. " 700 d",
      "./letsencrypt/chains " .. server.nobody_user .. " " .. server.nobody_group .. " 700 d",
      "./letsencrypt/chains/0a3654cf.chain " .. server.nobody_user .. " " .. server.nobody_group .. " 600 f",
      "./letsencrypt/conf.d root root 755 d",
      "./letsencrypt/config root root 644 f",
      "./letsencrypt/locks " .. server.nobody_user .. " " .. server.nobody_group .. " 755 d",
      "./storage " .. server.nobody_user .. " " .. server.nobody_group .. " 755 d",
      "./storage/file " .. server.nobody_user .. " " .. server.nobody_group .. " 700 d",
      "./storage/file/" .. ngx.escape_uri(server.ngrok_hostname .. ":latest") .. " " .. server.nobody_user .. " " .. server.nobody_group .. " 644 f",
      "./tmp root root 777 d",
    }, lines)
  end)
end)
