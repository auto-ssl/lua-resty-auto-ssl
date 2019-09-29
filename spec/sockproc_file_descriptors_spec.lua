local cjson = require "cjson.safe"
local http = require "resty.http"
local server = require "spec.support.server"
local shell_blocking = require "shell-games"

local function get_sockproc_file_descriptors(as_user, expect_no_results)
  local result, shell_err = shell_blocking.capture({ "sudo", "-u", as_user, "lsof", "-n", "-P", "-l", "-R", "-c", "sockproc", "-a", "-d", "0-255", "-F", "pnf" })
  if expect_no_results and shell_err and result["output"] == "" then
    return {}
  end
  assert.equal(nil, shell_err)

  local lines = {}
  local index = 1
  for line in string.gmatch(result["output"], "[^\n]+") do
    if index > 1 then
      local _, err
      line, _, err = ngx.re.sub(line, "\\s*type=STREAM", "")
      assert.equal(nil, err)

      line, _, err = ngx.re.sub(line, "^n/.*logs/error.log$", "n/dev/null")
      assert.equal(nil, err)

      table.insert(lines, line)
    end

    index = index + 1
  end

  return lines
end

describe("sockproc file descriptors", function()
  before_each(server.stop)
  after_each(server.stop)

  it("does not inherit nginx file descriptors", function()
    server.start({
      auto_ssl_http_server_config = [[
        location /get-lua-root {
          content_by_lua_block {
            local cjson = require "cjson.safe"
            ngx.print(cjson.encode({
              lua_root = auto_ssl.lua_root,
            }))
          }
        }
      ]],
    })

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:9080/get-lua-root")
    assert.equal(nil, err)
    assert.equal(200, res.status)
    local data, json_err = cjson.decode(res.body)
    assert.equal(nil, json_err)
    local lua_root = data["lua_root"]
    assert.String(lua_root)

    -- Already running
    assert.same({
      "f0", "n/dev/null",
      "f1", "n/dev/null",
      "f2", "n/dev/null",
      "f3", "n/tmp/shell.sock",
    }, get_sockproc_file_descriptors("root"))

    -- sockproc not running
    server.stop_sockproc()
    assert.same({}, get_sockproc_file_descriptors("root", true))

    -- current dir as current user
    server.stop_sockproc()
    shell_blocking.capture_combined({ lua_root .. "/bin/resty-auto-ssl/start_sockproc" }, { umask = "0022" })
    assert.same({
      "f0", "n/dev/null",
      "f1", "n/dev/null",
      "f2", "n/dev/null",
      "f3", "n/tmp/shell.sock",
    }, get_sockproc_file_descriptors("root"))

    -- /tmp dir as current user
    server.stop_sockproc()
    shell_blocking.capture_combined({ lua_root .. "/bin/resty-auto-ssl/start_sockproc" }, { umask = "0022", chdir = "/tmp" })
    assert.same({
      "f0", "n/dev/null",
      "f1", "n/dev/null",
      "f2", "n/dev/null",
      "f3", "n/tmp/shell.sock",
    }, get_sockproc_file_descriptors("root"))
  end)

  it("does not inherit nginx file descriptors when nginx started from directory workers don't have permissions to", function()
    server.start({
      pwd = "/root",
      master_process = "on",
      auto_ssl_http_server_config = [[
        location /get-lua-root {
          content_by_lua_block {
            local cjson = require "cjson.safe"
            ngx.print(cjson.encode({
              lua_root = auto_ssl.lua_root,
            }))
          }
        }
      ]],
    })

    local httpc = http.new()
    local res, err = httpc:request_uri("http://127.0.0.1:9080/get-lua-root")
    assert.equal(nil, err)
    assert.equal(200, res.status)
    local data, json_err = cjson.decode(res.body)
    assert.equal(nil, json_err)
    local lua_root = data["lua_root"]
    assert.String(lua_root)

    -- Already running
    assert.same({
      "f0", "n/dev/null",
      "f1", "n/dev/null",
      "f2", "n/dev/null",
      "f3", "n/tmp/shell.sock",
    }, get_sockproc_file_descriptors(server.nobody_user))

    -- sockproc not running
    server.stop_sockproc()
    assert.same({}, get_sockproc_file_descriptors(server.nobody_user, true))

    -- current dir as current user
    server.stop_sockproc()
    shell_blocking.capture_combined({ "sudo", "-u", server.nobody_user, lua_root .. "/bin/resty-auto-ssl/start_sockproc" }, { umask = "0022" })
    assert.same({
      "f0", "n/dev/null",
      "f1", "n/dev/null",
      "f2", "n/dev/null",
      "f3", "n/tmp/shell.sock",
    }, get_sockproc_file_descriptors(server.nobody_user))

    -- /tmp dir as current user
    server.stop_sockproc()
    shell_blocking.capture_combined({ "sudo", "-u", server.nobody_user, lua_root .. "/bin/resty-auto-ssl/start_sockproc" }, { umask = "0022", chdir = "/tmp" })
    assert.same({
      "f0", "n/dev/null",
      "f1", "n/dev/null",
      "f2", "n/dev/null",
      "f3", "n/tmp/shell.sock",
    }, get_sockproc_file_descriptors(server.nobody_user))
  end)
end)
