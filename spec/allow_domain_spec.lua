local cjson = require "cjson.safe"
local file = require "pl.file"
local http = require "resty.http"
local server = require "spec.support.server"

describe("allow_domain", function()
  before_each(server.stop)
  after_each(server.stop)

  it("verifies domain from remote server", function()
    server.start({
      auto_ssl_pre_new = [[
        options["allow_domain"] = function(domain)
          if ngx.re.match(domain, "^([0-9]\\.[0-9]\\.[0-9]\\.[0-9])$", "ijo") then
            return false
          elseif ngx.re.match(domain, "(amazonaws.com|google-analytics.com)$", "ijo") then
            return false
          end

          local httpc = (require "resty.http").new()
          local cjson = (require "cjson")
  
          local url = "http://localhost:3000/domains?d=" .. domain
          httpc:set_timeout(10000)
          local res, req_err = httpc:request_uri(url, {
            ssl_verify = false,
            method = "GET"
          })
  
          if not res then
            ngx.log(ngx.ERR, "Verification failed (" .. (url or "") .. "): " .. (req_err or ""))
            return false
          end
  
          if res.status ~= 200 then
            ngx.log(ngx.ERR, "Verification returns bad HTTP status code (" .. (url or "") .. "): " .. (res.status or ""))
            return false
          end
  
          local resp = res.body
          if not resp or resp == "" then
            ngx.log(ngx.ERR, "Verification returns bad response body (" .. (url or "") .. "): " .. (resp or ""))
            return false
          end
  
          local data = cjson.decode(resp)
          if not data["valid"] then
            ngx.log(ngx.ERR, "Invalid domain: " .. domain)
            return false
          end
          return true
        end
      ]],
    })

    local httpc = http.new()
    local _, connect_err = httpc:connect("127.0.0.1", 9443)
    assert.equal(nil, connect_err)

    local _, ssl_err = httpc:ssl_handshake(nil, server.ngrok_hostname, true)
    assert.equal(nil, ssl_err)
  end)
end)