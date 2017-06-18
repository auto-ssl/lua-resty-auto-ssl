use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

# Since master_on is enabled, if the tests are being run as root, then set the
# nginx "user" to root (so it doesn't default to the separate "nobody" user,
# which interferes with some of the expected permissions).
my ($current_user, $current_passwd, $current_uid, $current_gid) = getpwuid($>);
if($current_user eq "root") {
  my $current_group = getgrgid($current_gid);
  $ENV{TEST_NGINX_USER} = "user $current_user $current_group;";
} else {
  $ENV{TEST_NGINX_USER} = "";
}

# Run more times than normal to make sure there's no weird concurrency issues
# across multiple workers.
repeat_each(10);

master_on();
workers(5);
worker_connections(1024);

plan tests => repeat_each() * (blocks() * 6);

no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: issues a new SSL certificate when multiple nginx workers are running and concurrent requests are made
--- main_config
$TEST_NGINX_USER
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;
  lua_shared_dict test_counts 128k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return true
      end,
    })
    auto_ssl:init()
  }

  init_worker_by_lua_block {
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.crt;
    ssl_certificate_key $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.key;
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate()
    }

    location /foo {
      echo -n "foo";
    }
  }

  server {
    listen 9080;
    location /.well-known/acme-challenge/ {
      content_by_lua_block {
        auto_ssl:challenge_server()
      }
    }
  }

  server {
    listen 127.0.0.1:8999;
    client_body_buffer_size 128k;
    client_max_body_size 128k;
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate $TEST_NGINX_ROOT_DIR/t/certs/letsencrypt_staging_chain.pem;
  lua_ssl_verify_depth 5;
  location /t {
    content_by_lua_block {
      local host = "$TEST_NGINX_NGROK_HOSTNAME"

      -- Since repeat_each is being used, clear the cached information across
      -- test runs so we try to issue a new cert each time.
      ngx.log(ngx.DEBUG, "auto-ssl: delete: domain:fullchain_der:" .. host)
      ngx.shared.auto_ssl:flush_all()
      ngx.shared.test_counts:flush_all()
      os.execute("rm -rf $TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/*")

      local http = require "resty.http"

      local function make_http_requests()
        local httpc = http.new()

        local _, err = httpc:set_timeout(30000)
        if err then ngx.say("http set_timeout error", err); return end
        local _, err = httpc:connect("127.0.0.1", 9443)
        if err then ngx.say("http connect error: ", err); return end
        local _, err = httpc:ssl_handshake(nil, host, true)
        if err then ngx.say("http ssl_handshake error: ", err); return end

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
        if err then ngx.say("http error: ", err); return end

        for _, res in ipairs(responses) do
          local body, err = res:read_body()
          if err then ngx.say("http read_body error: ", err); return end

          -- Keep track of the total number of successful requests across all
          -- the parallel requests.
          if res.status == 200 and body == "foo" then
            local _, err = ngx.shared.test_counts:incr("successes", 1)
            if err then ngx.say("incr error: ", err); return end
          else
            ngx.say("Unexpected Response: " .. res.status .. " Body: " .. body)
          end
        end

        local _, err = httpc:close()
        if err then ngx.say("http close error: ", err); return end
      end

      local _, err = ngx.shared.test_counts:set("successes", 0)
      if err then ngx.say("set error: ", err); return end

      -- Make 50 concurrent requests to see how separate connections are
      -- handled during initial registration.
      local threads = {}
      for i = 1, 50 do
        table.insert(threads, ngx.thread.spawn(make_http_requests))
      end
      for _, thread in ipairs(threads) do
        ngx.thread.wait(thread)
      end

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
      ngx.say("Successes: ", ngx.shared.test_counts:get("successes"))
    }
  }
--- timeout: 120s
--- request
GET /t
--- response_body
Successes: 1000
--- error_log
auto-ssl: issuing new certificate for
--- no_error_log
[error]
[alert]
[emerg]
