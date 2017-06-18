use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

repeat_each(1);

plan tests => repeat_each() * (blocks() * 7);

no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: logs when running out of memory in shared dict
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

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
      local http = require "resty.http"
      local resty_random = require "resty.random"
      local str = require "resty.string"

      -- Fill the shdict with random things to simulate what happens when old
      -- data gets forced out.
      for i = 1, 15 do
        local random = resty_random.bytes(256000)
        local _, err = ngx.shared.auto_ssl:set("foobar" .. i, str.to_hex(random))
        if err then ngx.say("set error: ", err); return end
      end

      -- Ensure items are getting forced out as expected, after filling it up.
      local random = resty_random.bytes(256000)
      local _, err, forcible = ngx.shared.auto_ssl:set("foobar-force", str.to_hex(random))
      if err then ngx.say("set error: ", err); return end
      if not forcible then ngx.say("set didn't force other items out of shdict, as expected"); return end

      -- Ensure we can make a successful request.
      local httpc = http.new()
      local host = "$TEST_NGINX_NGROK_HOSTNAME"
      local _, err = httpc:set_timeout(30000)
      if err then ngx.say("http set_timeout error", err); return end
      local _, err = httpc:connect("127.0.0.1", 9443)
      if err then ngx.say("http connect error: ", err); return end
      local _, err = httpc:ssl_handshake(nil, host, true)
      if err then ngx.say("http ssl_handshake error: ", err); return end

      local res, err = httpc:request({
        path = "/foo",
        headers = { ["Host"] = host },
      })
      local body, err = res:read_body()
      if err then ngx.say("http read_body error: ", err); return end

      ngx.say("Status: " .. res.status)
      ngx.say("Body: " .. body)
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
Status: 200
Body: foo
--- error_log
auto-ssl: issuing new certificate for
'lua_shared_dict auto_ssl' might be too small
--- no_error_log
[warn]
[alert]
[emerg]

=== TEST 2: can issue a new certificate after all memory is flushed
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

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
      local http = require "resty.http"
      local resty_random = require "resty.random"
      local str = require "resty.string"

      -- Completely wipe certs from storage, to simulate a new registration
      -- after completely running out of memory.
      ngx.shared.auto_ssl:flush_all()
      os.execute("rm -rf $TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/*")
      os.execute("rm -rf $TEST_NGINX_RESTY_AUTO_SSL_DIR/letsencrypt/certs/*")

      -- Ensure we can make a successful request.
      local httpc = http.new()
      local host = "$TEST_NGINX_NGROK_HOSTNAME"
      local _, err = httpc:set_timeout(30000)
      if err then ngx.say("http set_timeout error", err); return end
      local _, err = httpc:connect("127.0.0.1", 9443)
      if err then ngx.say("http connect error: ", err); return end
      local _, err = httpc:ssl_handshake(nil, host, true)
      if err then ngx.say("http ssl_handshake error: ", err); return end

      local res, err = httpc:request({
        path = "/foo",
        headers = { ["Host"] = host },
      })
      local body, err = res:read_body()
      if err then ngx.say("http read_body error: ", err); return end

      ngx.say("Status: " .. res.status)
      ngx.say("Body: " .. body)
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
Status: 200
Body: foo
--- error_log
auto-ssl: issuing new certificate for
--- no_error_log
[warn]
[error]
[alert]
[emerg]
