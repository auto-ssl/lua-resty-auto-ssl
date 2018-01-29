use strict;
use warnings;
use Test::Nginx::Socket::Lua;
use File::Path qw(make_path);
require "./t/inc/setup.pl";
AutoSsl::setup();

make_path("$ENV{TEST_NGINX_RESTY_AUTO_SSL_DIR}/redis");
my $redis = Expect->spawn("redis-server ./t/config/redis.conf") or die "failed to spawn redis-server: $!";
$redis->log_stdout(0);
$redis->expect(10, "now ready") or die "failed to start redis: " . $redis->exp_before();

repeat_each(1);

plan tests => repeat_each() * (blocks() * 7);

check_accum_error_log();
no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: issues a new SSL certificate and stores it in redis
--- http_config
  lua_package_path '$TEST_NGINX_LUA_SHARE_DIR/?.lua;;';

  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.redis",
      json_adapter = "resty.auto-ssl.json_adapters.dkjson",
      redis = {
        port = 9999,
      },
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
      server_tokens off;
      more_clear_headers Date;
      echo "foo";
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
      local redis = require "resty.redis"
      local r = redis:new()
      local ok, err = r:connect("127.0.0.1", 9999)
      if not ok then
        ngx.say("failed to connect to redis: ", err)
      end

      local res, err = r:set("$TEST_NGINX_NGROK_HOSTNAME:latest", '{"invalid_json"')
      if err then
        ngx.say("failed to set data in redis: ", err)
        return
      end

      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, "$TEST_NGINX_NGROK_HOSTNAME", true)
      if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
      end

      local req = "GET /foo HTTP/1.0\r\nHost: $TEST_NGINX_NGROK_HOSTNAME\r\nConnection: close\r\n\r\n"
      local bytes, err = sock:send(req)
      if not bytes then
        ngx.say("failed to send http request: ", err)
        return
      end

      while true do
        local line, err = sock:receive()
        if not line then
          break
        end

        ngx.say("received: ", line)
      end

      local ok, err = sock:close()
      if not ok then
        ngx.say("failed to close: ", err)
        return
      end

      local redis = require "resty.redis"
      local r = redis:new()
      local ok, err = r:connect("127.0.0.1", 9999)
      if not ok then
        ngx.say("failed to connect to redis: ", err)
      end

      local res, err = r:get("$TEST_NGINX_NGROK_HOSTNAME:latest")
      if err then
        ngx.say("failed to fetch from redis: ", err)
        return
      end

      ngx.say("latest cert: " .. type(res))

      local cjson = require "cjson"
      local data = cjson.decode(res)
      ngx.say("latest cert fullchain_pem: " .. type(data["fullchain_pem"]))
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
received: HTTP/1.1 200 OK
received: Server: openresty
received: Content-Type: text/plain
received: Connection: close
received: 
received: foo
latest cert: string
latest cert fullchain_pem: string
--- error_log eval
[
  "auto-ssl: error fetching certificate from storage for $ENV{TEST_NGINX_NGROK_HOSTNAME}: unterminated object at line 1, column 1",
  "auto-ssl: issuing new certificate for",
]
--- no_error_log
[warn]
[alert]
[emerg]
