use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4);

our $CWD = cwd();

no_long_string();

$ENV{TEST_NGINX_LUA_PACKAGE_PATH} = "$::CWD/lib/?.lua;;";

run_tests();

__DATA__

=== TEST 1: SSL registration
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    local auto_ssl = require "lib.resty.auto-ssl"
    auto_ssl.allow_domain = function()
      return true
    end
    auto_ssl.init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate /tmp/test.crt;
    ssl_certificate_key /tmp/test.key;
    ssl_certificate_by_lua_block {
      local auto_ssl = require "lib.resty.auto-ssl"
      auto_ssl.ssl_certificate()
    }
  }

  server {
    listen 9080;
    location /.well-known/acme-challenge/ {
      content_by_lua_block {
        local auto_ssl = require "lib.resty.auto-ssl"
        auto_ssl.challenge_server()
      }
    }
  }

  server {
    listen 127.0.0.1:8999;
    location / {
      content_by_lua_block {
        local auto_ssl = require "lib.resty.auto-ssl"
        auto_ssl.hook_server()
      }
    }
  }
--- config
  location /t {
    content_by_lua_block {
    }
  }
--- request
GET /t
--- no_error_log
[error]
[lua]
