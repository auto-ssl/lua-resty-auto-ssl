use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

repeat_each(1);

plan tests => repeat_each() * (5 + 6);

no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: writes a friendly error message when auto_ssl_settings dict is missing
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
    })
    auto_ssl:init()
  }
--- config
--- timeout: 30s
--- request
GET /
--- must_die
--- ignore_response
--- error_log
auto-ssl: dict auto_ssl_settings could not be found. Please add it to your configuration: `lua_shared_dict auto_ssl_settings 64k;`
--- no_error_log
[warn]
[alert]
[emerg]

=== TEST 2: doesn't change the hook secret after reloading
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
    })
    auto_ssl:init()
  }

  init_worker_by_lua_block {
    auto_ssl:init_worker()
  }

--- config
  location /t {
    content_by_lua_block {
      local secret1 = ngx.shared.auto_ssl_settings:get("hook_server:secret")
      auto_ssl:init()
      local secret2 = ngx.shared.auto_ssl_settings:get("hook_server:secret")

      if secret1 == secret2 then
        ngx.say("OK")
      else
        ngx.say("NOPE")
      end
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
OK
--- error_log
--- no_error_log
[warn]
[error]
[alert]
[emerg]
