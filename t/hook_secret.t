use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

repeat_each(1);

plan tests => repeat_each() * (5);

no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: writes a friendly error message when auto_ssl_settings dict is missing
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;

  init_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
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
