use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

repeat_each(1);

plan tests => repeat_each() * (blocks() * 6);

no_long_string();

run_tests();

__DATA__

=== TEST 1: without secret
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.file",
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
  location /t {
    content_by_lua_block {
      local http = require "resty.http"

      local httpc = http.new()
      local res, err = httpc:request_uri("http://127.0.0.1:8999/", {
        method = "POST",
        body = "a=1&b=2",
        headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      ngx.say("Status: " .. res.status)
    }
  }
--- request
GET /t
--- response_body
Status: 401
--- error_log
auto-ssl: unauthorized access to hook server (hook secret did not match)
--- no_error_log
[warn]
[alert]
[emerg]

=== TEST 2: unknown path
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.file",
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
  location /t {
    content_by_lua_block {
      local http = require "resty.http"

      local httpc = http.new()
      local res, err = httpc:request_uri("http://127.0.0.1:8999/foobar", {
        method = "POST",
        body = "a=1&b=2",
        headers = {
          ["X-Hook-Secret"] = ngx.shared.auto_ssl_settings:get("hook_server:secret"),
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      ngx.say("Status: " .. res.status)
    }
  }
--- request
GET /t
--- response_body
Status: 404
--- error_log
auto-ssl: unknown request to hook server: /foobar
--- no_error_log
[warn]
[alert]
[emerg]

=== TEST 3: missing POST args
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.file",
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
  location /t {
    content_by_lua_block {
      local http = require "resty.http"

      local httpc = http.new()
      local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
        method = "POST",
        body = "foo=bar",
        headers = {
          ["X-Hook-Secret"] = ngx.shared.auto_ssl_settings:get("hook_server:secret"),
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      ngx.say("Status: " .. res.status)
    }
  }
--- request
GET /t
--- response_body
Status: 500
--- error_log
assertion failed!
--- no_error_log
[warn]
[alert]
[emerg]

=== TEST 4: POST body execeeds allowed size
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.file",
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
  location /t {
    content_by_lua_block {
      local http = require "resty.http"
      local resty_random = require "resty.random"
      local str = require "resty.string"

      local httpc = http.new()
      local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
        method = "POST",
        body = str.to_hex(resty_random.bytes(256000)),
        headers = {
          ["X-Hook-Secret"] = ngx.shared.auto_ssl_settings:get("hook_server:secret"),
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      ngx.say("Status: " .. res.status)
    }
  }
--- request
GET /t
--- response_body
Status: 413
--- error_log
client intended to send too large body
--- no_error_log
[warn]
[alert]
[emerg]

=== TEST 5: POST body execeeds buffer size
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.file",
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
    listen 127.0.0.1:8999;
    client_body_buffer_size 128k;
    client_max_body_size 1m;
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  location /t {
    content_by_lua_block {
      local http = require "resty.http"
      local resty_random = require "resty.random"
      local str = require "resty.string"

      local httpc = http.new()
      local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
        method = "POST",
        body = str.to_hex(resty_random.bytes(256000)),
        headers = {
          ["X-Hook-Secret"] = ngx.shared.auto_ssl_settings:get("hook_server:secret"),
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      ngx.say("Status: " .. res.status)
    }
  }
--- request
GET /t
--- response_body
Status: 500
--- error_log
a client request body is buffered to a temporary file
auto-ssl: failed to parse POST args: request body in temp file not supported
--- no_error_log
[alert]
[emerg]

=== TEST 6: successful deploy-challenge
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      storage_adapter = "resty.auto-ssl.storage_adapters.file",
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
  location /t {
    content_by_lua_block {
      local http = require "resty.http"
      local resty_random = require "resty.random"
      local str = require "resty.string"

      local httpc = http.new()
      local res, err = httpc:request_uri("http://127.0.0.1:8999/deploy-challenge", {
        method = "POST",
        body = "domain=example.com&token_filename=foo&token_value=bar",
        headers = {
          ["X-Hook-Secret"] = ngx.shared.auto_ssl_settings:get("hook_server:secret"),
          ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      ngx.say("Status: " .. res.status)
      ngx.say("Body:" .. res.body)

      local res, err = httpc:request_uri("http://127.0.0.1:9080/.well-known/acme-challenge/foo", {
        headers = {
          ["Host"] = "example.com",
        },
      })
      ngx.say("Challenge Status: " .. res.status)
      ngx.print("Challenge Body: " .. res.body)
    }
  }
--- request
GET /t
--- response_body
Status: 200
Body:
Challenge Status: 200
Challenge Body: bar
--- no_error_log
[error]
[warn]
[alert]
[emerg]
