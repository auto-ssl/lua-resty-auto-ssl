use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

repeat_each(1);

plan tests => repeat_each() * (blocks() * 7 + 12);

check_accum_error_log();
no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: issues a new SSL certificate
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
--- error_log
auto-ssl: issuing new certificate for
--- no_error_log
[warn]
[error]
[alert]
[emerg]

=== TEST 2: returns an existing SSL certificate
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
--- error_log
--- no_error_log
[warn]
[error]
[alert]
[emerg]
issuing new certificate for

=== TEST 3: returns the fallback SSL certificate when SNI isn't used
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
      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, nil, true)
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
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 18: self signed certificate
--- error_log
auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - 
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 4: disallows all domains for registration by default
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
      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, "default-disallow-$TEST_NGINX_NGROK_HOSTNAME", true)
      if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
      end

      local req = "GET /foo HTTP/1.0\r\nHost: default-disallow-$TEST_NGINX_NGROK_HOSTNAME\r\nConnection: close\r\n\r\n"
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
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 18: self signed certificate
--- error_log
auto-ssl: domain not allowed - using fallback - default-disallow-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 5: calls the allow_domain function which can perform more complex logic
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        ngx.log(ngx.INFO, "allow_domain called")
        if string.find(domain, "not-going-to-find") then
          return true
        else
          return false
        end
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
      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, "allow-domain-fn-check-$TEST_NGINX_NGROK_HOSTNAME", true)
      if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
      end

      local req = "GET /foo HTTP/1.0\r\nHost: allow-domain-fn-check-$TEST_NGINX_NGROK_HOSTNAME\r\nConnection: close\r\n\r\n"
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
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 18: self signed certificate
--- error_log
allow_domain called
auto-ssl: domain not allowed - using fallback - allow-domain-fn-check-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 6: options can also be set with the set() function after new()
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new()
    auto_ssl:set("dir", "$TEST_NGINX_RESTY_AUTO_SSL_DIR")
    auto_ssl:set("ca", "https://acme-staging.api.letsencrypt.org/directory")
    auto_ssl:set("allow_domain", function(domain)
      ngx.log(ngx.INFO, "allow_domain set() called")
      if string.find(domain, "not-going-to-find") then
        return true
      else
        return false
      end
    end)
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
      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, "set-options-fn-$TEST_NGINX_NGROK_HOSTNAME", true)
      if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
      end

      local req = "GET /foo HTTP/1.0\r\nHost: set-options-fn-$TEST_NGINX_NGROK_HOSTNAME\r\nConnection: close\r\n\r\n"
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
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 18: self signed certificate
--- error_log
allow_domain set() called
auto-ssl: domain not allowed - using fallback - set-options-fn-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 7: returns the fallback SSL certificate when the domain is allowed and valid, but the domain challenge fails
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return string.find(domain, "ngrok.io")
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
      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, "not-ours-$TEST_NGINX_NGROK_HOSTNAME", true)
      if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
      end

      local req = "GET /foo HTTP/1.0\r\nHost: not-ours-$TEST_NGINX_NGROK_HOSTNAME\r\nConnection: close\r\n\r\n"
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
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 18: self signed certificate
--- error_log
auto-ssl: issuing new certificate for not-ours-
auto-ssl: dehydrated failed
auto-ssl: could not get certificate for not-ours-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 8: returns the fallback SSL certificate when the domain is allowed, but not resolvable
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
      local sock = ngx.socket.tcp()
      sock:settimeout(30000)
      local ok, err = sock:connect("127.0.0.1:9443")
      if not ok then
        ngx.say("failed to connect: ", err)
        return
      end

      local sess, err = sock:sslhandshake(nil, "unresolvable-sdjfklsdjf.example", true)
      if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
      end

      local req = "GET /foo HTTP/1.0\r\nHost: unresolvable-sdjfklsdjf.example\r\nConnection: close\r\n\r\n"
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
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 18: self signed certificate
--- error_log
auto-ssl: issuing new certificate for unresolvable-
auto-ssl: dehydrated failed
auto-ssl: could not get certificate for unresolvable-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 9: allows for custom logic to control domain name to handle lack of SNI support
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      request_domain = function(ssl, ssl_options)
        local domain, err = ssl.server_name()
        if (not domain or err) and ssl_options and ssl_options["port"] then
          if ssl_options["port"] == 9443 then
            domain = "non-sni-" .. ssl_options["port"] .. "-$TEST_NGINX_NGROK_HOSTNAME"
          elseif ssl_options["port"] == 9444 then
            domain = "non-sni-mismatch-" .. ssl_options["port"] .. "-$TEST_NGINX_NGROK_HOSTNAME"
          elseif ssl_options["port"] == 9446 then
            domain = "non-sni-disallowed-" .. ssl_options["port"] .. "-$TEST_NGINX_NGROK_HOSTNAME"
          end
        end

        return domain, err
      end,
      allow_domain = function(domain, auto_ssl, ssl_options)
        if ssl_options and ssl_options["port"] == 9446 then
          return false
        else
          return true
        end
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
      auto_ssl:ssl_certificate({ port = 9443 })
    }

    location /foo {
      server_tokens off;
      more_clear_headers Date;
      echo "foo";
    }
  }

  server {
    listen 9444 ssl;
    ssl_certificate $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.crt;
    ssl_certificate_key $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.key;
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate({ port = 9444 })
    }

    location /foo {
      server_tokens off;
      more_clear_headers Date;
      echo "foo";
    }
  }

  server {
    listen 9445 ssl;
    ssl_certificate $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.crt;
    ssl_certificate_key $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.key;
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate({ port = 9445 })
    }

    location /foo {
      server_tokens off;
      more_clear_headers Date;
      echo "foo";
    }
  }

  server {
    listen 9446 ssl;
    ssl_certificate $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.crt;
    ssl_certificate_key $TEST_NGINX_ROOT_DIR/t/certs/example_fallback.key;
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate({ port = 9446 })
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
      local ports = { 9443, 9444, 9445, 9446 }
      for _, port in ipairs(ports) do
        local sock = ngx.socket.tcp()
        sock:settimeout(30000)
        local ok, err = sock:connect("127.0.0.1:" .. port)
        if not ok then
          ngx.say("failed to connect: " .. port .. ": ", err)
          goto continue
        end

        local sess, err = sock:sslhandshake(nil, nil, true)
        if not sess then
          ngx.say("failed to do SSL handshake: " .. port .. ": ", err)
          goto continue
        end

        local req = "GET /foo HTTP/1.0\r\nHost: non-sni-" .. port .. "-$TEST_NGINX_NGROK_HOSTNAME\r\nConnection: close\r\n\r\n"
        local bytes, err = sock:send(req)
        if not bytes then
          ngx.say("failed to send http request: " .. port .. ": ", err)
          goto continue
        end

        while true do
          local line, err = sock:receive()
          if not line then
            goto continue
          end

          ngx.say("received: " .. port .. ": ", line)
        end

        local ok, err = sock:close()
        if not ok then
          ngx.say("failed to close: " .. port .. ": ", err)
          goto continue
        end

        ::continue::
      end
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
failed to do SSL handshake: 9443: 18: self signed certificate
failed to do SSL handshake: 9444: 18: self signed certificate
failed to do SSL handshake: 9445: 18: self signed certificate
failed to do SSL handshake: 9446: 18: self signed certificate
--- error_log
auto-ssl: issuing new certificate for non-sni-9443-
lua ssl certificate verify error: (18: self signed certificate)
auto-ssl: issuing new certificate for non-sni-mismatch-9444-
lua ssl certificate verify error: (18: self signed certificate)
auto-ssl: could not determine domain for request (SNI not supported?) - using fallback - 
lua ssl certificate verify error: (18: self signed certificate)
auto-ssl: domain not allowed - using fallback - non-sni-disallowed-9446-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 10: deletes dehydrated temporary files after successful cert deployment
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
      local shell_blocking = require "shell-games"
      local result, err = shell_blocking.capture_combined({ "find", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/dehydrated/certs", "-maxdepth", "1", "-name", "$TEST_NGINX_NGROK_HOSTNAME" })
      if err then
        ngx.say("failed to list certs directory: ", err)
        return nil, err
      end
      ngx.say("cert: " .. tostring(#result["output"] > 0))

      -- Delete the stored files and wipe the in-memory cache.
      local _, err = shell_blocking.capture_combined({ "rm", "-rf", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest") })
      if err then
        ngx.say("failed to delete cert: ", err)
        return nil, err
      end
      local keys = ngx.shared.auto_ssl:get_keys()
      for _, key in ipairs(keys) do
        if key ~= "hook_server:secret" and key ~= "sockproc_started" then
          ngx.shared.auto_ssl:delete(key)
        end
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

      local result, err = shell_blocking.capture_combined({ "find", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/dehydrated/certs", "-maxdepth", "1", "-name", "$TEST_NGINX_NGROK_HOSTNAME" })
      if err then
        ngx.say("failed to list certs directory: ", err)
        return nil, err
      end
      ngx.say("cert: " .. tostring(#result["output"] > 0))
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
cert: false
received: HTTP/1.1 200 OK
received: Server: openresty
received: Content-Type: text/plain
received: Connection: close
received: 
received: foo
cert: false
--- error_log
auto-ssl: issuing new certificate for
--- no_error_log
[error]
[alert]
[emerg]

=== TEST 11: retains dehydrated temporary files if cert deployment fails
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
      local shell_blocking = require "shell-games"
      local result, err = shell_blocking.capture_combined({ "find", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/dehydrated/certs", "-maxdepth", "1", "-name", "$TEST_NGINX_NGROK_HOSTNAME" })
      if err then
        ngx.say("failed to list certs directory: ", err)
        return nil, err
      end
      ngx.say("cert: " .. tostring(#result["output"] > 0))

      -- Delete the stored files and wipe the in-memory cache.
      local _, err = shell_blocking.capture_combined({ "rm", "-rf", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest") })
      if err then
        ngx.say("failed to delete cert: ", err)
        return nil, err
      end
      local keys = ngx.shared.auto_ssl:get_keys()
      for _, key in ipairs(keys) do
        if key ~= "hook_server:secret" and key ~= "sockproc_started" then
          ngx.shared.auto_ssl:delete(key)
        end
      end

      -- Create a directory where the storage file would normally belong so
      -- that attempt to write this cert to storage will temporarily fail.
      local _, err = shell_blocking.capture_combined({ "mkdir", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest") })
      if err then
        ngx.say("failed to change directory permissions: ", err)
        return nil, err
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
      end

      local result, err = shell_blocking.capture_combined({ "find", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/dehydrated/certs", "-maxdepth", "1", "-name", "$TEST_NGINX_NGROK_HOSTNAME" })
      if err then
        ngx.say("failed to list certs directory: ", err)
        return nil, err
      end
      ngx.say("cert: " .. tostring(#result["output"] > 0))

      local _, err = shell_blocking.capture_combined({ "rm", "-rf", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest") })
      if err then
        ngx.say("failed to delete cert: ", err)
        return nil, err
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

      local result, err = shell_blocking.capture_combined({ "find", "$TEST_NGINX_RESTY_AUTO_SSL_DIR/dehydrated/certs", "-maxdepth", "1", "-name", "$TEST_NGINX_NGROK_HOSTNAME" })
      if err then
        ngx.say("failed to list certs directory: ", err)
        return nil, err
      end
      ngx.say("cert: " .. tostring(#result["output"] > 0))
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
cert: false
failed to do SSL handshake: 18: self signed certificate
cert: true
received: HTTP/1.1 200 OK
received: Server: openresty
received: Content-Type: text/plain
received: Connection: close
received: 
received: foo
cert: false
--- error_log
auto-ssl: issuing new certificate for
auto-ssl: failed to open file for writing:
auto-ssl: failed to set cert
auto-ssl: dehydrated failed
auto-ssl: issuing new certificate failed
auto-ssl: could not get certificate for
auto-ssl: issuing new certificate for
Checking domain name(s) of existing cert... unchanged.
auto-ssl: dehydrated succeeded, but certs still missing from storage - trying to manually copy
--- no_error_log
[alert]
[emerg]

=== TEST 12: hook server port can be changed
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_shared_dict auto_ssl 1m;
  lua_shared_dict auto_ssl_settings 64k;

  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      hook_server_port = 9888,
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
    listen 127.0.0.1:9888;
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
--- error_log
--- no_error_log
[alert]
[emerg]

=== TEST 13: fills in missing expiry dates in storage from certificate expiration on renewal
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
      renew_check_interval = 1,
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
      local cjson = require "cjson"

      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "r")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      local content = file:read("*all")
      file:close()

      local data = cjson.decode(content)
      local original_expiry = data["expiry"]
      ngx.say("cert expiry 1: " .. type(data["expiry"]))

      data["expiry"] = nil
      ngx.say("cert expiry 2: " .. type(data["expiry"]))

      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "w")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      file:write(cjson.encode(data))
      file:close()

      -- Wait for scheduled renewals to happen (since the check interval is
      -- every 1 second).
      ngx.sleep(5)

      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "r")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      local content = file:read("*all")
      file:close()

      local data = cjson.decode(content)
      ngx.say("cert expiry 3: " .. type(data["expiry"]))
      ngx.say("cert expiry equal: " .. tostring(original_expiry == data["expiry"]))
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
cert expiry 1: number
cert expiry 2: nil
cert expiry 3: number
cert expiry equal: true
--- error_log
auto-ssl: checking certificate renewals for
auto-ssl: setting expiration date of
auto-ssl: expiry date is more than 30 days out
--- no_error_log
[warn]
[error]
[alert]
[emerg]
issuing new certificate for
auto-ssl: existing certificate is expired, deleting

=== TEST 14: removes cert if expiration has expired and renewal fails
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
      renew_check_interval = 1,
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
      local cjson = require "cjson"

      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "r")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      local content = file:read("*all")
      file:close()

      local data = cjson.decode(content)
      ngx.say("cert expiry 1: " .. type(data["expiry"]))

      -- Set the expiration time to some time in the past.
      data["expiry"] = 1000

      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "w")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      file:write(cjson.encode(data))
      file:close()

      -- Wait for scheduled renewals to happen (since the check interval is
      -- every 1 second).
      ngx.sleep(5)

      -- Since this cert renewal is still valid, it should still remain despite
      -- being marked as expired.
      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "r")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      local content = file:read("*all")
      file:close()

      local data = cjson.decode(content)
      ngx.say("cert expiry 2: " .. data["expiry"])

      -- Copy the cert to an unresolvable domain to verify that failed renewals
      -- will be removed.
      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("unresolvable-sdjfklsdjf.example:latest"), "w")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      file:write(cjson.encode(data))
      file:close()

      -- Wait for scheduled renewals to happen (since the check interval is
      -- every 1 second).
      ngx.sleep(5)

      -- Verify that the valid cert still remains (despite being marked as
      -- expired).
      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "r")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end
      local content = file:read("*all")
      file:close()

      local data = cjson.decode(content)
      ngx.say("cert expiry 3: " .. data["expiry"])

      -- Verify that the failed renewal gets deleted.
      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("unresolvable-sdjfklsdjf.example:latest"), "r")
      if err then
        ngx.say("failed to open file")
      else
        ngx.say("unexpectedly found file remaining")
      end
    }
  }
--- timeout: 30s
--- request
GET /t
--- response_body
cert expiry 1: number
cert expiry 2: 1000
cert expiry 3: 1000
failed to open file
--- error_log
auto-ssl: checking certificate renewals for
auto-ssl: issuing renewal certificate failed
auto-ssl: existing certificate is expired, deleting
--- no_error_log
[alert]
[emerg]
issuing new certificate for
