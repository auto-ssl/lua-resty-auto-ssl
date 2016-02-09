use Test::Nginx::Socket::Lua;
do "./t/inc/setup.pl";

repeat_each(2);

plan tests => repeat_each() * (blocks() * 6 + 6);

check_accum_error_log();
no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: issues a new SSL certificate
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return true
      end,
    })
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
[error]
[alert]
[emerg]

=== TEST 2: returns an existing SSL certificate
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return true
      end,
    })
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
[error]
[alert]
[emerg]
issuing new certificate for

=== TEST 3: returns the fallback SSL certificate when SNI isn't used
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return true
      end,
    })
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
auto-ssl: could not determine domain with SNI - skipping
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 4: disallows all domains for registration by default
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
    })
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
auto-ssl: domain not allowed - skipping - default-disallow-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 5: calls the allow_domain function which can perform more complex logic
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
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
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
auto-ssl: domain not allowed - skipping - allow-domain-fn-check-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 6: options can also be set with the set() function after new()
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new()
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
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
auto-ssl: domain not allowed - skipping - set-options-fn-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 7: returns the fallback SSL certificate when the domain is allowed and valid, but the domain challenge fails
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return string.find(domain, "ngrok.io")
      end,
    })
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
auto-ssl: letsencrypt.sh failed
auto-ssl: could not get certificate for not-ours-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]

=== TEST 8: returns the fallback SSL certificate when the domain is allowed, but not resolvable
--- http_config
  resolver 8.8.8.8;
  lua_package_path "$TEST_NGINX_LUA_PACKAGE_PATH/?.lua;;";
  lua_shared_dict auto_ssl 1m;

  init_worker_by_lua_block {
    auto_ssl = (require "lib.resty.auto-ssl").new({
      dir = "$TEST_NGINX_RESTY_AUTO_SSL_DIR",
      ca = "https://acme-staging.api.letsencrypt.org/directory",
      allow_domain = function(domain)
        return true
      end,
    })
    auto_ssl:init_worker()
  }

  server {
    listen 9443 ssl;
    ssl_certificate ../../certs/example_fallback.crt;
    ssl_certificate_key ../../certs/example_fallback.key;
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
    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
--- config
  lua_ssl_trusted_certificate ../../certs/letsencrypt_staging_chain.pem;
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
auto-ssl: letsencrypt.sh failed
auto-ssl: could not get certificate for unresolvable-
lua ssl certificate verify error: (18: self signed certificate)
--- no_error_log
[alert]
[emerg]
