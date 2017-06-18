use strict;
use warnings;
use Test::Nginx::Socket::Lua;
require "./t/inc/setup.pl";
AutoSsl::setup();

my ($nobody_user, $nobody_passwd, $nobody_uid, $nobody_gid) = getpwnam "nobody";
$ENV{TEST_NGINX_NOBODY_USER} = $nobody_user;
$ENV{TEST_NGINX_NOBODY_GROUP} = getgrgid($nobody_gid);

repeat_each(1);

plan tests => repeat_each() * (blocks() * 7);

check_accum_error_log();
no_long_string();
no_shuffle();
master_on();
workers(2);

run_tests();

__DATA__

=== TEST 1: issues a new SSL certificate and stores it as a file
--- main_config
user $TEST_NGINX_NOBODY_USER $TEST_NGINX_NOBODY_GROUP;
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
      local ngx_re = require "ngx.re"
      local run_command = require "resty.auto-ssl.utils.run_command"
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

      local file, err = io.open("$TEST_NGINX_RESTY_AUTO_SSL_DIR/storage/file/" .. ngx.escape_uri("$TEST_NGINX_NGROK_HOSTNAME:latest"), "r")
      if err then
        ngx.say("failed to open file: ", err)
        return nil, err
      end

      local content = file:read("*all")
      file:close()
      ngx.say("latest cert: " .. type(content))

      local _, output, err = run_command("find $TEST_NGINX_RESTY_AUTO_SSL_DIR -not -path '*ngrok.io*' -printf '%p %u %g %m\n'")
      if err then
        ngx.say("failed to find file permissions: ", err)
        return nil, err
      end
      ngx.say("permissions:")
      output = string.gsub(output, "%s+$", "")
      local lines, err = ngx_re.split(output, "\n")
      if err then
        ngx.say("failed to sort file permissions output ", err)
        return nil, err
      end
      table.sort(lines)
      output = table.concat(lines, "\n")
      output = string.gsub(output, " $TEST_NGINX_NOBODY_GROUP ", " nobody ")
      ngx.say(output)
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
permissions:
/tmp/resty-auto-ssl-test-worker-perms nobody root 755
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt root root 777
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/.acme-challenges nobody nobody 755
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/accounts nobody nobody 700
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK nobody nobody 700
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK/account_key.pem nobody nobody 600
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/accounts/aHR0cHM6Ly9hY21lLXN0YWdpbmcuYXBpLmxldHNlbmNyeXB0Lm9yZy9kaXJlY3RvcnkK/registration_info.json nobody nobody 600
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/certs nobody nobody 700
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/conf.d root root 755
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/config root root 644
/tmp/resty-auto-ssl-test-worker-perms/letsencrypt/locks nobody nobody 755
/tmp/resty-auto-ssl-test-worker-perms/storage nobody nobody 755
/tmp/resty-auto-ssl-test-worker-perms/storage/file nobody nobody 700
--- error_log
auto-ssl: issuing new certificate for
--- no_error_log
[warn]
[error]
[alert]
[emerg]
