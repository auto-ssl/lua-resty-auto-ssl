# lua-resty-auto-ssl

On the fly (and free) SSL registration and renewal inside [OpenResty/nginx](http://openresty.org) with [Let's Encrypt](https://letsencrypt.org).

This OpenResty plugin automatically and transparently issues SSL certificates from Let's Encrypt (a free certificate authority) as requests are received. It works like:

- A SSL request for a SNI hostname is received.
- If the system already has a SSL certificate for that domain, it is immediately returned (with OCSP stapling).
- If the system does not yet have an SSL certificate for this domain, it issues a new SSL certificate from Let's Encrypt. Domain validation is handled for you. After receiving the new certificate (usually within a few seconds), the new certificate is saved, cached, and returned to the client (without dropping the original request).

This uses the `ssl_certificate_by_lua` functionality in OpenResty 1.9.7.2+.

## Installation

Requirements:

- [OpenResty](http://openresty.org/#Download) 1.9.7.2 or higher
- OpenSSL 1.0.2e or higher
- [LuaRocks](http://openresty.org/#UsingLuaRocks)

```sh
$ sudo luarocks install lua-resty-auto-ssl

# Create /etc/resty-auto-ssl and make sure it's writable by whichever user your
# nginx workers run as (in this example, "www-data").
$ sudo mkdir /etc/resty-auto-ssl
$ sudo chown www-data /etc/resty-auto-ssl
```

Implement the necessary configuration inside your nginx config. Here is a minimal example:

```nginx
http {
  # The "auto_ssl" shared dict must be defined with enough storage space to
  # hold your certificate data.
  lua_shared_dict auto_ssl 1m;

  # A DNS resolver must be defined for OSCP stapling to function.
  resolver 8.8.8.8;

  # Intial setup tasks.
  init_worker_by_lua_block {
    local auto_ssl = require "resty.auto-ssl"

    # Define a function to determine which SNI domains to automatically handle
    # and register new certificates for. Defaults to not allowing any domains,
    # so this must be configured.
    auto_ssl.allow_domain = function(domain)
      return true
    end

    auto_ssl.init_worker()
  }

  # HTTPS server
  server {
    listen 443 ssl;

    # Dynamic handler for issuing or returning certs for SNI domains.
    ssl_certificate_by_lua_block {
      local auto_ssl = require "resty.auto-ssl"
      auto_ssl.ssl_certificate()
    }

    # You must still define a static ssl_certificate file for nginx to start.
    #
    # You may generate a self-signed fallback with:
    #
    # openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    #   -subj '/CN=resty-auto-ssl-fallback' \
    #   -keyout /etc/ssl/resty-auto-ssl-fallback.key \
    #   -out /etc/ssl/resty-auto-ssl-fallback.crt
    ssl_certificate /etc/ssl/resty-auto-ssl-fallback.crt;
    ssl_certificate_key /etc/ssl/resty-auto-ssl-fallback.key;
  }

  # HTTP server
  server {
    listen 80;

    # Endpoint used for performing domain verification with Let's Encrypt.
    location /.well-known/acme-challenge/ {
      content_by_lua_block {
        local auto_ssl = require "resty.auto-ssl"
        auto_ssl.challenge_server()
      }
    }
  }

  # Internal server running on port 8999 for handling certificate tasks.
  server {
    listen 127.0.0.1:8999;
    location / {
      content_by_lua_block {
        local auto_ssl = require "resty.auto-ssl"
        auto_ssl.hook_server()
      }
    }
  }
}
```

## Precautions

- **Allowed Hosts:** By default, resty-auto-ssl will not perform any SSL registrations until you define the `auto_ssl.allow_domain` function. You may return `true` to handle all possible domains, but be aware that bogus SNI hostnames can then be used to trigger an indefinite number of SSL registration attempts (which will be rejected). A better approach may be to whitelist. the allowed domains in some way.
- **Untrusted Code:** Ensure your OpenResty server where this is installed cannot execute untrusted code. The certificates and private keys have to be readable by the web server user, so it's important that this data is not compromised.
- **File Storage:** The default storage adapter persists the certificates to local files. You may want to consider another storage adapter for a couple reason:
  - File I/O causes blocking in OpenResty which should be avoided for optimal performance. However, files are only read and written once the first time a certificate is seen, and then things are cached in memory, so the actual amount of file I/O should be quite minimal.
  - Local files won't work if the certificates need to be shared across multiple servers (for a load-balanced environment).

## TODO

- Implement tests.
- Implement background task to perform automatic renewals.
- Implement Redis storage mechanism (non-blocking and suitable for multi-server environments).
