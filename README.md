# lua-resty-auto-ssl

[![Circle CI](https://circleci.com/gh/GUI/lua-resty-auto-ssl.svg?style=svg)](https://circleci.com/gh/GUI/lua-resty-auto-ssl)

On the fly (and free) SSL registration and renewal inside [OpenResty/nginx](http://openresty.org) with [Let's Encrypt](https://letsencrypt.org).

This OpenResty plugin automatically and transparently issues SSL certificates from Let's Encrypt (a free certificate authority) as requests are received. It works like:

- A SSL request for a SNI hostname is received.
- If the system already has a SSL certificate for that domain, it is immediately returned (with OCSP stapling).
- If the system does not yet have an SSL certificate for this domain, it issues a new SSL certificate from Let's Encrypt. Domain validation is handled for you. After receiving the new certificate (usually within a few seconds), the new certificate is saved, cached, and returned to the client (without dropping the original request).

This uses the `ssl_certificate_by_lua` functionality in OpenResty 1.9.7.2+.

## Status

Used in production (but the internal APIs might still be in flux).

## Installation

Requirements:

- [OpenResty](http://openresty.org/#Download) 1.9.7.2 or higher
  - Or nginx patched with [ssl_cert_cb_yield](https://github.com/openresty/openresty/blob/v1.11.2.2/patches/nginx-1.11.2-ssl_cert_cb_yield.patch) and built with [ngx_lua](https://github.com/openresty/lua-nginx-module#installation) 0.10.0 or higher
- OpenSSL 1.0.2e or higher
- [LuaRocks](http://openresty.org/#UsingLuaRocks)
- gcc, make (for initial install via LuaRocks)
- bash, curl, diff, grep, mktemp, sed (these are generally pre-installed on most systems, but may not be included in some minimal containers)


```sh
$ sudo luarocks install lua-resty-auto-ssl

# Create /etc/resty-auto-ssl and make sure it's writable by whichever user your
# nginx workers run as (in this example, "www-data").
$ sudo mkdir /etc/resty-auto-ssl
$ sudo chown www-data /etc/resty-auto-ssl
```

Implement the necessary configuration inside your nginx config. Here is a minimal example:

```nginx
events {
  worker_connections 1024;
}

http {
  # The "auto_ssl" shared dict should be defined with enough storage space to
  # hold your certificate data. 1MB of storage holds certificates for
  # approximately 100 separate domains.
  lua_shared_dict auto_ssl 1m;
  # The "auto_ssl" shared dict is used to temporarily store various settings
  # like the secret used by the hook server on port 8999. Do not change or
  # omit it.
  lua_shared_dict auto_ssl_settings 64k;

  # A DNS resolver must be defined for OCSP stapling to function.
  #
  # This example uses Google's DNS server. You may want to use your system's
  # default DNS servers, which can be found in /etc/resolv.conf. If your network
  # is not IPv6 compatible, you may wish to disable IPv6 results by using the
  # "ipv6=off" flag (like "resolver 8.8.8.8 ipv6=off").
  resolver 8.8.8.8;

  # Initial setup tasks.
  init_by_lua_block {
    auto_ssl = (require "resty.auto-ssl").new()

    -- Define a function to determine which SNI domains to automatically handle
    -- and register new certificates for. Defaults to not allowing any domains,
    -- so this must be configured.
    auto_ssl:set("allow_domain", function(domain)
      return true
    end)

    auto_ssl:init()
  }

  init_worker_by_lua_block {
    auto_ssl:init_worker()
  }

  # HTTPS server
  server {
    listen 443 ssl;

    # Dynamic handler for issuing or returning certs for SNI domains.
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate()
    }

    # You must still define a static ssl_certificate file for nginx to start.
    #
    # You may generate a self-signed fallback with:
    #
    # openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    #   -subj '/CN=sni-support-required-for-valid-ssl' \
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
        auto_ssl:challenge_server()
      }
    }
  }

  # Internal server running on port 8999 for handling certificate tasks.
  server {
    listen 127.0.0.1:8999;

    # Increase the body buffer size, to ensure the internal POSTs can always
    # parse the full POST contents into memory.
    client_body_buffer_size 128k;
    client_max_body_size 128k;

    location / {
      content_by_lua_block {
        auto_ssl:hook_server()
      }
    }
  }
}
```

## Configuration

Additional configuration options can be set on the `auto_ssl` instance that is created:

- **`allow_domain`**
  *Default:* `function(domain) return false end`

  A function that determines whether the incoming domain should automatically issue a new SSL certificate.

  By default, resty-auto-ssl will not perform any SSL registrations until you define the `allow_domain` function. You may return `true` to handle all possible domains, but be aware that bogus SNI hostnames can then be used to trigger an indefinite number of SSL registration attempts (which will be rejected). A better approach may be to whitelist the allowed domains in some way.

  *Example:*

  ```lua
  auto_ssl:set("allow_domain", function(domain)
    return ngx.re.match(domain, "^(example.com|example.net)$", "ijo")
  end)
  ```

- **`dir`**
  *Default:* `/etc/resty-auto-ssl`

  The base directory used for storing configuration, temporary files, and certificate files (if using the `file` storage adapter). This directory must be writable by the user nginx workers run as.

  *Example:*

  ```lua
  auto_ssl:set("dir", "/some/other/location")
  ```

- **`renew_check_interval`**
  *Default:* `86400`

  How frequently (in seconds) all of the domains should be checked for certificate renewals. Defaults to checking every 1 day. Certificates will automatically be renewed if the expire in less than 30 days.

  *Example:*

  ```lua
  auto_ssl:set("renew_check_interval", 172800)
  ```

- **`storage_adapter`**
  *Default:* `resty.auto-ssl.storage_adapters.file`
  *Options:* `resty.auto-ssl.storage_adapters.file`, `resty.auto-ssl.storage_adapters.redis`

  The storage mechanism used for persistent storage of the SSL certificates. File-based and redis-based storage adapters are supplied, but custom external adapters may also be specified (the value simply needs to be on the `lua_package_path`).

  The default storage adapter persists the certificates to local files. However, you may want to consider another storage adapter (like redis) for a couple reason:
    - File I/O causes blocking in OpenResty which should be avoided for optimal performance. However, files are only read and written the first time a certificate is seen, and then things are cached in memory, so the actual amount of file I/O should be quite minimal.
    - Local files won't work if the certificates need to be shared across multiple servers (for a load-balanced environment).

  *Example:*

  ```lua
  auto_ssl:set("storage_adapter", "resty.auto-ssl.storage_adapters.redis")
  ```

- **`redis`**
  *Default:* `{ host = "127.0.0.1", port = 6379 }`

  If the `redis` storage adapter is being used, then additional connection options can be specified on this table. Accepts the following options:

  - `host`
  - `port`
  - `socket` (for unix socket paths)
  - `auth`
  - `prefix`

  *Example:*

  ```lua
  auto_ssl:set("redis", {
    host = "10.10.10.1"
  })
  ```

- **`request_domain`**
  *Default:* `function(ssl, ssl_options) return ssl.server_name() end`

  A function that determines the hostname of the request. By default, the SNI domain is used, but a custom function can be implemented to determine the domain name for non-SNI requests (by basing the domain on something that can be determined outside of SSL, like the port or IP address that received the request).

  *Example:*

  This example, along with the accompanying nginx `server` blocks, will default to SNI domain names, but for non-SNI clients will respond with predefined hosts based on the connecting port. Connections to port 9000 will register and return a certificate for `foo.example.com`, while connections to port 9001 will register and return a certificate for `bar.example.com`. Any other ports will return the default nginx fallback certificate.

  ```lua
  auto_ssl:set("request_domain", function(ssl, ssl_options)
    local domain, err = ssl.server_name()
    if (not domain or err) and ssl_options and ssl_options["port"] then
      if ssl_options["port"] == 9000 then
        domain = "foo.example.com"
      elseif ssl_options["port"] == 9001 then
        domain = "bar.example.com"
      end
    end

    return domain, err
  end)
  ```

  ```nginx
  server {
    listen 9000 ssl;
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate({ port = 9000 })
    }
  }

  server {
    listen 9001 ssl;
    ssl_certificate_by_lua_block {
      auto_ssl:ssl_certificate({ port = 9001 })
    }
  }
  ```

- **`ca`**
  *Default:* the default Let's Encrypt CA

  URL of the Let's Encrypt environment to use. Normally you should not set this, unless you want make us of Let's Encrypts [staging environment](https://letsencrypt.org/docs/staging-environment/).

  *Example:*

  ```lua
  auto_ssl:set("ca", "https://some-other-letsencrypt.org/directory")
  ```

- **`hook_server_port`**
  *Default:* 8999

  Internally we use a special server server running on port 8999 for handling certificate tasks. The port used for this service may be changed here. Please note that you will also need to change it in your nginx configuration.

  *Example:*

  ```lua
  auto_ssl:set("hook_server_port", 90)
  ```

### Advanced Let's Encrypt Configuration

Internally, lua-resty-auto-ssl uses [dehydrated](https://github.com/lukas2511/dehydrated) as it's Let's Encrypt client. If you'd like to adjust lower-level settings, like the private key size, public key algorithm, or your registration e-mail, these settings can be configured in a custom dehydrated configuration file.

- For a full list of supported options, see [dehydrated's example config](https://github.com/lukas2511/dehydrated/blob/v0.4.0/docs/examples/config).
- Custom dehydrated configuration files can be placed inside the `/etc/resty-auto-ssl/letsencrypt/conf.d` directory by default (or adjust the path if you've changed the default lua-resty-auto-ssl `dir` setting).

Example `/etc/resty-auto-ssl/letsencrypt/conf.d/custom.sh`:

```sh
KEYSIZE="4096"
KEY_ALGO="rsa"
CONTACT_EMAIL="foo@example.com"
```

## Precautions

- **Allowed Hosts:** By default, resty-auto-ssl will not perform any SSL registrations until you define the `allow_domain` function. You may return `true` to handle all possible domains, but be aware that bogus SNI hostnames can then be used to trigger an indefinite number of SSL registration attempts (which will be rejected). A better approach may be to whitelist the allowed domains in some way.
- **Untrusted Code:** Ensure your OpenResty server where this is installed cannot execute untrusted code. The certificates and private keys have to be readable by the web server user, so it's important that this data is not compromised.
- **File Storage:** The default storage adapter persists the certificates to local files. However, you may want to consider another storage adapter (like redis) for a couple reason:
  - File I/O causes blocking in OpenResty which should be avoided for optimal performance. However, files are only read and written the first time a certificate is seen, and then things are cached in memory, so the actual amount of file I/O should be quite minimal.
  - Local files won't work if the certificates need to be shared across multiple servers (for a load-balanced environment).


## Development

After checking out the repo, Docker can be used to run the test suite:

```sh
$ docker-compose run app make test
```

The test suite is implemented using nginx' [`Test::Nginx`](https://metacpan.org/pod/Test::Nginx::Socket) cpan module.

## Credits

**[dehydrated](https://github.com/lukas2511/dehydrated)** is the client used internally that does all the heavy lifting with Let's Encrypt.

## TODO

- Document and formalize the API for other storage adapters.
- Open source the MongoDB storage adapter we're using in API Umbrella.
- Add the ability to encrypt data at rest for any storage adapter (based on what we built for API Umbrella's MongoDB storage adapter).
- We currently rely on [dehydrated](https://github.com/lukas2511/dehydrated) as our Let's Encrypt client. It's called in a non-blocking fashion via [lua-resty-shell](https://github.com/juce/lua-resty-shell) and [sockproc](https://github.com/juce/sockproc), however it might be simpler to eventually replace this approach with a native OpenResty Let's Encrypt client someday.
