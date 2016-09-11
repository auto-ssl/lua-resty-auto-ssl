# lua-resty-auto-ssl Change Log

## 0.9.0 - 2016-09-11

### Added
- Add support for Redis authentication when using the Redis storage adapter. Thanks to [@Eihrister](https://github.com/Eihrister).
- Add dependency checks during install and startup to provide better error messages in case system commands are not available.

### Fixed
- Fix compatibility on BusyBox-based systems where the `find` command did not support the `-printf` option.
- Fix compatibility for systems where bash is installed in a location other than `/bin/bash`.

## 0.8.6 - 2016-08-11

### Fixed
- Fix compatibility with OpenResty pre-built packages or when compiled with Lua 5.2 compatibility enabled (`LUAJIT_ENABLE_LUA52COMPAT`). Thanks to [@ikennaokpala](https://github.com/ikennaokpala).

## 0.8.5 - 2016-08-03

### Fixed
- Update letsencrypt.sh to account for new Let's Encrypt license as of August 1, 2016. This would lead to certificate registration errors for new users (but should not have affected existing lua-resty-auto-ssl users).

### Changed
- Improve error messages for OCSP stapling failures to aid in debugging.

## 0.8.4 - 2016-07-23

### Fixed
- Extend timeout for calling letsencrypt.sh from 15 seconds to 60 seconds to improve handling when Let's Encrypt may take longer to respond than normal.

## 0.8.3 - 2016-07-20

### Fixed
- Fix the default Redis port (6379) not being applied for the Redis storage adapter.
- Fix recovering certs from Let's Encrypt's local files if the cert was deleted from the adapter's storage (or if the cert failed to successfully be added the first time).
- Fix potential issues with calling letsencrypt.sh for very long domain names, or if the base directory was set to a long path.

## 0.8.2 - 2016-06-26

### Fixed
- Fix letsencrypt.sh directory permissions on startup.

## 0.8.1 - 2016-05-31

### Fixed
- Fix compatibility with Let's Encrypt API changes by upgrading vendored letsencrypt.sh to v0.2.0.
- Fix certificate renewals not being picked up until nginx restarts.

## 0.8.0 - 2016-04-10

### Changed
- Initial version published as LuaRock.
