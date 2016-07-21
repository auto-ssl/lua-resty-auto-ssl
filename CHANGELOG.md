# lua-resty-auto-ssl Change Log

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
