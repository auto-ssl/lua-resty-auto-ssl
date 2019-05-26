local check_dependencies = require "resty.auto-ssl.utils.check_dependencies"
local shell_blocking = require "shell-games"
local shell_execute = require "resty.auto-ssl.utils.shell_execute"
local start_sockproc = require "resty.auto-ssl.utils.start_sockproc"

local _M = {}

function _M.new(auto_ssl_instance)
  local self = {
    lua_root = auto_ssl_instance.lua_root,
    base_dir = auto_ssl_instance:get("dir"),
    hook_port = auto_ssl_instance:get("hook_server_port"),
    hook_secret = ngx.shared.auto_ssl_settings:get("hook_server:secret"),
    ca = auto_ssl_instance:get("ca"),
    storage = auto_ssl_instance.storage,
  }

  assert(type(self.lua_root) == "string", "lua_root must be a string")
  assert(type(self.base_dir) == "string", "dir must be a string")
  assert(type(self.hook_port) == "number", "hook_port must be a number")
  assert(self.hook_port <= 65535, "hook_port must be below 65536")
  assert(type(self.hook_secret) == "string", "hook_server:secret must be a string")

  return setmetatable(self, { __index = _M })
end

function _M.setup(self)
  check_dependencies({
    "bash",
    "curl",
    "diff",
    "grep",
    "mktemp",
    "openssl",
    "sed",
  })

  local _, mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", self.base_dir .. "/dehydrated/conf.d" }, { umask = "0022" })
  if mkdir_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create dehydrated/conf.d dir: ", mkdir_err)
  end

  local _, chmod_err = shell_blocking.capture_combined({ "chmod", "777", self.base_dir .. "/dehydrated" })
  if chmod_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create dehydrated dir permissions: ", chmod_err)
  end

  -- Remove the old "config.sh" file used by dehydrated v0.2.0. Now it's
  -- moved to just "config".
  os.remove(self.base_dir .. "/dehydrated/config.sh")

  local file, err = io.open(self.base_dir .. "/dehydrated/config", "w")
  if err then
    ngx.log(ngx.ERR, "auto-ssl: failed to open dehydrated config file")
  else
    file:write('# This file will be overwritten by resty-auto-ssl.\n')
    file:write('# Place any customizations in ' .. self.base_dir .. '/dehydrated/conf.d/*.sh\n\n')
    file:write('CONFIG_D="' .. self.base_dir .. '/dehydrated/conf.d"\n')
    file:write('LOCKFILE="' .. self.base_dir .. '/dehydrated/locks/lock"\n')
    file:write('WELLKNOWN="' .. self.base_dir .. '/dehydrated/.acme-challenges"\n')

    local ca = self.ca
    if ca then
      file:write('CA="' .. ca .. '"\n')
    end

    file:close()
  end
end

function _M.setup_worker(self)
  local _, mkdir_challenges_err = shell_blocking.capture_combined({ "mkdir", "-p", self.base_dir .. "/dehydrated/.acme-challenges" }, { umask = "0022" })
  if mkdir_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create dehydrated/.acme-challenges dir: ", mkdir_challenges_err)
  end
  local _, mkdir_locks_err = shell_blocking.capture_combined({ "mkdir", "-p", self.base_dir .. "/dehydrated/locks" }, { umask = "0022" })
  if mkdir_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create dehydrated/locks dir: ", mkdir_locks_err)
  end

  -- Start sockproc for executing shell commands asynchronously with
  -- "shell_execute".
  start_sockproc()
end

function _M.issue_cert(self, domain)
  assert(type(domain) == "string", "domain must be a string")

  -- Run dehydrated for this domain, using our custom hooks to handle the
  -- domain validation and the issued certificates.
  --
  -- Disable dehydrated's locking, since we perform our own domain-specific
  -- locking using the storage adapter.
  local result, err = shell_execute({
    "env",
    "HOOK_SECRET=" .. self.hook_secret,
    "HOOK_SERVER_PORT=" .. self.hook_port,
    self.lua_root .. "/bin/resty-auto-ssl/dehydrated",
    "--cron",
    "--accept-terms",
    "--no-lock",
    "--domain", domain,
    "--challenge", "http-01",
    "--config", self.base_dir .. "/dehydrated/config",
    "--hook", self.lua_root .. "/bin/resty-auto-ssl/dehydrated_hooks",
  })
  if result["status"] ~= 0 then
    ngx.log(ngx.ERR, "auto-ssl: dehydrated failed: ", result["command"], " status: ", result["status"], " out: ", result["output"], " err: ", err)
    return nil, "dehydrated failure"
  end

  ngx.log(ngx.DEBUG, "auto-ssl: dehydrated output: " .. result["output"])

  -- The result of running that command should result in the certs being
  -- populated in our storage (due to the deploy_cert hook triggering).
  local cert, get_cert_err = self.storage:get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
  end

  -- If dehydrated succeeded, but we still don't have any certs in storage, the
  -- issue might be that dehydrated succeeded and has local certs cached, but
  -- the initial attempt to deploy them and save them into storage failed (eg,
  -- storage was temporarily unavailable). If this occurs, try to manually fire
  -- the deploy_cert hook again to populate our storage with dehydrated's local
  -- copies.
  if not cert or not cert["fullchain_pem"] or not cert["privkey_pem"] then
    ngx.log(ngx.WARN, "auto-ssl: dehydrated succeeded, but certs still missing from storage - trying to manually copy - domain: " .. domain)

    result, err = shell_execute({
      "env",
      "HOOK_SECRET=" .. self.hook_secret,
      "HOOK_SERVER_PORT=" .. self.hook_port,
      self.lua_root .. "/bin/resty-auto-ssl/dehydrated_hooks",
      "deploy_cert",
      domain,
      self.base_dir .. "/dehydrated/certs/" .. domain .. "/privkey.pem",
      self.base_dir .. "/dehydrated/certs/" .. domain .. "/cert.pem",
      self.base_dir .. "/dehydrated/certs/" .. domain .. "/fullchain.pem",
      self.base_dir .. "/dehydrated/certs/" .. domain .. "/chain.pem",
      math.floor(ngx.now()),
    })
    if result["status"] ~= 0 then
      ngx.log(ngx.ERR, "auto-ssl: dehydrated manual hook.sh failed: ", result["command"], " status: ", result["status"], " out: ", result["output"], " err: ", err)
      return nil, "dehydrated failure"
    end

    -- Try fetching again.
    cert, get_cert_err = self.storage:get_cert(domain)
    if get_cert_err then
      ngx.log(ngx.ERR, "auto-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
    end
  end

  -- Return error if things are still unexpectedly missing.
  if not cert or not cert["fullchain_pem"] or not cert["privkey_pem"] then
    return nil, "dehydrated succeeded, but no certs present"
  end

  return cert
end

return _M
