local random_seed = require "resty.auto-ssl.utils.random_seed"
local renewal_job = require "resty.auto-ssl.jobs.renewal"
local shell_blocking = require "shell-games"
local start_sockproc = require "resty.auto-ssl.utils.start_sockproc"

return function(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")
  local _, mkdir_challenges_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/.acme-challenges" }, { umask = "0022" })
  if mkdir_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/.acme-challenges dir: ", mkdir_challenges_err)
  end
  local _, mkdir_locks_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/locks" }, { umask = "0022" })
  if mkdir_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/locks dir: ", mkdir_locks_err)
  end

  -- random_seed was called during the "init" master phase, but we want to
  -- ensure each worker process's random seed is different, so force another
  -- call in the init_worker phase.
  random_seed()

  -- Startup sockproc. This background process allows for non-blocking shell
  -- commands with resty.shell.
  --
  -- We do this in the init_worker phase, so that it will always be started
  -- with the same permissions as the nginx workers (and not the elevated
  -- permissions of the nginx master process).
  --
  -- If we implement a native resty Let's Encrypt ACME client (rather than
  -- relying on dehydrated), then we could get rid of the need for this
  -- background process, which would be nice.
  start_sockproc()

  local storage = auto_ssl_instance.storage
  local storage_adapter = storage.adapter
  if storage_adapter.setup_worker then
    storage_adapter:setup_worker()
  end

  renewal_job.spawn(auto_ssl_instance)
end
