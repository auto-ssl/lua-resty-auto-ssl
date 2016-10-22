local renewal_job = require "resty.auto-ssl.jobs.renewal"
local run_command = require "resty.auto-ssl.utils.run_command"
local start_sockproc = require "resty.auto-ssl.utils.start_sockproc"

return function(auto_ssl_instance)
  local base_dir = auto_ssl_instance:get("dir")
  local _, _, mkdir_challenges_err = run_command("umask 0022 && mkdir -p " .. base_dir .. "/letsencrypt/.acme-challenges")
  if mkdir_challenges_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/.acme-challenges dir: ", mkdir_challenges_err)
  end
  local _, _, mkdir_locks_err = run_command("umask 0022 && mkdir -p " .. base_dir .. "/letsencrypt/locks")
  if mkdir_locks_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/locks dir: ", mkdir_locks_err)
  end

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

  local storage = auto_ssl_instance:get("storage")
  local adapter = storage.adapter
  if adapter.setup_worker then
    adapter:setup_worker()
  end

  renewal_job.spawn(auto_ssl_instance)
end
