local random_seed = require "resty.auto-ssl.utils.random_seed"
local renewal_job = require "resty.auto-ssl.jobs.renewal"

return function(auto_ssl_instance)
  -- random_seed was called during the "init" master phase, but we want to
  -- ensure each worker process's random seed is different, so force another
  -- call in the init_worker phase.
  random_seed()

  local storage = auto_ssl_instance.storage
  local storage_adapter = storage.adapter
  if storage_adapter.setup_worker then
    storage_adapter:setup_worker()
  end

  local client = auto_ssl_instance.client
  if client.setup_worker then
    client:setup_worker()
  end

  renewal_job.spawn(auto_ssl_instance)
end
