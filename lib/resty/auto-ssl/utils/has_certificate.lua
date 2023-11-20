return function(auto_ssl_instance, domain, shmem_only)
  local shmem = ngx.shared.auto_ssl:get("domain:fullchain_der:" .. domain)
  if shmem then
    return true
  elseif shmem_only then
    return false
  end

  local storage = auto_ssl_instance.storage
  local cert = storage:get_cert(domain)
  if cert then
    return true
  end

  return false
end
