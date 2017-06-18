-- This server provides an internal-only API for the dehydrated bash hook
-- script to call. This allows for storing the tokens or certificates in the
-- configured storage adapter (which allows for non-local storage mechanisms
-- that can be shared across multiple servers, so this can work in a
-- multi-server, load-balanced environment).
return function(auto_ssl_instance)
  if ngx.var.http_x_hook_secret ~= ngx.shared.auto_ssl_settings:get("hook_server:secret") then
    ngx.log(ngx.ERR, "auto-ssl: unauthorized access to hook server (hook secret did not match)")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end

  ngx.req.read_body()
  local params, params_err = ngx.req.get_post_args()
  if not params then
    ngx.log(ngx.ERR, "auto-ssl: failed to parse POST args: ", params_err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  local path = ngx.var.request_uri
  local storage = auto_ssl_instance:get("storage")
  if path == "/deploy-challenge" then
    assert(params["domain"])
    assert(params["token_filename"])
    assert(params["token_value"])
    local _, err = storage:set_challenge(params["domain"], params["token_filename"], params["token_value"])
    if err then
      ngx.log(ngx.ERR, "auto-ssl: failed to set challenge: ", err)
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
  elseif path == "/clean-challenge" then
    assert(params["domain"])
    assert(params["token_filename"])
    local _, err = storage:delete_challenge(params["domain"], params["token_filename"])
    if err then
      ngx.log(ngx.ERR, "auto-ssl: failed to delete challenge: ", err)
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
  elseif path == "/deploy-cert" then
    assert(params["domain"])
    assert(params["fullchain"])
    assert(params["privkey"])
    local _, err = storage:set_cert(params["domain"], params["fullchain"], params["privkey"], params["cert"])
    if err then
      ngx.log(ngx.ERR, "auto-ssl: failed to set cert: ", err)
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
  else
    ngx.log(ngx.ERR, "auto-ssl: unknown request to hook server: ", path)
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end
end
