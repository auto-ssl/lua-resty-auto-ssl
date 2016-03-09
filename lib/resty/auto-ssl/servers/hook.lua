-- This server provides an internal-only API for the letsencrypt'sh bash hook
-- script to call. This allows for storing the tokens or certificates in the
-- configured storage adapter (which allows for non-local storage mechanisms
-- that can be shared across multiple servers, so this can work in a
-- multi-server, load-balanced environment).
return function(auto_ssl_instance)
  ngx.req.read_body()
  local path = ngx.var.request_uri
  local params = ngx.req.get_post_args()

  if ngx.var.http_x_hook_secret ~= ngx.shared.auto_ssl:get("hook_server:secret") then
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local storage = auto_ssl_instance:get("storage")
  if path == "/deploy-challenge" then
    assert(params["domain"])
    assert(params["token_filename"])
    assert(params["token_value"])
    local _, err = storage:set_challenge(params["domain"], params["token_filename"], params["token_value"])
    if err then
      ngx.log(ngx.ERR, "auto-ssl: failed to set challenge: ", err)
    end
  elseif path == "/clean-challenge" then
    assert(params["domain"])
    assert(params["token_filename"])
    local _, err = storage:delete_challenge(params["domain"], params["token_filename"])
    if err then
      ngx.log(ngx.ERR, "auto-ssl: failed to delete challenge: ", err)
    end
  elseif path == "/deploy-cert" then
    assert(params["domain"])
    assert(params["fullchain"])
    assert(params["privkey"])
    local _, err = storage:set_cert(params["domain"], params["fullchain"], params["privkey"], params["cert"])
    if err then
      ngx.log(ngx.ERR, "auto-ssl: failed to set cert: ", err)
    end
  end
end
