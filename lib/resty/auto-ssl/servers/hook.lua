local storage = require "resty.auto-ssl.storage"

-- This server provides an internal-only API for the letsencrypt'sh bash hook
-- script to call. This allows for storing the tokens or certificates in the
-- configured storage adapter (which allows for non-local storage mechanisms
-- that can be shared across multiple servers, so this can work in a
-- multi-server, load-balanced environment).
return function()
  ngx.req.read_body()
  local path = ngx.var.request_uri
  local params = ngx.req.get_post_args()

  if ngx.var.http_x_hook_secret ~= ngx.shared.auto_ssl:get("hook_server:secret") then
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  if path == "/deploy-challenge" then
    assert(params["domain"])
    assert(params["token_filename"])
    assert(params["token_value"])
    storage.set_challenge(params["domain"], params["token_filename"], params["token_value"])
  elseif path == "/clean-challenge" then
    assert(params["domain"])
    assert(params["token_filename"])
    storage.delete_challenge(params["domain"], params["token_filename"])
  elseif path == "/deploy-cert" then
    assert(params["domain"])
    assert(params["fullchain"])
    assert(params["privkey"])
    storage.set_cert(params["domain"], params["fullchain"], params["privkey"])
  end
end
