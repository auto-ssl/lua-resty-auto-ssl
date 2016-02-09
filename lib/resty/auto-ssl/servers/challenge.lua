-- This server should be setup to respond on port 80 to
-- /.well-known/acme-challenge/* requests. This handles Let's Encrypt's
-- HTTP-based verification and proves domain ownership by returning the
-- challenge token from our storage at the expected endpoint.
return function(auto_ssl_instance)
  -- Extract the dynamic token filename part out of the URL path.
  local path = ngx.var.request_uri
  local matches, match_err = ngx.re.match(path, "/([A-Za-z0-9\\-_]+)$")
  if not matches or not matches[1] then
    ngx.exit(ngx.HTTP_NOT_FOUND)
  elseif match_err then
    ngx.log(ngx.ERR, "auto-ssl: regex error: ", match_err)
  end
  local token_filename = matches[1]

  -- Return the challenge value for this token if it's found.
  local domain = ngx.var.host
  local storage = auto_ssl_instance:get("storage")
  local value = storage:get_challenge(domain, token_filename)
  if value then
    ngx.say(value)
    ngx.exit(ngx.HTTP_OK)
  else
    ngx.exit(ngx.HTTP_NOT_FOUND)
  end
end
