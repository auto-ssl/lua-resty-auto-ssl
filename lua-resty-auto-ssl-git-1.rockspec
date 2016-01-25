package = "lua-resty-auto-ssl"
version = "git-1"
source = {
  url = "git://github.com/GUI/lua-resty-auto-ssl.git",
}
description = {
  summary = "Automatic SSL handling for OpenResty",
  detailed = "On the fly (and free) SSL registration and renewal inside OpenResty/nginx with Let's Encrypt.",
  homepage = "https://github.com/GUI/lua-resty-auto-ssl",
  license = "MIT",
}
dependencies = {
  "lua-resty-http",
}
build = {
  type = "make",
  install_variables = {
    INST_LUADIR="$(LUADIR)",
  },
}
