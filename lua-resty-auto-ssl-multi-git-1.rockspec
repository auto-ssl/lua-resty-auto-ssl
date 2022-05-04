package = "lua-resty-auto-ssl-multi"
version = "git-1"
source = {
  url = "git+https://github.com/zyro-inc/lua-resty-auto-ssl-multi.git",
}
description = {
  summary = "Automatic SSL handling for OpenResty",
  detailed = "On the fly (and free) SSL registration and renewal inside OpenResty/nginx with Let's Encrypt.",
  homepage = "https://github.com/GUI/lua-resty-auto-ssl",
  license = "MIT",
}
dependencies = {
  "lua-resty-http",
  "shell-games >= 1.1.0",
  "dkjson",
}
build = {
  type = "make",
  build_variables = {
    CFLAGS="$(CFLAGS)",
    LIBFLAG="$(LIBFLAG)",
    LUA_LIBDIR="$(LUA_LIBDIR)",
    LUA_BINDIR="$(LUA_BINDIR)",
    LUA_INCDIR="$(LUA_INCDIR)",
    LUA="$(LUA)",
  },
  install_variables = {
    INST_PREFIX="$(PREFIX)",
    INST_BINDIR="$(BINDIR)",
    INST_LIBDIR="$(LIBDIR)",
    INST_LUADIR="$(LUADIR)",
    INST_CONFDIR="$(CONFDIR)",
  },
}
