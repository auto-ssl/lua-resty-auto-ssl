ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR:=$(ROOT_DIR)/build

.PHONY:
	lint \
	test \
	test_dependencies

all: \
	$(ROOT_DIR)/lib/resty/auto-ssl/vendor/letsencrypt.sh \
	$(ROOT_DIR)/lib/resty/auto-ssl/vendor/shell.lua \
	$(ROOT_DIR)/lib/resty/auto-ssl/vendor/sockproc

install:
	install -D -m 644 lib/resty/auto-ssl.lua $(INST_LUADIR)/resty/auto-ssl.lua
	install -D -m 644 lib/resty/auto-ssl/init_worker.lua $(INST_LUADIR)/resty/auto-ssl/init_worker.lua
	install -D -m 644 lib/resty/auto-ssl/servers/challenge.lua $(INST_LUADIR)/resty/auto-ssl/servers/challenge.lua
	install -D -m 644 lib/resty/auto-ssl/servers/hook.lua $(INST_LUADIR)/resty/auto-ssl/servers/hook.lua
	install -D -m 755 lib/resty/auto-ssl/shell/letsencrypt_hooks $(INST_LUADIR)/resty/auto-ssl/shell/letsencrypt_hooks
	install -D -m 755 lib/resty/auto-ssl/shell/start_sockproc $(INST_LUADIR)/resty/auto-ssl/shell/start_sockproc
	install -D -m 644 lib/resty/auto-ssl/ssl_certificate.lua $(INST_LUADIR)/resty/auto-ssl/ssl_certificate.lua
	install -D -m 644 lib/resty/auto-ssl/ssl_providers/lets_encrypt.lua $(INST_LUADIR)/resty/auto-ssl/ssl_providers/lets_encrypt.lua
	install -D -m 644 lib/resty/auto-ssl/storage.lua $(INST_LUADIR)/resty/auto-ssl/storage.lua
	install -D -m 644 lib/resty/auto-ssl/storage_adapters/file.lua $(INST_LUADIR)/resty/auto-ssl/storage_adapters/file.lua
	install -D -m 644 lib/resty/auto-ssl/utils/shell_execute.lua $(INST_LUADIR)/resty/auto-ssl/utils/shell_execute.lua
	install -D -m 644 lib/resty/auto-ssl/utils/start_sockproc.lua $(INST_LUADIR)/resty/auto-ssl/utils/start_sockproc.lua
	install -D -m 755 lib/resty/auto-ssl/vendor/letsencrypt.sh $(INST_LUADIR)/resty/auto-ssl/vendor/letsencrypt.sh
	install -D -m 644 lib/resty/auto-ssl/vendor/shell.lua $(INST_LUADIR)/resty/auto-ssl/vendor/shell.lua
	install -D -m 755 lib/resty/auto-ssl/vendor/sockproc $(INST_LUADIR)/resty/auto-ssl/vendor/sockproc

$(ROOT_DIR)/lib/resty/auto-ssl/vendor/letsencrypt.sh:
	curl -sSLo $@ "https://raw.githubusercontent.com/lukas2511/letsencrypt.sh/21c18dd3b8c2572b894d9ec2e5c3fc2589f56f32/letsencrypt.sh"
	chmod +x $@
	touch $@

$(ROOT_DIR)/lib/resty/auto-ssl/vendor/shell.lua:
	curl -sSLo $@ "https://raw.githubusercontent.com/juce/lua-resty-shell/0f88be3272c703686ef0d37f267f0616672c6931/lib/resty/shell.lua"

$(ROOT_DIR)/lib/resty/auto-ssl/vendor/sockproc:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && curl -sSLo sockproc-0d7b390c0b4879e29b7f3dff578285c42af613dc.tar.gz "https://github.com/juce/sockproc/archive/0d7b390c0b4879e29b7f3dff578285c42af613dc.tar.gz"
	cd $(BUILD_DIR) && tar -xf sockproc-0d7b390c0b4879e29b7f3dff578285c42af613dc.tar.gz
	cd $(BUILD_DIR)/sockproc-0d7b390c0b4879e29b7f3dff578285c42af613dc && make
	cp $(BUILD_DIR)/sockproc-0d7b390c0b4879e29b7f3dff578285c42af613dc/sockproc $@
	chmod +x $@
	touch $@

#
# Testing
#

TEST_BUILD_DIR:=$(ROOT_DIR)/t/build
TEST_VENDOR_DIR:=$(ROOT_DIR)/t/vendor
TEST_TMP_DIR:=$(ROOT_DIR)/t/tmp
TEST_LUAROCKS_DIR:=$(TEST_VENDOR_DIR)/lib/luarocks/rocks
TEST_LUA_SHARE_DIR:=$(TEST_VENDOR_DIR)/share/lua/5.1
TEST_LUA_LIB_DIR:=$(TEST_VENDOR_DIR)/lib/lua/5.1
PATH:=$(TEST_BUILD_DIR)/bin:$(TEST_BUILD_DIR)/nginx/sbin:$(TEST_BUILD_DIR)/luajit/bin:$(PATH)

LUACHECK:=luacheck
LUACHECK_VERSION:=0.13.0-1

OPENSSL_VERSION:=1.0.2e
OPENSSL:=openssl-$(OPENSSL_VERSION)

OPENRESTY_VERSION:=1.9.7.2
OPENRESTY:=ngx_openresty-$(OPENRESTY_VERSION)

LUAROCKS_VERSION=2.3.0
LUAROCKS=luarocks-$(LUAROCKS_VERSION)

NGROK_VERSION:=2.0.19
NGROK:=ngrok-$(NGROK_VERSION)

define test_luarocks_install
  $(eval PACKAGE:=$($(1)))
  $(eval PACKAGE_VERSION:=$($(1)_VERSION))
  luarocks --tree=$(TEST_VENDOR_DIR) install $(PACKAGE) $(PACKAGE_VERSION)
  touch $@
endef

$(TEST_TMP_DIR):
	mkdir -p $@

$(TEST_VENDOR_DIR):
	mkdir -p $@

$(TEST_LUAROCKS_DIR)/$(LUACHECK)/$(LUACHECK_VERSION): | $(TEST_VENDOR_DIR)
	$(call test_luarocks_install,LUACHECK)

$(TEST_TMP_DIR)/cpanm: | $(TEST_TMP_DIR)
	curl -o $@ -L http://cpanmin.us
	chmod +x $@
	touch $@

$(TEST_BUILD_DIR)/lib/perl5/Expect.pm: $(TEST_TMP_DIR)/cpanm
	$< -L $(TEST_BUILD_DIR) --notest Expect
	chmod u+w $@
	touch $@

$(TEST_BUILD_DIR)/lib/perl5/File/Slurp.pm: $(TEST_TMP_DIR)/cpanm
	$< -L $(TEST_BUILD_DIR) --notest File::Slurp
	chmod u+w $@
	touch $@

$(TEST_BUILD_DIR)/lib/perl5/Test/Nginx.pm: $(TEST_TMP_DIR)/cpanm
	$< -L $(TEST_BUILD_DIR) --notest LWP::Protocol::https
	$< -L $(TEST_BUILD_DIR) --notest https://github.com/openresty/test-nginx/archive/9eeb0957a5eb0f2dd800e9627a12191073adb2ad.tar.gz
	chmod u+w $@
	touch $@

$(TEST_VENDOR_DIR)/$(NGROK)/ngrok: | $(TEST_TMP_DIR) $(TEST_VENDOR_DIR)
	curl -L -o $(TEST_TMP_DIR)/ngrok_$(NGROK_VERSION)_linux_amd64.zip https://dl.ngrok.com/ngrok_$(NGROK_VERSION)_linux_amd64.zip
	unzip $(TEST_TMP_DIR)/ngrok_$(NGROK_VERSION)_linux_amd64.zip -d $(TEST_VENDOR_DIR)/$(NGROK)

$(TEST_TMP_DIR)/$(OPENSSL): | $(TEST_TMP_DIR)
	cd $(TEST_TMP_DIR) && rm -rf openssl*
	cd $(TEST_TMP_DIR) && curl -L -O http://mirrors.ibiblio.org/openssl/source/$(OPENSSL).tar.gz
	cd $(TEST_TMP_DIR) && tar -xf $(OPENSSL).tar.gz

$(TEST_TMP_DIR)/$(OPENRESTY)/.installed: $(TEST_TMP_DIR)/$(OPENSSL) | $(TEST_TMP_DIR)
	cd $(TEST_TMP_DIR) && rm -rf ngx_openresty*
	cd $(TEST_TMP_DIR) && curl -L -O https://openresty.org/download/$(OPENRESTY).tar.gz
	cd $(TEST_TMP_DIR) && tar -xf $(OPENRESTY).tar.gz
	cd $(TEST_TMP_DIR)/$(OPENRESTY) && ./configure --prefix=$(TEST_BUILD_DIR) --with-openssl=$(TEST_TMP_DIR)/$(OPENSSL)
	cd $(TEST_TMP_DIR)/$(OPENRESTY) && make
	cd $(TEST_TMP_DIR)/$(OPENRESTY) && make install
	touch $@

$(TEST_TMP_DIR)/$(LUAROCKS)/.installed: $(TEST_TMP_DIR)/$(OPENRESTY)/.installed | $(TEST_TMP_DIR)
	cd $(TEST_TMP_DIR) && rm -rf luarocks*
	cd $(TEST_TMP_DIR) && curl -L -O http://luarocks.org/releases/$(LUAROCKS).tar.gz
	cd $(TEST_TMP_DIR) && tar -xf $(LUAROCKS).tar.gz
	cd $(TEST_TMP_DIR)/$(LUAROCKS) && ./configure \
		--prefix=$(TEST_BUILD_DIR)/luajit \
		--with-lua=$(TEST_BUILD_DIR)/luajit \
		--with-lua-include=$(TEST_BUILD_DIR)/luajit/include/luajit-2.1 \
		--lua-suffix=jit-2.1.0-beta1
	cd $(TEST_TMP_DIR)/$(LUAROCKS) && make bootstrap
	touch $@

test_dependencies: \
	$(TEST_LUAROCKS_DIR)/$(LUACHECK)/$(LUACHECK_VERSION) \
	$(TEST_VENDOR_DIR)/$(NGROK)/ngrok \
	$(TEST_TMP_DIR)/$(OPENRESTY)/.installed \
	$(TEST_TMP_DIR)/$(LUAROCKS)/.installed \
	$(TEST_BUILD_DIR)/lib/perl5/Expect.pm \
	$(TEST_BUILD_DIR)/lib/perl5/File/Slurp.pm \
	$(TEST_BUILD_DIR)/lib/perl5/Test/Nginx.pm

lint: test_dependencies
	LUA_PATH="$(TEST_LUA_SHARE_DIR)/?.lua;$(TEST_LUA_SHARE_DIR)/?/init.lua;;" LUA_CPATH="$(TEST_LUA_LIB_DIR)/?.so;;" $(TEST_VENDOR_DIR)/bin/luacheck lib

test: test_dependencies lint
	PATH=$(PATH) luarocks make ./lua-resty-auto-ssl-git-1.rockspec
	PATH=$(PATH) PERL5LIB=$(TEST_BUILD_DIR)/lib/perl5 prove

grind:
	env TEST_NGINX_USE_VALGRIND=1 TEST_NGINX_SLEEP=5 $(MAKE) test
