ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR?=$(ROOT_DIR)/build

DEHYDRATED_VERSION:=v0.3.1
LUA_RESTY_SHELL_VERSION:=955243d70506c21e7cc29f61d745d1a8a718994f
SOCKPROC_VERSION:=fc8ad3f15a7b2cf2eaf39663b90010efc55e207c

RUNTIME_DEPENDENCIES:=bash curl diff grep mktemp openssl sed
$(foreach bin,$(RUNTIME_DEPENDENCIES),\
	$(if $(shell command -v $(bin) 2> /dev/null),,$(error `$(bin)` was not found in PATH. Please install `$(bin)` first)))

.PHONY:
	all \
	grind \
	install \
	lint \
	test \
	test_dependencies

all: \
	$(BUILD_DIR)/stamp-dehydrated-2-$(DEHYDRATED_VERSION) \
	$(BUILD_DIR)/stamp-lua-resty-shell-$(LUA_RESTY_SHELL_VERSION) \
	$(BUILD_DIR)/stamp-sockproc-2-$(SOCKPROC_VERSION)

install:
	install -d $(INST_LUADIR)/resty/auto-ssl
	install -m 644 lib/resty/auto-ssl.lua $(INST_LUADIR)/resty/auto-ssl.lua
	install -m 644 lib/resty/auto-ssl/init_master.lua $(INST_LUADIR)/resty/auto-ssl/init_master.lua
	install -m 644 lib/resty/auto-ssl/init_worker.lua $(INST_LUADIR)/resty/auto-ssl/init_worker.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/jobs
	install -m 644 lib/resty/auto-ssl/jobs/renewal.lua $(INST_LUADIR)/resty/auto-ssl/jobs/renewal.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/servers
	install -m 644 lib/resty/auto-ssl/servers/challenge.lua $(INST_LUADIR)/resty/auto-ssl/servers/challenge.lua
	install -m 644 lib/resty/auto-ssl/servers/hook.lua $(INST_LUADIR)/resty/auto-ssl/servers/hook.lua
	install -m 644 lib/resty/auto-ssl/ssl_certificate.lua $(INST_LUADIR)/resty/auto-ssl/ssl_certificate.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/ssl_providers
	install -m 644 lib/resty/auto-ssl/ssl_providers/lets_encrypt.lua $(INST_LUADIR)/resty/auto-ssl/ssl_providers/lets_encrypt.lua
	install -m 644 lib/resty/auto-ssl/storage.lua $(INST_LUADIR)/resty/auto-ssl/storage.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/storage_adapters
	install -m 644 lib/resty/auto-ssl/storage_adapters/file.lua $(INST_LUADIR)/resty/auto-ssl/storage_adapters/file.lua
	install -m 644 lib/resty/auto-ssl/storage_adapters/redis.lua $(INST_LUADIR)/resty/auto-ssl/storage_adapters/redis.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/utils
	install -m 644 lib/resty/auto-ssl/utils/shell_execute.lua $(INST_LUADIR)/resty/auto-ssl/utils/shell_execute.lua
	install -m 644 lib/resty/auto-ssl/utils/start_sockproc.lua $(INST_LUADIR)/resty/auto-ssl/utils/start_sockproc.lua
	install -m 644 lib/resty/auto-ssl/utils/run_command.lua $(INST_LUADIR)/resty/auto-ssl/utils/run_command.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/vendor
	install -m 644 lib/resty/auto-ssl/vendor/shell.lua $(INST_LUADIR)/resty/auto-ssl/vendor/shell.lua
	install -d $(INST_BINDIR)/resty-auto-ssl
	install -m 755 bin/letsencrypt_hooks $(INST_BINDIR)/resty-auto-ssl/letsencrypt_hooks
	install -m 755 bin/start_sockproc $(INST_BINDIR)/resty-auto-ssl/start_sockproc
	install -m 755 $(BUILD_DIR)/bin/dehydrated $(INST_BINDIR)/resty-auto-ssl/dehydrated
	install -m 755 $(BUILD_DIR)/bin/sockproc $(INST_BINDIR)/resty-auto-ssl/sockproc

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/stamp-dehydrated-2-$(DEHYDRATED_VERSION): | $(BUILD_DIR)
	rm -f $(BUILD_DIR)/stamp-dehydrated-*
	mkdir -p $(BUILD_DIR)/bin
	curl -sSLo $(BUILD_DIR)/bin/dehydrated "https://raw.githubusercontent.com/lukas2511/dehydrated/$(DEHYDRATED_VERSION)/dehydrated"
	chmod +x $(BUILD_DIR)/bin/dehydrated
	touch $@

$(BUILD_DIR)/stamp-lua-resty-shell-$(LUA_RESTY_SHELL_VERSION): | $(BUILD_DIR)
	rm -f $(BUILD_DIR)/stamp-lua-resty-shell-*
	curl -sSLo $(ROOT_DIR)/lib/resty/auto-ssl/vendor/shell.lua "https://raw.githubusercontent.com/juce/lua-resty-shell/$(LUA_RESTY_SHELL_VERSION)/lib/resty/shell.lua"
	touch $@

$(BUILD_DIR)/stamp-sockproc-2-$(SOCKPROC_VERSION): | $(BUILD_DIR)
	rm -f $(BUILD_DIR)/stamp-sockproc-*
	mkdir -p $(BUILD_DIR)/bin
	cd $(BUILD_DIR) && curl -sSLo sockproc-$(SOCKPROC_VERSION).tar.gz "https://github.com/juce/sockproc/archive/$(SOCKPROC_VERSION).tar.gz"
	cd $(BUILD_DIR) && tar -xf sockproc-$(SOCKPROC_VERSION).tar.gz
	cd $(BUILD_DIR)/sockproc-$(SOCKPROC_VERSION) && make
	cp $(BUILD_DIR)/sockproc-$(SOCKPROC_VERSION)/sockproc $(BUILD_DIR)/bin/sockproc
	chmod +x $(BUILD_DIR)/bin/sockproc
	touch $@

#
# Testing
#

ifeq ("$(LUA_MODE)", "lua52")
OPENRESTY_FLAGS:="--with-luajit-xcflags='-DLUAJIT_ENABLE_LUA52COMPAT'"
else
OPENRESTY_FLAGS:=
endif

TEST_RUN_DIR?=$(ROOT_DIR)/t/run
TEST_BUILD_DIR:=$(TEST_RUN_DIR)/build$(LUA_MODE)
TEST_VENDOR_DIR:=$(TEST_RUN_DIR)/vendor$(LUA_MODE)
TEST_TMP_DIR:=$(TEST_RUN_DIR)/tmp$(LUA_MODE)
TEST_LOGS_DIR:=$(TEST_RUN_DIR)/logs$(LUA_MODE)
TEST_LUAROCKS_DIR:=$(TEST_VENDOR_DIR)/lib/luarocks/rocks
TEST_LUA_SHARE_DIR:=$(TEST_VENDOR_DIR)/share/lua/5.1
TEST_LUA_LIB_DIR:=$(TEST_VENDOR_DIR)/lib/lua/5.1

LUACHECK:=luacheck
LUACHECK_VERSION:=0.19.1-1

OPENSSL_VERSION:=1.0.2k
OPENSSL:=openssl-$(OPENSSL_VERSION)

OPENRESTY_VERSION:=1.11.2.3
OPENRESTY:=openresty-$(OPENRESTY_VERSION)

LUAROCKS_VERSION=2.4.2
LUAROCKS=luarocks-$(LUAROCKS_VERSION)

NGROK_VERSION:=2.2.4
NGROK:=ngrok-$(NGROK_VERSION)

PERL_EXPECT_VERSION=1.33
PERL_EXTUTILS_MAKEMAKER_VERSION=7.24
PERL_TEST_NGINX_VERSION=0.26

PATH:=$(TEST_BUILD_DIR)/bin:$(TEST_BUILD_DIR)/nginx/sbin:$(TEST_BUILD_DIR)/luajit/bin:$(TEST_VENDOR_DIR)/$(NGROK):$(PATH)

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

$(TEST_LUAROCKS_DIR)/$(LUACHECK)/$(LUACHECK_VERSION): $(TEST_TMP_DIR)/stamp-$(LUAROCKS) | $(TEST_VENDOR_DIR)
	$(call test_luarocks_install,LUACHECK)

$(TEST_TMP_DIR)/cpanm: | $(TEST_TMP_DIR)
	curl -o $@ -L http://cpanmin.us
	chmod +x $@
	touch -c $@

# Install newer version of ExtUtils::MakeMaker for Expect's installation.
# Without this, older versions of the bundled MakeMaker don't properly install
# Expect's dependencies.
$(TEST_TMP_DIR)/stamp-perl-extutils-makemaker-$(PERL_EXTUTILS_MAKEMAKER_VERSION): $(TEST_TMP_DIR)/cpanm
	$(TEST_TMP_DIR)/cpanm -L $(TEST_BUILD_DIR) --no-wget --verbose --reinstall --notest ExtUtils::MakeMaker@$(PERL_EXTUTILS_MAKEMAKER_VERSION)
	touch $@

$(TEST_TMP_DIR)/stamp-perl-expect-$(PERL_EXPECT_VERSION): $(TEST_TMP_DIR)/stamp-perl-extutils-makemaker-$(PERL_EXTUTILS_MAKEMAKER_VERSION) $(TEST_TMP_DIR)/cpanm
	$(TEST_TMP_DIR)/cpanm -L $(TEST_BUILD_DIR) --no-wget --verbose --reinstall --notest Expect@$(PERL_EXPECT_VERSION)
	touch $@

$(TEST_TMP_DIR)/stamp-perl-test-nginx-$(PERL_TEST_NGINX_VERSION): $(TEST_TMP_DIR)/cpanm
	$(TEST_TMP_DIR)/cpanm -L $(TEST_BUILD_DIR) --no-wget --verbose --reinstall --notest Test::Nginx@$(PERL_TEST_NGINX_VERSION)
	touch $@

UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
$(TEST_VENDOR_DIR)/$(NGROK)/ngrok: | $(TEST_TMP_DIR) $(TEST_VENDOR_DIR)
	curl -L -o $(TEST_TMP_DIR)/ngrok-$(NGROK_VERSION)-linux-amd64.tar.gz https://bin.equinox.io/a/kpdp6Edfc5q/ngrok-$(NGROK_VERSION)-linux-amd64.tar.gz
	mkdir -p $(TEST_VENDOR_DIR)/$(NGROK)
	tar -C $(TEST_VENDOR_DIR)/$(NGROK) -xf $(TEST_TMP_DIR)/ngrok-$(NGROK_VERSION)-linux-amd64.tar.gz
endif
ifeq ($(UNAME), Darwin)
$(TEST_VENDOR_DIR)/$(NGROK)/ngrok: | $(TEST_TMP_DIR) $(TEST_VENDOR_DIR)
	curl -L -o $(TEST_TMP_DIR)/ngrok_$(NGROK_VERSION)-darwin-amd64.zip https://bin.equinox.io/a/jhmzSv18UeY/ngrok-$(NGROK_VERSION)-darwin-amd64.zip
	unzip $(TEST_TMP_DIR)/ngrok_$(NGROK_VERSION)-darwin-amd64.zip -d $(TEST_VENDOR_DIR)/$(NGROK)
endif

$(TEST_TMP_DIR)/$(OPENSSL): | $(TEST_TMP_DIR)
	cd $(TEST_TMP_DIR) && rm -rf openssl*
	cd $(TEST_TMP_DIR) && curl -L -O https://www.openssl.org/source/$(OPENSSL).tar.gz
	cd $(TEST_TMP_DIR) && tar -xf $(OPENSSL).tar.gz

$(TEST_TMP_DIR)/stamp-$(OPENRESTY): $(TEST_TMP_DIR)/$(OPENSSL) | $(TEST_TMP_DIR)
	cd $(TEST_TMP_DIR) && rm -rf openresty*
	cd $(TEST_TMP_DIR) && curl -L -O https://github.com/openresty/openresty/releases/download/v$(OPENRESTY_VERSION)/$(OPENRESTY).tar.gz
	cd $(TEST_TMP_DIR) && tar -xf $(OPENRESTY).tar.gz
	cd $(TEST_TMP_DIR)/$(OPENRESTY) && ./configure --prefix=$(TEST_BUILD_DIR) --with-debug --with-openssl=$(TEST_TMP_DIR)/$(OPENSSL) $(OPENRESTY_FLAGS)
	cd $(TEST_TMP_DIR)/$(OPENRESTY) && make
	cd $(TEST_TMP_DIR)/$(OPENRESTY) && make install
	touch $@

$(TEST_TMP_DIR)/stamp-$(LUAROCKS): $(TEST_TMP_DIR)/stamp-$(OPENRESTY) | $(TEST_TMP_DIR)
	cd $(TEST_TMP_DIR) && rm -rf luarocks*
	cd $(TEST_TMP_DIR) && curl -L -O http://luarocks.org/releases/$(LUAROCKS).tar.gz
	cd $(TEST_TMP_DIR) && tar -xf $(LUAROCKS).tar.gz
	cd $(TEST_TMP_DIR)/$(LUAROCKS) && ./configure \
		--prefix=$(TEST_BUILD_DIR)/luajit \
		--with-lua=$(TEST_BUILD_DIR)/luajit \
		--with-lua-include=$(TEST_BUILD_DIR)/luajit/include/luajit-2.1 \
		--lua-suffix=jit-2.1.0-beta2
	cd $(TEST_TMP_DIR)/$(LUAROCKS) && make bootstrap
	touch $@

test_dependencies: \
	$(TEST_LUAROCKS_DIR)/$(LUACHECK)/$(LUACHECK_VERSION) \
	$(TEST_VENDOR_DIR)/$(NGROK)/ngrok \
	$(TEST_TMP_DIR)/stamp-$(OPENRESTY) \
	$(TEST_TMP_DIR)/stamp-$(LUAROCKS) \
	$(TEST_TMP_DIR)/stamp-perl-expect-$(PERL_EXPECT_VERSION) \
	$(TEST_TMP_DIR)/stamp-perl-test-nginx-$(PERL_TEST_NGINX_VERSION)

lint: test_dependencies
	LUA_PATH="$(TEST_LUA_SHARE_DIR)/?.lua;$(TEST_LUA_SHARE_DIR)/?/init.lua;;" LUA_CPATH="$(TEST_LUA_LIB_DIR)/?.so;;" $(TEST_VENDOR_DIR)/bin/luacheck lib

test: test_dependencies lint
	PATH=$(PATH) ROOT_DIR=$(ROOT_DIR) TEST_RUN_DIR=$(TEST_RUN_DIR) TEST_BUILD_DIR=$(TEST_BUILD_DIR) TEST_LOGS_DIR=$(TEST_LOGS_DIR) TEST_LUA_SHARE_DIR=$(TEST_LUA_SHARE_DIR) TEST_LUA_LIB_DIR=$(TEST_LUA_LIB_DIR) t/run_tests

grind:
	env TEST_NGINX_USE_VALGRIND=1 TEST_NGINX_SLEEP=5 $(MAKE) test
