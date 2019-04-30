ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR?=$(ROOT_DIR)/build

DEHYDRATED_VERSION:=0bc0bd13d6abdc027c58bec12f7c2d3198d3a677
LUA_RESTY_SHELL_VERSION:=955243d70506c21e7cc29f61d745d1a8a718994f
SOCKPROC_VERSION:=680121312d16dc20456b5d0fed00e2b0e160e0db

RUNTIME_DEPENDENCIES:=bash curl cut date diff grep mktemp openssl sed

.PHONY: \
	all \
	check-dependencies \
	grind \
	install \
	install-test-deps \
	install-test-deps-apk \
	install-test-deps-apt \
	install-test-deps-yum \
	lint \
	test

all: \
	check-dependencies \
	$(BUILD_DIR)/stamp-dehydrated-2-$(DEHYDRATED_VERSION) \
	$(BUILD_DIR)/stamp-lua-resty-shell-$(LUA_RESTY_SHELL_VERSION) \
	$(BUILD_DIR)/stamp-sockproc-2-$(SOCKPROC_VERSION)

check-dependencies:
	$(foreach bin,$(RUNTIME_DEPENDENCIES),\
		$(if $(shell command -v $(bin) 2> /dev/null),,$(error `$(bin)` was not found in PATH. Please install `$(bin)` first)))

install: check-dependencies
	install -d $(INST_LUADIR)/resty/auto-ssl
	install -m 644 lib/resty/auto-ssl.lua $(INST_LUADIR)/resty/auto-ssl.lua
	install -m 644 lib/resty/auto-ssl/init_master.lua $(INST_LUADIR)/resty/auto-ssl/init_master.lua
	install -m 644 lib/resty/auto-ssl/init_worker.lua $(INST_LUADIR)/resty/auto-ssl/init_worker.lua
	install -d $(INST_LUADIR)/resty/auto-ssl/jobs
	install -d $(INST_LUADIR)/resty/auto-ssl/json_adapters
	install -m 644 lib/resty/auto-ssl/json_adapters/cjson.lua $(INST_LUADIR)/resty/auto-ssl/json_adapters/cjson.lua
	install -m 644 lib/resty/auto-ssl/json_adapters/dkjson.lua $(INST_LUADIR)/resty/auto-ssl/json_adapters/dkjson.lua
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
	install -m 644 lib/resty/auto-ssl/utils/random_seed.lua $(INST_LUADIR)/resty/auto-ssl/utils/random_seed.lua
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

install-test-deps-apk:
	apk add --no-cache \
		coreutils \
		findutils \
		gcc \
		lsof \
		openssl \
		procps \
		perl-app-cpanminus \
		perl-dev \
		redis \
		sudo \
		wget
	curl -fsSL -o /tmp/ngrok.tar.gz https://bin.equinox.io/a/iVLSfdAz1X4/ngrok-2.2.8-linux-amd64.tar.gz
	tar -xvf /tmp/ngrok.tar.gz -C /usr/local/bin/
	rm -f /tmp/ngrok.tar.gz
	chmod +x /usr/local/bin/ngrok

install-test-deps-apt:
	apt-get update
	apt-get -y install \
		lsof \
		cpanminus \
		redis-server \
		sudo
	curl -fsSL -o /tmp/ngrok.deb https://bin.equinox.io/a/mRgETDaBsGt/ngrok-2.2.8-linux-amd64.deb
	dpkg -i /tmp/ngrok.deb || apt-get -fy install
	rm -f /tmp/ngrok.deb

install-test-deps-yum:
	yum -y install epel-release
	yum -y install \
		gcc \
		lsof \
		procps-ng \
		perl-App-cpanminus \
		redis \
		sudo \
		https://bin.equinox.io/a/8eF5UNUMwxo/ngrok-2.2.8-linux-amd64.rpm

install-test-deps:
	luarocks install dkjson 2.5-2
	luarocks install luacheck 0.22.1-1
	cpanm --notest Expect@1.35
	cpanm --notest Test::Nginx@0.26

lint:
	luacheck lib

test: lint
	PATH=$(PATH) ROOT_DIR=$(ROOT_DIR) t/run_tests

grind:
	env TEST_NGINX_USE_VALGRIND=1 TEST_NGINX_SLEEP=5 $(MAKE) test
