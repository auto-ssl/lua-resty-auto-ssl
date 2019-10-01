ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR?=$(ROOT_DIR)/build

DEHYDRATED_VERSION:=05eda91a2fbaed1e13c733230238fc68475c535e
LUA_RESTY_SHELL_VERSION:=955243d70506c21e7cc29f61d745d1a8a718994f
SOCKPROC_VERSION:=92aba736027bb5d96e190b71555857ac5bb6b2be

RUNTIME_DEPENDENCIES:=bash curl cut date diff grep mktemp openssl sed

.PHONY: \
	all \
	check-dependencies \
	install \
	install-test-deps \
	lint \
	test \
	release

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
	install -m 644 lib/resty/auto-ssl/utils/parse_openssl_time.lua $(INST_LUADIR)/resty/auto-ssl/utils/parse_openssl_time.lua
	install -m 644 lib/resty/auto-ssl/utils/random_seed.lua $(INST_LUADIR)/resty/auto-ssl/utils/random_seed.lua
	install -m 644 lib/resty/auto-ssl/utils/shell_execute.lua $(INST_LUADIR)/resty/auto-ssl/utils/shell_execute.lua
	install -m 644 lib/resty/auto-ssl/utils/shuffle_table.lua $(INST_LUADIR)/resty/auto-ssl/utils/shuffle_table.lua
	install -m 644 lib/resty/auto-ssl/utils/start_sockproc.lua $(INST_LUADIR)/resty/auto-ssl/utils/start_sockproc.lua
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

install-test-deps:
	rm -rf /tmp/resty-auto-ssl-test-luarocks
	mkdir -p /tmp/resty-auto-ssl-test-luarocks
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install busted 2.0.0-1
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install etlua 1.3.0-1
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install inspect 3.1.1-0
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install lua-resty-http 0.15-0
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install luacheck 0.23.0-1
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install luaposix 34.1.1-1
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install penlight 1.5.4-1
	luarocks install luarocks-fetch-gitrec && luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install process 1.9.0-1
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks install shell-games 1.0.1-1

lint:
	luacheck lib spec

test:
	luarocks --tree=/tmp/resty-auto-ssl-test-luarocks make ./lua-resty-auto-ssl-git-1.rockspec
	rm -rf /tmp/resty-auto-ssl-server-luarocks
	luarocks --tree=/tmp/resty-auto-ssl-server-luarocks make ./lua-resty-auto-ssl-git-1.rockspec
	luarocks --tree=/tmp/resty-auto-ssl-server-luarocks install dkjson 2.5-2
	busted ./spec

release:
	# Ensure the rockspec has been renamed and updated.
	grep -q -F 'version = "${VERSION}-1"' "lua-resty-auto-ssl-${VERSION}-1.rockspec"
	grep -q -F 'tag = "v${VERSION}"' "lua-resty-auto-ssl-${VERSION}-1.rockspec"
	# Ensure the CHANGELOG has been updated.
	grep -q -F '## ${VERSION} -' CHANGELOG.md
	# Make sure tests pass.
	docker-compose run --rm -v "${PWD}:/app" app make test
	# Check for remote tag.
	git ls-remote -t | grep -F "refs/tags/v${VERSION}^{}"
	# Verify LuaRock can be built locally.
	docker-compose run --rm -v "${PWD}:/app" app luarocks pack "lua-resty-auto-ssl-${VERSION}-1.rockspec"
	# Upload to LuaRocks
	docker-compose run --rm -v "${HOME}/.luarocks/upload_config.lua:/root/.luarocks/upload_config.lua" -v "${PWD}:/app" app luarocks upload "lua-resty-auto-ssl-${VERSION}-1.rockspec"
