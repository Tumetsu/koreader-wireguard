WIREPROXY_VERSION ?= v1.1.3
PLUGIN := wireguard.koplugin
DIST := dist

# GOARM=7 suits Cortex-A7/A9/A53 readers (PocketBook, Kobo, Kindle); the
# binary is static (CGO off), so it does not care about the firmware's libc.
GOFLAGS_ARM := CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7

.PHONY: all wireproxy wireproxy-host package test lint clean

all: package

wireproxy: $(PLUGIN)/bin/wireproxy

$(PLUGIN)/bin/wireproxy:
	mkdir -p $(DIST)/gobin
	GOBIN= GOPATH=$(CURDIR)/$(DIST)/gopath GOMODCACHE=$(shell go env GOMODCACHE) $(GOFLAGS_ARM) \
		go install -trimpath -ldflags="-s -w" github.com/windtf/wireproxy/cmd/wireproxy@$(WIREPROXY_VERSION)
	cp $(DIST)/gopath/bin/linux_arm/wireproxy $@
	chmod +x $@
	# wireproxy is ISC-licensed: ship its notice alongside the binary.
	cp $(shell go env GOMODCACHE)/github.com/windtf/wireproxy@$(WIREPROXY_VERSION)/LICENSE $(PLUGIN)/bin/wireproxy.LICENSE
	chmod u+w $(PLUGIN)/bin/wireproxy.LICENSE

# Native build, used by the tests.
wireproxy-host: $(DIST)/host/wireproxy

$(DIST)/host/wireproxy:
	mkdir -p $(DIST)/host
	GOBIN=$(CURDIR)/$(DIST)/host CGO_ENABLED=0 \
		go install -trimpath github.com/windtf/wireproxy/cmd/wireproxy@$(WIREPROXY_VERSION)

package: wireproxy
	mkdir -p $(DIST)
	rm -f $(DIST)/$(PLUGIN).zip
	zip -r $(DIST)/$(PLUGIN).zip $(PLUGIN) -x '*/.gitkeep'

test: wireproxy-host
	WIREPROXY=$(CURDIR)/$(DIST)/host/wireproxy sh tests/tunnel_test.sh
	WIREPROXY=$(CURDIR)/$(DIST)/host/wireproxy luajit tests/plugin_test.lua

lint:
	shellcheck -s sh $(PLUGIN)/wgctl.sh tests/tunnel_test.sh
	luajit -bl $(PLUGIN)/main.lua >/dev/null
	luajit -bl $(PLUGIN)/_meta.lua >/dev/null

clean:
	chmod -R u+w $(DIST) 2>/dev/null || true
	rm -rf $(DIST) $(PLUGIN)/bin/wireproxy $(PLUGIN)/bin/wireproxy.LICENSE
