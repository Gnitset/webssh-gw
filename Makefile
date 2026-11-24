GO ?= go
XTERM_VERSION ?= 5.5.0
ADDON_FIT_VERSION ?= 0.10.0
NOVNC_VERSION ?= 1.7.0
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: all server wasm wasmexec deps vendor clean

all: deps server wasm wasmexec vendor

deps:
	$(GO) mod tidy

# Fetched once and cached here; each target is skipped by make if the file
# already exists. `make clean` removes them to force a re-fetch.
vendor: web/xterm.js web/xterm.css web/addon-fit.js web/novnc/core/rfb.js

web/xterm.js:
	curl -L -o web/xterm.js https://unpkg.com/@xterm/xterm@$(XTERM_VERSION)/lib/xterm.js

web/xterm.css:
	curl -L -o web/xterm.css https://unpkg.com/@xterm/xterm@$(XTERM_VERSION)/css/xterm.css

web/addon-fit.js:
	curl -L -o web/addon-fit.js https://unpkg.com/@xterm/addon-fit@$(ADDON_FIT_VERSION)/lib/addon-fit.js

# noVNC ships as a tree of ES modules (core/*.js importing each other and
# vendor/pako/*.js by relative path), not a single bundle, so this pulls the
# npm tarball and extracts just those two subtrees instead of one curl per
# file.
web/novnc/core/rfb.js:
	rm -rf web/novnc
	mkdir -p web/novnc
	curl -L https://registry.npmjs.org/@novnc/novnc/-/novnc-$(NOVNC_VERSION).tgz | tar xz -C web/novnc --strip-components=1 package/core package/vendor

server:
	$(GO) build -ldflags "-X main.buildTime=$(BUILD_TIME)" -o webssh-gw ./server

wasm:
	GOOS=js GOARCH=wasm $(GO) build -o web/main.wasm ./client

# Copy the Go runtime shim next to the wasm. Path moved in Go 1.21+.
wasmexec:
	@if [ -f "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" ]; then \
		cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" web/ ; \
	else \
		cp "$$($(GO) env GOROOT)/misc/wasm/wasm_exec.js" web/ ; \
	fi
	@echo "wasm_exec.js copied"

clean:
	rm -f webssh-gw web/main.wasm web/wasm_exec.js web/xterm.js web/xterm.css web/addon-fit.js
	rm -rf web/novnc
