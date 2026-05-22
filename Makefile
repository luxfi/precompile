# Lux precompile build wiring.
#
# accel v1.1.3+ auto-discovers the lux-gpu substrate (libluxgpu_hqc.a
# + lux/gpu/hqc.h headers) by probing every standard install prefix
# via cgo. The default `go build ./...` invocation works without any
# env var, as long as ONE of the following is true:
#
#   1. `pkg-config lux-gpu` resolves (cmake --install put a
#      lux-gpu.pc on PKG_CONFIG_PATH); OR
#   2. /usr/local has the lux-gpu install (cmake default prefix); OR
#   3. /opt/homebrew has it (Homebrew on Apple Silicon); OR
#   4. /opt/lux has it (canonical Lux prefix); OR
#   5. The Go workspace has luxfi/mlx as a sibling repo with a
#      ready-to-link `mlx/build/libluxgpu_hqc.a`.
#
# To target a non-standard install, set LUX_GPU_PREFIX:
#
#   LUX_GPU_PREFIX=/opt/custom make ci
#
# That gets fed into CGO_CFLAGS / CGO_LDFLAGS automatically. Power
# users can still set CGO_CFLAGS / CGO_LDFLAGS directly.

# Optional override; empty means "use accel's auto-discovery".
LUX_GPU_PREFIX ?=

ifneq ($(LUX_GPU_PREFIX),)
export CGO_CFLAGS  += -I$(LUX_GPU_PREFIX)/include
export CGO_LDFLAGS += -L$(LUX_GPU_PREFIX)/lib
endif

export GOWORK := off

.PHONY: build test test-long vet bench clean ci print-env

build:
	go build ./...

test:
	go test -count=1 -short -timeout 300s ./...

test-long:
	go test -count=1 -timeout 600s ./...

vet:
	go vet ./...

bench:
	go test -bench=. -benchmem -run=^$$ -timeout 600s ./...

ci: vet build test

# Diagnostic: print the resolved cgo env so a debugging dev can see
# what the build will use. With LUX_GPU_PREFIX empty, accel falls
# back to its built-in fallback chain (see accel.GPUPaths()).
print-env:
	@echo "LUX_GPU_PREFIX = $(LUX_GPU_PREFIX)"
	@echo "CGO_CFLAGS     = $(CGO_CFLAGS)"
	@echo "CGO_LDFLAGS    = $(CGO_LDFLAGS)"
	@echo "GOWORK         = $(GOWORK)"
