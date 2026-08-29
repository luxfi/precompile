# Lux precompile build wiring.
#
# accel v1.1.3+ auto-discovers the lux-gpu substrate (libluxgpu_hqc.a
# + lux/gpu/hqc.h headers). The default build does NOT call pkg-config;
# instead, `ops/code/code_cpu.go` hardcodes a list of `#cgo CFLAGS: -I`
# and `#cgo LDFLAGS: -L` directives covering every standard prefix, and
# the compiler/linker silently skip any -I/-L that doesn't exist on the
# host. The default `go build ./...` invocation works without any env
# var as long as ONE of the following has the install:
#
#   1. /usr/local (cmake default prefix); OR
#   2. /opt/homebrew (Homebrew on Apple Silicon); OR
#   3. /opt/homebrew/opt/lux-gpu (keg-only Homebrew); OR
#   4. /usr/local/opt/lux-gpu (Homebrew on Intel Mac); OR
#   5. /opt/lux (canonical Lux prefix); OR
#   6. The Go workspace has luxfi/mlx as a sibling repo with a
#      ready-to-link `mlx/build/libluxgpu_hqc.a`.
#
# To target a non-listed install, set LUX_GPU_PREFIX:
#
#   LUX_GPU_PREFIX=/opt/custom make ci
#
# That gets fed into CGO_CFLAGS / CGO_LDFLAGS automatically. Power
# users can still set CGO_CFLAGS / CGO_LDFLAGS directly.
#
# pkg-config is only consulted when the build tag `lux_gpu_pkgconfig`
# is set explicitly (`go build -tags=lux_gpu_pkgconfig ./...`). In
# that mode the build FAILS if `pkg-config lux-gpu` does not resolve;
# there is no hardcoded-prefix fallback. The runtime introspector
# `accel.GPUPaths()` also queries pkg-config, but only as a diagnostic.

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

# The FHE tests are the reason this target exists and the reason it is slow. A
# single homomorphic multiply is ~240s of wall clock at the network's parameter
# set, so the full suite runs ~28 minutes and 600s could never have covered it.
# They skip under -short, so `make test` does not run them at all -- which is how
# a comparison that decrypted the wrong boolean in half of all runs stayed
# invisible while CI stayed green.
test-long:
	go test -count=1 -timeout 3600s ./...

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
