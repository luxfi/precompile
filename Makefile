# Lux precompile build wiring.
#
# accel v1.1.2 introduced the ops/code package (HQC code-based KEM)
# which is a CGO bridge to libluxgpu_hqc.a built by the sibling mlx
# repo. accel's default `#cgo CFLAGS: -I${SRCDIR}/../../../mlx/include`
# resolves against the accel module path, which inside the Go module
# cache does NOT have a sibling mlx/ directory. Consumers therefore
# MUST set CGO_CFLAGS / CGO_LDFLAGS explicitly to point at a built
# mlx tree.
#
# This Makefile centralises that wiring so devs and CI use the same
# flags. The mlx checkout is expected at ~/work/lux/mlx (a symlink to
# the canonical luxcpp/gpu source tree); override via MLX_ROOT.

MLX_ROOT ?= $(HOME)/work/lux/mlx

export CGO_CFLAGS := -I$(MLX_ROOT)/include
export CGO_LDFLAGS := -L$(MLX_ROOT)/build
export GOWORK := off

.PHONY: build test vet bench clean

build:
	go build ./...

test:
	go test -count=1 -short -timeout 300s ./...

test-long:
	go test -count=1 -timeout 600s ./...

vet:
	go vet ./...

bench:
	go test -bench=. -benchmem -run=^$ -timeout 600s ./...

ci: vet build test

# Diagnostic: print the resolved CGO env so a debugging dev can see
# what the build will actually use.
print-env:
	@echo "MLX_ROOT     = $(MLX_ROOT)"
	@echo "CGO_CFLAGS   = $(CGO_CFLAGS)"
	@echo "CGO_LDFLAGS  = $(CGO_LDFLAGS)"
	@echo "GOWORK       = $(GOWORK)"
