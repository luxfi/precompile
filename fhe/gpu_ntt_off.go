// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !gpu

package fhe

// builtWithGPU reports whether this binary was compiled with the GPU NTT
// substrate available (`-tags gpu` + cgo).
const builtWithGPU = false

// armGPUNTT is the default build's no-op. Without `-tags gpu` (and cgo), the
// FHE precompile runs the pure-Go TFHE path end-to-end; there is no GPU
// dispatcher to arm. GPU NTT acceleration is opt-in at build time via
// `-tags gpu` with cgo enabled and the lux-lattice GPU library linked
// (pkg-config: lux-lattice). See gpu_ntt_on.go for the armed path.
func armGPUNTT() GPUNTTStatus {
	return GPUNTTStatus{
		Built:   false,
		Armed:   false,
		Backend: "CPU (pure Go)",
		Reason:  "built without -tags gpu (cgo): pure-Go TFHE NTT, no GPU dispatcher",
	}
}
