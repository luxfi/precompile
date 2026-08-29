// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && gpu

package fhe

import (
	"fmt"

	luxfhe "github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/gpu"
	"github.com/luxfi/lattice/v7/ring"
)

// builtWithGPU reports whether this binary was compiled with the GPU NTT
// substrate available (`-tags gpu` + cgo).
const builtWithGPU = true

// gpuProbeVectors is the size of the deterministic byte-equality corpus the
// gate runs (forward and inverse) before arming GPU dispatch. Each vector is a
// full ring element. Sized to exercise many distinct coefficient values
// through the GPU modular-reduction path for the FHE bootstrap modulus.
const gpuProbeVectors = 64

// armGPUNTT derives the FHE bootstrap ring for the precompile's parameter
// literal (Params), binds the lattice GPU Montgomery NTT context to that
// exact SubRing, and runs the byte-equality gate: forward and inverse GPU NTT
// versus the canonical pure-Go SubRing NTT across a deterministic corpus. GPU
// dispatch is enabled ONLY if every coefficient is byte-identical. Any
// divergence or error unregisters the GPU context and leaves the ring on the
// pure-Go path (fail-closed to CPU).
//
// Reach (stated honestly): the precompile and luxfi/fhe share the bootstrap
// ring's (N, Q) but not the *ring.SubRing pointer — fhe encapsulates paramsBR,
// exposing only N()/NBR()/QLWE()/QBR(). The lattice GPU dispatcher keys by
// pointer identity (gpu.LookupSubRing), so this function proves and arms the
// byte-identical GPU NTT substrate for the precompile's exact ring parameters.
// Routing fhe's *own* bootstrap SubRing through that substrate is a one-line
// gpu.RegisterSubRing hook inside luxfi/fhe (NewShortIntEvaluator), under the
// same build tag; the byte-equality contract proven here is the prerequisite
// that makes that hook consensus-safe. See the GPU bridge note in the package
// doc / report.
func armGPUNTT() GPUNTTStatus {
	// Derive the exact bootstrap ring parameters from the precompile's FHE
	// parameter literal so this gate tracks any future parameter change
	// instead of hard-coding (N, Q).
	params, err := luxfhe.NewParametersFromLiteral(Params)
	if err != nil {
		return GPUNTTStatus{Built: true, Backend: "CPU (pure Go)",
			Reason: fmt.Sprintf("param load failed: %v; pure-Go NTT", err)}
	}
	N := params.NBR()
	Q := params.QBR()
	st := GPUNTTStatus{Built: true, Backend: "CPU (pure Go)", N: N, Q: Q}

	if !gpu.Available() {
		st.Reason = "GPU library unavailable at runtime; pure-Go NTT"
		return st
	}

	// Canonical pure-Go ring (the consensus oracle) for (N, Q).
	r, err := ring.NewRing(N, []uint64{Q})
	if err != nil {
		st.Reason = fmt.Sprintf("ring.NewRing(N=%d, Q=%#x): %v; pure-Go NTT", N, Q, err)
		return st
	}
	sr := r.SubRings[0]

	// Bind a Montgomery GPU context to this exact SubRing. The context
	// captures the SubRing's roots / MRedConstant / NInv, so its output is
	// byte-equal to ring.SubRing.NTT by construction — the gate below
	// verifies that construction holds for this build and host.
	if _, err := gpu.RegisterSubRing(sr); err != nil {
		st.Reason = fmt.Sprintf("gpu.RegisterSubRing: %v; pure-Go NTT", err)
		return st
	}

	if ok, vec, coeff := probeRingByteEqual(sr, N, Q); !ok {
		gpu.UnregisterSubRing(sr) // FAIL CLOSED: divergent GPU never arms.
		st.Reason = fmt.Sprintf(
			"GPU NTT diverged from CPU at vec=%d coeff=%d; fail-closed to CPU", vec, coeff)
		return st
	}

	// Gate passed. Enable single-poly GPU dispatch at >= N for registered
	// rings. The lattice dispatcher still falls through to the pure-Go NTT for
	// any unregistered ring or on any C error, so arming only ever *adds* a
	// byte-identical fast path; it never removes the CPU fallback.
	gpu.SetNTTThreshold(uint32(N))
	st.Armed = true
	st.Backend = gpu.GetBackend()
	st.Reason = fmt.Sprintf(
		"GPU NTT armed for FHE bootstrap ring N=%d Q=%#x on %s (byte-identical gate passed)",
		N, Q, st.Backend)
	return st
}

// probeRingByteEqual runs the byte-equality corpus through the GPU-bound
// SubRing context and the pure-Go SubRing, in both directions, and reports
// whether every coefficient is byte-identical. Returns the (vector, coeff)
// coordinates of the first divergence otherwise.
func probeRingByteEqual(sr *ring.SubRing, N int, Q uint64) (bool, int, int) {
	ctx := gpu.LookupSubRing(sr)
	if ctx == nil {
		return false, -1, -1
	}

	// Forward direction.
	cpuFwd := make([][]uint64, gpuProbeVectors)
	gpuFwd := make([][]uint64, gpuProbeVectors)
	for v := 0; v < gpuProbeVectors; v++ {
		in := deterministicVec(uint64(v), N, Q)
		c := make([]uint64, N)
		g := make([]uint64, N)
		copy(c, in)
		copy(g, in)
		sr.NTT(c, c) // pure-Go consensus oracle
		if err := ctx.Forward(g, 1); err != nil {
			return false, v, -1
		}
		cpuFwd[v] = c
		gpuFwd[v] = g
	}
	if ok, v, i := byteEqualCorpus(cpuFwd, gpuFwd); !ok {
		return false, v, i
	}

	// Inverse direction, applied to the (matching) forward outputs.
	cpuBwd := make([][]uint64, gpuProbeVectors)
	gpuBwd := make([][]uint64, gpuProbeVectors)
	for v := 0; v < gpuProbeVectors; v++ {
		c := make([]uint64, N)
		g := make([]uint64, N)
		copy(c, cpuFwd[v])
		copy(g, cpuFwd[v])
		sr.INTT(c, c)
		if err := ctx.Backward(g, 1); err != nil {
			return false, v, -1
		}
		cpuBwd[v] = c
		gpuBwd[v] = g
	}
	if ok, v, i := byteEqualCorpus(cpuBwd, gpuBwd); !ok {
		return false, v, i
	}
	return true, -1, -1
}
