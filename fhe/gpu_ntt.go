// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"encoding/binary"
	"sync"

	"github.com/luxfi/crypto"
)

// GPU acceleration of the FHE precompile, stated precisely.
//
// luxfi/fhe is an FHEW/TFHE scheme: each ciphertext is a bundle of LWE bits
// and every arithmetic/comparison op is a Boolean circuit whose gates are
// programmable bootstraps. The dominant cost of a bootstrap is the negacyclic
// number-theoretic transform (NTT) over the blind-rotation ring, run on the
// CPU by github.com/luxfi/lattice/v7. The GPU FHE kernels accelerate exactly
// that NTT (and, in the fused-PBS bridge, the whole blind rotation).
//
// THE CONSENSUS INVARIANT. The FHE precompile is on a deterministic execution
// path: every validator must derive the byte-identical result ciphertext, or
// the chain forks. Therefore GPU acceleration here is *only ever* a
// transparent, byte-identical optimization of the underlying NTT. It must
// never change which ciphertext is produced. The gate below runs the GPU NTT
// and the canonical pure-Go NTT on a deterministic corpus and refuses to arm
// unless every coefficient is byte-identical. Any divergence, missing GPU
// library, or link/runtime error leaves the precompile on the pure-Go path
// (fail-closed to CPU). A one-coefficient disagreement between an accelerated
// validator and a pure-Go validator is a fork; the gate exists to make that
// impossible by construction.
//
// This is the orthogonal decomposition (church of Hickey): WHAT the precompile
// computes (a TFHE op over LWE-bit ciphertexts) is one concern, owned by the
// CPU path in fhe_ops.go; WHETHER the NTT underneath runs on a byte-identical
// GPU kernel is a separate concern, owned here. The two are never braided: the
// op handlers do not know or care whether the NTT was accelerated.

// GPUNTTStatus reports whether byte-identical GPU acceleration of the TFHE
// bootstrap NTT is armed for the FHE precompile's ring on this build and host.
type GPUNTTStatus struct {
	Built   bool   // compiled with `-tags gpu` and cgo
	Armed   bool   // byte-equality gate passed and GPU NTT dispatch enabled
	Backend string // "CPU (pure Go)", "Metal", "CUDA", ...
	N       int    // bootstrap ring degree the gate probed
	Q       uint64 // bootstrap ring modulus the gate probed
	Reason  string // human-readable status / why not armed
}

var (
	gpuNTTOnce   sync.Once
	gpuNTTStatus GPUNTTStatus
)

// GPUNTT returns the GPU-NTT acceleration status for the FHE precompile,
// running the byte-equality gate exactly once. Safe for concurrent use. In a
// default build it always reports the pure-Go CPU path.
func GPUNTT() GPUNTTStatus {
	gpuNTTOnce.Do(func() { gpuNTTStatus = armGPUNTT() })
	return gpuNTTStatus
}

// byteEqualCorpus is the determinism gate's sole decision predicate: it reports
// whether every coefficient of every GPU output vector equals the corresponding
// CPU output vector. Only a true result may arm GPU dispatch. It is factored
// out here, free of any GPU dependency, so the fail-closed behaviour is
// unit-testable on every platform — including CI nodes that have no GPU.
//
// On divergence it returns ok=false with the (vector, coeff) coordinates of the
// first mismatch so a rejection is diagnosable in logs.
func byteEqualCorpus(cpu, gpu [][]uint64) (ok bool, vec, coeff int) {
	if len(cpu) != len(gpu) {
		return false, -1, -1
	}
	for v := range cpu {
		if len(cpu[v]) != len(gpu[v]) {
			return false, v, -1
		}
		for i := range cpu[v] {
			if cpu[v][i] != gpu[v][i] {
				return false, v, i
			}
		}
	}
	return true, -1, -1
}

// deterministicVec returns a length-N ring element whose coefficients are a
// domain-separated keccak stream reduced mod Q. Deterministic in (seed, N, Q)
// so the byte-equality corpus is identical on every validator and every run —
// a probe vector must not depend on wall-clock or PRNG state.
func deterministicVec(seed uint64, N int, Q uint64) []uint64 {
	out := make([]uint64, N)
	var ctr [16]byte
	binary.BigEndian.PutUint64(ctr[:8], seed)
	for i := 0; i < N; i++ {
		binary.BigEndian.PutUint64(ctr[8:], uint64(i))
		h := crypto.Keccak256(ctr[:])
		out[i] = binary.BigEndian.Uint64(h[:8]) % Q
	}
	return out
}
