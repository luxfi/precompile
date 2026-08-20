// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && gpu

package fhe

import (
	"testing"

	luxfhe "github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/gpu"
	"github.com/luxfi/lattice/v7/ring"
)

// These tests are the real-hardware determinism corpus. They run only in a
// `-tags gpu` cgo build linked against the lux-lattice GPU library, on a host
// with a usable GPU (Metal on Apple Silicon, CUDA on NVIDIA). They prove the
// consensus invariant the gate depends on: the GPU negacyclic NTT is
// byte-identical to the canonical pure-Go NTT for the FHE precompile's exact
// bootstrap ring parameters.
//
// Run on Metal (M1):
//   SDKROOT=$(xcrun --show-sdk-path) \
//   PKG_CONFIG_PATH=<dir with lux-lattice.pc -> libluxlattice> \
//   DYLD_LIBRARY_PATH=/opt/homebrew/lib \
//   CGO_ENABLED=1 GOWORK=off go test -tags gpu ./fhe/ -run GPU -v

// fheBootstrapRing returns the precompile's actual TFHE blind-rotation ring
// (whatever Params names) as a fully-initialized pure-Go SubRing.
func fheBootstrapRing(t *testing.T) (*ring.SubRing, int, uint64) {
	t.Helper()
	params, err := luxfhe.NewParametersFromLiteral(Params)
	if err != nil {
		t.Fatalf("load Params: %v", err)
	}
	N, Q := params.NBR(), params.QBR()
	r, err := ring.NewRing(N, []uint64{Q})
	if err != nil {
		t.Fatalf("ring.NewRing(N=%d, Q=%#x): %v", N, Q, err)
	}
	return r.SubRings[0], N, Q
}

// TestGPU_FHEBootstrapNTT_ByteIdenticalToCPU is the keystone proof: for the FHE
// precompile's exact bootstrap modulus, the GPU forward and inverse NTT equal
// the pure-Go SubRing NTT coefficient-for-coefficient across a large corpus.
// The existing lattice gpu suite only covers a 61-bit prime; this proves it for
// the bootstrap modulus the precompile actually uses.
func TestGPU_FHEBootstrapNTT_ByteIdenticalToCPU(t *testing.T) {
	if !gpu.Available() {
		t.Skip("GPU library not available at runtime")
	}
	sr, N, Q := fheBootstrapRing(t)
	t.Logf("FHE bootstrap ring: N=%d Q=%#x backend=%s", N, Q, gpu.GetBackend())

	ctx, err := gpu.NewMontgomeryNTTContext(sr)
	if err != nil {
		t.Fatalf("NewMontgomeryNTTContext: %v", err)
	}
	defer ctx.Close()

	const vectors = 1024
	for v := 0; v < vectors; v++ {
		in := deterministicVec(uint64(v), N, Q)

		// Forward: GPU vs pure-Go, byte-for-byte.
		cpuFwd := make([]uint64, N)
		gpuFwd := make([]uint64, N)
		copy(cpuFwd, in)
		copy(gpuFwd, in)
		sr.NTT(cpuFwd, cpuFwd)
		if err := ctx.Forward(gpuFwd, 1); err != nil {
			t.Fatalf("vec=%d Forward: %v", v, err)
		}
		for i := 0; i < N; i++ {
			if cpuFwd[i] != gpuFwd[i] {
				t.Fatalf("FORWARD divergence vec=%d coeff=%d: cpu=%#016x gpu=%#016x",
					v, i, cpuFwd[i], gpuFwd[i])
			}
		}

		// Inverse on the matching forward output: GPU vs pure-Go.
		cpuBwd := make([]uint64, N)
		gpuBwd := make([]uint64, N)
		copy(cpuBwd, cpuFwd)
		copy(gpuBwd, cpuFwd)
		sr.INTT(cpuBwd, cpuBwd)
		if err := ctx.Backward(gpuBwd, 1); err != nil {
			t.Fatalf("vec=%d Backward: %v", v, err)
		}
		for i := 0; i < N; i++ {
			if cpuBwd[i] != gpuBwd[i] {
				t.Fatalf("INVERSE divergence vec=%d coeff=%d: cpu=%#016x gpu=%#016x",
					v, i, cpuBwd[i], gpuBwd[i])
			}
		}
	}
	t.Logf("byte-identical GPU<->CPU NTT proven over %d vectors (forward+inverse) for FHE ring N=%d Q=%#x",
		vectors, N, Q)
}

// TestGPU_RingDispatch_ByteIdentical proves the END-TO-END dispatcher path the
// TFHE bootstrap actually hits: ring.Ring.NTT routes a *registered* SubRing
// through the GPU and an *unregistered* SubRing through pure-Go. With dispatch
// armed at threshold N, both must yield identical bytes — i.e. if luxfi/fhe
// registers its bootstrap ring, every ringQBR.NTT inside blindrot.Evaluate is
// byte-identical to the pure-Go path, hence so is the whole bootstrap, hence so
// is every FHE op the precompile computes.
func TestGPU_RingDispatch_ByteIdentical(t *testing.T) {
	if !gpu.Available() {
		t.Skip("GPU library not available at runtime")
	}
	_, N, Q := fheBootstrapRing(t)

	// Two independent rings with the SAME parameters. Register only one.
	gpuRing, err := ring.NewRing(N, []uint64{Q})
	if err != nil {
		t.Fatalf("NewRing gpu: %v", err)
	}
	cpuRing, err := ring.NewRing(N, []uint64{Q})
	if err != nil {
		t.Fatalf("NewRing cpu: %v", err)
	}
	srGPU := gpuRing.SubRings[0]
	srCPU := cpuRing.SubRings[0]

	if _, err := gpu.RegisterSubRing(srGPU); err != nil {
		t.Fatalf("RegisterSubRing: %v", err)
	}
	defer gpu.UnregisterSubRing(srGPU)
	gpu.SetNTTThreshold(uint32(N)) // arm single-poly dispatch at >= N
	defer gpu.SetNTTThreshold(0)   // restore default (off)

	const vectors = 256
	for v := 0; v < vectors; v++ {
		in := deterministicVec(uint64(v)+0xABCD, N, Q)
		viaGPU := make([]uint64, N)
		viaCPU := make([]uint64, N)
		copy(viaGPU, in)
		copy(viaCPU, in)

		// Both calls are the exact ring.SubRing.NTT entry blindrot uses; only
		// srGPU is registered, so only it dispatches to the GPU.
		srGPU.NTT(viaGPU, viaGPU)
		srCPU.NTT(viaCPU, viaCPU)

		for i := 0; i < N; i++ {
			if viaGPU[i] != viaCPU[i] {
				t.Fatalf("dispatch divergence vec=%d coeff=%d: gpu=%#016x cpu=%#016x",
					v, i, viaGPU[i], viaCPU[i])
			}
		}
	}
	t.Logf("ring.NTT dispatcher byte-identical (GPU-registered vs pure-Go) over %d vectors", vectors)
}

// TestGPU_ArmGPUNTT_ArmsAndIsByteSafe proves the production gate (armGPUNTT via
// GPUNTT) arms on real hardware AND reports a real GPU backend — meaning the
// byte-equality corpus inside the gate passed for the FHE ring on this host.
func TestGPU_ArmGPUNTT_ArmsAndIsByteSafe(t *testing.T) {
	if !gpu.Available() {
		t.Skip("GPU library not available at runtime")
	}
	st := GPUNTT()
	if !st.Built {
		t.Fatalf("Built=false in a -tags gpu binary")
	}
	if !st.Armed {
		t.Fatalf("gate did not arm on real GPU: %s", st.Reason)
	}
	if st.Backend == "CPU (pure Go)" {
		t.Fatalf("armed but backend still CPU: %s", st.Reason)
	}
	// Derived from Params, never restated: a hard-coded pair here would keep
	// asserting the OLD ring after a parameter change and pass while the GPU
	// evaluated a different one than the CPU.
	want, perr := luxfhe.NewParametersFromLiteral(Params)
	if perr != nil {
		t.Fatalf("load Params: %v", perr)
	}
	if st.N != want.NBR() || st.Q != want.QBR() {
		t.Fatalf("GPU ring N=%d Q=%#x does not match Params N=%d Q=%#x — the GPU would "+
			"evaluate a different ring than the CPU evaluator", st.N, st.Q, want.NBR(), want.QBR())
	}
	t.Logf("armed: %s", st.Reason)
}

// TestGPU_Gate_FailClosedOnInjectedDivergence proves the gate's rejection
// branch at the corpus level on real hardware: take the genuine GPU output,
// flip one coefficient, and confirm byteEqualCorpus rejects it — the same
// predicate armGPUNTT uses to decide whether to UnregisterSubRing and fall back
// to CPU. (Metal cannot be made to diverge on demand, so divergence is injected
// into a copy of its real output; the decision predicate is identical.)
func TestGPU_Gate_FailClosedOnInjectedDivergence(t *testing.T) {
	if !gpu.Available() {
		t.Skip("GPU library not available at runtime")
	}
	sr, N, Q := fheBootstrapRing(t)
	ctx, err := gpu.NewMontgomeryNTTContext(sr)
	if err != nil {
		t.Fatalf("NewMontgomeryNTTContext: %v", err)
	}
	defer ctx.Close()

	in := deterministicVec(7, N, Q)
	cpu := make([]uint64, N)
	gpuOut := make([]uint64, N)
	copy(cpu, in)
	copy(gpuOut, in)
	sr.NTT(cpu, cpu)
	if err := ctx.Forward(gpuOut, 1); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	// Genuine output is byte-identical: gate accepts.
	if ok, _, _ := byteEqualCorpus([][]uint64{cpu}, [][]uint64{gpuOut}); !ok {
		t.Fatalf("genuine GPU output rejected — real divergence on this host")
	}

	// Inject a single-coefficient divergence: gate must reject (fail-closed).
	bad := make([]uint64, N)
	copy(bad, gpuOut)
	bad[N/2] ^= 1
	if ok, v, i := byteEqualCorpus([][]uint64{cpu}, [][]uint64{bad}); ok {
		t.Fatalf("injected divergence ACCEPTED — gate would fail open (fork risk)")
	} else {
		t.Logf("fail-closed confirmed: rejected at vec=%d coeff=%d", v, i)
	}
}
