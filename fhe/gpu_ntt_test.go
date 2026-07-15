// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import "testing"

// These tests pin the determinism gate's decision logic and the default-build
// posture. They carry NO build tag and require NO GPU, so they run on every CI
// node and prove the fail-closed property independently of any accelerator.

// TestByteEqualCorpus_AcceptsIdentical proves the gate accepts a byte-identical
// corpus (the only condition under which GPU dispatch may arm).
func TestByteEqualCorpus_AcceptsIdentical(t *testing.T) {
	cpu := [][]uint64{{1, 2, 3, 4}, {5, 6, 7, 8}}
	gpu := [][]uint64{{1, 2, 3, 4}, {5, 6, 7, 8}}
	ok, v, i := byteEqualCorpus(cpu, gpu)
	if !ok {
		t.Fatalf("identical corpus rejected at vec=%d coeff=%d", v, i)
	}
}

// TestByteEqualCorpus_FailClosedOnDivergence proves the gate REJECTS any
// single-coefficient divergence and pinpoints it. This is the consensus
// safety property: a GPU NTT that differs from the CPU NTT in even one
// coefficient must never arm, so a divergent ciphertext can never commit.
func TestByteEqualCorpus_FailClosedOnDivergence(t *testing.T) {
	cases := []struct {
		name      string
		cpu, gpu  [][]uint64
		wantVec   int
		wantCoeff int
	}{
		{
			name:      "single coeff flip",
			cpu:       [][]uint64{{1, 2, 3, 4}, {5, 6, 7, 8}},
			gpu:       [][]uint64{{1, 2, 3, 4}, {5, 6, 99, 8}}, // 7 -> 99
			wantVec:   1,
			wantCoeff: 2,
		},
		{
			name:      "off-by-one in last coeff",
			cpu:       [][]uint64{{0, 0, 0, 0}},
			gpu:       [][]uint64{{0, 0, 0, 1}},
			wantVec:   0,
			wantCoeff: 3,
		},
		{
			name:      "length mismatch (vector count)",
			cpu:       [][]uint64{{1}, {2}},
			gpu:       [][]uint64{{1}},
			wantVec:   -1,
			wantCoeff: -1,
		},
		{
			name:      "length mismatch (vector size)",
			cpu:       [][]uint64{{1, 2, 3}},
			gpu:       [][]uint64{{1, 2}},
			wantVec:   0,
			wantCoeff: -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, v, i := byteEqualCorpus(tc.cpu, tc.gpu)
			if ok {
				t.Fatalf("divergent corpus was ACCEPTED — gate failed open (fork risk)")
			}
			if v != tc.wantVec || i != tc.wantCoeff {
				t.Fatalf("divergence located at vec=%d coeff=%d, want vec=%d coeff=%d",
					v, i, tc.wantVec, tc.wantCoeff)
			}
		})
	}
}

// TestDeterministicVec_StableAndInRange proves the probe corpus is a pure
// function of (seed, N, Q) — identical across runs/validators — and that every
// coefficient is reduced into [0, Q). A probe vector that varied per run could
// let a divergence slip past the gate on one node but not another.
func TestDeterministicVec_StableAndInRange(t *testing.T) {
	const N = 1024
	const Q = uint64(0x7fff801) // FHE bootstrap modulus (PN10QP27)
	a := deterministicVec(42, N, Q)
	b := deterministicVec(42, N, Q)
	if len(a) != N {
		t.Fatalf("len=%d want %d", len(a), N)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at i=%d: %d != %d", i, a[i], b[i])
		}
		if a[i] >= Q {
			t.Fatalf("coeff %d = %d not reduced mod Q=%d", i, a[i], Q)
		}
	}
	// Different seed must give a different stream (sanity: not all-equal).
	c := deterministicVec(43, N, Q)
	same := true
	for i := range a {
		if a[i] != c[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("seed 42 and 43 produced identical vectors")
	}
}

// TestGPUNTT_DefaultOff_IsPureGo proves the default build (no -tags gpu) never
// arms GPU dispatch and reports the pure-Go CPU path. In a `-tags gpu` build
// this test is replaced by the real-HW arming assertions in gpu_ntt_on_test.go.
func TestGPUNTT_DefaultOff_IsPureGo(t *testing.T) {
	if builtWithGPU {
		t.Skip("built with -tags gpu; armed-path assertions live in gpu_ntt_on_test.go")
	}
	st := GPUNTT()
	if st.Built {
		t.Fatalf("default build reports Built=true")
	}
	if st.Armed {
		t.Fatalf("default build reports Armed=true — GPU must be opt-in")
	}
	if st.Backend != "CPU (pure Go)" {
		t.Fatalf("default backend = %q, want CPU (pure Go)", st.Backend)
	}
}
