//go:build cgo

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Benchmark suite measuring real wall-clock per FHE op on commodity hardware.
// Used to derive gas-cost floors for DoS resistance under realistic mainnet
// fee config (12M gas limit on Lux C-Chain).
//
// Re-run on each target arch to validate the gas-cost re-derivation:
//   go test -run NONE -bench BenchmarkFHE -benchtime=1x ./fhe/...

package fhe

import (
	"math/big"
	"testing"
)

// BenchmarkFHEMul_Uint8 — schoolbook O(n^2) bootstrapping multiply.
// On Apple M1 Max (high-end ARM commodity): ~78 s/op. This sets the
// upper bound on per-op wall-clock and dominates the gas-floor derivation.
func BenchmarkFHEMul_Uint8(b *testing.B) {
	if err := initTFHE(); err != nil {
		b.Fatal(err)
	}
	ctA := tfheTrivialEncrypt(big.NewInt(3), TypeEuint8)
	ctB := tfheTrivialEncrypt(big.NewInt(4), TypeEuint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := tfheMul(ctA, ctB, TypeEuint8)
		if result == nil {
			b.Fatal("nil result")
		}
	}
}

// BenchmarkFHEAdd_Uint8 — linear bootstrapping add. Two orders of magnitude
// faster than mul on the same parameters, but still dominated by FHE
// bootstrap latency.
func BenchmarkFHEAdd_Uint8(b *testing.B) {
	if err := initTFHE(); err != nil {
		b.Fatal(err)
	}
	ctA := tfheTrivialEncrypt(big.NewInt(3), TypeEuint8)
	ctB := tfheTrivialEncrypt(big.NewInt(4), TypeEuint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := tfheAdd(ctA, ctB, TypeEuint8)
		if result == nil {
			b.Fatal("nil result")
		}
	}
}
