// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
)

// p3qBenchFixture pre-computes a signed-MLDSA65 payload + EncodeInput
// wire frame so each benchmark iteration only exercises the precompile
// dispatch + FIPS 204 verifier (no key-gen, no sign).
type p3qBenchFixture struct {
	input  []byte
	gas    uint64
	pkBuf  []byte
	sigBuf []byte
	hash   []byte
}

func mkFixture(b *testing.B) *p3qBenchFixture {
	b.Helper()
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	hash := bytes.Repeat([]byte{0x42}, MessageHashSize)
	sig, err := sk.SignCtx(rand.Reader, hash, PrecompileCtx)
	if err != nil {
		b.Fatalf("SignCtx: %v", err)
	}
	pk := sk.PublicKey.Bytes()
	input := EncodeInput(ModeMLDSA65, sig, pk, hash)
	gas := P3QVerifyPrecompile.RequiredGas(input)
	return &p3qBenchFixture{input: input, gas: gas * 2, pkBuf: pk, sigBuf: sig, hash: hash}
}

// BenchmarkP3Q_Verify_Pulsar_MLDSA65 measures one full P3Q precompile
// dispatch (kind-byte dispatch + structural checks + FIPS 204 verify)
// for the canonical Pulsar / ML-DSA-65 happy path. b.N >= 10000 by
// default; the run wraps the existing TestP3Q_RoundTrip_RealMLDSA path.
func BenchmarkP3Q_Verify_Pulsar_MLDSA65(b *testing.B) {
	f := mkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, f.input, f.gas, true)
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
}

// BenchmarkP3Q_Verify_KindDispatch_N1 measures the per-call dispatch
// cost on a single-kind workload — every iteration is KindPulsar.
// Pairs with the N=64 / N=1024 batch variants below to show the
// kind-byte dispatch overhead vs a hypothetical single-kind slot.
func BenchmarkP3Q_Verify_KindDispatch_N1(b *testing.B) {
	f := mkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, f.input, f.gas, true)
	}
}

// BenchmarkP3Q_Verify_KindDispatch_N64 iterates a verify-batch of 64
// inside one b.N step. ns/op is per-batch; per-verify is ns/op / 64.
func BenchmarkP3Q_Verify_KindDispatch_N64(b *testing.B) {
	f := mkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 64; j++ {
			_, _, _ = P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, f.input, f.gas, true)
		}
	}
}

// BenchmarkP3Q_Verify_KindDispatch_N1024 iterates a verify-batch of 1024.
// ns/op is per-batch; per-verify is ns/op / 1024.
func BenchmarkP3Q_Verify_KindDispatch_N1024(b *testing.B) {
	f := mkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1024; j++ {
			_, _, _ = P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, f.input, f.gas, true)
		}
	}
}

// BenchmarkP3Q_RequiredGas isolates the gas-only path (no verify) so
// the kind-byte dispatch + structural-check cost can be measured
// independently from the FIPS 204 verifier.
func BenchmarkP3Q_RequiredGas(b *testing.B) {
	input := make([]byte, MinInputLength+MLDSA65SignatureSize+MLDSA65PublicKeySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = P3QVerifyPrecompile.RequiredGas(input)
	}
}

// BenchmarkP3Q_Verify_Standalone measures the in-process Verify entry
// point (the off-chain pre-flight + chains/zkvm dispatch path) at
// MLDSA-65. This is the API path without precompile-level gas
// accounting and AccessibleState plumbing.
func BenchmarkP3Q_Verify_Standalone(b *testing.B) {
	f := mkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(ModeMLDSA65, f.pkBuf, f.sigBuf, f.hash); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}
