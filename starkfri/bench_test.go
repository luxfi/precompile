// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package starkfri

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
)

// buildBenchInput re-implements the package-local buildInput helper for
// bench scope (cannot share private test helpers across files cleanly).
// Wire: [1B version][4B proof_len][N proof][4B pub_len][M pub].
func buildBenchInput(version byte, proof, pub []byte) []byte {
	out := make([]byte, 0, 1+4+len(proof)+4+len(pub))
	out = append(out, version)
	var pl [4]byte
	binary.BigEndian.PutUint32(pl[:], uint32(len(proof)))
	out = append(out, pl[:]...)
	out = append(out, proof...)
	var ul [4]byte
	binary.BigEndian.PutUint32(ul[:], uint32(len(pub)))
	out = append(out, ul[:]...)
	out = append(out, pub...)
	return out
}

// BenchmarkStarkFRI_Verify_AcceptAll measures the full precompile path
// (gas check + wire parse + MagicHeader check + verifier dispatch) with
// an accept-all callback registered. Proof body is a representative 2KiB
// payload — typical STARK-FRI proof footprint for Goldilocks/Plonky3.
func BenchmarkStarkFRI_Verify_AcceptAll(b *testing.B) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	defer RegisterVerifier(nil)

	body := make([]byte, 2048-MinProofLength)
	for i := range body {
		body[i] = byte(i)
	}
	proof := sfProof(body)
	pub := make([]byte, 128)
	input := buildBenchInput(VersionV1, proof, pub)
	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
}

// BenchmarkStarkFRI_Verify_RejectMagic measures the structural-only
// path: MagicHeader missing, verifier never invoked. Tests how cheap
// the early-reject is when input fails the magic check.
func BenchmarkStarkFRI_Verify_RejectMagic(b *testing.B) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	defer RegisterVerifier(nil)

	body := make([]byte, 2048)
	for i := range body {
		body[i] = byte(i)
	}
	// Wrong magic header — first 4 bytes are not "P3Q1".
	proof := body
	pub := make([]byte, 128)
	input := buildBenchInput(VersionV1, proof, pub)
	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
	}
}

// BenchmarkStarkFRI_Verify_Standalone measures the in-process Verify
// entry-point (off-chain pre-flight) at the same 2 KiB proof size.
func BenchmarkStarkFRI_Verify_Standalone(b *testing.B) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	defer RegisterVerifier(nil)

	body := make([]byte, 2048-MinProofLength)
	for i := range body {
		body[i] = byte(i)
	}
	proof := sfProof(body)
	pub := make([]byte, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Verify(proof, pub)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// BenchmarkStarkFRI_RequiredGas isolates the gas-only path.
func BenchmarkStarkFRI_RequiredGas(b *testing.B) {
	input := make([]byte, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = StarkFRIVerifyPrecompile.RequiredGas(input)
	}
}
