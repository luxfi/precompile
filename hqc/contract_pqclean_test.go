// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build hqc_pqclean

package hqc

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/hqc"
	"github.com/luxfi/geth/common"
)

// TestRun_E2E_HQC128 — full end-to-end under the cgo-PQClean backend.
//
//	1. Generate an HQC-128 keypair off-chain (crypto/hqc.KeyGen).
//	2. Build the precompile wire input: op(0x01) || mode(0x00) || seed(32B) || pk.
//	3. Run the precompile → returns ct || ss.
//	4. Off-chain decapsulate the ct with the sk → recovered ss must
//	   equal the precompile's ss byte-for-byte.
//
// This is the property the HQC precompile exists to provide on-chain:
// a verifier can generate a ciphertext that decapsulates (off-chain)
// to the same shared secret a smart contract observed, and the
// transition is deterministic via the supplied seed.
func TestRun_E2E_HQC128(t *testing.T) {
	sk, err := hqc.KeyGen(hqc.HQC128, rand.Reader)
	if err != nil {
		t.Fatalf("hqc.KeyGen: %v", err)
	}
	pk := sk.Pub
	params := hqc.MustParamsFor(hqc.HQC128)

	seed := bytes.Repeat([]byte{0xAB}, SeedSize)
	in := make([]byte, 0, 2+SeedSize+params.PublicKeySize)
	in = append(in, 0x01)      // op = Encapsulate
	in = append(in, 0x00)      // mode = HQC-128
	in = append(in, seed...)   // 32-byte deterministic-rng seed
	in = append(in, pk.Bytes...)

	out, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if err != nil {
		t.Fatalf("precompile Run: %v", err)
	}
	if len(out) != params.CiphertextSize+params.SharedSecretSize {
		t.Fatalf("out len = %d, want %d (CT %d + SS %d)",
			len(out),
			params.CiphertextSize+params.SharedSecretSize,
			params.CiphertextSize,
			params.SharedSecretSize,
		)
	}
	ctBytes := out[:params.CiphertextSize]
	ssChain := out[params.CiphertextSize:]

	// Off-chain decapsulate.
	ssOff, err := hqc.Decapsulate(sk, &hqc.Ciphertext{
		Mode:  hqc.HQC128,
		Bytes: ctBytes,
	})
	if err != nil {
		t.Fatalf("off-chain Decapsulate: %v", err)
	}
	if !bytes.Equal(ssChain, ssOff) {
		t.Fatalf("ss mismatch\n  on-chain:  %x\n  off-chain: %x", ssChain, ssOff)
	}

	// Determinism: rerun the precompile with the same input; output
	// must be byte-identical. (Validators rely on this.)
	out2, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if err != nil {
		t.Fatalf("precompile rerun: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("precompile non-deterministic (load-bearing for consensus)")
	}
}

// TestRun_E2E_HQC192 — same flow, HQC-192 mode byte 0x01.
func TestRun_E2E_HQC192(t *testing.T) {
	sk, err := hqc.KeyGen(hqc.HQC192, rand.Reader)
	if err != nil {
		t.Fatalf("hqc.KeyGen: %v", err)
	}
	pk := sk.Pub
	params := hqc.MustParamsFor(hqc.HQC192)

	seed := bytes.Repeat([]byte{0xCD}, SeedSize)
	in := make([]byte, 0, 2+SeedSize+params.PublicKeySize)
	in = append(in, 0x01)
	in = append(in, 0x01) // mode = HQC-192
	in = append(in, seed...)
	in = append(in, pk.Bytes...)

	out, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 2_000_000, true)
	if err != nil {
		t.Fatalf("precompile Run: %v", err)
	}
	ctBytes := out[:params.CiphertextSize]
	ssChain := out[params.CiphertextSize:]

	ssOff, err := hqc.Decapsulate(sk, &hqc.Ciphertext{
		Mode:  hqc.HQC192,
		Bytes: ctBytes,
	})
	if err != nil {
		t.Fatalf("off-chain Decapsulate: %v", err)
	}
	if !bytes.Equal(ssChain, ssOff) {
		t.Fatalf("HQC-192 ss mismatch")
	}
}

// TestRun_E2E_HQC256 — same flow, HQC-256 mode byte 0x02.
func TestRun_E2E_HQC256(t *testing.T) {
	sk, err := hqc.KeyGen(hqc.HQC256, rand.Reader)
	if err != nil {
		t.Fatalf("hqc.KeyGen: %v", err)
	}
	pk := sk.Pub
	params := hqc.MustParamsFor(hqc.HQC256)

	seed := bytes.Repeat([]byte{0xEF}, SeedSize)
	in := make([]byte, 0, 2+SeedSize+params.PublicKeySize)
	in = append(in, 0x01)
	in = append(in, 0x02) // mode = HQC-256
	in = append(in, seed...)
	in = append(in, pk.Bytes...)

	out, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 3_000_000, true)
	if err != nil {
		t.Fatalf("precompile Run: %v", err)
	}
	ctBytes := out[:params.CiphertextSize]
	ssChain := out[params.CiphertextSize:]

	ssOff, err := hqc.Decapsulate(sk, &hqc.Ciphertext{
		Mode:  hqc.HQC256,
		Bytes: ctBytes,
	})
	if err != nil {
		t.Fatalf("off-chain Decapsulate: %v", err)
	}
	if !bytes.Equal(ssChain, ssOff) {
		t.Fatalf("HQC-256 ss mismatch")
	}
}
