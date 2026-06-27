// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && starkfri_p3q

// verify_cgo_test.go — Known-Answer Test (KAT) and throughput
// measurement for the REAL strict-PQ STARK/FRI verifier binding.
//
// These run only with `-tags starkfri_p3q` (which also pulls in
// verify_cgo.go and links libp3q_c_abi.a). Run with:
//
//	make -C ../../p3q staticlib
//	go test  -tags starkfri_p3q -run TestStarkFRI_KAT       ./starkfri
//	go test  -tags starkfri_p3q -run TestStarkFRI_KAT -v    ./starkfri
//	go test  -tags starkfri_p3q -bench BenchmarkStarkFRI_RealVerify \
//	         -benchtime=2s ./starkfri
//
// The golden vectors are produced by the p3q toy prover and persisted
// at p3q/vectors/ (regenerate with `make -C ../../p3q vectors`). They
// are real STARK/FRI proofs over Goldilocks with cSHAKE256 Merkle
// commitments — the SHA3 proof is ~29.7 KiB.
package starkfri

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/geth/common"
)

// goldenDir locates p3q/vectors relative to this package
// (precompile/starkfri → ../../p3q/vectors).
func goldenDir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join("..", "..", "p3q", "vectors")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("p3q golden vectors not present at %s (run `make -C ../../p3q vectors`): %v", dir, err)
	}
	return dir
}

// loadGolden reads a (public_input, proof) golden pair. The on-disk
// proof is p3q-native (first byte = ProofSystemId 0x10/0x11). We wrap it
// in the precompile envelope by prepending the "P3Q1" MagicHeader, which
// is exactly the on-chain wire the precompile's structural gate expects.
func loadGolden(t testing.TB, name string) (pub, envelopeProof []byte) {
	t.Helper()
	dir := goldenDir(t)
	pi, err := os.ReadFile(filepath.Join(dir, name+".public_input.bin"))
	if err != nil {
		t.Skipf("missing %s.public_input.bin: %v", name, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, name+".proof.bin"))
	if err != nil {
		t.Skipf("missing %s.proof.bin: %v", name, err)
	}
	// Envelope: "P3Q1" || p3q-native-proof. The adapter in verify_cgo.go
	// strips the 4-byte magic and forwards the rest to p3q_verify.
	env := make([]byte, 0, len(MagicHeader)+len(body))
	env = append(env, []byte(MagicHeader)...)
	env = append(env, body...)
	return pi, env
}

// useRealVerifier installs the real cgo backend for the duration of the
// calling test/benchmark and restores the prior registration on cleanup.
// The verifier registration is process-global mutable state and other
// tests in this binary call RegisterVerifier(nil); this makes each KAT
// self-sufficient regardless of run order (the init() registration alone
// is not enough once a sibling test has cleared the global).
func useRealVerifier(tb testing.TB) {
	tb.Helper()
	prev := loadVerifier()
	RegisterVerifier(p3qVerifierFn)
	tb.Cleanup(func() { RegisterVerifier(prev) })
}

// runPrecompile drives the full on-chain path: wire-encode
// [version][proof_len][proof][pub_len][pub], then StarkFRIVerifyPrecompile.Run.
// Returns the precompile error (nil == accepted).
func runPrecompile(tb testing.TB, pub, envelopeProof []byte) error {
	tb.Helper()
	input := buildInput(VersionV1, envelopeProof, pub)
	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := StarkFRIVerifyPrecompile.Run(
		nil, common.Address{}, ContractStarkFRIVerifyAddress,
		input, gas, true,
	)
	return err
}

// TestStarkFRI_KAT_AcceptReal is the positive KAT: a genuine STARK/FRI
// proof, dispatched through the full precompile Run() path, MUST verify.
// This proves the binding is wired (init() registered the real cgo
// verifier) and that the verifier actually accepts a valid proof — not a
// stub that returns true unconditionally (the negative tests below pin
// that distinction).
func TestStarkFRI_KAT_AcceptReal(t *testing.T) {
	useRealVerifier(t)
	for _, name := range []string{"p3q_v1_sha3_golden", "p3q_v1_keccak_golden"} {
		t.Run(name, func(t *testing.T) {
			pub, proof := loadGolden(t, name)
			if err := runPrecompile(t, pub, proof); err != nil {
				t.Fatalf("real golden proof must verify through the precompile, got: %v", err)
			}
		})
	}
}

// TestStarkFRI_KAT_RejectTampered is the negative KAT. For each byte
// position class in a real proof, flipping a single bit MUST cause the
// precompile to reject (return a non-nil error). This is the property
// that distinguishes a REAL verifier from a stub: a sound FRI verifier
// rejects any mutation of the Merkle-committed data, the FRI openings,
// the final polynomial, or the echoed query indices.
//
// We flip:
//   - a byte in the proof BODY (post-magic) at several offsets — these
//     land in the header / trace root / FRI layer roots / final poly /
//     query openings and must break Merkle auth, the colinearity fold,
//     or the transcript echo.
//   - a byte in the PUBLIC INPUT — must break the Fiat-Shamir binding.
func TestStarkFRI_KAT_RejectTampered(t *testing.T) {
	useRealVerifier(t)
	pub, proof := loadGolden(t, "p3q_v1_sha3_golden")

	// Sanity: the untampered proof verifies (so a rejection below is
	// attributable to the tamper, not a broken baseline).
	if err := runPrecompile(t, pub, proof); err != nil {
		t.Fatalf("baseline real proof must verify before tamper test: %v", err)
	}

	// Body offsets to flip (relative to the post-magic p3q-native proof).
	// Offset 0 = ProofSystemId byte; 1.. = header; then trace_root,
	// FRI layer roots, final poly, query openings deeper in.
	bodyLen := len(proof) - len(MagicHeader)
	bodyOffsets := []int{
		1,           // header (log_degree_bound)
		11,          // first byte of the public-input echo / trace area
		bodyLen / 4, // FRI layer-root / final-poly region
		bodyLen / 2, // query-openings region (Merkle siblings)
		bodyLen - 2, // last query opening's last auth byte
	}
	for _, off := range bodyOffsets {
		// Operate on a fresh copy each time.
		mutant := make([]byte, len(proof))
		copy(mutant, proof)
		// off is into the body; the body starts at len(MagicHeader).
		mutant[len(MagicHeader)+off] ^= 0x01
		if err := runPrecompile(t, pub, mutant); err == nil {
			t.Fatalf("tampered proof (body off=%d) MUST be rejected, but precompile accepted", off)
		}
	}

	// Flip a byte in the public input — Fiat-Shamir binding must break.
	badPub := make([]byte, len(pub))
	copy(badPub, pub)
	badPub[0] ^= 0xff
	if err := runPrecompile(t, badPub, proof); err == nil {
		t.Fatal("tampered public input MUST be rejected, but precompile accepted")
	}
}

// TestStarkFRI_KAT_NotAStub is an explicit anti-stub assertion: a
// random proof of the same length as the real one must NOT verify. A
// stub that returns true unconditionally would pass the accept test but
// fails here.
func TestStarkFRI_KAT_NotAStub(t *testing.T) {
	useRealVerifier(t)
	pub, real := loadGolden(t, "p3q_v1_sha3_golden")
	// Same length, "P3Q1" magic preserved (so it clears the structural
	// gate), but the body after the ProofSystemId byte is garbage.
	fake := make([]byte, len(real))
	copy(fake[:len(MagicHeader)], []byte(MagicHeader))
	// Preserve a valid ProofSystemId byte so we exercise the verifier,
	// not the unsupported-profile reject.
	fake[len(MagicHeader)] = 0x10 // ProofSystemId::Sha3
	for i := len(MagicHeader) + 1; i < len(fake); i++ {
		fake[i] = byte(i * 31)
	}
	if err := runPrecompile(t, pub, fake); err == nil {
		t.Fatal("a garbage proof MUST be rejected; an accept here means the binding is a stub")
	}
}

// BenchmarkStarkFRI_RealVerify measures the REAL end-to-end verify rate
// (verifies/sec) through the full precompile Run() path: gas accounting
// + wire parse + magic check + cgo dispatch + genuine FRI verification.
// This is the trustless-rollup V in bundled-tx/sec = K * V * markets.
//
// Report with:
//
//	go test -tags starkfri_p3q -bench BenchmarkStarkFRI_RealVerify \
//	        -benchtime=2s ./starkfri
//
// ns/op inverts to verifies/sec.
func BenchmarkStarkFRI_RealVerify(b *testing.B) {
	useRealVerifier(b)
	pub, proof := loadGolden(b, "p3q_v1_sha3_golden")
	input := buildInput(VersionV1, proof, pub)
	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2

	// Warm up the lazily-initialised cSHAKE backend (OnceLock in Rust).
	if _, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true); err != nil {
		b.Fatalf("warm-up verify failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := StarkFRIVerifyPrecompile.Run(
			nil, common.Address{}, ContractStarkFRIVerifyAddress,
			input, gas, true,
		)
		if err != nil {
			b.Fatalf("verify failed at iter %d: %v", i, err)
		}
	}
}

// BenchmarkStarkFRI_RealVerify_Standalone measures the in-process
// Verify() entry point (off-chain pre-flight) on the same real proof,
// isolating the cgo + FRI cost from the EVM gas/parse overhead.
func BenchmarkStarkFRI_RealVerify_Standalone(b *testing.B) {
	useRealVerifier(b)
	pub, proof := loadGolden(b, "p3q_v1_sha3_golden")
	if ok, err := Verify(proof, pub); err != nil || !ok {
		b.Fatalf("warm-up standalone verify: ok=%v err=%v", ok, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := Verify(proof, pub)
		if err != nil || !ok {
			b.Fatalf("standalone verify failed at iter %d: ok=%v err=%v", i, ok, err)
		}
	}
}
