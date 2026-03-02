// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vrf

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"

	edwards "filippo.io/edwards25519"
)

const testGas = 100_000

// ─── Gas ──────────────────────────────────────────────────────────────────────

func TestRequiredGas(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  uint64
	}{
		{"empty", nil, 0},
		{"verify", []byte{OpVerify}, GasVerify},
		{"proof_to_hash", []byte{OpProofToHash}, GasProofToHash},
		{"unknown_op", []byte{0xFF}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VRFPrecompile.RequiredGas(tt.input); got != tt.want {
				t.Errorf("RequiredGas = %d, want %d", got, tt.want)
			}
		})
	}
}

// ─── Out of Gas ───────────────────────────────────────────────────────────────

func TestOutOfGas(t *testing.T) {
	input := append([]byte{OpVerify}, make([]byte, 200)...)
	_, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, GasVerify-1, true)
	if err == nil {
		t.Error("expected out of gas error")
	}
}

// ─── Empty / Short Input ──────────────────────────────────────────────────────

func TestEmptyInput(t *testing.T) {
	result, gas, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, nil, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil result for empty input")
	}
	if gas != testGas {
		t.Errorf("expected full gas returned, got %d", gas)
	}
}

func TestVerifyShortInput(t *testing.T) {
	input := []byte{OpVerify, 0x01, 0x02}
	result, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil for short verify input")
	}
}

func TestProofToHashShortInput(t *testing.T) {
	input := append([]byte{OpProofToHash}, make([]byte, 10)...)
	result, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil for short proof_to_hash input")
	}
}

// ─── Unknown Operation ────────────────────────────────────────────────────────

func TestUnknownOp(t *testing.T) {
	input := []byte{0xFF}
	result, gas, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil for unknown op")
	}
	if gas != testGas {
		t.Errorf("expected full gas on unknown op, got %d", gas)
	}
}

// ─── Invalid Public Key ───────────────────────────────────────────────────────

func TestVerifyInvalidPublicKey(t *testing.T) {
	pk := make([]byte, 32)
	alpha := []byte("test")
	proof := make([]byte, ProofSize)

	input := buildVerifyInput(pk, alpha, proof)
	result, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil for invalid public key")
	}
}

// ─── Invalid Proof ────────────────────────────────────────────────────────────

func TestVerifyInvalidProof(t *testing.T) {
	// Generate a proof with one key, try to verify against a different key.
	sk1 := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	_, pk1 := expandSecretKey(sk1)

	sk2 := mustHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	_, pk2 := expandSecretKey(sk2)

	alpha := []byte("test message")

	// Prove with sk1
	pi := testProve(sk1, pk1, alpha)

	// Verify against pk2 -- must fail
	input := buildVerifyInput(pk2.Bytes(), alpha, pi)
	result, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil when verifying proof against wrong public key")
	}
}

// ─── Self-Consistency Tests ───────────────────────────────────────────────────

func TestProveAndVerify(t *testing.T) {
	tests := []struct {
		name  string
		skHex string
		alpha []byte
	}{
		{
			name:  "empty_alpha",
			skHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			alpha: []byte{},
		},
		{
			name:  "single_byte",
			skHex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			alpha: []byte{0x72},
		},
		{
			name:  "two_bytes",
			skHex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			alpha: []byte{0xaf, 0x82},
		},
		{
			name:  "ascii_string",
			skHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			alpha: []byte("Example of ECVRF-EDWARDS25519-SHA512-ELL2"),
		},
		{
			name:  "long_alpha",
			skHex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			alpha: make([]byte, 256),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk := mustHex(tt.skHex)
			x, Y := expandSecretKey(sk)

			// Prove
			pi := testProve(sk, Y, tt.alpha)
			if len(pi) != ProofSize {
				t.Fatalf("proof size = %d, want %d", len(pi), ProofSize)
			}

			// Verify via precompile
			input := buildVerifyInput(Y.Bytes(), tt.alpha, pi)
			result, gas, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			if err != nil {
				t.Fatalf("Run error: %v", err)
			}
			if gas != testGas-GasVerify {
				t.Errorf("remaining gas = %d, want %d", gas, testGas-GasVerify)
			}
			if result == nil {
				t.Fatal("verification returned nil (failed)")
			}
			if len(result) != BetaSize {
				t.Fatalf("beta length = %d, want %d", len(result), BetaSize)
			}

			// ProofToHash must return the same beta
			p2hInput := append([]byte{OpProofToHash}, pi...)
			p2hResult, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, p2hInput, testGas, true)
			if err != nil {
				t.Fatalf("ProofToHash error: %v", err)
			}
			if hex.EncodeToString(p2hResult) != hex.EncodeToString(result) {
				t.Errorf("ProofToHash beta differs from Verify beta")
			}

			// Determinism: same input, same output
			result2, _, _ := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			if hex.EncodeToString(result) != hex.EncodeToString(result2) {
				t.Error("VRF verify is not deterministic")
			}

			// Different alpha must produce different beta
			otherAlpha := append(tt.alpha, 0xFF)
			otherPi := testProve(sk, Y, otherAlpha)
			otherInput := buildVerifyInput(Y.Bytes(), otherAlpha, otherPi)
			otherResult, _, _ := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, otherInput, testGas, true)
			if otherResult != nil && hex.EncodeToString(result) == hex.EncodeToString(otherResult) {
				t.Error("different alpha produced same beta")
			}

			_ = x // used in prove
		})
	}
}

// ─── Uniqueness: Different keys produce different outputs ─────────────────────

func TestUniqueness(t *testing.T) {
	sk1 := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	sk2 := mustHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	alpha := []byte("uniqueness test")

	_, Y1 := expandSecretKey(sk1)
	_, Y2 := expandSecretKey(sk2)

	pi1 := testProve(sk1, Y1, alpha)
	pi2 := testProve(sk2, Y2, alpha)

	// Both must verify
	input1 := buildVerifyInput(Y1.Bytes(), alpha, pi1)
	result1, _, _ := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input1, testGas, true)
	if result1 == nil {
		t.Fatal("sk1 proof failed to verify")
	}

	input2 := buildVerifyInput(Y2.Bytes(), alpha, pi2)
	result2, _, _ := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input2, testGas, true)
	if result2 == nil {
		t.Fatal("sk2 proof failed to verify")
	}

	// Different keys must produce different betas
	if hex.EncodeToString(result1) == hex.EncodeToString(result2) {
		t.Error("different secret keys produced the same beta")
	}
}

// ─── Truncated / Corrupted Proofs ─────────────────────────────────────────────

func TestCorruptedProof(t *testing.T) {
	sk := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	_, Y := expandSecretKey(sk)
	alpha := []byte("corruption test")
	pi := testProve(sk, Y, alpha)

	// Flip a byte in the proof
	corrupted := make([]byte, len(pi))
	copy(corrupted, pi)
	corrupted[40] ^= 0xFF // corrupt the c scalar

	input := buildVerifyInput(Y.Bytes(), alpha, corrupted)
	result, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("corrupted proof should not verify")
	}
}

// ─── Gas Accounting ───────────────────────────────────────────────────────────

func TestGasAccountingVerify(t *testing.T) {
	sk := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	_, Y := expandSecretKey(sk)
	alpha := []byte{}
	pi := testProve(sk, Y, alpha)

	input := buildVerifyInput(Y.Bytes(), alpha, pi)
	_, gas, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if gas != testGas-GasVerify {
		t.Errorf("remaining gas = %d, want %d", gas, testGas-GasVerify)
	}
}

func TestGasAccountingProofToHash(t *testing.T) {
	sk := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	_, Y := expandSecretKey(sk)
	pi := testProve(sk, Y, []byte{})

	input := append([]byte{OpProofToHash}, pi...)
	_, gas, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	if err != nil {
		t.Fatal(err)
	}
	if gas != testGas-GasProofToHash {
		t.Errorf("remaining gas = %d, want %d", gas, testGas-GasProofToHash)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func buildVerifyInput(pk, alpha, proof []byte) []byte {
	var alphaLen [2]byte
	binary.BigEndian.PutUint16(alphaLen[:], uint16(len(alpha)))

	input := []byte{OpVerify}
	input = append(input, pk...)
	input = append(input, alphaLen[:]...)
	input = append(input, alpha...)
	input = append(input, proof...)
	return input
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ─── Test-only VRF Prove (RFC 9381 section 5.1) ──────────────────────────────

// expandSecretKey expands a 32-byte Ed25519 secret key into the scalar x
// and public point Y = x*B, using the same derivation as Ed25519.
func expandSecretKey(sk []byte) (*edwards.Scalar, *edwards.Point) {
	h := sha512.Sum512(sk)

	// SetBytesWithClamping applies RFC 8032 clamping and reduces mod L.
	x, err := new(edwards.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		panic(err)
	}

	Y := new(edwards.Point).ScalarBaseMult(x)
	return x, Y
}

// testProve implements ECVRF_prove (RFC 9381 section 5.1) for testing.
func testProve(sk []byte, Y *edwards.Point, alpha []byte) []byte {
	// Expand SK using Ed25519 key derivation.
	expanded := sha512.Sum512(sk)

	x, err := new(edwards.Scalar).SetBytesWithClamping(expanded[:32])
	if err != nil {
		panic(err)
	}

	pkBytes := Y.Bytes()

	// H = hash_to_curve(pk, alpha)
	H := hashToCurveELL2(pkBytes, alpha)
	if H == nil {
		panic("hash_to_curve returned nil")
	}

	// Gamma = x * H
	Gamma := new(edwards.Point).ScalarMult(x, H)

	// Nonce generation (RFC 9381 section 5.4.2.1):
	// k_string = SHA-512(truncated_hashed_sk || encode(H))
	// truncated_hashed_sk = expanded[32:64]
	nonceHash := sha512.New()
	nonceHash.Write(expanded[32:64])
	nonceHash.Write(H.Bytes())
	nonceDigest := nonceHash.Sum(nil)

	// Reduce to scalar (mod L)
	k, err := edwards.NewScalar().SetUniformBytes(nonceDigest)
	if err != nil {
		panic(err)
	}

	// U = k * B
	U := new(edwards.Point).ScalarBaseMult(k)

	// V = k * H
	V := new(edwards.Point).ScalarMult(k, H)

	// c = challenge_generation(Y, H, Gamma, U, V)
	c := challengeGeneration(Y, H, Gamma, U, V)

	// s = k + c * x (mod L)
	cx := new(edwards.Scalar).Multiply(c, x)
	s := new(edwards.Scalar).Add(k, cx)

	// Encode proof: Gamma(32) || c(16) || s(32)
	pi := make([]byte, ProofSize)
	copy(pi[:32], Gamma.Bytes())
	cBytes := c.Bytes()
	copy(pi[32:48], cBytes[:16]) // First 16 bytes of c
	copy(pi[48:80], s.Bytes())

	return pi
}

// ─── Benchmark ────────────────────────────────────────────────────────────────

func BenchmarkVerify(b *testing.B) {
	sk := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	_, Y := expandSecretKey(sk)
	alpha := []byte{}
	pi := testProve(sk, Y, alpha)
	input := buildVerifyInput(Y.Bytes(), alpha, pi)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true) //nolint:errcheck
	}
}

func BenchmarkProofToHash(b *testing.B) {
	sk := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	_, Y := expandSecretKey(sk)
	pi := testProve(sk, Y, []byte{})
	input := append([]byte{OpProofToHash}, pi...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true) //nolint:errcheck
	}
}
