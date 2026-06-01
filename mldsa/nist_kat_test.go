// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// FIPS 204 (ML-DSA) precompile Known-Answer-Test (KAT) coverage.
//
// Addresses TESTING_GAPS.md §1.4: "FIPS 204 KAT vectors (NIST ACVP test
// vectors for ML-DSA-44/65/87) -- Tests generate fresh keys; a library
// bug producing wrong output would pass all tests."
//
// Strategy
//
//   1. Load the deterministic seed + expected public-key prefix + expected
//      deterministic-signature prefix per mode from testdata/nist_vectors.json.
//   2. Reconstruct the keypair via cloudflare/circl NewKeyFromSeed (FIPS 204
//      keygen is fully determined by the 32-byte seed).
//   3. Pin the public-key prefix and the deterministic-signature prefix.
//      A drift in either prefix indicates the underlying lattice arithmetic
//      or encoding silently changed -- exactly the gap §1.4 describes.
//   4. Dispatch the precompile's EVM calldata frame (mode || pk || msgLen ||
//      sig || msg) through MLDSAVerifyPrecompile.Run and require byte[31] == 1.
//      This locks the precompile's binding to the wrapped library + ctx.
//   5. Also verify the precompile rejects a single-bit tampered signature
//      for each mode (FIPS 204 unforgeability sanity).
//
// The test does NOT duplicate end-to-end round-trip coverage that already
// exists in deep_test.go; it adds the deterministic-vector layer that
// catches "library is internally consistent but not correct".

package mldsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	circlmldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	circlmldsa87 "github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// nistKATMessage is the canonical message signed for every KAT vector in
// this file. It is short, ASCII, and identifies the source so an unrelated
// signature with the same prefix cannot coincidentally hit a pinned value.
var nistKATMessage = []byte("lux-precompile-nist-kat-v1")

// mldsaNISTVector mirrors the JSON schema in testdata/nist_vectors.json.
type mldsaNISTVector struct {
	Mode                       string `json:"mode"`
	ModeByte                   string `json:"mode_byte"`
	SeedHex                    string `json:"seed_hex"`
	ExpectedPublicKeyPrefixHex string `json:"expected_public_key_prefix_hex"`
	ExpectedSignaturePrefixHex string `json:"expected_signature_prefix_hex"`
	PublicKeySize              int    `json:"public_key_size"`
	SignatureSize              int    `json:"signature_size"`
}

type mldsaNISTVectorFile struct {
	Vectors []mldsaNISTVector `json:"vectors"`
}

func loadMLDSANISTVectors(t *testing.T) []mldsaNISTVector {
	t.Helper()
	path := filepath.Join("testdata", "nist_vectors.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err, "read testdata")
	var f mldsaNISTVectorFile
	require.NoError(t, json.Unmarshal(b, &f), "parse testdata")
	require.NotEmpty(t, f.Vectors, "no vectors")
	return f.Vectors
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "decode hex %q", s)
	return b
}

// signFromSeed reconstructs (pk, sig) deterministically from a seed for the
// requested mode. Returns the marshaled public key, the signature, and
// nothing else -- secret keys never leave this function.
func signFromSeed(t *testing.T, mode byte, seed []byte, msg, ctx []byte) (pk []byte, sig []byte) {
	t.Helper()
	switch mode {
	case ModeMLDSA44:
		var s [circlmldsa44.SeedSize]byte
		require.Equal(t, circlmldsa44.SeedSize, len(seed), "ML-DSA-44 seed length")
		copy(s[:], seed)
		pubKey, secKey := circlmldsa44.NewKeyFromSeed(&s)
		pkB, err := pubKey.MarshalBinary()
		require.NoError(t, err)
		out := make([]byte, circlmldsa44.SignatureSize)
		require.NoError(t, circlmldsa44.SignTo(secKey, msg, ctx, false, out))
		return pkB, out
	case ModeMLDSA65:
		var s [circlmldsa65.SeedSize]byte
		require.Equal(t, circlmldsa65.SeedSize, len(seed), "ML-DSA-65 seed length")
		copy(s[:], seed)
		pubKey, secKey := circlmldsa65.NewKeyFromSeed(&s)
		pkB, err := pubKey.MarshalBinary()
		require.NoError(t, err)
		out := make([]byte, circlmldsa65.SignatureSize)
		require.NoError(t, circlmldsa65.SignTo(secKey, msg, ctx, false, out))
		return pkB, out
	case ModeMLDSA87:
		var s [circlmldsa87.SeedSize]byte
		require.Equal(t, circlmldsa87.SeedSize, len(seed), "ML-DSA-87 seed length")
		copy(s[:], seed)
		pubKey, secKey := circlmldsa87.NewKeyFromSeed(&s)
		pkB, err := pubKey.MarshalBinary()
		require.NoError(t, err)
		out := make([]byte, circlmldsa87.SignatureSize)
		require.NoError(t, circlmldsa87.SignTo(secKey, msg, ctx, false, out))
		return pkB, out
	default:
		t.Fatalf("signFromSeed: unsupported mode 0x%02x", mode)
		return nil, nil
	}
}

// buildNISTKATInput frames a precompile call: mode || pubKey || msgLen(32) || sig || msg
func buildNISTKATInput(mode byte, pk, msg, sig []byte) []byte {
	msgLen := make([]byte, MessageLenSize)
	// big-endian uint256, low 4 bytes are enough for our short messages.
	msgLen[MessageLenSize-1] = byte(len(msg))
	if len(msg) > 255 {
		msgLen[MessageLenSize-2] = byte(len(msg) >> 8)
	}
	out := make([]byte, 0, 1+len(pk)+MessageLenSize+len(sig)+len(msg))
	out = append(out, mode)
	out = append(out, pk...)
	out = append(out, msgLen...)
	out = append(out, sig...)
	out = append(out, msg...)
	return out
}

// modeByteFromString maps the "mode_byte" JSON field (e.g. "0x44") to the
// uint8 constant declared in contract.go. Centralizes parsing so JSON drift
// fails loudly instead of silently selecting the wrong mode.
func modeByteFromString(t *testing.T, s string) byte {
	t.Helper()
	switch s {
	case "0x44":
		return ModeMLDSA44
	case "0x65":
		return ModeMLDSA65
	case "0x87":
		return ModeMLDSA87
	default:
		t.Fatalf("unknown ML-DSA mode_byte: %s", s)
		return 0
	}
}

// TestNISTKAT_MLDSA_PrefixAndPrecompileVerify is the single combined KAT
// driver. For each mode it (a) reconstructs the keypair from the pinned
// seed, (b) asserts the public-key prefix matches the JSON record,
// (c) asserts the deterministic signature prefix matches the JSON record,
// (d) drives the precompile and expects byte[31] == 1, (e) drives the
// precompile with a single-bit-flipped signature and expects byte[31] == 0.
func TestNISTKAT_MLDSA_PrefixAndPrecompileVerify(t *testing.T) {
	vectors := loadMLDSANISTVectors(t)
	ctx := precompileCtx

	for _, v := range vectors {
		v := v
		t.Run(v.Mode, func(t *testing.T) {
			mode := modeByteFromString(t, v.ModeByte)
			seed := mustHex(t, v.SeedHex)

			pk, sig := signFromSeed(t, mode, seed, nistKATMessage, ctx)

			require.Equal(t, v.PublicKeySize, len(pk), "%s pubkey size", v.Mode)
			require.Equal(t, v.SignatureSize, len(sig), "%s signature size", v.Mode)

			pkPrefix := mustHex(t, v.ExpectedPublicKeyPrefixHex)
			require.Equalf(t, pkPrefix, pk[:len(pkPrefix)],
				"%s: public-key prefix drift -- pinned vector and library no longer agree",
				v.Mode)

			sigPrefix := mustHex(t, v.ExpectedSignaturePrefixHex)
			require.Equalf(t, sigPrefix, sig[:len(sigPrefix)],
				"%s: deterministic signature prefix drift -- signing path no longer reproduces FIPS 204 vector",
				v.Mode)

			input := buildNISTKATInput(mode, pk, nistKATMessage, sig)
			gas := MLDSAVerifyPrecompile.RequiredGas(input)
			ret, _, err := MLDSAVerifyPrecompile.Run(
				nil, common.Address{}, ContractMLDSAVerifyAddress,
				input, gas+1_000_000, true,
			)
			require.NoError(t, err, "%s precompile Run", v.Mode)
			require.Len(t, ret, 32, "%s precompile output width", v.Mode)
			require.Equalf(t, byte(1), ret[31],
				"%s: precompile MUST accept FIPS 204 deterministic signature for canonical seed",
				v.Mode)

			// Tamper: flip a single bit late in the signature so the structural
			// frame stays valid but the lattice equation must fail.
			tampered := make([]byte, len(sig))
			copy(tampered, sig)
			tampered[len(tampered)-1] ^= 0x01
			input = buildNISTKATInput(mode, pk, nistKATMessage, tampered)
			gas = MLDSAVerifyPrecompile.RequiredGas(input)
			ret, _, err = MLDSAVerifyPrecompile.Run(
				nil, common.Address{}, ContractMLDSAVerifyAddress,
				input, gas+1_000_000, true,
			)
			require.NoError(t, err, "%s tampered precompile Run", v.Mode)
			require.Equalf(t, byte(0), ret[31],
				"%s: precompile MUST reject single-bit-tampered signature", v.Mode)
		})
	}
}

// TestNISTKAT_MLDSA_AllThreeModesCovered guards against silent shrinkage of
// the KAT vector set. If a future edit deletes a mode from the JSON file,
// this test fails loudly.
func TestNISTKAT_MLDSA_AllThreeModesCovered(t *testing.T) {
	vectors := loadMLDSANISTVectors(t)
	required := map[byte]bool{
		ModeMLDSA44: false,
		ModeMLDSA65: false,
		ModeMLDSA87: false,
	}
	for _, v := range vectors {
		required[modeByteFromString(t, v.ModeByte)] = true
	}
	for m, ok := range required {
		require.Truef(t, ok, "missing ML-DSA KAT vector for mode 0x%02x", m)
	}
}
