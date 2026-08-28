// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Drift pins for the ML-DSA precompile.
//
// These vectors are SELF-GENERATED, not published by NIST: a seed is chosen
// here, the keypair and a deterministic signature are reconstructed from it
// through cloudflare/circl, and the leading bytes of each are recorded in
// testdata/drift_vectors.json. They answer one question -- "does this
// library still produce the same bytes it produced yesterday" -- and they
// answer it cheaply, for all three parameter sets, including the
// precompile's own framing and its rejection of a tampered signature.
//
// They do NOT answer "is this library correct". A pinned prefix agrees with
// whatever produced it. The published NIST ACVP vectors live in
// kat_test.go, and that is the file to read for FIPS 204 conformance.

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

// pinnedMessage is the canonical message signed for every KAT vector in
// this file. It is short, ASCII, and identifies the source so an unrelated
// signature with the same prefix cannot coincidentally hit a pinned value.
var pinnedMessage = []byte("lux-precompile-nist-kat-v1")

// mldsaDriftVector mirrors the JSON schema in testdata/nist_vectors.json.
type mldsaDriftVector struct {
	Mode                       string `json:"mode"`
	ModeByte                   string `json:"mode_byte"`
	SeedHex                    string `json:"seed_hex"`
	ExpectedPublicKeyPrefixHex string `json:"expected_public_key_prefix_hex"`
	ExpectedSignaturePrefixHex string `json:"expected_signature_prefix_hex"`
	PublicKeySize              int    `json:"public_key_size"`
	SignatureSize              int    `json:"signature_size"`
}

type mldsaDriftVectorFile struct {
	Vectors []mldsaDriftVector `json:"vectors"`
}

func loadMLDSADriftVectors(t *testing.T) []mldsaDriftVector {
	t.Helper()
	path := filepath.Join("testdata", "drift_vectors.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err, "read testdata")
	var f mldsaDriftVectorFile
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

// buildPinnedInput frames a precompile call: mode || pubKey || msgLen(32) || sig || msg
func buildPinnedInput(mode byte, pk, msg, sig []byte) []byte {
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

// TestDrift_MLDSA_PinnedPrefixes is the single combined KAT
// driver. For each mode it (a) reconstructs the keypair from the pinned
// seed, (b) asserts the public-key prefix matches the JSON record,
// (c) asserts the deterministic signature prefix matches the JSON record,
// (d) drives the precompile and expects byte[31] == 1, (e) drives the
// precompile with a single-bit-flipped signature and expects byte[31] == 0.
func TestDrift_MLDSA_PinnedPrefixes(t *testing.T) {
	vectors := loadMLDSADriftVectors(t)
	ctx := precompileCtx

	for _, v := range vectors {
		v := v
		t.Run(v.Mode, func(t *testing.T) {
			mode := modeByteFromString(t, v.ModeByte)
			seed := mustHex(t, v.SeedHex)

			pk, sig := signFromSeed(t, mode, seed, pinnedMessage, ctx)

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

			input := buildPinnedInput(mode, pk, pinnedMessage, sig)
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
			input = buildPinnedInput(mode, pk, pinnedMessage, tampered)
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

// TestDrift_MLDSA_AllThreeModesPinned guards against silent shrinkage of
// the KAT vector set. If a future edit deletes a mode from the JSON file,
// this test fails loudly.
func TestDrift_MLDSA_AllThreeModesPinned(t *testing.T) {
	vectors := loadMLDSADriftVectors(t)
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
