// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Drift pins for the ML-KEM precompile.
//
// These vectors are SELF-GENERATED, not published by NIST: a seed is chosen
// here, the keypair is reconstructed through cloudflare/circl, and the
// leading bytes of the public key are recorded in
// testdata/drift_vectors.json. Alongside the pin they assert the property
// the precompile exists to guarantee -- given (caller, raw seed, public
// key) the output is byte-identical across calls, because a validator that
// reached for randomness here would split the chain -- and that the
// returned shared secret is the one its ciphertext carries.
//
// They do NOT answer "is this library correct". A pinned prefix agrees with
// whatever produced it. The published NIST ACVP vectors live in
// kat_test.go, and that is the file to read for FIPS 203 conformance.

package mlkem

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	circlmlkem1024 "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	circlmlkem512 "github.com/cloudflare/circl/kem/mlkem/mlkem512"
	circlmlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

type mlkemDriftVector struct {
	Mode                       string `json:"mode"`
	ModeByte                   string `json:"mode_byte"`
	KeySeedHex                 string `json:"key_seed_hex"`
	EncapSeedHex               string `json:"encap_seed_hex"`
	ExpectedPublicKeyPrefixHex string `json:"expected_public_key_prefix_hex"`
	PublicKeySize              int    `json:"public_key_size"`
	CiphertextSize             int    `json:"ciphertext_size"`
	SharedSecretSize           int    `json:"shared_secret_size"`
}

type mlkemDriftVectorFile struct {
	Vectors []mlkemDriftVector `json:"vectors"`
}

func loadMLKEMDriftVectors(t *testing.T) []mlkemDriftVector {
	t.Helper()
	path := filepath.Join("testdata", "drift_vectors.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err, "read testdata")
	var f mlkemDriftVectorFile
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

func modeByteFromString(t *testing.T, s string) byte {
	t.Helper()
	switch s {
	case "0x00":
		return ModeMLKEM512
	case "0x01":
		return ModeMLKEM768
	case "0x02":
		return ModeMLKEM1024
	default:
		t.Fatalf("unknown ML-KEM mode_byte: %s", s)
		return 0
	}
}

// publicKeyFromKeygenSeed returns the canonical FIPS 203 public key bytes
// for the given mode and the canonical 64-byte keygen seed. It also returns
// a closure that decapsulates a ciphertext using the private key (so the
// test can confirm the precompile's shared secret).
func publicKeyFromKeygenSeed(t *testing.T, mode byte, seed []byte) (pk []byte, decaps func(ct []byte) []byte) {
	t.Helper()
	switch mode {
	case ModeMLKEM512:
		require.Equal(t, circlmlkem512.KeySeedSize, len(seed), "ML-KEM-512 seed length")
		pub, sec := circlmlkem512.NewKeyFromSeed(seed)
		pkB, err := pub.MarshalBinary()
		require.NoError(t, err)
		return pkB, func(ct []byte) []byte {
			ss := make([]byte, circlmlkem512.SharedKeySize)
			sec.DecapsulateTo(ss, ct)
			return ss
		}
	case ModeMLKEM768:
		require.Equal(t, circlmlkem768.KeySeedSize, len(seed), "ML-KEM-768 seed length")
		pub, sec := circlmlkem768.NewKeyFromSeed(seed)
		pkB, err := pub.MarshalBinary()
		require.NoError(t, err)
		return pkB, func(ct []byte) []byte {
			ss := make([]byte, circlmlkem768.SharedKeySize)
			sec.DecapsulateTo(ss, ct)
			return ss
		}
	case ModeMLKEM1024:
		require.Equal(t, circlmlkem1024.KeySeedSize, len(seed), "ML-KEM-1024 seed length")
		pub, sec := circlmlkem1024.NewKeyFromSeed(seed)
		pkB, err := pub.MarshalBinary()
		require.NoError(t, err)
		return pkB, func(ct []byte) []byte {
			ss := make([]byte, circlmlkem1024.SharedKeySize)
			sec.DecapsulateTo(ss, ct)
			return ss
		}
	default:
		t.Fatalf("publicKeyFromKeygenSeed: unsupported mode 0x%02x", mode)
		return nil, nil
	}
}

// buildEncapInput frames a precompile encapsulate call:
//
//	op(0x01) || mode || seed(32) || publicKey
func buildEncapInput(mode byte, seed, pk []byte) []byte {
	out := make([]byte, 0, 2+SeedSize+len(pk))
	out = append(out, OpEncapsulate)
	out = append(out, mode)
	out = append(out, seed...)
	out = append(out, pk...)
	return out
}

// TestDrift_MLKEM_PinnedPrefixAndDeterminism is the combined KAT
// driver. For each FIPS 203 parameter set it:
//
//  1. Reconstructs the public key from the canonical 64-byte keygen seed
//     and pins pk[:32] against the JSON record.
//  2. Calls the precompile twice with identical (caller, seed, pubkey) and
//     asserts byte-identical output.
//  3. Splits the output into ciphertext + shared_secret per the documented
//     precompile layout, and asserts that the off-line decapsulate of that
//     ciphertext using the test's private key recovers the precompile's
//     shared secret. This is the ML-KEM correctness equation -- if it
//     fails the precompile is producing ciphertexts no honest receiver
//     can decapsulate, which is the §1.7 silent-failure mode.
//  4. Calls the precompile with a tampered ciphertext-side input does not
//     apply (the precompile is encaps-only; decaps is off-chain). We
//     instead tamper with the SEED and assert the output ciphertext
//     changes -- the determinism is keyed on seed, not pubkey alone.
func TestDrift_MLKEM_PinnedPrefixAndDeterminism(t *testing.T) {
	vectors := loadMLKEMDriftVectors(t)

	for _, v := range vectors {
		v := v
		t.Run(v.Mode, func(t *testing.T) {
			mode := modeByteFromString(t, v.ModeByte)
			keySeed := mustHex(t, v.KeySeedHex)
			encapSeed := mustHex(t, v.EncapSeedHex)
			require.Equal(t, SeedSize, len(encapSeed), "%s encap seed must be %d bytes", v.Mode, SeedSize)

			pk, decaps := publicKeyFromKeygenSeed(t, mode, keySeed)
			require.Equal(t, v.PublicKeySize, len(pk), "%s pubkey size", v.Mode)

			expectedPKPrefix := mustHex(t, v.ExpectedPublicKeyPrefixHex)
			require.Equalf(t, expectedPKPrefix, pk[:len(expectedPKPrefix)],
				"%s: public-key prefix drift -- FIPS 203 keygen diverged from pinned vector",
				v.Mode)

			input := buildEncapInput(mode, encapSeed, pk)
			gas := MLKEMPrecompile.RequiredGas(input)

			ret1, _, err := MLKEMPrecompile.Run(
				nil, common.Address{}, ContractAddress,
				input, gas+1_000_000, true,
			)
			require.NoError(t, err, "%s precompile Run #1", v.Mode)
			require.Equalf(t, v.CiphertextSize+v.SharedSecretSize, len(ret1),
				"%s precompile output length", v.Mode)

			// Determinism: same (caller, seed, pubkey) MUST produce same bytes.
			ret2, _, err := MLKEMPrecompile.Run(
				nil, common.Address{}, ContractAddress,
				input, gas+1_000_000, true,
			)
			require.NoError(t, err, "%s precompile Run #2", v.Mode)
			require.Equalf(t, ret1, ret2,
				"%s: precompile MUST be deterministic for identical (caller, seed, pubkey)",
				v.Mode)

			// Correctness equation: shared_secret recovered off-line MUST match
			// the precompile's reported shared_secret.
			ct := ret1[:v.CiphertextSize]
			ssPrecompile := ret1[v.CiphertextSize:]
			ssDecaps := decaps(ct)
			require.Equalf(t, ssPrecompile, ssDecaps,
				"%s: shared secret from precompile does not match off-line decapsulation; ML-KEM correctness equation broken",
				v.Mode)

			// Seed-sensitivity: flipping one bit of the caller-supplied seed
			// MUST change the precompile output. This catches accidental
			// pinning to a constant (e.g. callers picking the same seed and
			// getting identical ciphertexts every time).
			tamperedSeed := make([]byte, len(encapSeed))
			copy(tamperedSeed, encapSeed)
			tamperedSeed[0] ^= 0x01
			input = buildEncapInput(mode, tamperedSeed, pk)
			ret3, _, err := MLKEMPrecompile.Run(
				nil, common.Address{}, ContractAddress,
				input, gas+1_000_000, true,
			)
			require.NoError(t, err, "%s precompile Run #3 (tampered seed)", v.Mode)
			require.Falsef(t, bytes.Equal(ret1, ret3),
				"%s: seed-bit flip must change precompile output (else seed input is ignored)",
				v.Mode)
		})
	}
}

// TestDrift_MLKEM_AllThreeModesPinned guards against silent shrinkage of
// the KAT vector set.
func TestDrift_MLKEM_AllThreeModesPinned(t *testing.T) {
	vectors := loadMLKEMDriftVectors(t)
	required := map[byte]bool{
		ModeMLKEM512:  false,
		ModeMLKEM768:  false,
		ModeMLKEM1024: false,
	}
	for _, v := range vectors {
		required[modeByteFromString(t, v.ModeByte)] = true
	}
	for m, ok := range required {
		require.Truef(t, ok, "missing ML-KEM KAT vector for mode 0x%02x", m)
	}
}
