// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// FIPS 205 (SLH-DSA) precompile Known-Answer-Test (KAT) coverage.
//
// Addresses TESTING_GAPS.md §1.5 in two coupled ways:
//
//   - "FIPS 205 KAT vectors" -- we wire deterministic seed-driven KATs
//     (skSeed || skPrf || pkSeed per FIPS 205 Algorithm 18) for the 8
//     SLH-DSA parameter sets that had zero end-to-end coverage at the
//     precompile layer.
//   - "All 12 modes tested (... missing SHA2_192s/f, SHAKE_192s/f, SHA2_256s/f,
//     SHAKE_256s/f)" -- modes_test.go now exercises round-trip verify for all
//     12 modes from fresh keys, but it does NOT pin determinism. This file
//     adds the determinism pin for the 8 previously-uncovered modes.
//
// Pinning strategy:
//
//   pk[:n] is, by FIPS 205 §10.2, equal to pkSeed for every mode (n = security
//   parameter in bytes: 24 for 192-bit, 32 for 256-bit). We assert this both
//   as a sanity guard on the wrapper and as a positional anchor against any
//   future "I'll just shuffle the layout" refactor.
//
//   sig[:16] is the first 16 bytes of circl's SignDeterministic output (the
//   pseudorandom R bytes from FIPS 205 §10.2 line 5). Pinning this is enough
//   to detect changes to the keygen->sign deterministic chain. Pinning the
//   full signature (16-50 KB per mode) would balloon the test binary.
//
// The signature objects themselves are NOT embedded; they are reconstructed
// at test time from the seed. Each mode signs once (~0.5-1s for "f" variants,
// ~5-10s for "s" variants in CPU mode) so we mark all the slow ones to skip
// under -short.

package slhdsa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	luxslhdsa "github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var nistKATMessage = []byte("lux-precompile-nist-kat-v1")

type slhdsaNISTVector struct {
	Mode                       string `json:"mode"`
	ModeByte                   string `json:"mode_byte"`
	NBytes                     int    `json:"n_bytes"`
	SkSeedHex                  string `json:"sk_seed_hex"`
	SkPrfHex                   string `json:"sk_prf_hex"`
	PkSeedHex                  string `json:"pk_seed_hex"`
	ExpectedPublicKeyPrefixHex string `json:"expected_public_key_prefix_hex"`
	ExpectedSignaturePrefixHex string `json:"expected_signature_prefix_hex"`
	PublicKeySize              int    `json:"public_key_size"`
	SignatureSize              int    `json:"signature_size"`
}

type slhdsaNISTVectorFile struct {
	Vectors []slhdsaNISTVector `json:"vectors"`
}

func loadSLHDSANISTVectors(t *testing.T) []slhdsaNISTVector {
	t.Helper()
	path := filepath.Join("testdata", "nist_vectors.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err, "read testdata")
	var f slhdsaNISTVectorFile
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

// modeByteAndLib resolves the JSON mode label to (precompile mode byte,
// upstream Mode constant). Kept in one place so a typo in the JSON cannot
// silently route to the wrong mode.
func modeByteAndLib(t *testing.T, name string) (byte, luxslhdsa.Mode) {
	t.Helper()
	switch name {
	case "SHA2_192s":
		return ModeSHA2_192s, luxslhdsa.SHA2_192s
	case "SHA2_192f":
		return ModeSHA2_192f, luxslhdsa.SHA2_192f
	case "SHAKE_192s":
		return ModeSHAKE_192s, luxslhdsa.SHAKE_192s
	case "SHAKE_192f":
		return ModeSHAKE_192f, luxslhdsa.SHAKE_192f
	case "SHA2_256s":
		return ModeSHA2_256s, luxslhdsa.SHA2_256s
	case "SHA2_256f":
		return ModeSHA2_256f, luxslhdsa.SHA2_256f
	case "SHAKE_256s":
		return ModeSHAKE_256s, luxslhdsa.SHAKE_256s
	case "SHAKE_256f":
		return ModeSHAKE_256f, luxslhdsa.SHAKE_256f
	default:
		t.Fatalf("unknown SLH-DSA mode: %s", name)
		return 0, 0
	}
}

// buildSLHDSAInput frames a precompile call:
//
//	mode(1) || pkLen(2,BE) || pk || msgLen(2,BE) || msg || sig
//
// (See slhdsa/contract.go for the canonical layout.)
func buildSLHDSAInput(t *testing.T, mode byte, pk, msg, sig []byte) []byte {
	t.Helper()
	require.LessOrEqual(t, len(pk), 0xFFFF, "pk len must fit uint16")
	require.LessOrEqual(t, len(msg), 0xFFFF, "msg len must fit uint16")
	out := make([]byte, 0, 1+2+len(pk)+2+len(msg)+len(sig))
	out = append(out, mode)
	out = append(out, byte(len(pk)>>8), byte(len(pk)))
	out = append(out, pk...)
	out = append(out, byte(len(msg)>>8), byte(len(msg)))
	out = append(out, msg...)
	out = append(out, sig...)
	return out
}

// runNISTKAT executes the deterministic KAT for one parameter set:
//
//  1. Generate keypair from (skSeed || skPrf || pkSeed) via luxfi/crypto
//     wrapper (which streams (skSeed || skPrf || pkSeed) into circl's
//     GenerateKey -- this is the FIPS 205 keygen contract).
//  2. Assert pk[:n] == pkSeed (FIPS 205 §10.2 invariant). Catches wrapper-
//     level layout regressions.
//  3. Assert pk[:n] also matches the pinned ExpectedPublicKeyPrefixHex.
//  4. Sign with precompileCtx; assert sig[:16] matches the pinned
//     ExpectedSignaturePrefixHex. Catches changes in the sign-deterministic
//     chain.
//  5. Drive the precompile and require byte[31] == 1.
//  6. Tamper with the signature's last byte and require byte[31] == 0.
func runNISTKAT(t *testing.T, v slhdsaNISTVector) {
	t.Helper()
	mode, libMode := modeByteAndLib(t, v.Mode)

	skSeed := mustHex(t, v.SkSeedHex)
	skPrf := mustHex(t, v.SkPrfHex)
	pkSeed := mustHex(t, v.PkSeedHex)
	require.Equal(t, v.NBytes, len(skSeed), "%s skSeed length", v.Mode)
	require.Equal(t, v.NBytes, len(skPrf), "%s skPrf length", v.Mode)
	require.Equal(t, v.NBytes, len(pkSeed), "%s pkSeed length", v.Mode)

	var rng bytes.Buffer
	rng.Write(skSeed)
	rng.Write(skPrf)
	rng.Write(pkSeed)
	priv, err := luxslhdsa.GenerateKey(&rng, libMode)
	require.NoError(t, err, "%s GenerateKey", v.Mode)

	pk := priv.PublicKey.Bytes()
	require.Equal(t, v.PublicKeySize, len(pk), "%s pubkey size", v.Mode)

	// FIPS 205 §10.2: pk[:n] == pkSeed
	require.Equalf(t, pkSeed, pk[:v.NBytes],
		"%s: pk[:n] != pkSeed -- FIPS 205 keygen layout violated", v.Mode)

	expectedPKPrefix := mustHex(t, v.ExpectedPublicKeyPrefixHex)
	require.Equalf(t, expectedPKPrefix, pk[:len(expectedPKPrefix)],
		"%s: public-key prefix drift -- pinned vector and library no longer agree",
		v.Mode)

	sig, err := priv.SignCtx(nil, nistKATMessage, precompileCtx)
	require.NoError(t, err, "%s SignCtx", v.Mode)
	require.Equal(t, v.SignatureSize, len(sig), "%s signature size", v.Mode)

	expectedSigPrefix := mustHex(t, v.ExpectedSignaturePrefixHex)
	require.Equalf(t, expectedSigPrefix, sig[:len(expectedSigPrefix)],
		"%s: deterministic signature prefix drift -- sign path no longer reproduces FIPS 205 vector",
		v.Mode)

	input := buildSLHDSAInput(t, mode, pk, nistKATMessage, sig)
	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas+1_000_000, true,
	)
	require.NoError(t, err, "%s precompile Run", v.Mode)
	require.Len(t, ret, 32, "%s precompile output width", v.Mode)
	require.Equalf(t, byte(1), ret[31],
		"%s: precompile MUST accept FIPS 205 deterministic signature for canonical seed",
		v.Mode)

	// Tamper: flip the trailing byte of the signature.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)-1] ^= 0x01
	input = buildSLHDSAInput(t, mode, pk, nistKATMessage, tampered)
	gas = SLHDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err = SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas+1_000_000, true,
	)
	require.NoError(t, err, "%s tampered precompile Run", v.Mode)
	require.Equalf(t, byte(0), ret[31],
		"%s: precompile MUST reject single-bit-tampered signature", v.Mode)
}

// TestNISTKAT_SLHDSA_192_FastModes covers the two 192-bit "f" (fast signing)
// parameter sets. These sign in ~0.1-0.5s in CPU mode and so are always run.
func TestNISTKAT_SLHDSA_192_FastModes(t *testing.T) {
	vectors := loadSLHDSANISTVectors(t)
	for _, v := range vectors {
		if !strings.HasSuffix(v.Mode, "192f") {
			continue
		}
		v := v
		t.Run(v.Mode, func(t *testing.T) { runNISTKAT(t, v) })
	}
}

// TestNISTKAT_SLHDSA_256_FastModes covers the two 256-bit "f" parameter sets.
// Slower than 192f but still tractable; run under -short skips.
func TestNISTKAT_SLHDSA_256_FastModes(t *testing.T) {
	if testing.Short() {
		t.Skip("slow under -short")
	}
	vectors := loadSLHDSANISTVectors(t)
	for _, v := range vectors {
		if !strings.HasSuffix(v.Mode, "256f") {
			continue
		}
		v := v
		t.Run(v.Mode, func(t *testing.T) { runNISTKAT(t, v) })
	}
}

// TestNISTKAT_SLHDSA_SmallSignatureModes covers the four "s" (small
// signature) parameter sets across both 192- and 256-bit levels. These are
// the slow signers; skipped under -short.
func TestNISTKAT_SLHDSA_SmallSignatureModes(t *testing.T) {
	if testing.Short() {
		t.Skip("slow under -short")
	}
	vectors := loadSLHDSANISTVectors(t)
	for _, v := range vectors {
		if !strings.HasSuffix(v.Mode, "s") {
			continue
		}
		v := v
		t.Run(v.Mode, func(t *testing.T) { runNISTKAT(t, v) })
	}
}

// TestNISTKAT_SLHDSA_AllEightModesCovered guards against silent shrinkage of
// the KAT vector set. The 4 "smaller" modes (SHA2_128*, SHAKE_128*) are
// intentionally excluded because they are already round-trip-tested in
// slhdsa/modes_test.go.
func TestNISTKAT_SLHDSA_AllEightModesCovered(t *testing.T) {
	vectors := loadSLHDSANISTVectors(t)
	required := map[string]bool{
		"SHA2_192s":  false,
		"SHA2_192f":  false,
		"SHAKE_192s": false,
		"SHAKE_192f": false,
		"SHA2_256s":  false,
		"SHA2_256f":  false,
		"SHAKE_256s": false,
		"SHAKE_256f": false,
	}
	for _, v := range vectors {
		required[v.Mode] = true
	}
	for m, ok := range required {
		require.Truef(t, ok, "missing SLH-DSA KAT vector for mode %s", m)
	}
}
