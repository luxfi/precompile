// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Drift pins for the SLH-DSA precompile.
//
// These vectors are SELF-GENERATED, not published by NIST: the FIPS 205
// key seeds (skSeed || skPrf || pkSeed) are chosen here, the keypair and a
// deterministic signature are reconstructed through cloudflare/circl, and
// the leading bytes of each are recorded in testdata/drift_vectors.json.
//
// Their value is breadth. The published ACVP vectors in kat_test.go cover
// three parameter sets; these cover the eight that file does not, each with
// a full precompile round trip -- accept the honest frame, refuse the
// tampered one. pk[:n] is pkSeed by FIPS 205 section 10.2, so the pin is
// also a positional anchor against a layout change.
//
// They do NOT answer "is this library correct". A pinned prefix agrees with
// whatever produced it; kat_test.go is the file to read for FIPS 205
// conformance.

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

var pinnedMessage = []byte("lux-precompile-nist-kat-v1")

type slhdsaDriftVector struct {
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

type slhdsaDriftVectorFile struct {
	Vectors []slhdsaDriftVector `json:"vectors"`
}

func loadSLHDSADriftVectors(t *testing.T) []slhdsaDriftVector {
	t.Helper()
	path := filepath.Join("testdata", "drift_vectors.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err, "read testdata")
	var f slhdsaDriftVectorFile
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

// runDriftPin executes the deterministic KAT for one parameter set:
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
func runDriftPin(t *testing.T, v slhdsaDriftVector) {
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

	sig, err := priv.SignCtx(nil, pinnedMessage, precompileCtx)
	require.NoError(t, err, "%s SignCtx", v.Mode)
	require.Equal(t, v.SignatureSize, len(sig), "%s signature size", v.Mode)

	expectedSigPrefix := mustHex(t, v.ExpectedSignaturePrefixHex)
	require.Equalf(t, expectedSigPrefix, sig[:len(expectedSigPrefix)],
		"%s: deterministic signature prefix drift -- sign path no longer reproduces FIPS 205 vector",
		v.Mode)

	input := buildSLHDSAInput(t, mode, pk, pinnedMessage, sig)
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
	input = buildSLHDSAInput(t, mode, pk, pinnedMessage, tampered)
	gas = SLHDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err = SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas+1_000_000, true,
	)
	require.NoError(t, err, "%s tampered precompile Run", v.Mode)
	require.Equalf(t, byte(0), ret[31],
		"%s: precompile MUST reject single-bit-tampered signature", v.Mode)
}

// TestDrift_SLHDSA_192Fast covers the two 192-bit "f" (fast signing)
// parameter sets. These sign in ~0.1-0.5s in CPU mode and so are always run.
func TestDrift_SLHDSA_192Fast(t *testing.T) {
	vectors := loadSLHDSADriftVectors(t)
	for _, v := range vectors {
		if !strings.HasSuffix(v.Mode, "192f") {
			continue
		}
		v := v
		t.Run(v.Mode, func(t *testing.T) { runDriftPin(t, v) })
	}
}

// TestDrift_SLHDSA_256Fast covers the two 256-bit "f" parameter sets.
// Slower than 192f but still tractable.
func TestDrift_SLHDSA_256Fast(t *testing.T) {
	vectors := loadSLHDSADriftVectors(t)
	for _, v := range vectors {
		if !strings.HasSuffix(v.Mode, "256f") {
			continue
		}
		v := v
		t.Run(v.Mode, func(t *testing.T) { runDriftPin(t, v) })
	}
}

// TestDrift_SLHDSA_SmallSignature covers the four "s" (small
// signature) parameter sets across both 192- and 256-bit levels. These are
// the slow signers.
func TestDrift_SLHDSA_SmallSignature(t *testing.T) {
	vectors := loadSLHDSADriftVectors(t)
	for _, v := range vectors {
		if !strings.HasSuffix(v.Mode, "s") {
			continue
		}
		v := v
		t.Run(v.Mode, func(t *testing.T) { runDriftPin(t, v) })
	}
}

// TestDrift_SLHDSA_AllEightModesPinned guards against silent shrinkage of
// the KAT vector set. The 4 "smaller" modes (SHA2_128*, SHAKE_128*) are
// intentionally excluded because they are already round-trip-tested in
// slhdsa/modes_test.go.
func TestDrift_SLHDSA_AllEightModesPinned(t *testing.T) {
	vectors := loadSLHDSADriftVectors(t)
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
