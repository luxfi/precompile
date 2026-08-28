// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// NIST ACVP known-answer coverage for the SLH-DSA precompile (FIPS 205).
//
// testdata/acvp_fips205.json holds a subset of the NIST ACVP-Server demo
// sigVer vectors, restricted to signatureInterface=external and
// preHash=pure -- SLH-DSA.Verify(pk, M, sig, ctx), the exact function the
// precompile calls. Each vector carries its own context and NIST's verdict,
// so the wrapped verifier can be checked in both directions: it must accept
// what NIST accepts and refuse what NIST refuses. A round-trip test sees
// neither, because a verifier that is wrong in the same way as its signer
// still agrees with itself.

package slhdsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

type acvpSigVer struct {
	ParameterSet string `json:"parameterSet"`
	ModeByte     string `json:"modeByte"`
	TcID         int    `json:"tcId"`
	Pk           string `json:"pk"`
	Message      string `json:"message"`
	Context      string `json:"context"`
	Signature    string `json:"signature"`
	TestPassed   bool   `json:"testPassed"`
}

type acvpFIPS205 struct {
	Source string       `json:"source"`
	SigVer []acvpSigVer `json:"sigVer"`
}

func loadACVP(t *testing.T) []acvpSigVer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "acvp_fips205.json"))
	require.NoError(t, err)
	var f acvpFIPS205
	require.NoError(t, json.Unmarshal(b, &f))
	require.NotEmpty(t, f.SigVer)
	return f.SigVer
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func acvpMode(t *testing.T, s string) uint8 {
	t.Helper()
	switch s {
	case "0x00":
		return ModeSHA2_128s
	case "0x02":
		return ModeSHA2_192s
	case "0x10":
		return ModeSHAKE_128s
	}
	t.Fatalf("unknown SLH-DSA mode byte %q", s)
	return 0
}

// verdict drives the precompile and returns its answer byte.
func verdict(t *testing.T, input []byte) byte {
	t.Helper()
	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{},
		ContractSLHDSAVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
	return ret[31]
}

// The verifier the precompile calls agrees with NIST on every vector, in
// both directions. Accepting everything would pass a positive-only suite;
// refusing everything would pass a negative-only one. Requiring both, and
// requiring the vector set to contain both, is what makes this a test.
func TestKAT_VerifierAgreesWithFIPS205(t *testing.T) {
	vectors := loadACVP(t)
	seen := map[bool]int{}

	for _, v := range vectors {
		mode := acvpMode(t, v.ModeByte)
		pubSize, sigSize, _, libMode, err := getModeParams(mode)
		require.NoError(t, err)

		pk := fromHex(t, v.Pk)
		require.Equalf(t, pubSize, len(pk),
			"%s: the package's public-key size constant disagrees with FIPS 205", v.ParameterSet)

		pub, err := slhdsa.PublicKeyFromBytes(pk, libMode)
		require.NoError(t, err)

		got := pub.VerifySignatureCtx(
			fromHex(t, v.Message), fromHex(t, v.Signature), fromHex(t, v.Context))
		require.Equalf(t, v.TestPassed, got,
			"%s tc %d: verifier disagrees with the NIST verdict", v.ParameterSet, v.TcID)

		if v.TestPassed {
			require.Equalf(t, sigSize, len(fromHex(t, v.Signature)),
				"%s: the package's signature size constant disagrees with FIPS 205", v.ParameterSet)
		}
		seen[v.TestPassed]++
	}

	require.NotZero(t, seen[true], "no accepting vector: the suite proves only that it refuses")
	require.NotZero(t, seen[false], "no refusing vector: the suite proves only that it accepts")
}

// The precompile substitutes its own context for whatever the caller
// intended, so a signature NIST calls valid under some other context must
// be refused here. Without that binding, a signature produced for an
// unrelated protocol -- a UTXO, a Warp message -- would satisfy an
// on-chain verify.
func TestKAT_PrecompileRefusesForeignContext(t *testing.T) {
	accepted := 0
	for _, v := range loadACVP(t) {
		if !v.TestPassed {
			continue
		}
		accepted++
		mode := acvpMode(t, v.ModeByte)
		require.NotEqual(t, precompileCtx, fromHex(t, v.Context),
			"vector context collided with the precompile's own")

		in := prepareInputWithMode(mode, fromHex(t, v.Pk), fromHex(t, v.Message), fromHex(t, v.Signature))
		require.Equalf(t, byte(0), verdict(t, in),
			"%s tc %d: a signature under a foreign context verified", v.ParameterSet, v.TcID)
	}
	require.NotZero(t, accepted, "no NIST-valid vector to offer, so nothing was proved")
}

// SHA2 and SHAKE at the same security level have identical key and
// signature sizes, so a frame built for one parses cleanly as the other.
// For these six pairs mode confusion is NOT caught by the length checks --
// only the hash family inside the verifier separates them. Assert both
// halves: the sizes really do collide, and the verifier still says no.
func TestKAT_ModeConfusionAcrossHashFamilies(t *testing.T) {
	pairs := [][2]uint8{
		{ModeSHA2_128s, ModeSHAKE_128s},
		{ModeSHA2_128f, ModeSHAKE_128f},
		{ModeSHA2_192s, ModeSHAKE_192s},
		{ModeSHA2_192f, ModeSHAKE_192f},
		{ModeSHA2_256s, ModeSHAKE_256s},
		{ModeSHA2_256f, ModeSHAKE_256f},
	}
	for _, p := range pairs {
		aPub, aSig, _, _, err := getModeParams(p[0])
		require.NoError(t, err)
		bPub, bSig, _, _, err := getModeParams(p[1])
		require.NoError(t, err)
		require.Equalf(t, aPub, bPub, "0x%02x/0x%02x public-key sizes", p[0], p[1])
		require.Equalf(t, aSig, bSig, "0x%02x/0x%02x signature sizes", p[0], p[1])
	}

	swap := map[uint8]uint8{ModeSHA2_128s: ModeSHAKE_128s, ModeSHAKE_128s: ModeSHA2_128s}
	offered := 0
	for _, v := range loadACVP(t) {
		if !v.TestPassed {
			continue
		}
		mode := acvpMode(t, v.ModeByte)
		other, ok := swap[mode]
		if !ok {
			continue
		}
		offered++
		in := prepareInputWithMode(other, fromHex(t, v.Pk), fromHex(t, v.Message), fromHex(t, v.Signature))
		require.Equalf(t, byte(0), verdict(t, in),
			"%s tc %d verified as 0x%02x: the hash family is not separating the parameter sets",
			v.ParameterSet, v.TcID, other)
	}
	require.Equal(t, 2, offered, "both hash families must supply a vector for this to mean anything")
}
