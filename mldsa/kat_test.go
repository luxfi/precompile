// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// NIST ACVP known-answer coverage for the ML-DSA precompile (FIPS 204).
//
// testdata/acvp_fips204.json holds a subset of the NIST ACVP-Server demo
// vectors. Two kinds are used, and they answer two different questions:
//
//	keyGen  seed -> pk. Anchors the wrapped library's key derivation to
//	        bytes NIST published. A round-trip test cannot see a keygen
//	        that is wrong the same way in both directions; this can.
//
//	sigVer  pk, message, signature, testPassed. These exercise
//	        ML-DSA.Verify_internal -- the raw interface, with no context
//	        prefix. The precompile calls the EXTERNAL interface bound to
//	        precompileCtx, so a NIST-valid internal signature must be
//	        refused here. That is the property, not an accident.

package mldsa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

type acvpKeyGen struct {
	ParameterSet string `json:"parameterSet"`
	ModeByte     string `json:"modeByte"`
	TcID         int    `json:"tcId"`
	Seed         string `json:"seed"`
	Pk           string `json:"pk"`
}

type acvpSigVer struct {
	ParameterSet string `json:"parameterSet"`
	ModeByte     string `json:"modeByte"`
	TcID         int    `json:"tcId"`
	Pk           string `json:"pk"`
	Message      string `json:"message"`
	Signature    string `json:"signature"`
	TestPassed   bool   `json:"testPassed"`
}

type acvpFIPS204 struct {
	Source string       `json:"source"`
	KeyGen []acvpKeyGen `json:"keyGen"`
	SigVer []acvpSigVer `json:"sigVer"`
}

func loadACVP(t *testing.T) acvpFIPS204 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "acvp_fips204.json"))
	require.NoError(t, err)
	var f acvpFIPS204
	require.NoError(t, json.Unmarshal(b, &f))
	require.NotEmpty(t, f.KeyGen)
	require.NotEmpty(t, f.SigVer)
	return f
}

// run drives the precompile over a frame and returns the verdict byte.
func run(t *testing.T, input []byte) byte {
	t.Helper()
	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractMLDSAVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
	return ret[31]
}

// Key derivation reproduces the bytes NIST published, and the size
// constants this package hard-codes are the sizes NIST published.
func TestKAT_KeyGenMatchesFIPS204(t *testing.T) {
	for _, v := range loadACVP(t).KeyGen {
		t.Run(v.ParameterSet, func(t *testing.T) {
			mode := modeByteFromString(t, v.ModeByte)
			pk, _ := signFromSeed(t, mode, mustHex(t, v.Seed), pinnedMessage, nil)
			require.Equalf(t, mustHex(t, v.Pk), pk,
				"tc %d: derived public key differs from the NIST vector", v.TcID)

			declared, _, _, _, err := getModeParams(mode)
			require.NoError(t, err)
			require.Equal(t, declared, len(pk),
				"the package's public-key size constant disagrees with FIPS 204")
		})
	}
}

// A signature under a NIST-anchored key verifies through the precompile,
// and every single-byte corruption of the frame is refused.
func TestKAT_PrecompileUnderNISTAnchoredKey(t *testing.T) {
	for _, v := range loadACVP(t).KeyGen {
		t.Run(v.ParameterSet, func(t *testing.T) {
			mode := modeByteFromString(t, v.ModeByte)
			pk, sig := signFromSeed(t, mode, mustHex(t, v.Seed), pinnedMessage, precompileCtx)
			require.Equal(t, mustHex(t, v.Pk), pk, "key is not the NIST one")

			require.Equal(t, byte(1), run(t, buildPinnedInput(mode, pk, pinnedMessage, sig)),
				"a good signature under the NIST key must verify")

			// Corrupt one byte at the front, middle and end of the signature.
			for _, at := range []int{0, len(sig) / 2, len(sig) - 1} {
				bad := append([]byte{}, sig...)
				bad[at] ^= 0x01
				require.Equalf(t, byte(0), run(t, buildPinnedInput(mode, pk, pinnedMessage, bad)),
					"signature byte %d flipped and still accepted", at)
			}

			// Corrupt the message.
			msg := append([]byte{}, pinnedMessage...)
			msg[0] ^= 0x01
			require.Equal(t, byte(0), run(t, buildPinnedInput(mode, pk, msg, sig)),
				"message flipped and still accepted")

			// Corrupt the key.
			badPk := append([]byte{}, pk...)
			badPk[len(badPk)-1] ^= 0x01
			require.Equal(t, byte(0), run(t, buildPinnedInput(mode, badPk, pinnedMessage, sig)),
				"public key flipped and still accepted")

			// An all-zero signature of the right length is refused too.
			require.Equal(t, byte(0), run(t, buildPinnedInput(mode, pk, pinnedMessage, make([]byte, len(sig)))),
				"all-zero signature accepted")

			// So is an all-zero key.
			require.Equal(t, byte(0), run(t, buildPinnedInput(mode, make([]byte, len(pk)), pinnedMessage, sig)),
				"all-zero public key accepted")
		})
	}
}

// The precompile binds precompileCtx. NIST's sigVer vectors are signatures
// over the internal interface, which carries no context at all; the ones
// NIST marks valid are genuinely valid ML-DSA signatures, and the
// precompile must still refuse every one of them. If the precompile ever
// verified the internal interface, or verified with an empty context, an
// off-chain ML-DSA signature over an unrelated protocol would satisfy an
// on-chain verify.
func TestKAT_PrecompileRefusesInternalInterfaceSignatures(t *testing.T) {
	f := loadACVP(t)
	anyValid := false
	for _, v := range f.SigVer {
		mode := modeByteFromString(t, v.ModeByte)
		pk, msg, sig := mustHex(t, v.Pk), mustHex(t, v.Message), mustHex(t, v.Signature)
		require.Equal(t, byte(0), run(t, buildPinnedInput(mode, pk, msg, sig)),
			"%s tc %d (NIST testPassed=%v) accepted: the precompile is not bound to its context",
			v.ParameterSet, v.TcID, v.TestPassed)
		anyValid = anyValid || v.TestPassed
	}
	require.True(t, anyValid,
		"the vector set carries no NIST-valid signature, so it proves nothing")
}

// The context is load-bearing and exact. The same key and message signed
// under a different context -- including the empty one, and one that
// differs by a single byte -- must not verify.
func TestKAT_ContextIsExact(t *testing.T) {
	seed := mustHex(t, loadACVP(t).KeyGen[0].Seed)
	mode := ModeMLDSA44

	near := append([]byte{}, precompileCtx...)
	near[len(near)-1] ^= 0x01

	for name, ctx := range map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"off by one bit": near,
		"truncated":      precompileCtx[:len(precompileCtx)-1],
		"other scheme":   []byte("lux-evm-precompile-slhdsa-v1"),
	} {
		pk, sig := signFromSeed(t, mode, seed, pinnedMessage, ctx)
		require.Equalf(t, byte(0), run(t, buildPinnedInput(mode, pk, pinnedMessage, sig)),
			"a signature under context %q verified", name)
	}

	pk, sig := signFromSeed(t, mode, seed, pinnedMessage, precompileCtx)
	require.Equal(t, byte(1), run(t, buildPinnedInput(mode, pk, pinnedMessage, sig)),
		"the precompile's own context must verify")
}

// Mode confusion is structural for ML-DSA: no two parameter sets frame to
// the same length, so a frame built for one mode cannot be re-labelled as
// another. Assert both halves of that -- the sizes are distinct, and
// re-labelling is refused rather than misparsed.
func TestKAT_ModeConfusionIsStructural(t *testing.T) {
	modes := []uint8{ModeMLDSA44, ModeMLDSA65, ModeMLDSA87}

	seen := map[int]uint8{}
	for _, m := range modes {
		pkSize, sigSize, _, _, err := getModeParams(m)
		require.NoError(t, err)
		frameLen := ModeByte + pkSize + MessageLenSize + sigSize
		prev, dup := seen[frameLen]
		require.Falsef(t, dup, "modes 0x%02x and 0x%02x share a frame length", prev, m)
		seen[frameLen] = m
	}

	seed := mustHex(t, loadACVP(t).KeyGen[0].Seed)
	for _, signing := range modes {
		pk, sig := signFromSeed(t, signing, seed, pinnedMessage, precompileCtx)
		good := buildPinnedInput(signing, pk, pinnedMessage, sig)
		for _, claimed := range modes {
			if claimed == signing {
				continue
			}
			relabelled := append([]byte{}, good...)
			relabelled[0] = claimed
			gas := MLDSAVerifyPrecompile.RequiredGas(relabelled)
			_, _, err := MLDSAVerifyPrecompile.Run(
				nil, common.Address{}, ContractMLDSAVerifyAddress, relabelled, gas, true)
			require.Errorf(t, err,
				"a 0x%02x frame re-labelled 0x%02x was parsed instead of refused", signing, claimed)
		}
	}
}
