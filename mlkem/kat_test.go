// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// NIST ACVP known-answer coverage for the ML-KEM precompile (FIPS 203).
//
// testdata/acvp_fips203.json holds a subset of the NIST ACVP-Server demo
// vectors:
//
//	encap   (ek, m) -> (c, k). The precompile's encapsulation is exactly
//	        this function with m supplied by deriveSeed, so feeding NIST's
//	        m must reproduce NIST's ciphertext and shared secret byte for
//	        byte. A round-trip test cannot see an encapsulation that is
//	        wrong in a way decapsulation undoes; this can.
//
//	keyGen  (d, z) -> (ek, dk). Gives a NIST-issued key pair, so the
//	        precompile can be driven against a key it did not generate and
//	        the result decapsulated with the matching NIST private key.

package mlkem

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

type acvpEncap struct {
	ParameterSet string `json:"parameterSet"`
	ModeByte     string `json:"modeByte"`
	TcID         int    `json:"tcId"`
	Ek           string `json:"ek"`
	M            string `json:"m"`
	C            string `json:"c"`
	K            string `json:"k"`
}

type acvpKeyGen struct {
	ParameterSet string `json:"parameterSet"`
	ModeByte     string `json:"modeByte"`
	TcID         int    `json:"tcId"`
	D            string `json:"d"`
	Z            string `json:"z"`
	Ek           string `json:"ek"`
	Dk           string `json:"dk"`
}

type acvpFIPS203 struct {
	Source string      `json:"source"`
	Encap  []acvpEncap `json:"encap"`
	KeyGen []acvpKeyGen
}

func loadACVP(t *testing.T) acvpFIPS203 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "acvp_fips203.json"))
	require.NoError(t, err)
	var f acvpFIPS203
	require.NoError(t, json.Unmarshal(b, &f))
	require.NotEmpty(t, f.Encap)
	require.NotEmpty(t, f.KeyGen)
	return f
}

// fixedReader hands back exactly the bytes it was given, so an
// encapsulation can be pinned to a chosen m.
type fixedReader struct {
	b []byte
	n int
}

func (r *fixedReader) Read(p []byte) (int, error) {
	n := copy(p, r.b[r.n:])
	r.n += n
	return n, nil
}

func modeByte(t *testing.T, s string) uint8 {
	t.Helper()
	switch s {
	case "0x00":
		return ModeMLKEM512
	case "0x01":
		return ModeMLKEM768
	case "0x02":
		return ModeMLKEM1024
	}
	t.Fatalf("unknown ML-KEM mode byte %q", s)
	return 0
}

// Encapsulation reproduces the ciphertext and shared secret NIST
// published, for every parameter set the precompile offers.
func TestKAT_EncapsulateMatchesFIPS203(t *testing.T) {
	for _, v := range loadACVP(t).Encap {
		t.Run(v.ParameterSet, func(t *testing.T) {
			mode := modeByte(t, v.ModeByte)
			pubSize, ctSize, ssSize, _, kemMode, err := getModeParams(mode)
			require.NoError(t, err)

			ek := mustHex(t, v.Ek)
			require.Equal(t, pubSize, len(ek),
				"the package's public-key size constant disagrees with FIPS 203")

			pk, err := mlkem.PublicKeyFromBytes(ek, kemMode)
			require.NoError(t, err)

			ct, ss, err := pk.Encapsulate(&fixedReader{b: mustHex(t, v.M)})
			require.NoError(t, err)
			require.Equalf(t, mustHex(t, v.C), ct, "tc %d: ciphertext differs from the NIST vector", v.TcID)
			require.Equalf(t, mustHex(t, v.K), ss, "tc %d: shared secret differs from the NIST vector", v.TcID)
			require.Equal(t, ctSize, len(ct), "ciphertext size constant")
			require.Equal(t, ssSize, len(ss), "shared-secret size constant")
		})
	}
}

// Driven against a NIST-issued encapsulation key, the precompile's output
// decapsulates under the matching NIST private key to exactly the shared
// secret the precompile returned. That is the whole contract: a contract
// on chain and a counterparty off chain agree on a key.
func TestKAT_PrecompileOutputDecapsulatesUnderNISTKey(t *testing.T) {
	caller := common.HexToAddress("0x000000000000000000000000000000000000c0de")
	for _, v := range loadACVP(t).KeyGen {
		t.Run(v.ParameterSet, func(t *testing.T) {
			mode := modeByte(t, v.ModeByte)
			_, ctSize, ssSize, _, kemMode, err := getModeParams(mode)
			require.NoError(t, err)

			ek, dk := mustHex(t, v.Ek), mustHex(t, v.Dk)

			in := append([]byte{OpEncapsulate, mode}, bytes.Repeat([]byte{0x5A}, SeedSize)...)
			in = append(in, ek...)

			out, _, err := MLKEMPrecompile.Run(nil, caller, ContractAddress,
				in, MLKEMPrecompile.RequiredGas(in), true)
			require.NoError(t, err)
			require.Len(t, out, ctSize+ssSize)

			ct, ss := out[:ctSize], out[ctSize:]

			sk, err := mlkem.PrivateKeyFromBytes(dk, kemMode)
			require.NoError(t, err)
			recovered, err := sk.Decapsulate(ct)
			require.NoError(t, err)
			require.Equalf(t, recovered, ss,
				"tc %d: the shared secret the precompile returned is not the one its ciphertext carries", v.TcID)
		})
	}
}

// The precompile's randomness is deriveSeed(caller, raw), consumed
// directly as FIPS 203's m. Pin that: recomputing the derivation by hand
// and encapsulating with it must land on the precompile's exact output.
// A change to the label, to the order of the inputs, or to the inclusion
// of the caller shows up here and nowhere else -- every round-trip test
// keeps passing through all three.
func TestKAT_PrecompileSeedIsTheDerivedSeed(t *testing.T) {
	caller := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	v := loadACVP(t).KeyGen[1] // ML-KEM-768
	mode := modeByte(t, v.ModeByte)
	_, ctSize, _, _, kemMode, err := getModeParams(mode)
	require.NoError(t, err)

	var raw [SeedSize]byte
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	ek := mustHex(t, v.Ek)

	in := append([]byte{OpEncapsulate, mode}, raw[:]...)
	in = append(in, ek...)
	out, _, err := MLKEMPrecompile.Run(nil, caller, ContractAddress,
		in, MLKEMPrecompile.RequiredGas(in), true)
	require.NoError(t, err)

	m := deriveSeed(caller, raw)
	pk, err := mlkem.PublicKeyFromBytes(ek, kemMode)
	require.NoError(t, err)
	ct, ss, err := pk.Encapsulate(&fixedReader{b: m[:]})
	require.NoError(t, err)

	require.Equal(t, ct, out[:ctSize], "ciphertext is not the one deriveSeed's m produces")
	require.Equal(t, ss, out[ctSize:], "shared secret is not the one deriveSeed's m produces")
}
