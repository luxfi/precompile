// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// H-06: Pedersen generator H must not equal the standard generator G.
//
// Vulnerability: If the blinding generator H equals the base generator G,
// then the Pedersen commitment C = v*G + r*H = (v+r)*G, and the commitment
// is no longer hiding -- the blinding factor provides no protection.
//
// Furthermore, if hashToG1 ever falls through to returning the standard
// generator G (fallback path), the Pedersen scheme is broken.
//
// Fix: hashToG1 must always succeed with a point distinct from G.
func TestH06_PedersenHDistinctFromG(t *testing.T) {
	_, _, G, _ := bn254.Generators()

	require.False(t, genH.Equal(&G),
		"Blinding generator H must NOT equal standard generator G")
}

// H-06: All 32 vector generators must be distinct from G.
func TestH06_PedersenVectorGeneratorsDistinctFromG(t *testing.T) {
	_, _, G, _ := bn254.Generators()

	for i := range 32 {
		require.False(t, genVi[i].Equal(&G),
			"Vector generator V[%d] must NOT equal standard generator G", i)
	}
}

// H-06: All generators must be pairwise distinct.
//
// If any two generators are equal, the commitment scheme loses properties:
//   - Two equal generators in the vector means different values produce the
//     same commitment (binding broken for those indices).
func TestH06_PedersenAllGeneratorsPairwiseDistinct(t *testing.T) {
	allGens := make([]bn254.G1Affine, 0, 34)
	_, _, G, _ := bn254.Generators()
	allGens = append(allGens, G)
	allGens = append(allGens, genH)
	for i := range 32 {
		allGens = append(allGens, genVi[i])
	}

	for i := 0; i < len(allGens); i++ {
		for j := i + 1; j < len(allGens); j++ {
			require.False(t, allGens[i].Equal(&allGens[j]),
				"Generator %d and %d must be distinct", i, j)
		}
	}
}

// H-06: hashToG1 must not return the standard generator for any seed.
//
// The fallback path in hashToG1 (counter reaches 255 without finding a
// valid point) returns the standard generator G. This must never happen
// for the seeds actually used.
func TestH06_PedersenHashToG1NeverFallsBack(t *testing.T) {
	_, _, G, _ := bn254.Generators()

	// Test the exact seeds used in init()
	seeds := []string{"Lux_Pedersen_H_Generator"}
	for i := range 32 {
		seeds = append(seeds, "Lux_Pedersen_Gen_"+string(rune('A'+i)))
	}

	for _, seed := range seeds {
		pt := hashToG1(seed)
		require.False(t, pt.Equal(&G),
			"hashToG1(%q) must not return standard generator G (fallback)", seed)
		require.True(t, pt.IsOnCurve(),
			"hashToG1(%q) must return a point on BN254", seed)
		require.False(t, pt.IsInfinity(),
			"hashToG1(%q) must not return the identity point", seed)
	}
}

// H-06: hashToG1 with adversarial/random seeds must not return G.
func TestH06_PedersenHashToG1AdversarialSeeds(t *testing.T) {
	_, _, G, _ := bn254.Generators()

	adversarial := []string{
		"",
		"0",
		"G",
		"generator",
		"\x00\x00\x00\x00",
		string(make([]byte, 256)),
	}

	for _, seed := range adversarial {
		pt := hashToG1(seed)
		require.False(t, pt.Equal(&G),
			"hashToG1 with adversarial seed %q must not return G", seed)
	}
}

// H-06: Pedersen commit + verify round-trip.
//
// Verify the commitment scheme actually works after the fix.
func TestH06_PedersenCommitVerifyRoundTrip(t *testing.T) {
	// value = 42 (as 32-byte big-endian)
	value := make([]byte, 32)
	value[31] = 42
	// blinding = 7
	blinding := make([]byte, 32)
	blinding[31] = 7

	// Commit
	commitInput := append([]byte{OpCommit}, value...)
	commitInput = append(commitInput, blinding...)
	gas := PedersenPrecompile.RequiredGas(commitInput)

	commitResult, _, err := PedersenPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		commitInput, gas+100_000, false,
	)
	require.NoError(t, err)
	require.Len(t, commitResult, 32)

	// Verify: commitment_hash(32) + value(32) + blinding(32)
	verifyInput := append([]byte{OpVerify}, commitResult...)
	verifyInput = append(verifyInput, value...)
	verifyInput = append(verifyInput, blinding...)
	vGas := PedersenPrecompile.RequiredGas(verifyInput)

	verifyResult, _, err := PedersenPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		verifyInput, vGas+100_000, false,
	)
	require.NoError(t, err)
	require.Len(t, verifyResult, 32)
	require.Equal(t, byte(1), verifyResult[31], "Verify must return 1 for valid commitment")

	// Verify with wrong value fails
	wrongValue := make([]byte, 32)
	wrongValue[31] = 43
	wrongVerifyInput := append([]byte{OpVerify}, commitResult...)
	wrongVerifyInput = append(wrongVerifyInput, wrongValue...)
	wrongVerifyInput = append(wrongVerifyInput, blinding...)

	wrongResult, _, err := PedersenPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		wrongVerifyInput, vGas+100_000, false,
	)
	require.NoError(t, err)
	require.Equal(t, byte(0), wrongResult[31], "Verify must return 0 for wrong value")
}
