// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronathreshold

import (
	"testing"

	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/threshold"
	"github.com/stretchr/testify/require"
)

// TestExpectedSizeMatchesTheWire is the regression for a size constant
// that described a different format from the one the parser reads.
//
// ExpectedSignatureSize is the gate in Run and the only published
// description of how much signature a caller must supply. It is
// derived here from two independent sources and both must agree:
// the length of a signature the threshold library actually produces,
// and the number of polynomials deserializeSignature actually reads
// multiplied by the ring's own degree. A constant that agrees with
// neither is a specification a caller cannot satisfy.
func TestExpectedSizeMatchesTheWire(t *testing.T) {
	params, err := threshold.NewParams()
	require.NoError(t, err)

	// deserializeSignature reads, in order: c, then z (N polys), then
	// Delta (M polys), then the A matrix (M x N polys), then bTilde
	// (M polys). The group key travels with the signature because the
	// precompile is handed no key by any other route.
	polys := 1 + sign.N + sign.M + sign.M*sign.N + sign.M
	require.Equal(t, polys*params.R.N()*CoefficientSize, ExpectedSignatureSize,
		"the constant must count every polynomial the parser reads")

	real, _, err := generateThresholdSignature(2, 3, "wire size")
	require.NoError(t, err)
	require.Equal(t, ExpectedSignatureSize, len(real),
		"a signature the library produces must be exactly the size the precompile demands")
}

// TestRefusesEverythingShorterThanTheWire pins the gate itself: a body
// one byte short of a whole signature must be refused by the length
// check, before any polynomial is allocated.
func TestRefusesEverythingShorterThanTheWire(t *testing.T) {
	real, hash, err := generateThresholdSignature(2, 3, "truncation")
	require.NoError(t, err)

	full := createInput(2, 3, hash, real)
	out, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), full, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), out[31], "control: a whole signature verifies")

	for _, cut := range []int{1, 2, 1024, ExpectedSignatureSize / 2, ExpectedSignatureSize - 1} {
		short := createInput(2, 3, hash, real[:len(real)-cut])
		_, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), short, 10_000_000, true)
		require.ErrorIs(t, err, ErrInvalidInputLength,
			"a body %d bytes short must fail the length gate", cut)
	}
}
