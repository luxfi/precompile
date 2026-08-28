// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronathreshold

import (
	"testing"

	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// componentBounds names the wire offset at which each component of the
// serialized blob begins, in the order deserializeSignature reads
// them. Truncating one byte inside a component makes that component's
// read fail, which is how each error path is reached individually
// rather than all of them collapsing onto the first.
func componentBounds() []struct {
	name  string
	polys int
} {
	return []struct {
		name  string
		polys int
	}{
		{"c", 1},
		{"z", sign.N},
		{"Delta", sign.M},
		{"A", sign.M * sign.N},
		{"bTilde", sign.M},
	}
}

// TestParserFailsInsideEveryComponent walks the blob component by
// component, cutting it one byte into each, and requires a named error
// rather than a panic or a silent zero-fill.
//
// This matters beyond tidiness: deserializePoly allocates
// RingDegree big.Ints per polynomial and hands them to
// SetCoefficientsBigint. A read that quietly returned short would seed
// the verifier with attacker-influenced zero coefficients instead of
// refusing, and the caller would receive a verdict computed over a
// signature that was never fully supplied.
func TestParserFailsInsideEveryComponent(t *testing.T) {
	params, err := threshold.NewParams()
	require.NoError(t, err)

	full, _, err := generateThresholdSignature(2, 3, "component truncation")
	require.NoError(t, err)
	require.Len(t, full, ExpectedSignatureSize)

	// Control: the whole blob parses.
	_, _, err = deserializeSignature(params, full)
	require.NoError(t, err, "control: a complete blob must parse")

	offset := 0
	for _, c := range componentBounds() {
		start := offset
		offset += c.polys * PolyWireSize

		// One byte into this component's first polynomial: the
		// component before it is complete, this one is not.
		cut := start + 1
		_, _, err := deserializeSignature(params, full[:cut])
		require.Error(t, err, "truncating inside %s must fail", c.name)
		require.ErrorContains(t, err, "deserialize", "the error must name the stage that failed")

		// One byte before this component ends: the last polynomial of
		// the component is incomplete.
		_, _, err = deserializeSignature(params, full[:offset-1])
		require.Error(t, err, "truncating at the end of %s must fail", c.name)
	}
	require.Equal(t, ExpectedSignatureSize, offset,
		"the component walk must account for the whole blob")
}

// TestParserRejectsEmptyAndTiny pins the degenerate inputs. An empty
// buffer must fail on the very first coefficient, not produce a
// zero-valued signature that the verifier then evaluates.
func TestParserRejectsEmptyAndTiny(t *testing.T) {
	params, err := threshold.NewParams()
	require.NoError(t, err)

	for _, n := range []int{0, 1, 7, CoefficientSize, PolyWireSize - 1} {
		sig, key, err := deserializeSignature(params, make([]byte, n))
		require.Error(t, err, "a %d-byte blob cannot be a signature", n)
		require.Nil(t, sig)
		require.Nil(t, key)
	}
}

// TestPolyReaderRefusesShortRead exercises deserializePoly on its own
// boundary: a buffer holding every byte but the last of one
// polynomial must report which coefficient it ran out on, so a
// truncation is diagnosable rather than silent.
func TestPolyReaderRefusesShortRead(t *testing.T) {
	params, err := threshold.NewParams()
	require.NoError(t, err)
	r := params.R

	require.NoError(t, deserializePoly(contract.Read(contract.Poisoned(make([]byte, PolyWireSize), 256)), r, r.NewPoly()),
		"control: exactly one polynomial's worth of bytes reads cleanly")

	for _, n := range []int{0, 1, CoefficientSize - 1, PolyWireSize - CoefficientSize, PolyWireSize - 1} {
		err := deserializePoly(contract.Read(contract.Poisoned(make([]byte, n), 256)), r, r.NewPoly())
		require.Error(t, err, "a %d-byte buffer is not a polynomial", n)
		require.ErrorContains(t, err, "failed to read coefficient")
	}
}

// TestVerifyReportsParseFailure pins the wrapping: when the parser
// refuses, verifyThresholdSignature must surface a typed
// ErrDeserializationFailed rather than reporting a plain "invalid
// signature". The two are different claims — one says the caller sent
// a malformed blob, the other says the cryptography rejected it — and
// a caller retrying on the wrong one retries forever.
func TestVerifyReportsParseFailure(t *testing.T) {
	_, err := verifyThresholdSignature(make([]byte, 32), make([]byte, ExpectedSignatureSize-1))
	require.ErrorIs(t, err, ErrDeserializationFailed)

	// And a blob that parses but does not verify is NOT a parse
	// failure: it is a clean false.
	valid, err := verifyThresholdSignature(make([]byte, 32), make([]byte, ExpectedSignatureSize))
	require.NoError(t, err, "an all-zero blob is well-formed; it simply does not verify")
	require.False(t, valid)
}

// TestRunSurfacesParseFailure closes the same loop through the
// precompile: a body long enough to clear the header check but short
// of a whole signature must return the length error, and Run must
// never let a parse failure through as a verdict.
func TestRunSurfacesParseFailure(t *testing.T) {
	_, hash, err := generateThresholdSignature(2, 3, "run parse failure")
	require.NoError(t, err)

	input := createInput(2, 3, hash, make([]byte, ExpectedSignatureSize-1))
	out, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), input, 10_000_000, true)
	require.ErrorIs(t, err, ErrInvalidInputLength)
	require.Nil(t, out, "no verdict word may accompany a refusal")
}

// TestAcceptsTrailingPadding pins, as a decision rather than an
// accident, that the body length is checked as a lower bound: bytes
// past the signature are ignored. The sibling P3Q precompile documents
// the same convention.
//
// The consequence is that calldata is NOT canonical here — the same
// signature with any suffix yields the same verdict — so a caller that
// keys replay protection on the call payload rather than on the
// signature itself will not get uniqueness from this precompile.
func TestAcceptsTrailingPadding(t *testing.T) {
	sig, hash, err := generateThresholdSignature(2, 3, "padding")
	require.NoError(t, err)

	for _, pad := range []int{1, 32, 4096} {
		input := createInput(2, 3, hash, append(append([]byte{}, sig...), make([]byte, pad)...))
		out, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), input, 20_000_000, true)
		require.NoError(t, err)
		require.Equal(t, byte(1), out[31], "%d bytes of padding does not change the verdict", pad)
	}
}

func addr() (a common.Address) { return }

// TestParserPlacesEachComponentInItsOwnRing pins the wire format's
// ring assignment. The three rings carry different moduli — R is
// ~2^48, RXi is 2^18, RNu is 2^19 — so which ring a component is read
// into decides how its coefficients are reduced.
//
// On honestly produced blobs the choice is invisible: Delta and bTilde
// coefficients are already below their small moduli, so reading them
// into the wide ring leaves the values untouched and every round-trip
// test passes either way. The assignment only becomes observable on a
// blob a signer would not have produced. That is exactly why it needs
// pinning here rather than being left to the round trips.
func TestParserPlacesEachComponentInItsOwnRing(t *testing.T) {
	params, err := threshold.NewParams()
	require.NoError(t, err)

	qR := params.R.ModuliChain()[0]
	qXi := params.RXi.ModuliChain()[0]
	qNu := params.RNu.ModuliChain()[0]
	require.NotEqual(t, qR, qXi, "the test is only meaningful if the moduli differ")
	require.NotEqual(t, qXi, qNu)

	// A sentinel larger than both small moduli but smaller than R's, so
	// it survives R untouched and is reduced by RXi and RNu. RNu is
	// exactly twice RXi, so the value is also chosen to land above RXi
	// after reduction by RNu -- otherwise the two residues coincide and
	// the test could not tell the rings apart.
	sentinel := qNu + qXi + 7
	require.Less(t, sentinel, qR)

	blob := make([]byte, ExpectedSignatureSize)
	writeCoeff := func(polyIndex int, v uint64) {
		off := polyIndex * PolyWireSize
		for i := 0; i < CoefficientSize; i++ {
			blob[off+CoefficientSize-1-i] = byte(v >> (8 * i))
		}
	}

	// Polynomial indices, in the order deserializeSignature reads them.
	const cIndex = 0
	deltaIndex := 1 + sign.N                           // first Delta poly, ring RNu
	bTildeIndex := 1 + sign.N + sign.M + sign.M*sign.N // first bTilde poly, ring RXi

	writeCoeff(cIndex, sentinel)
	writeCoeff(deltaIndex, sentinel)
	writeCoeff(bTildeIndex, sentinel)

	sig, groupKey, err := deserializeSignature(params, blob)
	require.NoError(t, err)

	// Delta is read into RNu, so the sentinel comes back reduced.
	require.Equal(t, sentinel%qNu, sig.Delta[0].Coeffs[0][0],
		"Delta must be read into RNu (modulus %d), not a wider ring", qNu)
	require.NotEqual(t, sentinel, sig.Delta[0].Coeffs[0][0],
		"a wider ring would have left the sentinel unreduced")

	// bTilde is read into RXi.
	require.Equal(t, sentinel%qXi, groupKey.BTilde[0].Coeffs[0][0],
		"bTilde must be read into RXi (modulus %d)", qXi)
	require.NotEqual(t, sentinel, groupKey.BTilde[0].Coeffs[0][0])

	// The two small rings must not be confused with each other either.
	require.NotEqual(t, sentinel%qXi, sentinel%qNu,
		"the sentinel must distinguish RXi from RNu")
}

// TestRefusesZeroThreshold pins that a zero threshold is refused. A
// 0-of-n threshold is not a weak policy, it is the absence of one: it
// asserts that no shares at all are required, so accepting it would
// let a caller present the group key with any signature and claim the
// committee had authorised it.
//
// t is checked independently of n, so sweep n across zero, one, and
// larger, including n = 0 where both the zero check and the t <= n
// check would fire.
func TestRefusesZeroThreshold(t *testing.T) {
	sig, hash, err := generateThresholdSignature(2, 3, "zero threshold")
	require.NoError(t, err)

	for _, n := range []uint32{0, 1, 3, 1000, ^uint32(0)} {
		input := createInput(0, n, hash, sig)
		_, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), input, 20_000_000, true)
		require.ErrorIs(t, err, ErrInvalidThreshold,
			"t=0 must be refused whatever n is (n=%d)", n)
	}

	// n = 0 with any positive t is also refused, by t <= n.
	for _, tv := range []uint32{1, 2, ^uint32(0)} {
		input := createInput(tv, 0, hash, sig)
		_, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), input, 20_000_000, true)
		require.ErrorIs(t, err, ErrInvalidThreshold, "n=0 must be refused (t=%d)", tv)
	}

	// t = 1, n = 1 is the smallest structurally valid committee and
	// must NOT be refused by the threshold check — it reaches the
	// verifier, which is what decides the outcome.
	input := createInput(1, 1, hash, sig)
	_, _, err = CoronaThresholdPrecompile.Run(nil, addr(), addr(), input, 20_000_000, true)
	require.NotErrorIs(t, err, ErrInvalidThreshold, "t=n=1 is structurally valid")
}

// TestCanonicalizesCoefficientsModTheRing pins that the parser reduces
// every coefficient into [0, q) rather than trusting the wire value.
//
// This is load-bearing and it is not hypothetical. Measured on this
// tree over 3000 ceremonies: the Corona key generator emits, roughly
// once in 400 ceremonies, a BTilde coefficient equal to 262144 — which
// is exactly the RXi modulus, and therefore a non-canonical way of
// writing zero. threshold.Verify accepts that representative; this
// parser reduces it to 0; the library then rejects the signature it
// had just accepted in memory.
//
// The direction matters. The precompile is the STRICTER party: it
// canonicalizes and can therefore only reject material an off-chain
// verifier accepted, never accept material it rejected. So this is a
// false-negative, not a forgery surface — an honestly produced Corona
// signature fails on chain about one time in four hundred, and the
// signer must resample. Recorded here so the reduction is understood
// as the parser's contract rather than an accident of
// SetCoefficientsBigint, because "fixing" it by trusting the wire
// value would make the verifier accept unreduced representatives, and
// with them a second encoding of every coefficient.
func TestCanonicalizesCoefficientsModTheRing(t *testing.T) {
	params, err := threshold.NewParams()
	require.NoError(t, err)

	qR := params.R.ModuliChain()[0]
	qXi := params.RXi.ModuliChain()[0]
	qNu := params.RNu.ModuliChain()[0]

	write := func(blob []byte, polyIndex int, v uint64) {
		off := polyIndex * PolyWireSize
		for i := 0; i < CoefficientSize; i++ {
			blob[off+CoefficientSize-1-i] = byte(v >> (8 * i))
		}
	}

	const cIndex = 0
	deltaIndex := 1 + sign.N
	bTildeIndex := 1 + sign.N + sign.M + sign.M*sign.N

	// Exactly the modulus is the case observed in the wild: another
	// spelling of zero.
	for _, mult := range []uint64{1, 2, 5} {
		blob := make([]byte, ExpectedSignatureSize)
		write(blob, deltaIndex, mult*qNu)
		write(blob, bTildeIndex, mult*qXi)

		sig, gk, err := deserializeSignature(params, blob)
		require.NoError(t, err)
		require.Zero(t, sig.Delta[0].Coeffs[0][0],
			"%d*qNu is zero and must be stored as zero", mult)
		require.Zero(t, gk.BTilde[0].Coeffs[0][0],
			"%d*qXi is zero and must be stored as zero", mult)
	}

	// One below the modulus is the largest canonical value and must
	// survive untouched — reduction must not be an off-by-one.
	blob := make([]byte, ExpectedSignatureSize)
	write(blob, deltaIndex, qNu-1)
	write(blob, bTildeIndex, qXi-1)
	write(blob, cIndex, qR-1)
	sig, gk, err := deserializeSignature(params, blob)
	require.NoError(t, err)
	require.Equal(t, qNu-1, sig.Delta[0].Coeffs[0][0])
	require.Equal(t, qXi-1, gk.BTilde[0].Coeffs[0][0])

	// And q+1 reduces to 1, not to q+1 and not to 0.
	blob = make([]byte, ExpectedSignatureSize)
	write(blob, deltaIndex, qNu+1)
	write(blob, bTildeIndex, qXi+1)
	sig, gk, err = deserializeSignature(params, blob)
	require.NoError(t, err)
	require.Equal(t, uint64(1), sig.Delta[0].Coeffs[0][0])
	require.Equal(t, uint64(1), gk.BTilde[0].Coeffs[0][0])
}

// TestNoPrefixEscapesTheParser sweeps every truncation of a valid call
// and requires each to be refused with a length error, never a verdict
// and never a panic.
//
// Every input is submitted through contract.Poisoned, which is what a
// precompile's calldata actually looks like: len is the size the caller
// declared and paid for, cap is the rest of EVM memory, and the caller
// MSTOREd that memory. So a parser reaching past its input does not
// crash — it reads bytes the caller chose and answers over them. A
// fixture built with append carries spare capacity too, but zeroed, so
// an over-read reads as harmless zeros and the test passes whether or
// not the bound exists.
//
// The boundaries between fields are where an off-by-one lives and there
// is no reason to guess which, so this sweeps the header exhaustively
// and then samples the body.
func TestNoPrefixEscapesTheParser(t *testing.T) {
	real, hash, err := generateThresholdSignature(2, 3, "prefix sweep")
	require.NoError(t, err)
	full := createInput(2, 3, hash, real)

	out, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(),
		contract.Poisoned(full, 4096), 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), out[31], "control: the whole input verifies")

	cuts := make([]int, 0, MinInputSize+8)
	for n := 0; n <= MinInputSize; n++ {
		cuts = append(cuts, n)
	}
	cuts = append(cuts, MinInputSize+1, MinInputSize+PolyWireSize,
		len(full)/2, len(full)-1)

	for _, n := range cuts {
		in := contract.Poisoned(full[:n], 4096)
		require.NotPanics(t, func() {
			_, _, err := CoronaThresholdPrecompile.Run(nil, addr(), addr(), in, 10_000_000, true)
			require.ErrorIs(t, err, ErrInvalidInputLength,
				"a %d-byte prefix must be refused on length", n)
		}, "prefix of length %d panicked", n)
	}
}
