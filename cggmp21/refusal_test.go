// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

const allOnesHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// runRaw executes the precompile over arbitrary calldata with the quoted fee.
func runRaw(t *testing.T, input []byte) ([]byte, error) {
	t.Helper()
	res, _, err := CGGMP21VerifyPrecompile.Run(
		nil, common.Address{}, ContractCGGMP21VerifyAddress,
		input, CGGMP21VerifyPrecompile.RequiredGas(input), true,
	)
	return res, err
}

// TestCGGMP21_RefuseShortInput: everything below MinInputSize is refused with
// the length error, and exactly MinInputSize is admitted. One byte either side
// of the boundary must land on opposite sides.
func TestCGGMP21_RefuseShortInput(t *testing.T) {
	for _, size := range []int{0, 1, 8, 169} {
		_, err := runRaw(t, make([]byte, size))
		require.ErrorIs(t, err, ErrInvalidInputLength, "len=%d must be refused as short", size)
	}
	require.Equal(t, MinInputSize-1, 169, "the short boundary must track MinInputSize")

	_, err := runRaw(t, nil)
	require.ErrorIs(t, err, ErrInvalidInputLength, "nil calldata must be refused as short")

	// At exactly MinInputSize the length check passes and the threshold check runs.
	_, err = runRaw(t, make([]byte, MinInputSize))
	require.ErrorIs(t, err, ErrInvalidThreshold, "at MinInputSize the length check must pass")
	require.NotErrorIs(t, err, ErrInvalidInputLength)

	// One byte longer is also admitted.
	pk, mh, sig := katVector(t)
	long := append(buildInput(3, 5, pk, mh, sig), 0x00)
	res, err := runRaw(t, long)
	require.NoError(t, err)
	require.Equal(t, byte(1), res[31])
}

// TestCGGMP21_RefuseThreshold: t == 0 is meaningless and t > n is
// unsatisfiable; t == n is a legitimate n-of-n committee and MUST be admitted.
// Rejecting t == n would silently break every unanimous quorum on chain, so it
// is asserted as an acceptance.
func TestCGGMP21_RefuseThreshold(t *testing.T) {
	pk, mh, sig := katVector(t)
	run := func(threshold, n uint32) (byte, error) {
		res, err := runRaw(t, buildInput(threshold, n, pk, mh, sig))
		if err != nil {
			return 0, err
		}
		return res[31], nil
	}

	for _, tn := range [][2]uint32{
		{0, 0}, {0, 1}, {0, math.MaxUint32}, // t == 0
		{1, 0}, {6, 5}, {math.MaxUint32, 1}, // t > n
	} {
		_, err := run(tn[0], tn[1])
		require.ErrorIs(t, err, ErrInvalidThreshold, "t=%d n=%d must be refused", tn[0], tn[1])
	}

	for _, tn := range [][2]uint32{
		{1, 1}, {5, 5}, {1, 5}, {math.MaxUint32, math.MaxUint32}, {1, math.MaxUint32},
	} {
		got, err := run(tn[0], tn[1])
		require.NoError(t, err, "t=%d n=%d must be admitted", tn[0], tn[1])
		require.Equal(t, byte(1), got, "t=%d n=%d must verify", tn[0], tn[1])
	}

	// t == n is the boundary: n is admitted, n+1 is not.
	_, err := run(5, 5)
	require.NoError(t, err)
	_, err = run(6, 5)
	require.ErrorIs(t, err, ErrInvalidThreshold)
}

// TestCGGMP21_RefuseAllZeroInput: a fully zero envelope of exactly
// MinInputSize is refused on the threshold; under a valid threshold the
// all-zero key is refused as a key, not mistaken for one.
func TestCGGMP21_RefuseAllZeroInput(t *testing.T) {
	_, err := runRaw(t, make([]byte, MinInputSize))
	require.ErrorIs(t, err, ErrInvalidThreshold)

	zeroed := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(zeroed[0:4], 1)
	binary.BigEndian.PutUint32(zeroed[4:8], 1)
	_, err = runRaw(t, zeroed)
	require.ErrorIs(t, err, ErrInvalidPublicKey, "an all-zero public key must be refused as a key")
}

// TestCGGMP21_RefuseMalformedOperandLengths exercises the verifier core
// directly. Run always slices exactly 65/32/65, so these guards only fire for
// callers elsewhere in the process -- and they are the reason those callers
// cannot hand the curve a short buffer.
func TestCGGMP21_RefuseMalformedOperandLengths(t *testing.T) {
	pk, mh, sig := katVector(t)
	ok, err := verifyECDSASignature(pk, mh, sig)
	require.NoError(t, err)
	require.True(t, ok, "control")

	// The length check is the precompile's OWN precondition, not a restatement
	// of the crypto library's. Today crypto.UnmarshalPubkey happens to refuse a
	// wrong-length buffer too, so the two refusals differ only in the error
	// they carry: the precondition returns the bare sentinel, the library path
	// returns it wrapped with the library's reason. Asserting the bare sentinel
	// is what keeps the precondition in the code -- swap in a library that pads
	// or truncates and it becomes the only thing still refusing.
	for _, n := range []int{0, 33, 64, 66, 128} {
		bad := make([]byte, n)
		copy(bad, pk)
		ok, err := verifyECDSASignature(bad, mh, sig)
		require.False(t, ok)
		require.Equal(t, ErrInvalidPublicKey, err,
			"a %d-byte public key must be refused by the length precondition, unwrapped", n)
	}
	// A right-length key that is off the curve is a different refusal, and it
	// must say so: the sentinel wrapped around the library's reason.
	offCurve := mustHex(t, katPKHex)
	offCurve[64] ^= 0x01
	_, err = verifyECDSASignature(offCurve, mh, sig)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
	require.NotEqual(t, ErrInvalidPublicKey, err,
		"an off-curve key must carry the parse reason, not just the sentinel")
	for _, n := range []int{0, 31, 33, 64} {
		bad := make([]byte, n)
		copy(bad, mh)
		ok, err := verifyECDSASignature(pk, bad, sig)
		require.False(t, ok)
		require.Error(t, err, "message hash of %d bytes must be refused", n)
	}
	for _, n := range []int{0, 1, 64, 66, 130} {
		bad := make([]byte, n)
		copy(bad, sig)
		ok, err := verifyECDSASignature(pk, mh, bad)
		require.False(t, ok)
		require.ErrorIs(t, err, ErrInvalidSignature, "signature of %d bytes must be refused", n)

		rec, err := recoverPublicKey(mh, bad)
		require.Nil(t, rec)
		require.ErrorIs(t, err, ErrInvalidSignature, "recovery from %d bytes must be refused", n)
	}
}

// TestCGGMP21_RefuseUnrecoverableSignature: a signature whose r||s satisfies
// the equation but whose recovery byte cannot address a point must be refused
// rather than accepted on the strength of r||s alone. Normalisation subtracts
// 27, so v = 31 asks ecrecover for recovery id 4, which does not exist.
func TestCGGMP21_RefuseUnrecoverableSignature(t *testing.T) {
	pk, mh, sig := katVector(t)
	for _, v := range []byte{4, 26, 31, 255} {
		bad := append([]byte(nil), sig...)
		bad[64] = v
		require.True(t, crypto.VerifySignature(pk, mh, bad[:64]),
			"r||s alone must still satisfy the primitive (v=%d)", v)

		rec, err := recoverPublicKey(mh, bad)
		require.Nil(t, rec, "v=%d must not recover a key", v)
		require.Error(t, err, "v=%d must not recover a key", v)

		accepted, err := verdict(t, pk, mh, bad)
		require.NoError(t, err, "an unrecoverable signature is a verdict, not a revert")
		require.False(t, accepted, "v=%d must be refused", v)
	}
}

// TestCGGMP21_RefusalErrorsAreTyped: a caller must be able to tell the two
// refusal classes apart. Malformed keys revert with ErrInvalidPublicKey;
// malformed structure reverts with ErrInvalidThreshold or the length error;
// everything else is a zero word.
func TestCGGMP21_RefusalErrorsAreTyped(t *testing.T) {
	_, mh, sig := katVector(t)

	offCurve := mustHex(t, katPKHex)
	offCurve[64] ^= 0x01
	_, err := runRaw(t, buildInput(1, 1, offCurve, mh, sig))
	require.ErrorIs(t, err, ErrInvalidPublicKey)

	_, err = runRaw(t, buildInput(0, 1, offCurve, mh, sig))
	require.ErrorIs(t, err, ErrInvalidThreshold,
		"the structural check must run before the key is parsed")
}
