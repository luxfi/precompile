// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Known-answer vector for the CGGMP21 ECDSA verifier.
//
// These bytes are FROZEN. The other signature tests in this package mint a
// fresh key each run, so a uniformly wrong verifier still round-trips its own
// output and passes. A frozen vector cannot: it pins the wire layout
// (uncompressed 0x04||x||y key, r||s||v signature), the secp256k1 group, and
// the exact accept/reject boundary of the verify-plus-recover-and-compare
// pair. If the crypto dependency, the curve, or the field order ever changed
// underneath, these assertions flip.
//
// Provenance: one secp256k1 ECDSA signature, produced once from a fixed
// secret over keccak256("lux cggmp21 precompile known-answer vector v1").
// The recovery byte of this vector is 0.
const (
	katPKHex = "042c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645" +
		"64b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085"
	katMHHex  = "baa9ab4637fa887b33dde1b958253d4e7cbf304a478ece92fd35f81791399bd6"
	katSIGHex = "623251d064a74966be8e16cfbde3360c700f32c5c4e022c249b14d87162ff371" +
		"370387b7c36099cf0b67e680a3809e13f46c519e58981946aa1487b5a57a978a00"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func katVector(t *testing.T) (pk, mh, sig []byte) {
	t.Helper()
	pk, mh, sig = mustHex(t, katPKHex), mustHex(t, katMHHex), mustHex(t, katSIGHex)
	require.Len(t, pk, CGGMP21PublicKeySize)
	require.Len(t, mh, CGGMP21MessageHashSize)
	require.Len(t, sig, CGGMP21SignatureSize)
	return pk, mh, sig
}

// buildInput assembles calldata: t(4) || n(4) || pk(65) || msgHash(32) || sig(65).
func buildInput(threshold, n uint32, pk, mh, sig []byte) []byte {
	input := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(input[0:4], threshold)
	binary.BigEndian.PutUint32(input[4:8], n)
	copy(input[8:73], pk)
	copy(input[73:105], mh)
	copy(input[105:170], sig)
	return input
}

// verdict runs the precompile over a well-formed 3-of-5 envelope. A refusal
// arrives either as an error (malformed key) or as a zero word (bad
// signature); callers that only care whether the tuple was ACCEPTED read the
// bool.
func verdict(t *testing.T, pk, mh, sig []byte) (accepted bool, err error) {
	t.Helper()
	input := buildInput(3, 5, pk, mh, sig)
	res, _, err := CGGMP21VerifyPrecompile.Run(
		nil, common.Address{}, ContractCGGMP21VerifyAddress,
		input, CGGMP21VerifyPrecompile.RequiredGas(input), true,
	)
	if err != nil {
		require.Nil(t, res, "a refused call must not also return a word")
		return false, err
	}
	require.Len(t, res, 32)
	for i := 0; i < 31; i++ {
		require.Equal(t, byte(0), res[i], "verdict word must be a clean 0/1, byte %d dirty", i)
	}
	return res[31] == 1, nil
}

// TestCGGMP21_KAT_Accept: the frozen vector must verify, through the
// precompile and through the verifier core.
func TestCGGMP21_KAT_Accept(t *testing.T) {
	pk, mh, sig := katVector(t)

	ok, err := verifyECDSASignature(pk, mh, sig)
	require.NoError(t, err)
	require.True(t, ok, "frozen KAT must verify in the core")

	accepted, err := verdict(t, pk, mh, sig)
	require.NoError(t, err)
	require.True(t, accepted, "frozen KAT must verify on-chain")
}

// TestCGGMP21_KAT_TamperSig: a single flipped bit anywhere in r, s or v must
// reject. r and s carry the equation; v selects which of the candidate points
// ecrecover returns, and the recover-and-compare binds it.
func TestCGGMP21_KAT_TamperSig(t *testing.T) {
	pk, mh, _ := katVector(t)
	for _, pos := range []int{0, 1, 31, 32, 33, 63, 64} {
		for _, bit := range []byte{0x01, 0x80} {
			sig := mustHex(t, katSIGHex)
			sig[pos] ^= bit
			accepted, err := verdict(t, pk, mh, sig)
			require.NoError(t, err, "a tampered signature must be a verdict, not a revert")
			require.False(t, accepted, "sig bit flip at byte %d mask %#x must reject", pos, bit)
		}
	}
}

// TestCGGMP21_KAT_TamperMsg: a single flipped bit in the message hash must
// reject.
func TestCGGMP21_KAT_TamperMsg(t *testing.T) {
	pk, _, sig := katVector(t)
	for _, pos := range []int{0, 7, 16, 31} {
		mh := mustHex(t, katMHHex)
		mh[pos] ^= 0x01
		accepted, err := verdict(t, pk, mh, sig)
		require.NoError(t, err)
		require.False(t, accepted, "message-hash bit flip at byte %d must reject", pos)
	}
}

// TestCGGMP21_KAT_TamperPubKey: a single flipped bit in the public key must
// never be accepted. Almost every tampered coordinate leaves the curve, and
// the precompile REVERTS on those rather than returning a zero word -- that
// asymmetry is existing consensus behaviour, so it is pinned here rather than
// smoothed over.
func TestCGGMP21_KAT_TamperPubKey(t *testing.T) {
	_, mh, sig := katVector(t)
	reverts := 0
	for _, pos := range []int{1, 9, 32, 33, 48, 64} {
		for _, bit := range []byte{0x01, 0x40} {
			pk := mustHex(t, katPKHex)
			pk[pos] ^= bit
			accepted, err := verdict(t, pk, mh, sig)
			require.False(t, accepted, "pubkey bit flip at byte %d mask %#x must not be accepted", pos, bit)
			if err != nil {
				require.ErrorIs(t, err, ErrInvalidPublicKey)
				reverts++
			}
		}
	}
	require.NotZero(t, reverts, "an off-curve key must surface as ErrInvalidPublicKey")

	// The 0x04 prefix is part of the encoding, not the point.
	pk := mustHex(t, katPKHex)
	pk[0] = 0x03
	_, err := verdict(t, pk, mh, sig)
	require.ErrorIs(t, err, ErrInvalidPublicKey, "only the uncompressed 0x04 prefix is accepted")
}

// TestCGGMP21_KAT_KeyAndMessageAreBound: the verdict must depend on all three
// operands jointly. A verifier that ignores one of them shows up here.
func TestCGGMP21_KAT_KeyAndMessageAreBound(t *testing.T) {
	pk, mh, sig := katVector(t)

	// A second valid, on-curve key: the KAT key negated in Y (i.e. -P), which
	// is a genuine secp256k1 point and therefore reaches the equation rather
	// than the encoding check.
	otherPK := negateY(t, pk)
	accepted, err := verdict(t, otherPK, mh, sig)
	require.NoError(t, err, "-P is on the curve, so this must be a verdict and not a revert")
	require.False(t, accepted, "a different valid key must reject")

	otherMH := mustHex(t, katMHHex)
	otherMH[0] ^= 0xff
	accepted, err = verdict(t, pk, otherMH, sig)
	require.NoError(t, err)
	require.False(t, accepted, "a different message must reject")
}

// TestCGGMP21_KAT_Determinism: identical calldata must produce an identical
// word and an identical fee on every call. Consensus depends on it.
func TestCGGMP21_KAT_Determinism(t *testing.T) {
	pk, mh, sig := katVector(t)
	input := buildInput(3, 5, pk, mh, sig)
	gas := CGGMP21VerifyPrecompile.RequiredGas(input)
	want, _, err := CGGMP21VerifyPrecompile.Run(nil, common.Address{}, ContractCGGMP21VerifyAddress, input, gas, true)
	require.NoError(t, err)
	for i := 0; i < 64; i++ {
		got, rem, err := CGGMP21VerifyPrecompile.Run(nil, common.Address{}, ContractCGGMP21VerifyAddress, input, gas, true)
		require.NoError(t, err)
		require.Equal(t, want, got, "iteration %d diverged", i)
		require.Equal(t, uint64(0), rem, "quoted gas must be consumed exactly")
	}
}

// TestCGGMP21_KAT_SignerCountDoesNotChangeVerdict: the declared (t, n) is a
// structural claim only -- the verifier never sees n. Every admitted pair must
// give the same verdict for the same key/message/signature.
func TestCGGMP21_KAT_SignerCountDoesNotChangeVerdict(t *testing.T) {
	pk, mh, sig := katVector(t)
	for _, tn := range [][2]uint32{{1, 1}, {1, 5}, {5, 5}, {3, 5}, {1, MaxBilledSigners}, {1, 1 << 20}} {
		input := buildInput(tn[0], tn[1], pk, mh, sig)
		res, _, err := CGGMP21VerifyPrecompile.Run(
			nil, common.Address{}, ContractCGGMP21VerifyAddress,
			input, CGGMP21VerifyPrecompile.RequiredGas(input), true,
		)
		require.NoError(t, err, "t=%d n=%d", tn[0], tn[1])
		require.Equal(t, byte(1), res[31], "t=%d n=%d must not change the verdict", tn[0], tn[1])
	}
}

// TestCGGMP21_KAT_TrailingBytesIgnored: calldata longer than MinInputSize is
// accepted and the tail does not participate, in the fee or the verdict.
func TestCGGMP21_KAT_TrailingBytesIgnored(t *testing.T) {
	pk, mh, sig := katVector(t)
	exact := buildInput(3, 5, pk, mh, sig)
	long := append(append([]byte(nil), exact...), 0xde, 0xad, 0xbe, 0xef)

	gas := CGGMP21VerifyPrecompile.RequiredGas(long)
	require.Equal(t, CGGMP21VerifyPrecompile.RequiredGas(exact), gas,
		"trailing bytes must not change the fee")
	res, _, err := CGGMP21VerifyPrecompile.Run(nil, common.Address{}, ContractCGGMP21VerifyAddress, long, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), res[31], "trailing bytes must not change the verdict")
}
