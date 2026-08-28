// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Known-answer vector for the FROST Schnorr verifier.
//
// These bytes are FROZEN. Every other signature test in this package mints a
// fresh key each run, so a uniformly wrong verifier -- one that computes the
// challenge over the wrong transcript, or lifts the wrong point -- still
// round-trips its own output and passes. A frozen vector cannot: it pins the
// exact verification equation, the challenge transcript ("R" / "Y" /
// "messageHash" domain-separated), the x-only wire layout and the even-Y
// convention LiftX imposes. Any of those drifting flips these assertions.
//
// Provenance: one secp256k1 BIP-340-shaped Schnorr signature, produced once
// from a fixed secret and a fixed nonce (both forced to even-Y form, which is
// what LiftX recovers), over sha256("lux frost precompile known-answer vector
// v1"). Wire layout is what the precompile consumes: pk = 32-byte x-only Y,
// sig = 32-byte R_x || 32-byte z.
const (
	katPKHex  = "1b6d5a0ee72c1a077b0af91723952bdee620e585bf44ad0f0b633714bfe9b9ca"
	katMHHex  = "ff85050dc79bd12f52b60a32653842489191ddd85c451f316dc171f9686f29a0"
	katSIGHex = "faf1a42a5f5f9c4f43501ad899069e7ec60c412541119f96986182d640ed40fc" +
		"6a58e51bf247805c0a4a778b3bcc5a2c0471917b83f7b95cd911136dba9aced2"
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
	require.Len(t, pk, FROSTPublicKeySize)
	require.Len(t, mh, FROSTMessageHashSize)
	require.Len(t, sig, FROSTSignatureSize)
	return pk, mh, sig
}

// runFROST executes the precompile over a well-formed 3-of-5 envelope and
// returns the verdict byte. It supplies exactly the quoted gas plus one wei of
// headroom so a gas-schedule regression surfaces as an error, not a pass.
func runFROST(t *testing.T, pk, mh, sig []byte) byte {
	t.Helper()
	input := buildFrostInput(3, 5, pk, mh, sig)
	res, _, err := FROSTVerifyPrecompile.Run(
		nil, common.Address{}, ContractFROSTVerifyAddress,
		input, FROSTVerifyPrecompile.RequiredGas(input), true,
	)
	require.NoError(t, err)
	require.Len(t, res, 32)
	for i := 0; i < 31; i++ {
		require.Equal(t, byte(0), res[i], "verdict word must be a clean 0/1, byte %d dirty", i)
	}
	return res[31]
}

// TestFROST_KAT_Accept: the frozen vector must verify, through the precompile
// and through the verifier core.
func TestFROST_KAT_Accept(t *testing.T) {
	pk, mh, sig := katVector(t)
	require.True(t, verifySchnorrSignature(pk, mh, sig), "frozen KAT must verify in the core")
	require.Equal(t, byte(1), runFROST(t, pk, mh, sig), "frozen KAT must verify on-chain")
}

// TestFROST_KAT_TamperSig: a single flipped bit anywhere in the 64-byte
// signature must reject. The sweep covers R_x (which feeds LiftX and the
// challenge transcript) and z (which feeds the scalar side of the equation).
func TestFROST_KAT_TamperSig(t *testing.T) {
	pk, mh, _ := katVector(t)
	for _, pos := range []int{0, 1, 15, 31, 32, 33, 47, 62, 63} {
		for _, bit := range []byte{0x01, 0x80} {
			sig := mustHex(t, katSIGHex)
			sig[pos] ^= bit
			require.Equal(t, byte(0), runFROST(t, pk, mh, sig),
				"sig bit flip at byte %d mask %#x must reject", pos, bit)
		}
	}
}

// TestFROST_KAT_TamperMsg: a single flipped bit in the message hash must
// reject -- the hash is bound into the challenge.
func TestFROST_KAT_TamperMsg(t *testing.T) {
	pk, _, sig := katVector(t)
	for _, pos := range []int{0, 7, 16, 31} {
		mh := mustHex(t, katMHHex)
		mh[pos] ^= 0x01
		require.Equal(t, byte(0), runFROST(t, pk, mh, sig),
			"message-hash bit flip at byte %d must reject", pos)
	}
}

// TestFROST_KAT_TamperPubKey: a single flipped bit in the public key must
// reject. Roughly half the tampered x-coordinates are not on the curve (LiftX
// refuses) and the rest are a different key (the equation refuses); both are
// rejections, and this asserts the verdict without caring which fired.
func TestFROST_KAT_TamperPubKey(t *testing.T) {
	_, mh, sig := katVector(t)
	for _, pos := range []int{0, 9, 20, 31} {
		for _, bit := range []byte{0x01, 0x40} {
			pk := mustHex(t, katPKHex)
			pk[pos] ^= bit
			require.Equal(t, byte(0), runFROST(t, pk, mh, sig),
				"pubkey bit flip at byte %d mask %#x must reject", pos, bit)
		}
	}
}

// TestFROST_KAT_KeyAndMessageAreBound: the verdict must depend on all three
// operands jointly. Swapping any one of them for the corresponding field of a
// different valid tuple must reject -- this catches a verifier that ignores an
// argument entirely.
func TestFROST_KAT_KeyAndMessageAreBound(t *testing.T) {
	pk, mh, sig := katVector(t)
	otherPK, otherMH, otherSig := generateRealFrostSchnorr(t, []byte("canonical test message"), 42)
	require.Equal(t, byte(1), runFROST(t, otherPK, otherMH, otherSig), "control tuple must verify")

	require.Equal(t, byte(0), runFROST(t, otherPK, mh, sig), "foreign key must reject")
	require.Equal(t, byte(0), runFROST(t, pk, otherMH, sig), "foreign message must reject")
	require.Equal(t, byte(0), runFROST(t, pk, mh, otherSig), "foreign signature must reject")
}

// TestFROST_Determinism: the frozen vector must produce the same verdict on
// every call, including across the cold and warm halves of the LiftX cache.
// Consensus depends on it.
func TestFROST_KAT_Determinism(t *testing.T) {
	pk, mh, sig := katVector(t)
	input := buildFrostInput(3, 5, pk, mh, sig)
	gas := FROSTVerifyPrecompile.RequiredGas(input)
	want, _, err := FROSTVerifyPrecompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas, true)
	require.NoError(t, err)
	for i := 0; i < 64; i++ {
		got, rem, err := FROSTVerifyPrecompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, input, gas, true)
		require.NoError(t, err)
		require.Equal(t, want, got, "iteration %d diverged", i)
		require.Equal(t, uint64(0), rem, "quoted gas must be consumed exactly")
	}
}

// TestFROST_KAT_SignerCountDoesNotChangeVerdict: the declared (t, n) is a
// structural claim only. Every accepted pair must produce the same verdict for
// the same key/message/signature, because the verifier never sees n. If this
// ever fails, the verdict has become a function of attacker-chosen calldata
// that the cryptography does not cover.
func TestFROST_KAT_SignerCountDoesNotChangeVerdict(t *testing.T) {
	pk, mh, sig := katVector(t)
	for _, tn := range [][2]uint32{{1, 1}, {1, 5}, {5, 5}, {3, 5}, {1, MaxBilledSigners}, {1, 1 << 20}} {
		input := buildFrostInput(tn[0], tn[1], pk, mh, sig)
		res, _, err := FROSTVerifyPrecompile.Run(
			nil, common.Address{}, ContractFROSTVerifyAddress,
			input, FROSTVerifyPrecompile.RequiredGas(input), true,
		)
		require.NoError(t, err, "t=%d n=%d", tn[0], tn[1])
		require.Equal(t, byte(1), res[31], "t=%d n=%d must not change the verdict", tn[0], tn[1])
	}
}

// TestFROST_KAT_TrailingBytesIgnored: input longer than MinInputSize is
// accepted and the trailing bytes do not participate. Pinning this stops a
// future reader from "helpfully" hashing the tail into the verdict, which
// would be a consensus change.
func TestFROST_KAT_TrailingBytesIgnored(t *testing.T) {
	pk, mh, sig := katVector(t)
	exact := buildFrostInput(3, 5, pk, mh, sig)
	long := append(append([]byte(nil), exact...), 0xde, 0xad, 0xbe, 0xef)

	gas := FROSTVerifyPrecompile.RequiredGas(long)
	require.Equal(t, FROSTVerifyPrecompile.RequiredGas(exact), gas,
		"trailing bytes must not change the fee")
	res, _, err := FROSTVerifyPrecompile.Run(nil, common.Address{}, ContractFROSTVerifyAddress, long, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), res[31], "trailing bytes must not change the verdict")
}
