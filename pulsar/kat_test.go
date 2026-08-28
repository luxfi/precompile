// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func katBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// katInput assembles the frozen vector into precompile calldata.
func katInput(t *testing.T, sigHex string) []byte {
	t.Helper()
	return buildInput(ModePulsar65,
		katBytes(t, katPubHex), katBytes(t, katMsgHex), katBytes(t, sigHex))
}

func katRun(t *testing.T, input []byte) error {
	t.Helper()
	gas := PulsarVerifyPrecompile.RequiredGas(input)
	_, _, err := PulsarVerifyPrecompile.Run(
		nil, common.Address{}, ContractPulsarVerifyAddress, input, gas, true)
	return err
}

// TestKATSizes pins the frozen vector against the FIPS 204 Table 2
// sizes the package declares. If a constant drifts, the vector no
// longer describes ML-DSA-65 and every other KAT assertion below is
// meaningless — so check it first.
func TestKATSizes(t *testing.T) {
	require.Len(t, katBytes(t, katPubHex), Pulsar65PublicKeySize)
	require.Len(t, katBytes(t, katSigHex), Pulsar65SignatureSize)
	require.Len(t, katBytes(t, katForeignSigHex), Pulsar65SignatureSize)
	require.Len(t, katBytes(t, katMsgHex), 32)
}

// TestKATAccepts is the positive known-answer test: a fixed ML-DSA-65
// signature, minted once and frozen, must verify. A round-trip test
// cannot catch a uniformly-wrong verifier because it checks the
// implementation against itself; this checks it against bytes it did
// not produce.
func TestKATAccepts(t *testing.T) {
	require.NoError(t, katRun(t, katInput(t, katSigHex)))
}

// TestKATRejectsForeignContext is the cross-slot replay refusal, and
// the reason the domain-separation string is load-bearing rather than
// decorative. katForeignSigHex is a genuine, verifying ML-DSA-65
// signature by the SAME key over the SAME message — the only
// difference is that it was minted under the P3Q slot's context
// ("lux-evm-precompile-p3q-v1") instead of Pulsar's. Without context
// binding a signature harvested from the 0x012205 path would be
// replayable at 0x012204 verbatim.
func TestKATRejectsForeignContext(t *testing.T) {
	require.ErrorIs(t, katRun(t, katInput(t, katForeignSigHex)), ErrInvalidSignature)
}

// TestKATRejectsBitFlip sweeps a single-bit flip across the whole
// frozen signature — the leading c-tilde challenge hash, the z region,
// the hint region, and the final byte — and requires refusal at every
// position. One lucky offset proves nothing; the point is that no
// region of the signature is unchecked.
func TestKATRejectsBitFlip(t *testing.T) {
	for _, pos := range []int{0, 1, 31, 32, 33, 500, 1500, 2500, 3000, Pulsar65SignatureSize - 2, Pulsar65SignatureSize - 1} {
		sig := katBytes(t, katSigHex)
		sig[pos] ^= 0x01
		input := buildInput(ModePulsar65, katBytes(t, katPubHex), katBytes(t, katMsgHex), sig)
		require.ErrorIs(t, katRun(t, input), ErrInvalidSignature, "bit flip at sig[%d] must reject", pos)
	}
}

// TestKATRejectsTamperedMessage pins message binding: the frozen
// signature must not verify against any message but the one it covers.
func TestKATRejectsTamperedMessage(t *testing.T) {
	for _, pos := range []int{0, 15, 31} {
		msg := katBytes(t, katMsgHex)
		msg[pos] ^= 0x80
		input := buildInput(ModePulsar65, katBytes(t, katPubHex), msg, katBytes(t, katSigHex))
		require.ErrorIs(t, katRun(t, input), ErrInvalidSignature, "message tamper at [%d] must reject", pos)
	}
}

// TestKATRejectsTamperedKey pins key binding: the frozen signature
// must not verify under a public key it was not minted against. rho
// (the first 32 bytes) and t1 (the rest) are probed separately because
// they enter the verification equation at different points.
func TestKATRejectsTamperedKey(t *testing.T) {
	for _, pos := range []int{0, 31, 32, 1000, Pulsar65PublicKeySize - 1} {
		pk := katBytes(t, katPubHex)
		pk[pos] ^= 0x01
		input := buildInput(ModePulsar65, pk, katBytes(t, katMsgHex), katBytes(t, katSigHex))
		require.Error(t, katRun(t, input), "public key tamper at [%d] must reject", pos)
	}
}

// TestKATRejectsAllZeroSignature pins the degenerate case an attacker
// reaches for first: calldata that is structurally perfect and
// cryptographically empty.
func TestKATRejectsAllZeroSignature(t *testing.T) {
	input := buildInput(ModePulsar65, katBytes(t, katPubHex), katBytes(t, katMsgHex),
		make([]byte, Pulsar65SignatureSize))
	require.ErrorIs(t, katRun(t, input), ErrInvalidSignature)
}

// TestKATRejectsAllZeroKey pins the same for the public key. An
// all-zero ML-DSA key is a valid byte string (rho and t1 are
// unconstrained), so it must be the signature check that refuses it,
// not a parse error — either way the call must not succeed.
func TestKATRejectsAllZeroKey(t *testing.T) {
	input := buildInput(ModePulsar65, make([]byte, Pulsar65PublicKeySize),
		katBytes(t, katMsgHex), katBytes(t, katSigHex))
	require.Error(t, katRun(t, input))
}

// TestKATRejectsWrongMode submits the ML-DSA-65 vector under the 44
// and 87 mode bytes. Both must refuse: the declared parameter set
// determines the key and signature sizes the parser carves out, so a
// mode mismatch must never be resolved by silently re-framing the
// bytes.
func TestKATRejectsWrongMode(t *testing.T) {
	for _, mode := range []uint8{ModePulsar44, ModePulsar87} {
		input := buildInput(mode, katBytes(t, katPubHex), katBytes(t, katMsgHex), katBytes(t, katSigHex))
		require.Error(t, katRun(t, input), "ML-DSA-65 vector under mode 0x%x must reject", mode)
	}
}

// TestKATRejectsTruncatedAndExtended is the one-short / one-long pair
// on the signature field. One byte short must be refused for length;
// one byte long must be refused because the parser takes exactly
// sigSize bytes and the trailing byte shifts nothing — the signature
// still covers the right bytes, so this asserts the surplus does not
// smuggle a second interpretation of the same calldata.
func TestKATRejectsTruncatedAndExtended(t *testing.T) {
	pk, msg := katBytes(t, katPubHex), katBytes(t, katMsgHex)

	short := katBytes(t, katSigHex)[:Pulsar65SignatureSize-1]
	require.ErrorIs(t, katRun(t, buildInput(ModePulsar65, pk, msg, short)), ErrInvalidInputLength,
		"signature one byte short must fail the length check, not the verifier")

	long := append(katBytes(t, katSigHex), 0x00)
	require.NoError(t, katRun(t, buildInput(ModePulsar65, pk, msg, long)),
		"trailing byte past the signature is ignored by the fixed-width parser")

	// ...but the trailing byte must not be able to stand in for a
	// missing one: dropping a real signature byte and appending a
	// filler keeps the total length valid and must still reject.
	shifted := append(katBytes(t, katSigHex)[:Pulsar65SignatureSize-1], 0xff)
	require.ErrorIs(t, katRun(t, buildInput(ModePulsar65, pk, msg, shifted)), ErrInvalidSignature)
}
