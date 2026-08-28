// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"math"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// frameWithDeclaredLength builds a mode-0x65 frame whose message-length
// word says msgLen, regardless of what follows. Only the fee is under
// test here, so the frame need not be otherwise well-formed.
func frameWithDeclaredLength(msgLen uint64) []byte {
	in := make([]byte, ModeByte+MLDSA65PublicKeySize+MessageLenSize)
	in[0] = ModeMLDSA65
	at := ModeByte + MLDSA65PublicKeySize
	for i := range 8 {
		in[at+31-i] = byte(msgLen >> (i * 8))
	}
	return in
}

// No reachable branch of RequiredGas is free -- not the unknown mode, not
// the empty call, not the truncated batch header. An unmetered branch is a
// path an attacker can hammer for the cost of the CALL alone.
func TestGas_EveryBranchCharges(t *testing.T) {
	inputs := map[string][]byte{
		"nil":                  nil,
		"empty":                {},
		"mode only":            {ModeMLDSA44},
		"batch header partial": {OpBatchVerify, ModeMLDSA44},
		"batch empty":          {OpBatchVerify, ModeMLDSA44, 0x00, 0x00},
	}
	for m := range 256 {
		inputs["mode byte"] = []byte{byte(m)}
		require.NotZerof(t, MLDSAVerifyPrecompile.RequiredGas(inputs["mode byte"]),
			"mode 0x%02x is an unmetered branch", m)
	}
	for name, in := range inputs {
		require.NotZerof(t, MLDSAVerifyPrecompile.RequiredGas(in), "%s is an unmetered branch", name)
	}
}

// More security level, more verification work, more gas.
func TestGas_RisesWithSecurityLevel(t *testing.T) {
	fee := func(mode uint8) uint64 {
		return MLDSAVerifyPrecompile.RequiredGas([]byte{mode})
	}
	require.Less(t, fee(ModeMLDSA44), fee(ModeMLDSA65))
	require.Less(t, fee(ModeMLDSA65), fee(ModeMLDSA87))
}

// The fee is base + len*k and actually rises with the declared length.
func TestGas_RisesWithMessageLength(t *testing.T) {
	prev := uint64(0)
	for _, n := range []uint64{0, 1, 2, 32, 1024, 1_000_000} {
		got := MLDSAVerifyPrecompile.RequiredGas(frameWithDeclaredLength(n))
		require.Equal(t, MLDSA65VerifyBaseGas+n*MLDSAVerifyPerByteGas, got, "declared length %d", n)
		if n > 0 {
			require.Greaterf(t, got, prev, "declared length %d did not cost more than %d", n, n-1)
		}
		prev = got
	}
}

// The per-byte term is multiplied by an attacker-chosen 256-bit field, so
// the product must not wrap. At the last length that fits, the fee is still
// the honest sum; one byte further, it saturates instead of becoming small.
func TestGas_LengthCannotWrapTheFee(t *testing.T) {
	limit := (math.MaxUint64 - MLDSA65VerifyBaseGas) / MLDSAVerifyPerByteGas

	atLimit := MLDSAVerifyPrecompile.RequiredGas(frameWithDeclaredLength(limit))
	require.Equal(t, MLDSA65VerifyBaseGas+limit*MLDSAVerifyPerByteGas, atLimit)
	require.Greater(t, atLimit, MLDSA65VerifyBaseGas, "the fee wrapped at the limit")

	for _, over := range []uint64{limit + 1, limit + 2, math.MaxUint64 / 2, math.MaxUint64} {
		require.Equalf(t, uint64(math.MaxUint64),
			MLDSAVerifyPrecompile.RequiredGas(frameWithDeclaredLength(over)),
			"declared length %d wrapped instead of saturating", over)
	}

	// Saturation is not decorative: no caller can pay it, so the call dies
	// at the meter rather than reaching the parser.
	in := frameWithDeclaredLength(math.MaxUint64)
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		in, math.MaxUint64-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

// A batch charges per signature, and charging per signature is the point:
// N in one call must cost less than N calls, or nobody would batch.
func TestGas_BatchRisesWithCountAndBeatsSingles(t *testing.T) {
	fee := func(count int) uint64 {
		return MLDSAVerifyPrecompile.RequiredGas(
			[]byte{OpBatchVerify, ModeMLDSA44, byte(count >> 8), byte(count)})
	}
	require.Equal(t, BatchVerifyBaseGas, fee(0))

	prev := fee(0)
	for _, n := range []int{1, 2, 10, 255, 256, 4096, 65535} {
		got := fee(n)
		require.Equal(t, BatchVerifyBaseGas+uint64(n)*BatchVerifyPerSigGas, got, "count %d", n)
		require.Greaterf(t, got, prev, "count %d did not cost more than the count before it", n)
		prev = got
	}

	single := MLDSAVerifyPrecompile.RequiredGas([]byte{ModeMLDSA44})
	for _, n := range []int{2, 10, 65535} {
		require.Lessf(t, fee(n), uint64(n)*single, "a batch of %d costs more than %d singles", n, n)
	}

	// The count field is a uint16, so the widest batch is 65535 and the fee
	// cannot approach a uint64 wrap.
	require.Less(t, fee(65535), uint64(math.MaxUint64)/2)
}

// The quoted fee is what gets consumed, and one unit short is refused.
func TestGas_QuotedFeeIsCharged(t *testing.T) {
	msg := []byte("charge me")
	pk, sig, _ := createTestSignature(t, mldsa.MLDSA44, msg)
	in := createInputWithMode(ModeMLDSA44, pk, sig, msg)
	fee := MLDSAVerifyPrecompile.RequiredGas(in)
	require.Equal(t, MLDSA44VerifyBaseGas+uint64(len(msg))*MLDSAVerifyPerByteGas, fee)

	_, remaining, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		in, fee-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, err = MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress,
		in, fee+11, true)
	require.NoError(t, err)
	require.Equal(t, uint64(11), remaining)
}

// Refused input still consumes its fee: the caller does not get the gas
// back for handing the node something unparseable.
func TestGas_RefusalConsumesTheFee(t *testing.T) {
	for name, in := range map[string][]byte{
		"unknown mode": {0xFF},
		"mode only":    {ModeMLDSA44},
		"batch header": {OpBatchVerify, ModeMLDSA44},
	} {
		fee := MLDSAVerifyPrecompile.RequiredGas(in)
		_, remaining, err := MLDSAVerifyPrecompile.Run(nil, common.Address{},
			ContractMLDSAVerifyAddress, in, fee+3, true)
		require.Errorf(t, err, "%s", name)
		require.Equalf(t, uint64(3), remaining, "%s: fee not consumed on refusal", name)
	}
}
