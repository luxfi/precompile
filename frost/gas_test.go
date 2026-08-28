// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// clamp is MaxBilledSigners as a run-time value. Written as constant
// expressions, `MaxBilledSigners+1` and `MaxBilledSigners*2` stop COMPILING
// the moment the clamp is widened towards 2^32 -- which would hide a widened
// clamp behind a build error instead of surfacing it as a test failure.
var clamp = MaxBilledSigners

// gasFor quotes the fee for a declared signer count, over an otherwise
// well-formed envelope.
func gasFor(n uint32) uint64 {
	input := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(input[0:4], 1)
	binary.BigEndian.PutUint32(input[4:8], n)
	return FROSTVerifyGasCost(input)
}

// TestFROST_GasClamped: the declared signer count is attacker-chosen, so the
// fee must stop rising at MaxBilledSigners. Every count at or above the clamp
// bills exactly what the clamp bills -- including MaxUint32, where an
// unclamped schedule would quote 21 trillion gas.
func TestFROST_GasClamped(t *testing.T) {
	atCap := gasFor(clamp)
	for _, n := range []uint32{clamp, clamp + 1, clamp * 2, 2000, 1 << 20, math.MaxUint32 - 1, math.MaxUint32} {
		require.Equal(t, atCap, gasFor(n),
			"n=%d must bill exactly what the clamp bills", n)
	}
}

// TestFROST_GasClampIsPayable: a clamp that clamps to an unpayable number is
// no clamp at all. The worst case a caller can quote must fit inside a block,
// which is the whole reason the clamp exists.
func TestFROST_GasClampIsPayable(t *testing.T) {
	const blockCeiling = 30_000_000 // a conventional block gas limit
	require.LessOrEqual(t, gasFor(math.MaxUint32), uint64(blockCeiling),
		"the worst case a caller can quote must fit in a block")
}

// TestFROST_GasStrictlyMonotonicBelowClamp: below the clamp each additional
// declared signer costs exactly one per-signer unit, and never less. A
// non-monotonic or flat schedule below the clamp would mean the clamp is in
// the wrong place or the multiply was dropped.
func TestFROST_GasStrictlyMonotonicBelowClamp(t *testing.T) {
	prev := gasFor(0)
	require.Equal(t, FROSTVerifyBaseGas, prev, "zero declared signers bills base")
	// Sweep every count up to the clamp, but never more than a bounded number
	// of them: a widened clamp must fail this test, not hang it.
	limit := min(clamp, 4096)
	for n := uint32(1); n <= limit; n++ {
		got := gasFor(n)
		require.Greater(t, got, prev, "fee must strictly increase at n=%d", n)
		require.Equal(t, prev+FROSTVerifyPerSignerGas, got,
			"each signer below the clamp costs exactly one per-signer unit (n=%d)", n)
		prev = got
	}
	// One past the clamp the increments stop.
	require.Equal(t, prev, gasFor(clamp+1))
}

// TestFROST_GasNeverBelowBase: no declared count -- and no input length --
// may produce a fee under the base cost or a zero fee. A wrapped multiply
// would show up here as a cheap call for adversarial calldata.
func TestFROST_GasNeverBelowBase(t *testing.T) {
	for _, n := range []uint32{0, 1, clamp - 1, clamp, clamp + 1, math.MaxUint32} {
		got := gasFor(n)
		require.GreaterOrEqual(t, got, FROSTVerifyBaseGas, "n=%d dipped below base", n)
		require.NotZero(t, got, "n=%d billed nothing", n)
	}
}

// TestFROST_GasShortInputBillsBase: calldata too short to carry a signer
// count is billed at base -- never zero (which would make malformed calls
// free) and never more (there is no count to read).
func TestFROST_GasShortInputBillsBase(t *testing.T) {
	for _, size := range []int{0, 1, 7, 8, MinInputSize - 1} {
		got := FROSTVerifyGasCost(make([]byte, size))
		require.Equal(t, FROSTVerifyBaseGas, got, "len=%d must bill base", size)
		require.NotZero(t, got, "len=%d must not be free", size)
	}
	require.Equal(t, FROSTVerifyBaseGas, FROSTVerifyGasCost(nil), "nil calldata must bill base")
	// The boundary: one byte more and the count is read.
	full := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(full[4:8], 5)
	require.Equal(t, FROSTVerifyBaseGas+5*FROSTVerifyPerSignerGas, FROSTVerifyGasCost(full),
		"at exactly MinInputSize the declared count is billed")
}

// TestFROST_RequiredGasMatchesCostFunction: the method an EVM calls and the
// function an off-chain estimator calls must be the same number, for every
// shape of calldata. Two cost functions that can disagree is a consensus bug
// waiting to happen.
func TestFROST_RequiredGasMatchesCostFunction(t *testing.T) {
	for _, size := range []int{0, 8, MinInputSize - 1, MinInputSize, MinInputSize + 64} {
		input := make([]byte, size)
		if size >= 8 {
			binary.BigEndian.PutUint32(input[4:8], math.MaxUint32)
		}
		require.Equal(t, FROSTVerifyGasCost(input), FROSTVerifyPrecompile.RequiredGas(input),
			"len=%d: RequiredGas and FROSTVerifyGasCost disagree", size)
	}
}

// TestFROST_GasDeductedExactly: a call supplied with exactly the quote must
// succeed with nothing left, and one wei short must fail. This is what binds
// the quote to the deduction.
func TestFROST_GasDeductedExactly(t *testing.T) {
	pk, mh, sig := katVector(t)
	input := buildFrostInput(3, 5, pk, mh, sig)
	quote := FROSTVerifyPrecompile.RequiredGas(input)

	_, rem, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, quote, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), rem)

	_, rem, err = FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, quote+7, true)
	require.NoError(t, err)
	require.Equal(t, uint64(7), rem)

	_, _, err = FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, quote-1, true)
	require.Error(t, err, "one wei short of the quote must be refused")
}
