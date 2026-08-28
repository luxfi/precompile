// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronathreshold

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// gasInputForParties builds a minimal well-formed header declaring
// `parties` in the n field. The signature body is absent; only the
// header matters to the gas function.
func gasInputForParties(parties uint32) []byte {
	input := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(input[0:ThresholdSize], 1)
	binary.BigEndian.PutUint32(input[ThresholdSize:ThresholdSize+TotalPartiesSize], parties)
	return input
}

// TestGasCapsDeclaredParties is the regression for the uncapped
// per-party gas multiplier. `n` is read straight out of attacker-
// controlled calldata; before the fix a declared n = 2^32-1 billed
// 4.29e13 gas, six orders of magnitude past any block gas limit, so
// the call could never be paid for and the quoted fee bore no
// relation to the work performed. Both siblings (frost, cggmp21)
// already clamped; corona did not.
//
// The assertion is a refusal, not a magic number: past the cap the
// cost function must stop growing, and it must stay inside a single
// block's gas budget.
func TestGasCapsDeclaredParties(t *testing.T) {
	const blockGasLimit = 12_000_000 // C-Chain block budget

	atCap := CoronaThresholdGasCost(gasInputForParties(MaxBilledParties))
	require.Less(t, atCap, uint64(blockGasLimit),
		"cost at the cap must fit in one block")

	for _, n := range []uint32{
		MaxBilledParties + 1,
		MaxBilledParties * 2,
		1 << 20,
		math.MaxUint32 / 2,
		math.MaxUint32 - 1,
		math.MaxUint32,
	} {
		got := CoronaThresholdGasCost(gasInputForParties(n))
		require.Equal(t, atCap, got,
			"declared n=%d must bill the same as the cap: cost stops growing past %d", n, MaxBilledParties)
	}
}

// TestGasStrictlyMonotoneBelowCap pins the other half of the cap:
// clamping must not flatten the schedule for realistic committee
// sizes. Every extra declared party below the cap costs exactly
// CoronaThresholdPerPartyGas more.
func TestGasStrictlyMonotoneBelowCap(t *testing.T) {
	prev := CoronaThresholdGasCost(gasInputForParties(0))
	require.Equal(t, CoronaThresholdBaseGas, prev, "n=0 bills base only")

	for n := uint32(1); n <= MaxBilledParties; n++ {
		got := CoronaThresholdGasCost(gasInputForParties(n))
		require.Equal(t, prev+CoronaThresholdPerPartyGas, got,
			"n=%d must cost exactly one per-party step more than n=%d", n, n-1)
		prev = got
	}
}

// TestGasNeverWraps guards the other failure mode of an unchecked
// multiply: a product that wraps uint64 would make the precompile
// *cheaper* than its base for adversarial input. Cost must never dip
// below base, at any declared n.
func TestGasNeverWraps(t *testing.T) {
	for _, n := range []uint32{0, 1, 1000, 1 << 16, math.MaxUint32} {
		require.GreaterOrEqual(t, CoronaThresholdGasCost(gasInputForParties(n)), CoronaThresholdBaseGas,
			"n=%d must never bill below base", n)
	}
}

// TestEstimateGasMatchesCharge is the divergence guard. EstimateGas is
// the public quoting API (eth_estimateGas paths, off-chain fee
// preview); CoronaThresholdGasCost is what the EVM actually deducts.
// If a cap lands in one and not the other, callers are quoted a fee
// the chain will not charge — an estimator that over-quotes strands
// funds, one that under-quotes reverts mid-block. They must agree for
// every declared n, including past the cap.
func TestEstimateGasMatchesCharge(t *testing.T) {
	for _, n := range []uint32{0, 1, 2, 3, 5, 10, 999, MaxBilledParties, MaxBilledParties + 1, 1 << 20, math.MaxUint32} {
		require.Equal(t, EstimateGas(n), CoronaThresholdGasCost(gasInputForParties(n)),
			"quote and charge must agree at n=%d", n)
	}
}

// TestGasShortInputBillsBase pins the sub-header branch: an input too
// short to carry an n field bills base, never zero. A zero-gas arm
// would be a free-call spam vector.
func TestGasShortInputBillsBase(t *testing.T) {
	for _, size := range []int{0, 1, ThresholdSize, MinInputSize - 1} {
		got := CoronaThresholdGasCost(make([]byte, size))
		require.Equal(t, CoronaThresholdBaseGas, got, "len=%d bills base", size)
		require.NotZero(t, got, "len=%d must not be a free call", size)
	}
	require.Equal(t, CoronaThresholdBaseGas, CoronaThresholdPrecompile.RequiredGas(nil),
		"nil input bills base")

	// The loop above cannot see the header gate on its own: its inputs are
	// all zero, so the party count reads as 0 and EstimateGas(0) IS the
	// base. Removing the gate entirely left every assertion above passing.
	// A truncated header must declare a count the cost function would
	// otherwise charge for, or nothing is being held to anything.
	for _, size := range []int{ThresholdSize + TotalPartiesSize, MinInputSize - 1} {
		loud := contract.Poisoned(gasInputForParties(MaxBilledParties)[:size], 256)
		require.Equal(t, CoronaThresholdBaseGas, CoronaThresholdGasCost(loud),
			"a %d-byte header declaring %d parties still bills base: the count is "+
				"only consulted once the header is whole", size, MaxBilledParties)
	}

	// And the first whole header does charge for it, so the gate is a
	// boundary rather than a floor.
	whole := contract.Poisoned(gasInputForParties(MaxBilledParties), 256)
	require.Equal(t, EstimateGas(MaxBilledParties), CoronaThresholdGasCost(whole),
		"a whole %d-byte header bills the declared count", MinInputSize)
	require.Greater(t, CoronaThresholdGasCost(whole), CoronaThresholdBaseGas)
}

// TestRunChargesTheQuotedCost closes the loop through Run: the gas the
// cost function quotes is exactly the gas Run deducts, and one wei
// less than that is refused. Without this, a cap in RequiredGas that
// Run ignored would go unnoticed.
func TestRunChargesTheQuotedCost(t *testing.T) {
	input := gasInputForParties(math.MaxUint32)
	cost := CoronaThresholdPrecompile.RequiredGas(input)

	// Exactly enough: Run proceeds past the meter (and then fails the
	// body-length check, which is fine — we are measuring the meter).
	_, remaining, err := CoronaThresholdPrecompile.Run(
		nil, common.Address{}, CoronaThresholdPrecompile.Address(), input, cost, true)
	require.Error(t, err, "header-only input has no signature body")
	require.Zero(t, remaining, "exact payment leaves nothing")

	// One short: refused by the meter before any parsing.
	_, remaining, err = CoronaThresholdPrecompile.Run(
		nil, common.Address{}, CoronaThresholdPrecompile.Address(), input, cost-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	// Surplus is returned intact.
	_, remaining, err = CoronaThresholdPrecompile.Run(
		nil, common.Address{}, CoronaThresholdPrecompile.Address(), input, cost+777, true)
	require.Error(t, err)
	require.Equal(t, uint64(777), remaining, "unused gas is returned")
}
