// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Fee accrual, asserted EXACTLY rather than by consequence.
//
// The fee accumulators are Q128.128 fixed point. A one-unit error in them is
// 2^-128 of a token, so it is invisible to every payout assertion: converting it
// back through MulDiv(growth, L, Q128) floors to zero for any liquidity the
// uint128 cap allows. Behaviour tests therefore cannot see a rounding flip here.
// The only honest way to pin the direction is to assert the accumulator itself
// against the same composed dex call the contract makes.
package v3

import (
	"math/big"
	"testing"

	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

// TestFeeGrowthAccrual_IsExactAndRoundsDown pins the swap loop's accrual to the
// wei: feeGrowthGlobal must advance by exactly MulDiv(feeAmount, Q128, liquidity)
// — the round-DOWN quotient. Rounding it up would credit LPs fractionally more
// growth than the fee that was actually collected, every step of every swap.
func TestFeeGrowthAccrual_IsExactAndRoundsDown(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	poolId := poolIdOf(stdPool)
	L := e18x1000
	_, _, err := e.mint(trader, stdPool, -6000, 6000, L, false)
	require.NoError(t, err)

	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
	size := mustBig("1000000000000000") // 1e15, small enough to stay in range

	// Move the price OFF the tick-0 boundary first. Starting exactly on an aligned
	// tick costs the loop a zero-amount priming step; from here the next swap is a
	// single iteration, which is what makes the replay below exact.
	_, _, err = e.swap(trader, stdPool, true, new(big.Int).Neg(size), limit)
	require.NoError(t, err)

	// The loop's inputs for the one step that is about to run.
	sqrtBefore := loadSqrtPrice(e.db(), poolId)
	liqBefore := loadLiquidity(e.db(), poolId)
	fg0Before := loadFeeGrowthGlobal0(e.db(), poolId)
	eqBig(t, L, liqBefore)

	tickBefore := loadPoolTick(e.db(), poolId)
	tickNext, initialized := nextInitializedTick(e.db(), poolId, tickBefore, stdPool.tickSpacing, true)
	require.True(t, initialized, "the fixture must have a real boundary below")
	target, err := dex.GetSqrtRatioAtTick(tickNext)
	require.NoError(t, err)
	require.Truef(t, target.Cmp(limit) > 0, "the boundary must be nearer than the price limit")

	want := dex.ComputeSwapStep(sqrtBefore, target, liqBefore, new(big.Int).Neg(size), stdPool.fee)
	require.True(t, want.FeeAmount.Sign() > 0, "the step must actually charge a fee")

	_, rem, err := e.callRaw(trader, inSwap(stdPool, true, new(big.Int).Neg(size), limit), plentyGas, false)
	require.NoError(t, err)
	require.EqualValues(t, 1, swapSteps(t, plentyGas, rem), "the replay is only exact for a single-step swap")

	// The accrual, to the unit.
	growth := sub256(loadFeeGrowthGlobal0(e.db(), poolId), fg0Before)
	eqBig(t, dex.MulDiv(want.FeeAmount, dex.Q128, liqBefore), growth)

	// And it leans DOWN: the growth, valued back at the pool's own liquidity, can
	// never exceed the fee the pool actually took in.
	valued := dex.MulDiv(growth, liqBefore, dex.Q128)
	require.Truef(t, valued.Cmp(want.FeeAmount) <= 0,
		"accrued growth worth %s exceeds the %s fee collected", valued, want.FeeAmount)

	// The token1 accumulator is untouched: fees accrue to the INPUT side only.
	eqBig(t, big.NewInt(0), loadFeeGrowthGlobal1(e.db(), poolId))
}

// TestFeeGrowthAccrual_OtherDirectionAccruesToToken1 is the mirror: a oneForZero
// swap pays its fee in currency1, so only that accumulator may move.
func TestFeeGrowthAccrual_OtherDirectionAccruesToToken1(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	poolId := poolIdOf(stdPool)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)

	limit := new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))
	size := mustBig("1000000000000000")
	_, _, err = e.swap(trader, stdPool, false, new(big.Int).Neg(size), limit)
	require.NoError(t, err)

	sqrtBefore := loadSqrtPrice(e.db(), poolId)
	liqBefore := loadLiquidity(e.db(), poolId)
	fg1Before := loadFeeGrowthGlobal1(e.db(), poolId)
	fg0Before := loadFeeGrowthGlobal0(e.db(), poolId)

	tickBefore := loadPoolTick(e.db(), poolId)
	tickNext, initialized := nextInitializedTick(e.db(), poolId, tickBefore, stdPool.tickSpacing, false)
	require.True(t, initialized)
	target, err := dex.GetSqrtRatioAtTick(tickNext)
	require.NoError(t, err)
	require.True(t, target.Cmp(limit) < 0)

	want := dex.ComputeSwapStep(sqrtBefore, target, liqBefore, new(big.Int).Neg(size), stdPool.fee)
	require.True(t, want.FeeAmount.Sign() > 0)

	_, rem, err := e.callRaw(trader, inSwap(stdPool, false, new(big.Int).Neg(size), limit), plentyGas, false)
	require.NoError(t, err)
	require.EqualValues(t, 1, swapSteps(t, plentyGas, rem))

	eqBig(t, dex.MulDiv(want.FeeAmount, dex.Q128, liqBefore),
		sub256(loadFeeGrowthGlobal1(e.db(), poolId), fg1Before))
	eqBig(t, fg0Before, loadFeeGrowthGlobal0(e.db(), poolId))
}

// TestFeeGrowthAccrual_SkippedWhenNoLiquidity proves a step with no active
// liquidity accrues nothing — there is nobody to pay, and dividing by zero
// liquidity is the alternative.
func TestFeeGrowthAccrual_SkippedWhenNoLiquidity(t *testing.T) {
	e := soloPool(t)
	poolId := poolIdOf(stdPool)

	// Drain past every position, then read the accumulator.
	_, _, err := e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("500000000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), e.liquidityOf(stdPool))
	drained := loadFeeGrowthGlobal0(e.db(), poolId)

	// A further swap that stays INSIDE the empty band moves the price but must
	// accrue nothing: no liquidity, no fee, no growth. The limit stops short of
	// the deepest position so the price never re-enters a live range.
	stillEmpty, err := dex.GetSqrtRatioAtTick(-3000)
	require.NoError(t, err)
	_, _, err = e.swap(trader, stdPool, false, new(big.Int).Neg(oneE18), stillEmpty)
	require.NoError(t, err)

	after, tick := e.slot0(stdPool)
	eqBig(t, stillEmpty, after)
	require.Equal(t, int32(-3000), tick, "the price moved, so this is not a no-op swap")
	eqBig(t, big.NewInt(0), e.liquidityOf(stdPool))
	eqBig(t, drained, loadFeeGrowthGlobal0(e.db(), poolId))
	eqBig(t, big.NewInt(0), loadFeeGrowthGlobal1(e.db(), poolId))
}

// ---------------------------------------------------------------------------
// The range-membership convention.
// ---------------------------------------------------------------------------

// TestFeeGrowthInside_BoundaryConvention pins which side of a tick range is
// inclusive. V3 defines a position as in range for currentTick in
// [tickLower, tickUpper): the LOWER bound is inclusive and the UPPER exclusive.
//
// The two comparisons only differ from their neighbours when the current tick
// sits exactly ON a boundary, and the difference is which term the fee growth
// gets subtracted from. Getting it wrong mispays fees without breaking any
// conservation check — the pool stays solvent while paying the wrong LPs — so it
// is asserted here directly, with hand-set accumulators, rather than inferred.
func TestFeeGrowthInside_BoundaryConvention(t *testing.T) {
	poolId := poolIdOf(stdPool)
	const lower, upper int32 = 0, 600

	// A pool with global growth 1000/2000, and boundaries carrying a recorded
	// "outside" of 300/700 on the lower tick and 100/200 on the upper.
	newState := func() *mockState {
		m := newMockState()
		lo := dex.NewTickInfo()
		lo.LiquidityGross = oneE18
		lo.FeeGrowthOutside0X128 = big.NewInt(300)
		lo.FeeGrowthOutside1X128 = big.NewInt(700)
		storeTickInfo(m, poolId, lower, lo)

		hi := dex.NewTickInfo()
		hi.LiquidityGross = oneE18
		hi.FeeGrowthOutside0X128 = big.NewInt(100)
		hi.FeeGrowthOutside1X128 = big.NewInt(200)
		storeTickInfo(m, poolId, upper, hi)
		return m
	}
	fg0, fg1 := big.NewInt(1000), big.NewInt(2000)

	// AT the lower bound the position IS in range: growth below the range is the
	// tick's recorded outside value, taken as-is.
	//   inside0 = 1000 - 300 - 100 = 600
	in0, in1 := getFeeGrowthInside(newState(), poolId, lower, upper, lower, fg0, fg1)
	eqBig(t, big.NewInt(600), in0)
	eqBig(t, big.NewInt(1100), in1) // 2000 - 700 - 200

	// One tick BELOW the range the position is not in range, and "below" flips to
	// the complement: 1000 - (1000-300) - 100 = 200.
	in0, in1 = getFeeGrowthInside(newState(), poolId, lower, upper, lower-1, fg0, fg1)
	eqBig(t, big.NewInt(200), in0)
	eqBig(t, big.NewInt(500), in1) // 2000 - 1300 - 200

	// AT the upper bound the position is NOT in range: "above" flips to the
	// complement. 1000 - 300 - (1000-100) = -200 mod 2^256.
	in0, in1 = getFeeGrowthInside(newState(), poolId, lower, upper, upper, fg0, fg1)
	eqBig(t, sub256(big.NewInt(0), big.NewInt(200)), in0)
	eqBig(t, sub256(big.NewInt(0), big.NewInt(500)), in1)

	// One tick BELOW the upper bound it is still in range, and "above" is taken
	// as-is: 1000 - 300 - 100 = 600, the same as at the lower bound.
	in0, in1 = getFeeGrowthInside(newState(), poolId, lower, upper, upper-1, fg0, fg1)
	eqBig(t, big.NewInt(600), in0)
	eqBig(t, big.NewInt(1100), in1)

	// The two boundaries are asymmetric by design, and that asymmetry is the
	// property under test: at the lower tick the range is live, at the upper it is
	// not, so the two must NOT agree.
	atLower, _ := getFeeGrowthInside(newState(), poolId, lower, upper, lower, fg0, fg1)
	atUpper, _ := getFeeGrowthInside(newState(), poolId, lower, upper, upper, fg0, fg1)
	require.NotEqualf(t, atLower.String(), atUpper.String(),
		"the lower bound is inclusive and the upper exclusive; they cannot agree")
}

// TestActiveLiquidity_BoundaryConvention is the same convention as the pool sees
// it: a position starting AT the current tick counts toward active liquidity, one
// ending at it does not. This is the invariant the swap loop's crossing arithmetic
// has to agree with, and it is checked through the real entry points.
func TestActiveLiquidity_BoundaryConvention(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, tick := e.slot0(stdPool)
	require.Equal(t, int32(0), tick)

	// Lower bound == current tick: ACTIVE.
	_, _, err := e.mint(trader, stdPool, 0, 600, oneE18, false)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))

	// Upper bound == current tick: NOT active.
	_, _, err = e.mint(trader, stdPool, -600, 0, oneE18, false)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))

	// Removing the inactive one leaves the active total untouched.
	_, _, err = e.burn(trader, stdPool, -600, 0, oneE18)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))

	// Removing the active one drops it to zero.
	_, _, err = e.burn(trader, stdPool, 0, 600, oneE18)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), e.liquidityOf(stdPool))
}

// TestCrossTick_RoundTripRestoresTheAccumulator pins that crossing a boundary
// COMPLEMENTS its feeGrowthOutside rather than overwriting it.
//
// feeGrowthOutside(t) means "growth on the far side of t from the current
// price", so crossing t must reflect it: outside = global − outside. Overwriting
// it with the global instead looks right after ONE crossing (the accumulator
// starts at zero, and global − 0 == global) and is only wrong from the second
// crossing on. So the invariant is stated as a round trip: cross a boundary and
// cross back, and the accumulator for the token that saw no trading in between
// must return to exactly where it started.
func TestCrossTick_RoundTripRestoresTheAccumulator(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	poolId := poolIdOf(stdPool)
	const boundary int32 = -600

	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)
	// The boundary has to belong to a real position, or the swap walks past it
	// without ever calling crossTick.
	_, _, err = e.mint(trader, stdPool, boundary, 600, oneE18, false)
	require.NoError(t, err)

	// The boundary starts clean.
	eqBig(t, big.NewInt(0), loadTickInfo(e.db(), poolId, boundary).FeeGrowthOutside0X128)

	// Down to EXACTLY the boundary price. Stopping on it crosses the tick and ends
	// the loop in the same step, so no further token0 fee accrues afterwards and
	// the accumulator can be read at the moment of the crossing.
	atBoundary, err := dex.GetSqrtRatioAtTick(boundary)
	require.NoError(t, err)
	_, _, err = e.swap(trader, stdPool, true, new(big.Int).Neg(mustBig("500000000000000000000")), atBoundary)
	require.NoError(t, err)

	_, tick := e.slot0(stdPool)
	require.Lessf(t, tick, boundary, "the fixture must cross %d, stopped at %d", boundary, tick)

	fg0AtCross := loadFeeGrowthGlobal0(e.db(), poolId)
	require.True(t, fg0AtCross.Sign() > 0, "the downward leg must accrue a token0 fee")
	// One crossing: outside0 is the complement of zero, i.e. the whole global.
	eqBig(t, fg0AtCross, loadTickInfo(e.db(), poolId, boundary).FeeGrowthOutside0X128)

	// Back up across the same boundary. An upward swap pays its fee in token1, so
	// the token0 global must not move.
	justAbove, err := dex.GetSqrtRatioAtTick(boundary + 60)
	require.NoError(t, err)
	_, _, err = e.swap(trader, stdPool, false, new(big.Int).Neg(mustBig("500000000000000000000")), justAbove)
	require.NoError(t, err)

	_, tick = e.slot0(stdPool)
	require.GreaterOrEqualf(t, tick, boundary, "the fixture must cross back over %d, stopped at %d", boundary, tick)
	eqBig(t, fg0AtCross, loadFeeGrowthGlobal0(e.db(), poolId))

	// The second crossing complements it back to zero. Overwriting would leave the
	// whole global sitting there and mispay every position that spans this tick.
	eqBig(t, big.NewInt(0), loadTickInfo(e.db(), poolId, boundary).FeeGrowthOutside0X128)

	// The token1 accumulator, which DID see trading, is non-zero — proving the
	// round trip above is a real one and not a pair of no-op swaps.
	require.True(t, loadFeeGrowthGlobal1(e.db(), poolId).Sign() > 0)
	assertCustodyConsistent(t, e)
}

// TestUpdateTick_FirstReferenceConvention pins which side of a newly initialized
// boundary the growth-so-far is attributed to. V3's convention: when a tick is
// first referenced, all growth to date counts as being BELOW it if the tick is at
// or below the current tick, and as being above it otherwise.
//
// The value is part of the ABI — ticks() returns it — so it is asserted directly.
// It has to be: the convention is self-cancelling inside getFeeGrowthInside (the
// same figure enters the "below" and "above" terms and subtracts out), so no
// payout assertion can distinguish the two sides.
func TestUpdateTick_FirstReferenceConvention(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	poolId := poolIdOf(stdPool)

	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)
	// Trade so there is a non-zero growth to attribute, and leave the price inside
	// [-600, 600] so the new boundaries below sit on known sides of it.
	_, _, err = e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("1000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	fg0 := loadFeeGrowthGlobal0(e.db(), poolId)
	require.True(t, fg0.Sign() > 0, "the fixture must accrue before the new ticks exist")
	_, cur := e.slot0(stdPool)
	require.True(t, cur < 0 && cur > -600, "fixture tick %d must sit between the two boundaries", cur)

	// Boundaries straddling the current tick, both brand new.
	_, _, err = e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	// AT OR BELOW the current tick: the growth so far is recorded as "outside"
	// (i.e. below).
	_, _, below0, _ := ticksView(t, e, stdPool, -600)
	eqBig(t, fg0, below0)

	// ABOVE the current tick: nothing is attributed, so it stays zero.
	_, _, above0, _ := ticksView(t, e, stdPool, 600)
	eqBig(t, big.NewInt(0), above0)

	// The two sides genuinely differ — that asymmetry IS the convention.
	require.NotEqualf(t, below0.String(), above0.String(),
		"a boundary below the price and one above it must not record the same growth")

	// A boundary exactly AT the current tick counts as at-or-below.
	aligned := (cur / 60) * 60
	if aligned > cur {
		aligned -= 60
	}
	require.LessOrEqual(t, aligned, cur)
	_, _, err = e.mint(trader, stdPool, aligned, 6000, oneE18, false)
	require.NoError(t, err)
	_, _, at0, _ := ticksView(t, e, stdPool, aligned)
	eqBig(t, fg0, at0)
}
