// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// The read views, and the fee accounting they expose. A view that lies is worse
// than a view that is missing, so each one is checked against the state the
// mutators actually wrote rather than against a recorded sample.
package v3

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

// ticksView decodes the four words the ticks() selector returns.
func ticksView(t *testing.T, e *env, p poolCfg, tick int32) (gross, net, out0, out1 *big.Int) {
	t.Helper()
	ret, _, err := e.callRaw(trader, inTicks(p, tick), plentyGas, true)
	require.NoError(t, err)
	require.Len(t, ret, 128)
	return wordToUint(common.BytesToHash(ret[0:32])),
		wordToInt(common.BytesToHash(ret[32:64])),
		wordToUint(common.BytesToHash(ret[64:96])),
		wordToUint(common.BytesToHash(ret[96:128]))
}

// TestTicksView proves ticks() reports the boundary state a mint actually wrote:
// gross liquidity on both boundaries, and a liquidityNet that is POSITIVE on the
// lower tick and NEGATIVE on the upper — the sign convention the swap loop
// depends on to add liquidity going up and remove it going down.
func TestTicksView(t *testing.T) {
	e := fundedEnv(e18x1000)

	// An untouched tick reads as all zeros rather than failing.
	gross, net, out0, out1 := ticksView(t, e, stdPool, 12000)
	eqBig(t, big.NewInt(0), gross)
	eqBig(t, big.NewInt(0), net)
	eqBig(t, big.NewInt(0), out0)
	eqBig(t, big.NewInt(0), out1)

	L := oneE18
	_, _, err := e.mint(trader, stdPool, -600, 600, L, false)
	require.NoError(t, err)

	gross, net, _, _ = ticksView(t, e, stdPool, -600)
	eqBig(t, L, gross)
	eqBig(t, L, net)
	require.True(t, net.Sign() > 0, "the LOWER boundary adds liquidity when crossed upward")

	gross, net, _, _ = ticksView(t, e, stdPool, 600)
	eqBig(t, L, gross)
	eqBig(t, new(big.Int).Neg(L), net)
	require.True(t, net.Sign() < 0, "the UPPER boundary removes liquidity when crossed upward")

	// A second position sharing the lower boundary accumulates gross and net.
	_, _, err = e.mint(trader, stdPool, -600, 1200, L, false)
	require.NoError(t, err)
	gross, net, _, _ = ticksView(t, e, stdPool, -600)
	eqBig(t, new(big.Int).Mul(L, big.NewInt(2)), gross)
	eqBig(t, new(big.Int).Mul(L, big.NewInt(2)), net)

	// A boundary shared as LOWER by one position and UPPER by another has gross
	// from both but a net that cancels — the case the swap loop must get right.
	_, _, err = e.mint(trader, stdPool, -1200, -600, L, false)
	require.NoError(t, err)
	gross, net, _, _ = ticksView(t, e, stdPool, -600)
	eqBig(t, new(big.Int).Mul(L, big.NewInt(3)), gross)
	eqBig(t, L, net) // 2L (two lowers) - L (one upper)
}

// TestTicksView_ClearedOnFullBurn proves a boundary that flips back to
// uninitialized is ZEROED, so a stale feeGrowthOutside cannot leak into a future
// position that happens to reuse the tick.
func TestTicksView_ClearedOnFullBurn(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)
	_, _, err = e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	// Trade far enough to CROSS tick -600: a boundary only accumulates a non-zero
	// feeGrowthOutside once the price has actually passed through it.
	_, _, err = e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("50000000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)
	_, crossedTo := e.slot0(stdPool)
	require.Lessf(t, crossedTo, int32(-600), "the fixture must cross tick -600, stopped at %d", crossedTo)

	gross, _, out0, _ := ticksView(t, e, stdPool, -600)
	require.True(t, gross.Sign() > 0)
	require.True(t, out0.Sign() > 0, "crossing a boundary must record its feeGrowthOutside")

	// Burning the position entirely flips the boundary and must wipe it.
	_, _, err = e.burn(trader, stdPool, -600, 600, oneE18)
	require.NoError(t, err)
	gross, net, out0, out1 := ticksView(t, e, stdPool, -600)
	eqBig(t, big.NewInt(0), gross)
	eqBig(t, big.NewInt(0), net)
	eqBig(t, big.NewInt(0), out0)
	eqBig(t, big.NewInt(0), out1)
}

// TestSlot0AndLiquidityViews prove the two scalar views track the mutators. The
// interesting case is a position that is NOT in range: it must not change the
// pool's active liquidity, because active liquidity is what prices a swap.
func TestSlot0AndLiquidityViews(t *testing.T) {
	e := fundedEnv(e18x1000)

	sp, tick := e.slot0(stdPool)
	eqBig(t, dex.Q96, sp)
	require.Equal(t, int32(0), tick)
	eqBig(t, big.NewInt(0), e.liquidityOf(stdPool))

	// In range: active liquidity rises.
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))

	// Entirely ABOVE the price: no change to active liquidity.
	_, _, err = e.mint(trader, stdPool, 600, 1200, oneE18, false)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))

	// Entirely BELOW the price: also no change.
	_, _, err = e.mint(trader, stdPool, -1200, -600, oneE18, false)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))

	// The lower boundary is INCLUSIVE and the upper EXCLUSIVE (currentTick >=
	// lower && currentTick < upper), so a position starting exactly at the current
	// tick is active and one ENDING there is not.
	_, _, err = e.mint(trader, stdPool, 0, 600, oneE18, false)
	require.NoError(t, err)
	eqBig(t, new(big.Int).Mul(oneE18, big.NewInt(2)), e.liquidityOf(stdPool))

	_, _, err = e.mint(trader, stdPool, -600, 0, oneE18, false)
	require.NoError(t, err)
	eqBig(t, new(big.Int).Mul(oneE18, big.NewInt(2)), e.liquidityOf(stdPool))

	// A view of a pool that was never initialized reads as zero, not an error.
	empty := poolCfg{c0: tokenA, c1: tokenC, fee: 3000, tickSpacing: 60}
	sp, tick = e.slot0(empty)
	eqBig(t, big.NewInt(0), sp)
	require.Equal(t, int32(0), tick)
	eqBig(t, big.NewInt(0), e.liquidityOf(empty))
}

// TestPositionsView proves positions() reports the caller's own position and that
// positions are keyed by (owner, lower, upper) — one owner's state must never be
// visible under another's key.
func TestPositionsView(t *testing.T) {
	e := fundedEnv(e18x1000)
	other := common.HexToAddress("0x000000000000000000000000000000000000d00d")
	e.db().fund(tokenA, other, e18x1000)
	e.db().fund(tokenB, other, e18x1000)

	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)
	_, _, err = e.mint(other, stdPool, -600, 600, new(big.Int).Mul(oneE18, big.NewInt(3)), false)
	require.NoError(t, err)

	mine, owed0, owed1 := e.positionOf(trader, stdPool, -600, 600)
	eqBig(t, oneE18, mine)
	eqBig(t, big.NewInt(0), owed0)
	eqBig(t, big.NewInt(0), owed1)

	theirs, _, _ := e.positionOf(other, stdPool, -600, 600)
	eqBig(t, new(big.Int).Mul(oneE18, big.NewInt(3)), theirs)

	// A different range under the same owner is a different position.
	none, _, _ := e.positionOf(trader, stdPool, -1200, 1200)
	eqBig(t, big.NewInt(0), none)

	// An owner who never minted has nothing.
	stranger, _, _ := e.positionOf(common.HexToAddress("0xbeef"), stdPool, -600, 600)
	eqBig(t, big.NewInt(0), stranger)
}

// ---------------------------------------------------------------------------
// Fee growth: who earns, and who does not.
// ---------------------------------------------------------------------------

// TestFeeGrowth_OnlyInRangeLiquidityEarns is the property that makes
// concentrated liquidity work at all: a swap pays fees only to the positions that
// were actually in range while it happened. A position sitting entirely above or
// below the traded band must earn NOTHING, or LPs could farm fees without ever
// taking price risk.
func TestFeeGrowth_OnlyInRangeLiquidityEarns(t *testing.T) {
	e := fundedEnv(e18x1000)

	// Three positions: one spanning the price, one strictly above, one strictly
	// below. Only the first is in range at tick 0.
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)
	_, _, err = e.mint(trader, stdPool, 1200, 2400, oneE18, false)
	require.NoError(t, err)
	_, _, err = e.mint(trader, stdPool, -2400, -1200, oneE18, false)
	require.NoError(t, err)

	// A small swap that stays well inside [-600, 600].
	_, _, err = e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("1000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	// Burn zero-cost: burn 1 wei of each position to force a fee settlement, then
	// read what each was owed beyond its principal.
	inRange0, inRange1 := feesEarned(t, e, -600, 600)
	above0, above1 := feesEarned(t, e, 1200, 2400)
	below0, below1 := feesEarned(t, e, -2400, -1200)

	require.True(t, inRange0.Sign() > 0, "the in-range position must earn the token0 fee")
	eqBig(t, big.NewInt(0), inRange1) // the swap was token0-in, so no token1 fee

	eqBig(t, big.NewInt(0), above0)
	eqBig(t, big.NewInt(0), above1)
	eqBig(t, big.NewInt(0), below0)
	eqBig(t, big.NewInt(0), below1)
	assertCustodyConsistent(t, e)
}

// feesEarned settles a position's accrued fees by burning nothing of substance
// and returns what it was credited beyond principal. Burning 1 wei of liquidity
// returns 0 principal at these sizes, so what lands in tokensOwed is fee.
func feesEarned(t *testing.T, e *env, lower, upper int32) (fee0, fee1 *big.Int) {
	t.Helper()
	before0, before1 := owedOf(e, lower, upper)
	p0, p1, err := e.burn(trader, stdPool, lower, upper, big.NewInt(1))
	require.NoError(t, err)
	after0, after1 := owedOf(e, lower, upper)
	fee0 = new(big.Int).Sub(new(big.Int).Sub(after0, before0), p0)
	fee1 = new(big.Int).Sub(new(big.Int).Sub(after1, before1), p1)
	return fee0, fee1
}

func owedOf(e *env, lower, upper int32) (*big.Int, *big.Int) {
	_, o0, o1 := e.positionOf(trader, stdPool, lower, upper)
	return o0, o1
}

// TestFeeGrowth_SharedProRata proves two positions covering the same range over
// the same trade are paid in proportion to their liquidity — the accrual is per
// unit of liquidity, not per position.
func TestFeeGrowth_SharedProRata(t *testing.T) {
	e := fundedEnv(e18x1000)
	other := common.HexToAddress("0x000000000000000000000000000000000000f00d")
	e.db().fund(tokenA, other, e18x1000)
	e.db().fund(tokenB, other, e18x1000)

	small := mustBig("1000000000000000000") // 1e18
	large := mustBig("3000000000000000000") // 3e18, exactly 3x
	_, _, err := e.mint(trader, stdPool, -600, 600, small, false)
	require.NoError(t, err)
	_, _, err = e.mint(other, stdPool, -600, 600, large, false)
	require.NoError(t, err)

	_, _, err = e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("100000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	// Settle both by burning everything; owed then holds principal + fee.
	burnSmall0, _, err := e.burn(trader, stdPool, -600, 600, small)
	require.NoError(t, err)
	burnLarge0, _, err := e.burnAs(other, stdPool, -600, 600, large)
	require.NoError(t, err)

	owedSmall0, _, _ := positionOwed(e, trader, -600, 600)
	owedLarge0, _, _ := positionOwed(e, other, -600, 600)
	feeSmall := new(big.Int).Sub(owedSmall0, burnSmall0)
	feeLarge := new(big.Int).Sub(owedLarge0, burnLarge0)

	require.True(t, feeSmall.Sign() > 0 && feeLarge.Sign() > 0, "both positions must earn")

	// 3x the liquidity earns 3x the fee, to within a wei of integer division.
	want := new(big.Int).Mul(feeSmall, big.NewInt(3))
	diff := new(big.Int).Abs(new(big.Int).Sub(feeLarge, want))
	require.Truef(t, diff.Cmp(big.NewInt(4)) <= 0,
		"fees must be pro rata: 1x earned %s, 3x earned %s", feeSmall, feeLarge)

	// The pool never owes more than it holds.
	totalOwed := new(big.Int).Add(owedSmall0, owedLarge0)
	require.Truef(t, totalOwed.Cmp(e.reserve(tokenA)) <= 0,
		"owed %s exceeds the %s held", totalOwed, e.reserve(tokenA))
}

// burnAs is burn for an arbitrary caller (the base helper hard-codes its caller
// into the ABI blob but takes the caller as an argument; this names the intent).
func (e *env) burnAs(caller common.Address, p poolCfg, lower, upper int32, amount *big.Int) (*big.Int, *big.Int, error) {
	return e.burn(caller, p, lower, upper, amount)
}

func positionOwed(e *env, owner common.Address, lower, upper int32) (*big.Int, *big.Int, *big.Int) {
	l, o0, o1 := e.positionOf(owner, stdPool, lower, upper)
	return o0, o1, l
}

// TestFeeGrowthInside_AllFourQuadrants drives getFeeGrowthInside through every
// combination of the two comparisons it makes (current tick at or above the
// lower bound; current tick below the upper bound). Each quadrant is a different
// arm of the "growth below" / "growth above" subtraction, and getting one wrong
// mispays fees without ever tripping a conservation check.
func TestFeeGrowthInside_AllFourQuadrants(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	poolId := poolIdOf(stdPool)

	// Materialise the four ranges FIRST. A range only earns from trades that
	// happen after it exists, so creating them before the swaps is what makes the
	// "inside" figure non-zero at all.
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)
	for _, r := range [][2]int32{{-3000, -1200}, {-1200, 1200}, {1200, 3000}, {-3000, 3000}} {
		_, _, err := e.mint(trader, stdPool, r[0], r[1], oneE18, false)
		require.NoError(t, err)
	}

	// Now trade both ways, staying INSIDE [-1200, 1200] so no boundary is crossed
	// and the four quadrants stay in the configuration the test names.
	_, _, err = e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("100000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)
	_, _, err = e.swap(trader, stdPool, false,
		new(big.Int).Neg(mustBig("100000000000000000")),
		new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	fg0 := loadFeeGrowthGlobal0(e.db(), poolId)
	fg1 := loadFeeGrowthGlobal1(e.db(), poolId)
	require.True(t, fg0.Sign() > 0 && fg1.Sign() > 0, "the fixture must accrue on both tokens")

	_, cur := e.slot0(stdPool)

	// Quadrant A: current tick INSIDE the range (>= lower, < upper).
	require.True(t, cur > -1200 && cur < 1200, "fixture tick %d must sit inside", cur)
	inA0, inA1 := getFeeGrowthInside(e.db(), poolId, -1200, 1200, cur, fg0, fg1)
	require.True(t, inA0.Sign() > 0, "a range containing the traded band must show growth")

	// Quadrant B: current tick BELOW the range (< lower, < upper).
	inB0, inB1 := getFeeGrowthInside(e.db(), poolId, 1200, 3000, cur, fg0, fg1)

	// Quadrant C: current tick ABOVE the range (>= lower, >= upper).
	inC0, inC1 := getFeeGrowthInside(e.db(), poolId, -3000, -1200, cur, fg0, fg1)

	// Quadrant D: a wider range that also contains the tick.
	inD0, inD1 := getFeeGrowthInside(e.db(), poolId, -3000, 3000, cur, fg0, fg1)

	// Every result is a 256-bit value; none may exceed the global accumulator when
	// interpreted as a true (small) growth.
	for name, v := range map[string]*big.Int{
		"A0": inA0, "A1": inA1, "B0": inB0, "B1": inB1,
		"C0": inC0, "C1": inC1, "D0": inD0, "D1": inD1,
	} {
		require.Truef(t, v.Sign() >= 0, "%s must be a non-negative 256-bit value", name)
		require.Truef(t, v.Cmp(two256) < 0, "%s must stay inside 2^256", name)
	}

	// Growth inside a range that CONTAINS the traded band cannot exceed the global
	// growth, and a wider containing range sees at least as much as a narrower one.
	require.Truef(t, inA0.Cmp(fg0) <= 0, "inside %s must not exceed global %s", inA0, fg0)
	require.Truef(t, inD0.Cmp(inA0) >= 0, "the wider range must see at least as much growth")

	// Ranges the price never entered saw no growth of their own.
	eqBig(t, big.NewInt(0), inB0)
	eqBig(t, big.NewInt(0), inC0)
	eqBig(t, big.NewInt(0), inB1)
	eqBig(t, big.NewInt(0), inC1)
}

// TestFeeGrowthWrapsWithoutLoss proves the accumulators are read modulo 2^256, so
// a global counter that has wrapped past the top still yields the true (small)
// growth for a position. Uniswap relies on this `unchecked` arithmetic; a naive
// signed subtraction here would hand a position an astronomically large fee.
func TestFeeGrowthWrapsWithoutLoss(t *testing.T) {
	m := newMockState()
	poolId := poolIdOf(stdPool)
	nearTop := new(big.Int).Sub(two256, big.NewInt(1000))

	// A global accumulator that has wrapped: it started near the top and is now a
	// small number, having passed 2^256.
	wrapped := big.NewInt(500)
	storeFeeGrowthGlobal0(m, poolId, wrapped)

	// A tick whose feeGrowthOutside was recorded BEFORE the wrap.
	info := dex.NewTickInfo()
	info.LiquidityGross = oneE18
	info.FeeGrowthOutside0X128 = nearTop
	storeTickInfo(m, poolId, -600, info)
	storeTickInfo(m, poolId, 600, dex.NewTickInfo())

	inside0, _ := getFeeGrowthInside(m, poolId, -600, 600, 0, wrapped, big.NewInt(0))

	// The true growth since that tick was recorded is 1000 + 500 = 1500, recovered
	// exactly by the modular subtraction — not a ~2^256 number.
	eqBig(t, big.NewInt(1500), inside0)
	require.Truef(t, inside0.Cmp(big.NewInt(1<<20)) < 0,
		"a wrapped accumulator must not read as an astronomical fee: got %s", inside0)
}

// ---------------------------------------------------------------------------
// collect(): the pay-out cap.
// ---------------------------------------------------------------------------

// TestCollect_CapsAtOwed proves collect pays min(requested, owed) on each leg
// independently. Both arms of that minimum matter: taking the request when it is
// larger would pay out tokens the position never earned.
func TestCollect_CapsAtOwed(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)
	burn0, burn1, err := e.burn(trader, stdPool, -600, 600, oneE18)
	require.NoError(t, err)
	require.True(t, burn0.Sign() > 0 && burn1.Sign() > 0)

	// Ask for LESS than owed on leg 0 and MORE than owed on leg 1: the first arm
	// of the minimum on one leg, the second arm on the other, in one call.
	part := big.NewInt(1000)
	over := new(big.Int).Mul(burn1, big.NewInt(1000))
	got0, got1, err := e.collect(trader, stdPool, -600, 600, part, over)
	require.NoError(t, err)
	eqBig(t, part, got0)  // capped by the REQUEST
	eqBig(t, burn1, got1) // capped by what is OWED

	// The remainder is still there, and a second call drains it exactly.
	_, owed0, owed1 := e.positionOf(trader, stdPool, -600, 600)
	eqBig(t, new(big.Int).Sub(burn0, part), owed0)
	eqBig(t, big.NewInt(0), owed1)

	maxU := new(big.Int).Set(maxUint128)
	rest0, rest1, err := e.collect(trader, stdPool, -600, 600, maxU, maxU)
	require.NoError(t, err)
	eqBig(t, new(big.Int).Sub(burn0, part), rest0)
	eqBig(t, big.NewInt(0), rest1)

	// Nothing left; a third collect is a clean no-op that moves no value.
	balBefore := e.db().bal(tokenA, trader)
	again0, again1, err := e.collect(trader, stdPool, -600, 600, maxU, maxU)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), again0)
	eqBig(t, big.NewInt(0), again1)
	eqBig(t, balBefore, e.db().bal(tokenA, trader))
	assertCustodyConsistent(t, e)
}

// TestCollect_OnEmptyPositionIsHarmless proves collect on a position that never
// existed — and on a pool that was never initialized — pays nothing and touches
// nothing. collect does not check pool existence, so this pins that the absence
// of that check is harmless: with no owed balance there is nothing to pay.
func TestCollect_OnEmptyPositionIsHarmless(t *testing.T) {
	e := newEnv()
	maxU := new(big.Int).Set(maxUint128)
	ghost := poolCfg{c0: tokenA, c1: tokenC, fee: 3000, tickSpacing: 60}

	got0, got1, err := e.collect(trader, ghost, -600, 600, maxU, maxU)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), got0)
	eqBig(t, big.NewInt(0), got1)
	eqBig(t, big.NewInt(0), e.reserve(tokenA))
	eqBig(t, big.NewInt(0), e.reserve(tokenC))
	require.Empty(t, e.db().tokens, "a collect on nothing must move no tokens")
}

// TestBigMin covers the helper's two arms directly, including equality, and pins
// that it returns a COPY — an aliased result would let a later mutation of the
// return value corrupt a position's stored owed balance.
func TestBigMin(t *testing.T) {
	a, b := big.NewInt(5), big.NewInt(9)
	eqBig(t, a, bigMin(a, b))
	eqBig(t, a, bigMin(b, a))
	eqBig(t, a, bigMin(a, a))

	// Equality takes the first arm and still copies.
	got := bigMin(a, b)
	got.SetInt64(999)
	eqBig(t, big.NewInt(5), a)
	require.NotSame(t, a, bigMin(a, b))
	require.NotSame(t, b, bigMin(b, a))
}

// TestModularWordCodecs pins the signed/unsigned word boundary the whole ABI
// rests on: a tick of -1 must encode as the all-ones word and read back as -1,
// not as 2^256-1.
func TestModularWordCodecs(t *testing.T) {
	for _, v := range []int64{0, 1, -1, 60, -60, 887272, -887272} {
		w := intWord(big.NewInt(v))
		eqBig(t, big.NewInt(v), wordToInt(w))
	}

	// The unsigned reading of -1 is the top of the range: the two codecs are
	// genuinely different views of the same 32 bytes.
	minusOne := intWord(big.NewInt(-1))
	eqBig(t, new(big.Int).Sub(two256, big.NewInt(1)), wordToUint(minusOne))

	// Round trip at the unsigned top.
	top := new(big.Int).Sub(two256, big.NewInt(1))
	eqBig(t, top, wordToUint(uintWord(top)))

	// add256/sub256 wrap rather than growing without bound.
	eqBig(t, big.NewInt(0), add256(top, big.NewInt(1)))
	eqBig(t, top, sub256(big.NewInt(0), big.NewInt(1)))
}
