// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// The edges each entry point shares but reaches by its own line: the pool-key
// decode, the second tick word, the second settlement leg, and the two ends of
// the price band the swap loop clamps against.
package v3

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

// badKey is a well-formed 128-byte pool key that violates currency ordering. It
// has the RIGHT LENGTH, so it gets past each selector's size check and dies in
// the shared decoder — the path a length check alone would not exercise.
var badKey = poolCfg{c0: tokenB, c1: tokenA, fee: 3000, tickSpacing: 60}

// TestPoolKeyRefusedInEverySelector proves the decode guard is on all nine entry
// points, not just the ones with an obvious test. Each call is exactly the right
// length, so only the key itself can refuse it.
func TestPoolKeyRefusedInEverySelector(t *testing.T) {
	e := fundedEnv(e18x1000)
	maxU := new(big.Int).Set(maxUint128)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	for name, call := range map[string]struct {
		in       []byte
		readOnly bool
	}{
		"initialize": {inInitialize(badKey, dex.Q96), false},
		"mint":       {inMint(badKey, -600, 600, oneE18), false},
		"burn":       {inBurn(badKey, -600, 600, oneE18), false},
		"collect":    {inCollect(badKey, -600, 600, maxU, maxU), false},
		"swap":       {inSwap(badKey, true, new(big.Int).Neg(oneE18), limit), false},
		"slot0":      {inSlot0(badKey), true},
		"liquidity":  {inLiquidity(badKey), true},
		"ticks":      {inTicks(badKey, 0), true},
		"positions":  {inPositions(badKey, trader, -600, 600), true},
	} {
		_, _, err := e.callRaw(trader, call.in, plentyGas, call.readOnly)
		require.ErrorIsf(t, err, ErrCurrencyOrder, "%s must refuse an unsorted pool key", name)
	}
}

// TestBadTickWordRefusedOnBothSides walks the SECOND tick word of burn and
// collect. Each selector decodes two ticks through separate calls, so a guard on
// one says nothing about the other.
func TestBadTickWordRefusedOnBothSides(t *testing.T) {
	e := fundedEnv(e18x1000)
	evil := rawWord(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(60)))

	// burn, upper tick.
	burn := append(selBytes(selBurn), stdPool.words()...)
	burn = append(burn, tickWord(-600)...)
	burn = append(burn, evil...)
	burn = append(burn, uintArg(oneE18)...)
	_, _, err := e.callRaw(trader, burn, plentyGas, false)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)

	// collect, upper tick.
	coll := append(selBytes(selCollect), stdPool.words()...)
	coll = append(coll, tickWord(-600)...)
	coll = append(coll, evil...)
	coll = append(coll, uintArg(big.NewInt(1))...)
	coll = append(coll, uintArg(big.NewInt(1))...)
	_, _, err = e.callRaw(trader, coll, plentyGas, false)
	require.ErrorIs(t, err, dex.ErrTickOutOfRange)
}

// TestCollect_SecondLegFailureSurfaces proves collect reports a failure on the
// CURRENCY1 leg, not just currency0. Both legs pay independently, so a guard
// tested only on the first proves nothing about the second.
func TestCollect_SecondLegFailureSurfaces(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	poolId := poolIdOf(stdPool)
	posKey := dex.PositionKey(trader, -600, 600, salt)
	pos := loadPosition(e.db(), poolId, posKey)

	// Leg 0 is payable; leg 1 claims more than the vault can actually deliver.
	pos.TokensOwed0 = big.NewInt(1)
	inflated := new(big.Int).Add(e.reserve(tokenB), oneE18)
	pos.TokensOwed1 = inflated
	storePosition(e.db(), poolId, posKey, pos)
	storeReserve(e.db(), tokenB, inflated)

	_, _, err = e.collect(trader, stdPool, -600, 600, big.NewInt(1), inflated)
	require.ErrorIs(t, err, ErrTransferFailed, "a failure on the second leg must surface")
}

// TestCollect_SecondLegReserveUnderflowSurfaces is the same leg, refused one step
// earlier: the ledger says the payout is not backed.
func TestCollect_SecondLegReserveUnderflowSurfaces(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	poolId := poolIdOf(stdPool)
	posKey := dex.PositionKey(trader, -600, 600, salt)
	pos := loadPosition(e.db(), poolId, posKey)
	pos.TokensOwed0 = big.NewInt(1)
	pos.TokensOwed1 = new(big.Int).Add(e.reserve(tokenB), big.NewInt(1)) // one wei unbacked
	storePosition(e.db(), poolId, posKey, pos)

	_, _, err = e.collect(trader, stdPool, -600, 600, big.NewInt(1), pos.TokensOwed1)
	require.ErrorIs(t, err, ErrReserveUnderflow)
}

// TestSwap_UnfundedCallerRefusedAtSettlement proves the swap's inbound leg is a
// real transfer: a caller who cannot pay is refused at settlement rather than
// being handed the output on credit.
func TestSwap_UnfundedCallerRefusedAtSettlement(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)

	pauper := common.HexToAddress("0x0000000000000000000000000000000000000bad")
	poolBBefore := e.db().bal(tokenB, v3Addr)

	_, _, err = e.swap(pauper, stdPool, true,
		new(big.Int).Neg(mustBig("1000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.ErrorIs(t, err, ErrTransferFailed)

	// The output leg never ran: the pauper got nothing and the pool lost nothing.
	eqBig(t, big.NewInt(0), e.db().bal(tokenB, pauper))
	eqBig(t, poolBBefore, e.db().bal(tokenB, v3Addr))
}

// TestSwap_UnfundedCallerOnTheOtherDirection is the same refusal for oneForZero,
// where the inbound asset is currency1.
func TestSwap_UnfundedCallerOnTheOtherDirection(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)

	pauper := common.HexToAddress("0x0000000000000000000000000000000000000bad")
	_, _, err = e.swap(pauper, stdPool, false,
		new(big.Int).Neg(mustBig("1000000000000000")),
		new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1)))
	require.ErrorIs(t, err, ErrTransferFailed)
	eqBig(t, big.NewInt(0), e.db().bal(tokenA, pauper))
}

// ---------------------------------------------------------------------------
// Both ends of the price band.
// ---------------------------------------------------------------------------

// soloPool is one position over [-1920, 1920] on a well-funded pool: no
// overlapping ranges, so it drains cleanly to either extreme and the swap loop
// can be walked all the way to a band edge.
func soloPool(t *testing.T) *env {
	t.Helper()
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	_, _, err := e.mint(trader, stdPool, -1920, 1920, mustBig("100000000000000000000"), false)
	require.NoError(t, err)
	return e
}

// TestSwap_WalksToTheBottomOfTheBand drives the loop down past every position
// until the price sits on MIN_SQRT_RATIO's doorstep. The tick-bitmap search
// returns whole-word boundaries, which below the deepest word lie BELOW MinTick,
// so the loop's lower clamp is what keeps the tick math in its domain.
func TestSwap_WalksToTheBottomOfTheBand(t *testing.T) {
	e := soloPool(t)
	floor := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	_, a1, err := e.swap(trader, stdPool, true, new(big.Int).Neg(mustBig("500000000000000000000")), floor)
	require.NoError(t, err)
	require.True(t, new(big.Int).Neg(a1).Sign() > 0, "the drain must pay out token1")

	price, tick := e.slot0(stdPool)
	eqBig(t, floor, price)
	require.Equal(t, dex.MinTick, tick, "the tick must clamp to MIN_TICK, not run past it")
	require.Zerof(t, e.liquidityOf(stdPool).Sign(),
		"every position is behind the price now, active liquidity must be 0, got %s", e.liquidityOf(stdPool))
	assertCustodyConsistent(t, e)

	// The pool kept everything it was owed and paid out no more than it held.
	require.True(t, e.reserve(tokenB).Sign() >= 0)
}

// TestSwap_WalksToTheTopOfTheBand is the mirror image: the upper clamp, and the
// oneForZero arm of the tick update on a crossing (going up, the pool's tick
// becomes the boundary itself rather than one below it).
func TestSwap_WalksToTheTopOfTheBand(t *testing.T) {
	e := soloPool(t)
	ceiling := new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))

	a0, _, err := e.swap(trader, stdPool, false, new(big.Int).Neg(mustBig("500000000000000000000")), ceiling)
	require.NoError(t, err)
	require.True(t, new(big.Int).Neg(a0).Sign() > 0, "the drain must pay out token0")

	price, tick := e.slot0(stdPool)
	eqBig(t, ceiling, price)
	require.Equal(t, dex.MaxTick-1, tick, "the tick must clamp inside the band")
	eqBig(t, big.NewInt(0), e.liquidityOf(stdPool))
	assertCustodyConsistent(t, e)
	require.True(t, e.reserve(tokenA).Sign() >= 0)
}

// TestSwap_CrossesInitializedTickUpward proves the upward crossing arm: an
// initialized boundary above the price must ADD its liquidity when the price
// passes it, mirroring TestPool_CrossTick's downward case.
func TestSwap_CrossesInitializedTickUpward(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))

	// Wide base plus a band that only becomes active above tick 600.
	_, _, err := e.mint(trader, stdPool, -6000, 6000, oneE18, false)
	require.NoError(t, err)
	_, _, err = e.mint(trader, stdPool, 600, 1200, new(big.Int).Mul(oneE18, big.NewInt(5)), false)
	require.NoError(t, err)

	before := e.liquidityOf(stdPool)
	eqBig(t, oneE18, before) // only the wide position is active at tick 0

	// Push the price up past 600 but stop before 1200, so the band is active.
	limit, err := dex.GetSqrtRatioAtTick(900)
	require.NoError(t, err)
	_, _, err = e.swap(trader, stdPool, false, new(big.Int).Neg(mustBig("10000000000000000000")), limit)
	require.NoError(t, err)

	_, tick := e.slot0(stdPool)
	require.Greaterf(t, tick, int32(600), "the swap must cross tick 600 upward, stopped at %d", tick)
	require.Less(t, tick, int32(1200))

	after := e.liquidityOf(stdPool)
	require.Truef(t, after.Cmp(before) > 0, "crossing upward into a band must ADD liquidity: %s !> %s", after, before)
	eqBig(t, new(big.Int).Mul(oneE18, big.NewInt(6)), after)
	assertCustodyConsistent(t, e)

	// And coming back down deactivates it again — the crossing is symmetric.
	backLimit, err := dex.GetSqrtRatioAtTick(0)
	require.NoError(t, err)
	_, _, err = e.swap(trader, stdPool, true, new(big.Int).Neg(mustBig("10000000000000000000")), backLimit)
	require.NoError(t, err)
	eqBig(t, oneE18, e.liquidityOf(stdPool))
	assertCustodyConsistent(t, e)
}

// TestSwap_ExactlyOnABoundaryStartsThere pins the loop's first iteration when the
// price sits precisely on an initialized tick: the step does no economic work,
// crosses the boundary, and steps the tick — it must not stall.
func TestSwap_ExactlyOnABoundaryStartsThere(t *testing.T) {
	e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)
	// A boundary exactly at the current tick.
	_, _, err = e.mint(trader, stdPool, -600, 0, oneE18, false)
	require.NoError(t, err)

	price, tick := e.slot0(stdPool)
	eqBig(t, dex.Q96, price)
	require.Equal(t, int32(0), tick)

	// Going down from exactly tick 0 crosses the boundary at 0 immediately.
	_, _, err = e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("1000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	_, after := e.slot0(stdPool)
	require.Less(t, after, int32(0))
	// The [-600, 0] band is now active, so liquidity went UP.
	eqBig(t, new(big.Int).Add(e18x1000, oneE18), e.liquidityOf(stdPool))
	assertCustodyConsistent(t, e)
}
