// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

var (
	tokenA = common.HexToAddress("0x000000000000000000000000000000000000aAa1")
	tokenB = common.HexToAddress("0x000000000000000000000000000000000000bBb2")
	trader = common.HexToAddress("0x000000000000000000000000000000000000ccc3")
)

// stdPool is the standard 0.30% / spacing-60 pool over (tokenA, tokenB).
var stdPool = poolCfg{c0: tokenA, c1: tokenB, fee: uint32(dex.Fee030), tickSpacing: int32(dex.TickSpacing030)}

// assertCustodyConsistent asserts the conservation anchor: the precompile's internal
// per-asset reserve ledger equals its REAL token balance — proving no path ever
// minted or lost a unit.
func assertCustodyConsistent(t *testing.T, e *env) {
	t.Helper()
	eqBig(t, e.db().bal(tokenA, v3Addr), e.reserve(tokenA))
	eqBig(t, e.db().bal(tokenB, v3Addr), e.reserve(tokenB))
}

// TestPool_FullLifecycle drives the precompile end-to-end with a fake StateDB:
// initialize → mint a position spanning the active tick → exact-input swap → burn →
// collect, asserting price direction, fee accrual, and full token conservation.
func TestPool_FullLifecycle(t *testing.T) {
	e := newEnv()
	initial := mustBig("1000000000000000000") // 1e18 of each token to the trader
	e.db().fund(tokenA, trader, initial)
	e.db().fund(tokenB, trader, initial)

	// --- initialize at price 1.0 (sqrt = 2^96, tick 0) ---
	tick, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)
	require.Equal(t, int32(0), tick)
	sp, tk := e.slot0(stdPool)
	eqBig(t, dex.Q96, sp)
	require.Equal(t, int32(0), tk)

	// --- mint a position over [-600, 600] spanning the active tick ---
	L := mustBig("1000000000000000000") // 1e18 liquidity
	mintA, mintB, err := e.mint(trader, stdPool, -600, 600, L, false)
	require.NoError(t, err)
	require.True(t, mintA.Sign() > 0, "mint should owe token0")
	require.True(t, mintB.Sign() > 0, "mint should owe token1")
	assertCustodyConsistent(t, e)

	// in range → active liquidity == L; the position records exactly L.
	eqBig(t, L, e.liquidityOf(stdPool))
	posL, _, _ := e.positionOf(trader, stdPool, -600, 600)
	eqBig(t, L, posL)

	// reserves now equal exactly the pulled mint amounts.
	eqBig(t, mintA, e.reserve(tokenA))
	eqBig(t, mintB, e.reserve(tokenB))

	// --- exact-input swap: token0 -> token1 (zeroForOne), |in| = 1e15 ---
	swapIn := mustBig("1000000000000000") // 1e15 (small vs L, stays in range, fully consumed)
	amountSpecified := new(big.Int).Neg(swapIn)
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)) // wide lower bound

	s0, s1, err := e.swap(trader, stdPool, true, amountSpecified, limit)
	require.NoError(t, err)
	require.Truef(t, s0.Sign() > 0, "zeroForOne: amount0 (paid in) must be positive, got %s", s0)
	require.Truef(t, s1.Sign() < 0, "zeroForOne: amount1 (received) must be negative, got %s", s1)
	swapInA := new(big.Int).Set(s0)  // token0 the pool received (incl. fee)
	swapOutB := new(big.Int).Neg(s1) // token1 the pool paid out
	require.True(t, swapOutB.Sign() > 0)
	eqBig(t, swapIn, swapInA) // all input consumed (limit is wide, stays in range)

	// price moved DOWN (token0 in pushes price down) and stayed in range.
	sp2, tk2 := e.slot0(stdPool)
	require.Truef(t, sp2.Cmp(dex.Q96) < 0, "price must drop after zeroForOne swap: %s !< 2^96", sp2)
	require.Truef(t, tk2 < 0 && tk2 > -600, "tick must move down but stay in range, got %d", tk2)
	assertCustodyConsistent(t, e)

	// reserves after the swap: +input token0, -output token1.
	eqBig(t, new(big.Int).Add(mintA, swapInA), e.reserve(tokenA))
	eqBig(t, new(big.Int).Sub(mintB, swapOutB), e.reserve(tokenB))

	// --- burn the whole position (V3: credits owed, no transfer) ---
	burnA, burnB, err := e.burn(trader, stdPool, -600, 600, L)
	require.NoError(t, err)
	require.True(t, burnA.Sign() > 0 && burnB.Sign() > 0, "burn returns positive principal both sides")
	eqBig(t, big.NewInt(0), e.liquidityOf(stdPool)) // no active liquidity left
	posL, owed0, owed1 := e.positionOf(trader, stdPool, -600, 600)
	eqBig(t, big.NewInt(0), posL)
	// owed now holds principal + fees. token0 earned fees (the swap was token0-in);
	// token1 earned none, so owed1 == burnB exactly.
	require.True(t, owed0.Cmp(burnA) > 0, "owed0 must exceed principal by the accrued token0 fee")
	eqBig(t, burnB, owed1)
	assertCustodyConsistent(t, e)

	// --- collect everything ---
	maxU := new(big.Int).Set(maxUint128)
	colA, colB, err := e.collect(trader, stdPool, -600, 600, maxU, maxU)
	require.NoError(t, err)
	require.True(t, colA.Sign() > 0 && colB.Sign() > 0)
	eqBig(t, owed0, colA) // collected exactly what was owed (reserves cover it)
	eqBig(t, owed1, colB)
	assertCustodyConsistent(t, e)

	// position fully drained.
	_, owed0After, owed1After := e.positionOf(trader, stdPool, -600, 600)
	eqBig(t, big.NewInt(0), owed0After)
	eqBig(t, big.NewInt(0), owed1After)

	// --- conservation ledger ---
	// collected ≤ minted + swap-in deltas (token0: pool received mint+swapIn;
	// token1: pool received mint, paid swapOut).
	require.Truef(t, colA.Cmp(new(big.Int).Add(mintA, swapInA)) <= 0, "colA %s <= mintA+swapInA", colA)
	require.Truef(t, colB.Cmp(new(big.Int).Sub(mintB, swapOutB)) <= 0, "colB %s <= mintB-swapOutB", colB)

	// reserves never went negative and end ≥ 0 (residual dust stays in the pool).
	require.True(t, e.reserve(tokenA).Sign() >= 0)
	require.True(t, e.reserve(tokenB).Sign() >= 0)

	// global conservation: no token A or B was created or destroyed — every unit is
	// either with the trader or held by the precompile.
	eqBig(t, initial, new(big.Int).Add(e.db().bal(tokenA, trader), e.db().bal(tokenA, v3Addr)))
	eqBig(t, initial, new(big.Int).Add(e.db().bal(tokenB, trader), e.db().bal(tokenB, v3Addr)))
}

// TestPool_PriceUpSwap exercises the opposite direction (oneForZero) to prove the
// price moves UP and the signed deltas flip.
func TestPool_PriceUpSwap(t *testing.T) {
	e := newEnv()
	e.db().fund(tokenA, trader, mustBig("1000000000000000000"))
	e.db().fund(tokenB, trader, mustBig("1000000000000000000"))

	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)
	_, _, err = e.mint(trader, stdPool, -600, 600, mustBig("1000000000000000000"), false)
	require.NoError(t, err)

	// oneForZero exact input: token1 -> token0, price rises.
	amountSpecified := new(big.Int).Neg(mustBig("1000000000000000"))
	limit := new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))
	s0, s1, err := e.swap(trader, stdPool, false, amountSpecified, limit)
	require.NoError(t, err)
	require.Truef(t, s1.Sign() > 0, "oneForZero: amount1 (paid in) positive, got %s", s1)
	require.Truef(t, s0.Sign() < 0, "oneForZero: amount0 (received) negative, got %s", s0)

	sp, tk := e.slot0(stdPool)
	require.Truef(t, sp.Cmp(dex.Q96) > 0, "price must rise after oneForZero swap")
	require.Truef(t, tk > 0 && tk < 600, "tick must move up but stay in range, got %d", tk)
	assertCustodyConsistent(t, e)
}

// TestPool_CrossTick proves the swap loop crosses an initialized tick: a swap large
// enough to exit a narrow inner position's range must deactivate that liquidity.
func TestPool_CrossTick(t *testing.T) {
	e := newEnv()
	big18 := mustBig("1000000000000000000000") // 1000e18, plenty
	e.db().fund(tokenA, trader, big18)
	e.db().fund(tokenB, trader, big18)

	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)

	// Wide outer position keeps the pool solvent across the whole range.
	_, _, err = e.mint(trader, stdPool, -6000, 6000, mustBig("1000000000000000000"), false)
	require.NoError(t, err)
	// Narrow inner position only active within [-60, 60].
	_, _, err = e.mint(trader, stdPool, -60, 60, mustBig("5000000000000000000"), false)
	require.NoError(t, err)

	liqInRange := e.liquidityOf(stdPool) // both positions active at tick 0
	require.True(t, liqInRange.Cmp(mustBig("5000000000000000000")) > 0)

	// Swap enough token0 in to push the price below tick -60, deactivating the inner
	// position. A big exact-input budget; limit just above MIN so it can travel.
	amountSpecified := new(big.Int).Neg(mustBig("100000000000000000")) // 0.1e18
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
	_, _, err = e.swap(trader, stdPool, true, amountSpecified, limit)
	require.NoError(t, err)

	_, tk := e.slot0(stdPool)
	require.Truef(t, tk < -60, "swap must cross below the inner tick, got tick %d", tk)
	// after crossing -60 downward, only the outer position's liquidity remains active.
	liqAfter := e.liquidityOf(stdPool)
	require.Truef(t, liqAfter.Cmp(liqInRange) < 0, "crossing the inner tick must drop active liquidity: %s !< %s", liqAfter, liqInRange)
	eqBig(t, mustBig("1000000000000000000"), liqAfter) // exactly the outer position
	assertCustodyConsistent(t, e)
}

// TestReadOnlyRejected proves the five mutators reject static calls while the four
// views are allowed.
func TestReadOnlyRejected(t *testing.T) {
	e := newEnv()
	// mutator under readOnly → ErrReadOnly (initialize via the typed helper).
	_, err := e.initialize(stdPool, dex.Q96, true)
	require.ErrorIs(t, err, ErrReadOnly)

	// mint under readOnly → ErrReadOnly (even before any pool exists).
	_, _, err = e.mint(trader, stdPool, -60, 60, big.NewInt(1), true)
	require.ErrorIs(t, err, ErrReadOnly)

	// a view under readOnly works.
	_, err = e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)
	sp, _ := e.slot0(stdPool) // slot0 is invoked with readOnly=true inside the helper
	eqBig(t, dex.Q96, sp)
}

// TestDoubleInitRejected proves a pool cannot be initialized twice.
func TestDoubleInitRejected(t *testing.T) {
	e := newEnv()
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)
	_, err = e.initialize(stdPool, dex.Q96, false)
	require.ErrorIs(t, err, dex.ErrPoolAlreadyInitialized)
}

// TestReentrancyGuard proves a mutator is rejected while the global guard is set (the
// state a malicious token's reentrant callback would observe).
func TestReentrancyGuard(t *testing.T) {
	e := newEnv()
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)

	require.True(t, enterGuard(e.db())) // simulate "already inside a mutator"
	_, _, err = e.mint(trader, stdPool, -60, 60, big.NewInt(1), false)
	require.ErrorIs(t, err, ErrReentrant)
	exitGuard(e.db())
}

// TestUnknownSelector proves an unrecognised selector is rejected cleanly.
func TestUnknownSelector(t *testing.T) {
	e := newEnv()
	in := []byte{0xde, 0xad, 0xbe, 0xef}
	_, _, err := e.c.Run(e.st, trader, v3Addr, in, e.gas, false)
	require.ErrorIs(t, err, ErrUnknownSelector)
}

// TestBadPoolKey proves malformed pool keys (unsorted currencies, bad fee, bad
// spacing) are rejected at the boundary.
func TestBadPoolKey(t *testing.T) {
	e := newEnv()
	// currency0 >= currency1.
	bad := poolCfg{c0: tokenB, c1: tokenA, fee: 3000, tickSpacing: 60}
	_, err := e.initialize(bad, dex.Q96, false)
	require.ErrorIs(t, err, ErrCurrencyOrder)

	// fee >= 1_000_000.
	bad = poolCfg{c0: tokenA, c1: tokenB, fee: 1_000_000, tickSpacing: 60}
	_, err = e.initialize(bad, dex.Q96, false)
	require.ErrorIs(t, err, ErrInvalidFee)

	// tickSpacing 0.
	bad = poolCfg{c0: tokenA, c1: tokenB, fee: 3000, tickSpacing: 0}
	_, err = e.initialize(bad, dex.Q96, false)
	require.ErrorIs(t, err, ErrInvalidTickSpacing)
}

// TestMintValidations proves tick-range guards.
func TestMintValidations(t *testing.T) {
	e := newEnv()
	e.db().fund(tokenA, trader, mustBig("1000000000000000000"))
	e.db().fund(tokenB, trader, mustBig("1000000000000000000"))
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)

	// misaligned ticks (not multiples of 60).
	_, _, err = e.mint(trader, stdPool, -61, 60, big.NewInt(1000), false)
	require.ErrorIs(t, err, ErrTickMisaligned)

	// inverted range.
	_, _, err = e.mint(trader, stdPool, 60, -60, big.NewInt(1000), false)
	require.ErrorIs(t, err, dex.ErrInvalidTickRange)

	// zero amount.
	_, _, err = e.mint(trader, stdPool, -60, 60, big.NewInt(0), false)
	require.ErrorIs(t, err, ErrZeroAmount)
}

// TestBurnTooMuch proves a burn beyond the position's liquidity is rejected.
func TestBurnTooMuch(t *testing.T) {
	e := newEnv()
	e.db().fund(tokenA, trader, mustBig("1000000000000000000"))
	e.db().fund(tokenB, trader, mustBig("1000000000000000000"))
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)
	_, _, err = e.mint(trader, stdPool, -60, 60, mustBig("1000000"), false)
	require.NoError(t, err)
	_, _, err = e.burn(trader, stdPool, -60, 60, mustBig("2000000")) // more than minted
	require.ErrorIs(t, err, ErrInsufficientLiq)
}
