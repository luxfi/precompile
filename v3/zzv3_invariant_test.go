// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Invariants: the properties that must hold for EVERY input, not the outputs of
// a few samples. A concentrated-liquidity AMM is a custodian; the things worth
// asserting are conservation of value, the direction every rounding decision
// leans, and the fact that a price limit is a limit.
//
// The randomised sweeps use ONE explicit seed, declared at sweepSeed below and
// never derived from the clock. A consensus test that fails one run in fifty is
// worse than no test at all: it teaches the reader to re-run instead of read.
package v3

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

// sweepSeed fixes every randomised case in this file. Change it only to widen
// the search deliberately, and only alongside a re-run of the mutation checks.
const sweepSeed = 20260828

// zeroFeePool is the instrument for isolating ROUNDING from fees: with feePips
// at zero, the only thing standing between a trader and a free round trip is the
// direction each division leans. Any test that passes here is testing rounding.
var zeroFeePool = poolCfg{c0: tokenA, c1: tokenB, fee: 0, tickSpacing: 60}

// alignedRange draws a spacing-aligned, in-band, strictly-ordered tick range.
func alignedRange(r *rand.Rand, spacing int32) (lower, upper int32) {
	const maxUnit = 14787 // 14787*60 == 887220, the widest 60-aligned tick
	for {
		a := int32(r.Intn(2*maxUnit+1)) - maxUnit
		b := int32(r.Intn(2*maxUnit+1)) - maxUnit
		if a == b {
			continue
		}
		if a > b {
			a, b = b, a
		}
		return a * spacing, b * spacing
	}
}

// ---------------------------------------------------------------------------
// Value conservation across mint and burn.
// ---------------------------------------------------------------------------

// TestInvariant_BurnNeverReturnsMoreThanMintCost sweeps random ranges at random
// prices and asserts the single most important liquidity property: minting L and
// immediately burning L can NEVER credit more of either token than the mint
// pulled in. If it could, an LP would have a free-money loop that needs no
// counterparty — mint, burn, collect, repeat.
//
// Both legs compose dex.GetAmountsForLiquidity at the same price, so the honest
// expectation is exact equality; the assertion is the one-sided bound, because
// that is the property that keeps the pool solvent, and equality is checked
// separately so a change to either leg is visible.
func TestInvariant_BurnNeverReturnsMoreThanMintCost(t *testing.T) {
	r := rand.New(rand.NewSource(sweepSeed))
	huge := new(big.Int).Lsh(big.NewInt(1), 200)

	for i := 0; i < 200; i++ {
		e := newEnv()
		e.db().fund(tokenA, trader, huge)
		e.db().fund(tokenB, trader, huge)

		// A random starting price, drawn as a tick so it is always in band.
		startTick := int32(r.Intn(1_200_000)) - 600_000
		startPrice, err := dex.GetSqrtRatioAtTick(startTick)
		require.NoError(t, err)
		_, err = e.initialize(stdPool, startPrice, false)
		require.NoError(t, err)

		lower, upper := alignedRange(r, stdPool.tickSpacing)
		L := new(big.Int).Add(big.NewInt(int64(r.Intn(1_000_000_000))+1), big.NewInt(1))
		L.Mul(L, big.NewInt(1_000_000))

		mint0, mint1, err := e.mint(trader, stdPool, lower, upper, L, false)
		if err != nil {
			// A range so far from the price that one leg overflows the caller's
			// funding is a funding fact, not an invariant violation.
			require.ErrorIs(t, err, ErrTransferFailed)
			continue
		}

		burn0, burn1, err := e.burn(trader, stdPool, lower, upper, L)
		require.NoError(t, err)

		require.Truef(t, burn0.Cmp(mint0) <= 0,
			"case %d [%d,%d] L=%s tick=%d: burn credited %s of token0 for a %s mint",
			i, lower, upper, L, startTick, burn0, mint0)
		require.Truef(t, burn1.Cmp(mint1) <= 0,
			"case %d [%d,%d] L=%s tick=%d: burn credited %s of token1 for a %s mint",
			i, lower, upper, L, startTick, burn1, mint1)

		// No trading happened, so the two legs must agree exactly.
		eqBig(t, mint0, burn0)
		eqBig(t, mint1, burn1)

		// And the pool still holds every unit it took in.
		assertCustodyConsistent(t, e)
		require.True(t, e.reserve(tokenA).Cmp(mint0) >= 0)
		require.True(t, e.reserve(tokenB).Cmp(mint1) >= 0)
	}
}

// TestInvariant_MintBurnCollectCannotExtractMoreThanDeposited closes the loop the
// previous test opens: burn only credits, so the property that actually matters
// is what COLLECT pays out. Over a random sweep, the tokens leaving the pool must
// never exceed the tokens that entered it.
func TestInvariant_MintBurnCollectCannotExtractMoreThanDeposited(t *testing.T) {
	r := rand.New(rand.NewSource(sweepSeed))
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	maxU := new(big.Int).Set(maxUint128)

	for i := 0; i < 100; i++ {
		e := fundedEnv(huge)
		lower, upper := alignedRange(r, stdPool.tickSpacing)
		L := big.NewInt(int64(r.Intn(1_000_000_000)) + 1_000_000)

		before0 := e.db().bal(tokenA, trader)
		before1 := e.db().bal(tokenB, trader)

		if _, _, err := e.mint(trader, stdPool, lower, upper, L, false); err != nil {
			require.ErrorIs(t, err, ErrTransferFailed)
			continue
		}
		_, _, err := e.burn(trader, stdPool, lower, upper, L)
		require.NoError(t, err)
		_, _, err = e.collect(trader, stdPool, lower, upper, maxU, maxU)
		require.NoError(t, err)

		after0 := e.db().bal(tokenA, trader)
		after1 := e.db().bal(tokenB, trader)
		require.Truef(t, after0.Cmp(before0) <= 0,
			"case %d [%d,%d]: LP ended with MORE token0 than they started with (%s > %s)",
			i, lower, upper, after0, before0)
		require.Truef(t, after1.Cmp(before1) <= 0,
			"case %d [%d,%d]: LP ended with MORE token1 than they started with (%s > %s)",
			i, lower, upper, after1, before1)

		assertCustodyConsistent(t, e)
		require.True(t, e.reserve(tokenA).Sign() >= 0)
		require.True(t, e.reserve(tokenB).Sign() >= 0)
	}
}

// ---------------------------------------------------------------------------
// Value conservation across a swap.
// ---------------------------------------------------------------------------

// TestInvariant_SwapRoundTripCannotProfit_ZeroFee is the rounding test proper.
// On a ZERO-FEE pool, swap out and immediately swap back: the trader must never
// end with more than they started. There is no fee to hide behind, so the only
// thing that can make this hold is that every division inside the step engine
// leans toward the pool — amountIn up, amountOut down.
func TestInvariant_SwapRoundTripCannotProfit_ZeroFee(t *testing.T) {
	r := rand.New(rand.NewSource(sweepSeed))
	lowLimit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
	highLimit := new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))

	for i := 0; i < 60; i++ {
		e := newEnv()
		e.db().fund(tokenA, trader, e18x1000)
		e.db().fund(tokenB, trader, e18x1000)
		_, err := e.initialize(zeroFeePool, dex.Q96, false)
		require.NoError(t, err)
		_, _, err = e.mint(trader, zeroFeePool, -6000, 6000, e18x1000, false)
		require.NoError(t, err)

		// A random trade size, small enough to stay inside the range.
		size := new(big.Int).Mul(big.NewInt(int64(r.Intn(1_000_000))+1), big.NewInt(1_000_000_000))
		startA := e.db().bal(tokenA, trader)
		startB := e.db().bal(tokenB, trader)

		out0, out1, err := e.swap(trader, zeroFeePool, true, new(big.Int).Neg(size), lowLimit)
		require.NoError(t, err)
		received := new(big.Int).Neg(out1)
		require.Truef(t, received.Sign() > 0, "case %d: swap of %s produced nothing", i, size)
		require.True(t, out0.Sign() > 0)

		// Swap the whole proceeds straight back.
		_, _, err = e.swap(trader, zeroFeePool, false, new(big.Int).Neg(received), highLimit)
		require.NoError(t, err)

		endA := e.db().bal(tokenA, trader)
		endB := e.db().bal(tokenB, trader)
		require.Truef(t, endA.Cmp(startA) <= 0,
			"case %d size=%s: round trip PROFITED %s token0 on a zero-fee pool — rounding leans the wrong way",
			i, size, new(big.Int).Sub(endA, startA))
		require.Truef(t, endB.Cmp(startB) <= 0,
			"case %d size=%s: round trip PROFITED %s token1", i, size, new(big.Int).Sub(endB, startB))
		assertCustodyConsistent(t, e)
	}
}

// TestInvariant_SwapRoundTripLosesTheFee is the same trip on a fee-bearing pool:
// the loss must be at least the fee the pool charged, not merely non-positive.
func TestInvariant_SwapRoundTripLosesTheFee(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)

	size := mustBig("1000000000000000") // 1e15
	startA := e.db().bal(tokenA, trader)

	_, out1, err := e.swap(trader, stdPool, true, new(big.Int).Neg(size), new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)
	received := new(big.Int).Neg(out1)

	_, _, err = e.swap(trader, stdPool, false, new(big.Int).Neg(received), new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	endA := e.db().bal(tokenA, trader)
	lost := new(big.Int).Sub(startA, endA)
	require.True(t, lost.Sign() > 0, "a fee-bearing round trip must cost the trader something")

	// Two legs at 0.30% each: the loss is at least ~0.59% of the notional, less a
	// wei of rounding. Bounded below so a fee that silently stopped being charged
	// shows up here.
	minLoss := new(big.Int).Div(new(big.Int).Mul(size, big.NewInt(59)), big.NewInt(10_000))
	require.Truef(t, lost.Cmp(minLoss) >= 0, "round trip lost %s, expected at least %s (two 0.3%% legs)", lost, minLoss)
	assertCustodyConsistent(t, e)
}

// TestInvariant_SwapMovesReservesExactly proves settlement is exactly the signed
// deltas the call reports: the input reserve rises by amount0, the output reserve
// falls by |amount1|, the real balances agree, and no token is created anywhere.
func TestInvariant_SwapMovesReservesExactly(t *testing.T) {
	r := rand.New(rand.NewSource(sweepSeed))
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)

	supplyA := new(big.Int).Add(e.db().bal(tokenA, trader), e.db().bal(tokenA, v3Addr))
	supplyB := new(big.Int).Add(e.db().bal(tokenB, trader), e.db().bal(tokenB, v3Addr))

	for i := 0; i < 40; i++ {
		zeroForOne := r.Intn(2) == 0
		limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
		if !zeroForOne {
			limit = new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))
		}
		size := new(big.Int).Mul(big.NewInt(int64(r.Intn(500_000))+1), big.NewInt(1_000_000_000))

		res0 := e.reserve(tokenA)
		res1 := e.reserve(tokenB)

		a0, a1, err := e.swap(trader, stdPool, zeroForOne, new(big.Int).Neg(size), limit)
		require.NoErrorf(t, err, "case %d", i)

		eqBig(t, new(big.Int).Add(res0, a0), e.reserve(tokenA))
		eqBig(t, new(big.Int).Add(res1, a1), e.reserve(tokenB))
		assertCustodyConsistent(t, e)

		// The pool takes IN on one side and pays OUT on the other, never both ways.
		require.Truef(t, a0.Sign()*a1.Sign() <= 0, "case %d: a swap must not move both legs the same way", i)

		// Nothing minted, nothing burned.
		eqBig(t, supplyA, new(big.Int).Add(e.db().bal(tokenA, trader), e.db().bal(tokenA, v3Addr)))
		eqBig(t, supplyB, new(big.Int).Add(e.db().bal(tokenB, trader), e.db().bal(tokenB, v3Addr)))
		require.True(t, e.reserve(tokenA).Sign() > 0 && e.reserve(tokenB).Sign() > 0)
	}
}

// TestInvariant_PoolStaysSolventUnderRandomTrading is the long-run version: a
// mixed stream of mints, burns, collects and swaps in both directions, after
// which the ledger must still equal the real balance for both tokens, no reserve
// may have gone negative, and the total supply of each token is unchanged.
func TestInvariant_PoolStaysSolventUnderRandomTrading(t *testing.T) {
	r := rand.New(rand.NewSource(sweepSeed))
	e := fundedEnv(e18x1000)
	maxU := new(big.Int).Set(maxUint128)

	supplyA := new(big.Int).Add(e.db().bal(tokenA, trader), e.db().bal(tokenA, v3Addr))
	supplyB := new(big.Int).Add(e.db().bal(tokenB, trader), e.db().bal(tokenB, v3Addr))

	// A wide base position so the pool is never empty at the active tick.
	_, _, err := e.mint(trader, stdPool, -60000, 60000, mustBig("100000000000000000000"), false)
	require.NoError(t, err)

	type held struct{ lower, upper int32 }
	positions := map[held]*big.Int{}

	for step := 0; step < 400; step++ {
		switch r.Intn(4) {
		case 0: // mint
			lower, upper := alignedRange(r, stdPool.tickSpacing)
			L := big.NewInt(int64(r.Intn(1_000_000_000)) + 1_000_000)
			if _, _, err := e.mint(trader, stdPool, lower, upper, L, false); err == nil {
				k := held{lower, upper}
				if positions[k] == nil {
					positions[k] = big.NewInt(0)
				}
				positions[k] = new(big.Int).Add(positions[k], L)
			}
		case 1: // burn part of a held position
			for k, L := range positions {
				if L.Sign() > 0 {
					part := new(big.Int).Div(L, big.NewInt(2))
					if part.Sign() == 0 {
						part = new(big.Int).Set(L)
					}
					_, _, err := e.burn(trader, stdPool, k.lower, k.upper, part)
					require.NoErrorf(t, err, "step %d: burning %s of an owned %s", step, part, L)
					positions[k] = new(big.Int).Sub(L, part)
				}
				break
			}
		case 2: // collect
			for k := range positions {
				_, _, err := e.collect(trader, stdPool, k.lower, k.upper, maxU, maxU)
				require.NoErrorf(t, err, "step %d: collect must never fail on an owned position", step)
				break
			}
		default: // swap
			zeroForOne := r.Intn(2) == 0
			limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
			if !zeroForOne {
				limit = new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))
			}
			size := new(big.Int).Mul(big.NewInt(int64(r.Intn(100_000))+1), big.NewInt(1_000_000_000))
			_, _, err := e.swap(trader, stdPool, zeroForOne, new(big.Int).Neg(size), limit)
			require.NoErrorf(t, err, "step %d: a funded in-range swap must succeed", step)
		}

		// The anchor, every single step.
		assertCustodyConsistent(t, e)
		require.Truef(t, e.reserve(tokenA).Sign() >= 0, "step %d: token0 reserve went negative", step)
		require.Truef(t, e.reserve(tokenB).Sign() >= 0, "step %d: token1 reserve went negative", step)
		eqBig(t, supplyA, new(big.Int).Add(e.db().bal(tokenA, trader), e.db().bal(tokenA, v3Addr)))
		eqBig(t, supplyB, new(big.Int).Add(e.db().bal(tokenB, trader), e.db().bal(tokenB, v3Addr)))
	}

	// The pool never paid out anything it did not hold.
	require.True(t, e.db().bal(tokenA, v3Addr).Sign() > 0)
	require.True(t, e.db().bal(tokenB, v3Addr).Sign() > 0)
}

// ---------------------------------------------------------------------------
// The price limit.
// ---------------------------------------------------------------------------

// TestPriceLimit_WrongSideRefused proves a limit on the wrong side of the current
// price is refused in BOTH directions. Without the check, a zeroForOne swap given
// a limit ABOVE the price would have its target clamped upward and the step engine
// would be asked to move the price the wrong way.
func TestPriceLimit_WrongSideRefused(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)
	price, _ := e.slot0(stdPool)
	size := new(big.Int).Neg(mustBig("1000000000000000"))

	// zeroForOne pushes the price DOWN, so the limit must be strictly below it.
	for name, limit := range map[string]*big.Int{
		"at the current price": new(big.Int).Set(price),
		"above the price":      new(big.Int).Add(price, big.NewInt(1)),
		"far above":            new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1)),
		"at MIN_SQRT_RATIO":    new(big.Int).Set(dex.MinSqrtRatio),
		"below MIN":            big.NewInt(1),
		"zero":                 big.NewInt(0),
	} {
		_, _, err := e.swap(trader, stdPool, true, size, limit)
		require.ErrorIsf(t, err, dex.ErrInvalidSqrtPrice, "zeroForOne with a limit %s must be refused", name)
	}

	// oneForZero pushes the price UP, so the limit must be strictly above it.
	for name, limit := range map[string]*big.Int{
		"at the current price": new(big.Int).Set(price),
		"below the price":      new(big.Int).Sub(price, big.NewInt(1)),
		"far below":            new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)),
		"at MAX_SQRT_RATIO":    new(big.Int).Set(dex.MaxSqrtRatio),
		"above MAX":            new(big.Int).Add(dex.MaxSqrtRatio, big.NewInt(1)),
	} {
		_, _, err := e.swap(trader, stdPool, false, size, limit)
		require.ErrorIsf(t, err, dex.ErrInvalidSqrtPrice, "oneForZero with a limit %s must be refused", name)
	}

	// A refused swap changed nothing.
	priceAfter, _ := e.slot0(stdPool)
	eqBig(t, price, priceAfter)
}

// TestPriceLimit_NeverCrossed proves the limit is honoured, not merely validated:
// a swap with far more input than the range can absorb must stop AT the limit and
// leave input unconsumed, in both directions.
func TestPriceLimit_NeverCrossed(t *testing.T) {
	// --- zeroForOne: the price must never end BELOW the limit ---
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -60000, 60000, e18x1000, false)
	require.NoError(t, err)

	limitDown, err := dex.GetSqrtRatioAtTick(-600)
	require.NoError(t, err)
	spend := mustBig("500000000000000000000") // far more than the range can take
	a0, _, err := e.swap(trader, stdPool, true, new(big.Int).Neg(spend), limitDown)
	require.NoError(t, err)

	priceAfter, tickAfter := e.slot0(stdPool)
	require.Truef(t, priceAfter.Cmp(limitDown) >= 0,
		"price %s ended past the limit %s", priceAfter, limitDown)
	eqBig(t, limitDown, priceAfter) // it stops exactly ON the limit
	require.Equal(t, int32(-600), tickAfter)
	require.Truef(t, a0.Cmp(spend) < 0, "hitting the limit must leave input unspent: %s of %s", a0, spend)
	assertCustodyConsistent(t, e)

	// --- oneForZero: the price must never end ABOVE the limit ---
	e2 := fundedEnv(e18x1000)
	_, _, err = e2.mint(trader, stdPool, -60000, 60000, e18x1000, false)
	require.NoError(t, err)

	limitUp, err := dex.GetSqrtRatioAtTick(600)
	require.NoError(t, err)
	_, a1, err := e2.swap(trader, stdPool, false, new(big.Int).Neg(spend), limitUp)
	require.NoError(t, err)

	priceAfter2, tickAfter2 := e2.slot0(stdPool)
	require.Truef(t, priceAfter2.Cmp(limitUp) <= 0,
		"price %s ended past the limit %s", priceAfter2, limitUp)
	eqBig(t, limitUp, priceAfter2)
	require.Equal(t, int32(600), tickAfter2)
	require.True(t, a1.Cmp(spend) < 0)
	assertCustodyConsistent(t, e)
}

// TestPriceLimit_HonouredUnderRandomTargets sweeps random limits between the
// current price and each extreme, asserting the swap never ends past whichever
// limit it was given.
func TestPriceLimit_HonouredUnderRandomTargets(t *testing.T) {
	r := rand.New(rand.NewSource(sweepSeed))
	spend := mustBig("100000000000000000000")

	for i := 0; i < 30; i++ {
		e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 200))
		_, _, err := e.mint(trader, stdPool, -60000, 60000, e18x1000, false)
		require.NoError(t, err)

		zeroForOne := r.Intn(2) == 0
		bound := int32(r.Intn(20_000) + 60)
		if zeroForOne {
			bound = -bound
		}
		limit, err := dex.GetSqrtRatioAtTick(bound)
		require.NoError(t, err)

		_, _, err = e.swap(trader, stdPool, zeroForOne, new(big.Int).Neg(spend), limit)
		require.NoErrorf(t, err, "case %d bound=%d", i, bound)

		after, _ := e.slot0(stdPool)
		if zeroForOne {
			require.Truef(t, after.Cmp(limit) >= 0, "case %d: price %s below limit %s", i, after, limit)
		} else {
			require.Truef(t, after.Cmp(limit) <= 0, "case %d: price %s above limit %s", i, after, limit)
		}
		assertCustodyConsistent(t, e)
	}
}

// TestSwap_ExactOutputStopsAtRequestedAmount covers the other sign convention:
// a positive amountSpecified is an exact-OUTPUT order, and the pool must deliver
// exactly that and charge the input it took to produce it.
func TestSwap_ExactOutputStopsAtRequestedAmount(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -60000, 60000, e18x1000, false)
	require.NoError(t, err)

	want := mustBig("1000000000000000") // 1e15 of token1, exactly
	a0, a1, err := e.swap(trader, stdPool, true, want, new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)

	eqBig(t, want, new(big.Int).Neg(a1))
	require.Truef(t, a0.Cmp(want) > 0, "an exact-output swap must charge more input than it delivers: in %s, out %s", a0, want)
	assertCustodyConsistent(t, e)
}

// TestSwap_NonCanonicalBoolIsTruthy pins the ABI tolerance of the zeroForOne
// word: any non-zero word means true. Worth pinning because a stricter or looser
// reading would silently reverse a trade's direction.
func TestSwap_NonCanonicalBoolIsTruthy(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -6000, 6000, e18x1000, false)
	require.NoError(t, err)

	in := append(selBytes(selSwap), stdPool.words()...)
	in = append(in, uintArg(big.NewInt(2))...) // not 0 or 1
	in = append(in, intArg(new(big.Int).Neg(mustBig("1000000000000000")))...)
	in = append(in, uintArg(new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))...)

	ret, _, err := e.callRaw(trader, in, plentyGas, false)
	require.NoError(t, err)
	a0 := wordToInt(common.BytesToHash(ret[0:32]))
	require.True(t, a0.Sign() > 0, "a truthy word must be read as zeroForOne")
}

// ---------------------------------------------------------------------------
// Gas: the swap loop.
// ---------------------------------------------------------------------------

// manyTickPool builds a pool with `n` initialized tick boundaries below the
// active tick, plus a wide position keeping it solvent all the way down. Every
// narrow position spans exactly one tick spacing, so a downward swap crosses one
// initialized tick per spacing it travels.
func manyTickPool(t *testing.T, n int32) *env {
	t.Helper()
	e := newEnv()
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	e.db().fund(tokenA, trader, huge)
	e.db().fund(tokenB, trader, huge)
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)

	_, _, err = e.mint(trader, stdPool, -60*(n+2), 60*(n+2), mustBig("100000000000000000000"), false)
	require.NoError(t, err)
	for k := int32(0); k < n; k++ {
		_, _, err = e.mint(trader, stdPool, -60*(k+1), -60*k, mustBig("10000000000000000000"), false)
		require.NoErrorf(t, err, "narrow position %d", k)
	}
	return e
}

// drainSwap is a swap that crosses every one of the n narrow boundaries and then
// stops on a price limit one spacing below the last of them. It deliberately
// stops SHORT of exhausting the wide position — see
// TestDrainOfOverlappingPositionsIsRefusedNotUnbacked for what a total drain
// does and why.
func drainSwap(t *testing.T, n int32) []byte {
	t.Helper()
	limit, err := dex.GetSqrtRatioAtTick(-60 * (n + 1))
	require.NoError(t, err)
	return inSwap(stdPool, true, new(big.Int).Neg(mustBig("50000000000000000000")), limit)
}

// swapSteps returns how many loop iterations a swap paid for, derived from the
// gas it consumed. Only the loop charges beyond the base fee, so this is exact.
func swapSteps(t *testing.T, supplied, remaining uint64) uint64 {
	t.Helper()
	used := supplied - remaining
	require.GreaterOrEqual(t, used, GasSwapBase)
	require.Zerof(t, (used-GasSwapBase)%GasSwapStep,
		"gas used (%d) must be the base fee plus a whole number of step charges", used)
	return (used - GasSwapBase) / GasSwapStep
}

// TestGas_SwapLoopIsBounded is the DoS question, answered by measurement: a swap
// that would cross many initialized ticks must run OUT OF GAS rather than loop.
// The loop charges GasSwapStep before each iteration, so a caller who supplies
// only k steps' worth cannot get a (k+1)th iteration for free.
func TestGas_SwapLoopIsBounded(t *testing.T) {
	const ticks = 30

	// First, how many steps does it genuinely need?
	e := manyTickPool(t, ticks)
	_, rem, err := e.callRaw(trader, drainSwap(t, ticks), plentyGas, false)
	require.NoError(t, err)
	needed := swapSteps(t, plentyGas, rem)
	require.Greaterf(t, needed, uint64(ticks/2),
		"the fixture must actually cross many ticks; it took %d steps", needed)

	// Now starve it: every budget short of what it needs must fail, and fail with
	// ErrOutOfGas rather than by silently truncating the swap.
	for _, k := range []uint64{0, 1, 2, needed / 2, needed - 1} {
		e := manyTickPool(t, ticks)
		budget := GasSwapBase + k*GasSwapStep + (GasSwapStep - 1) // k full steps, then short
		_, rem, err := e.callRaw(trader, drainSwap(t, ticks), budget, false)
		require.ErrorIsf(t, err, ErrOutOfGas, "a %d-step budget must not buy a %d-step swap", k, needed)
		require.Zerof(t, rem, "an out-of-gas swap must leave no gas")

		// Nothing settled: an aborted swap must not have moved custody.
		assertCustodyConsistent(t, e)
	}

	// And exactly enough succeeds — the bound is tight, not merely present.
	e = manyTickPool(t, ticks)
	_, _, err = e.callRaw(trader, drainSwap(t, ticks), GasSwapBase+needed*GasSwapStep, false)
	require.NoError(t, err, "a budget of exactly %d steps must complete the swap", needed)
}

// TestGas_CallerPaysForEveryCrossing answers the second half: a caller cannot
// force extra tick crossings without paying for each. Crossing more ticks must
// cost strictly more gas, in exact multiples of GasSwapStep.
func TestGas_CallerPaysForEveryCrossing(t *testing.T) {
	var prev uint64
	for _, ticks := range []int32{4, 10, 20, 40} {
		e := manyTickPool(t, ticks)
		_, rem, err := e.callRaw(trader, drainSwap(t, ticks), plentyGas, false)
		require.NoError(t, err)

		used := plentyGas - rem
		steps := swapSteps(t, plentyGas, rem)
		require.Equalf(t, GasSwapBase+steps*GasSwapStep, used,
			"gas used must be exactly the base plus one charge per step (%d ticks)", ticks)
		require.Greaterf(t, steps, prev, "crossing more ticks must cost more steps (%d ticks)", ticks)

		// Each extra spacing crossed costs at least one more step than the last
		// configuration — the charge tracks the work, it is not amortised away.
		prev = steps
	}
}

// TestGas_NoLiquidityWalkIsAlsoCharged closes the last hole in the loop's
// accounting. Below the deepest position the pool has NO liquidity, and the loop
// still walks tick-bitmap word by tick-bitmap word down to the price limit doing
// no economic work. Those iterations are the cheapest thing an attacker could ask
// for, so they must be charged like any other: a caller who wants the walk pays
// GasSwapStep for every word of it.
func TestGas_NoLiquidityWalkIsAlsoCharged(t *testing.T) {
	// A shallow pool, then a swap aimed at the very bottom of the price band.
	nearBottom := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))
	shallow := inSwap(stdPool, true, new(big.Int).Neg(mustBig("50000000000000000000")), nearBottom)

	e := manyTickPool(t, 2)
	_, rem, err := e.callRaw(trader, shallow, plentyGas, false)
	// The walk itself succeeds or is refused on the drain rounding (see
	// TestDrainOfOverlappingPositionsIsRefusedNotUnbacked); either way it was METERED.
	if err != nil {
		require.ErrorIs(t, err, ErrReserveUnderflow)
	}
	longWalk := plentyGas - rem
	require.Greaterf(t, longWalk, GasSwapBase+40*GasSwapStep,
		"walking the empty band to MIN_SQRT_RATIO must be charged per step, cost only %d", longWalk)

	// The same pool with a nearby limit costs far less: the charge is per step
	// travelled, not a flat fee.
	e2 := manyTickPool(t, 2)
	_, rem2, err := e2.callRaw(trader, drainSwap(t, 2), plentyGas, false)
	require.NoError(t, err)
	shortWalk := plentyGas - rem2
	require.Lessf(t, shortWalk, longWalk, "a shorter price journey must cost less gas")

	// And the long walk is bounded: it cannot exceed one step per bitmap word
	// between the start tick and MIN_TICK, plus the crossings.
	wordsInBand := uint64((dex.MaxTick - dex.MinTick) / (256 * 60))
	require.Lessf(t, swapSteps(t, plentyGas, rem), wordsInBand+64,
		"the empty-band walk must be bounded by the number of bitmap words")
}

// TestDrainOfOverlappingPositionsIsRefusedNotUnbacked documents a REAL rounding
// asymmetry, and pins the fact that it is caught rather than paid.
//
// Deposits are rounded down ONCE PER POSITION over that position's whole range.
// Pay-outs are rounded down ONCE PER STEP over the COMBINED active liquidity, and
// floor(a+b) can exceed floor(a)+floor(b) by one. So a swap that exhausts a pool
// holding OVERLAPPING positions can compute a pay-out a few wei above the sum of
// the deposits — measured at +5 wei for 30 overlapping positions, 0 for one.
//
// Uniswap V3-core avoids this by rounding MINT UP; the package doc (§3) chooses
// round-down on both legs and leans on the reserve ledger instead. That choice is
// CUSTODY-safe — subReserve refuses, so not one unbacked wei leaves — but it is
// not liveness-neutral: the final drain reverts instead of paying out. This test
// asserts the safe half, so if the guard were ever removed the loss would surface
// here rather than on-chain.
func TestDrainOfOverlappingPositionsIsRefusedNotUnbacked(t *testing.T) {
	e := manyTickPool(t, 30)
	depositedB := new(big.Int).Set(e.reserve(tokenB))
	poolBBefore := e.db().bal(tokenB, v3Addr)

	// Aim past the deepest liquidity: this asks the pool for everything it has.
	_, _, err := e.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("50000000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.ErrorIs(t, err, ErrReserveUnderflow,
		"a full drain must be refused by the ledger, never paid from thin air")

	// The refusal is total: not one wei of token1 left the pool.
	eqBig(t, poolBBefore, e.db().bal(tokenB, v3Addr))
	eqBig(t, depositedB, e.reserve(tokenB))

	// A single-position pool has no overlap and drains cleanly, which is what
	// isolates the cause to the combined-liquidity rounding.
	solo := fundedEnv(e18x1000)
	_, _, err = solo.mint(trader, stdPool, -1920, 1920, mustBig("100000000000000000000"), false)
	require.NoError(t, err)
	_, a1, err := solo.swap(trader, stdPool, true,
		new(big.Int).Neg(mustBig("50000000000000000000")),
		new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1)))
	require.NoError(t, err, "a single position must drain without tripping the ledger")
	require.True(t, new(big.Int).Neg(a1).Sign() > 0)
	assertCustodyConsistent(t, solo)
}

// TestGas_ShortSwapIsCheap proves the per-step charge is not a flat surcharge: a
// swap that stays inside one tick range pays for a small, fixed number of steps,
// so honest traffic is not priced as though it were the adversarial case.
func TestGas_ShortSwapIsCheap(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -60000, 60000, e18x1000, false)
	require.NoError(t, err)

	_, rem, err := e.callRaw(trader,
		inSwap(stdPool, true, new(big.Int).Neg(mustBig("1000000000000000")), new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))),
		plentyGas, false)
	require.NoError(t, err)

	steps := swapSteps(t, plentyGas, rem)
	require.LessOrEqualf(t, steps, uint64(2), "an in-range swap should take one or two steps, took %d", steps)
	require.GreaterOrEqual(t, steps, uint64(1))
}

// TestGas_FlatFeeOpsHaveBoundedWork is the DoS check on the five flat fees. Each
// of initialize/mint/burn/collect does a FIXED number of slot writes for a FIXED
// argument size — there is no loop and no caller-controlled repetition — so the
// gas they charge cannot be outrun. Asserted by measurement: the charge is
// identical regardless of how extreme the (valid) arguments are.
func TestGas_FlatFeeOpsHaveBoundedWork(t *testing.T) {
	maxU := new(big.Int).Set(maxUint128)

	// The widest legal range and a near-maximal liquidity cost exactly the same
	// as the narrowest range and the smallest liquidity.
	wide := func(t *testing.T) (uint64, uint64, uint64) {
		e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 220))
		_, remM, err := e.callRaw(trader, inMint(stdPool, -887220, 887220, mustBig("1000000000000000000000000")), plentyGas, false)
		require.NoError(t, err)
		_, remB, err := e.callRaw(trader, inBurn(stdPool, -887220, 887220, mustBig("1000000000000000000000000")), plentyGas, false)
		require.NoError(t, err)
		_, remC, err := e.callRaw(trader, inCollect(stdPool, -887220, 887220, maxU, maxU), plentyGas, false)
		require.NoError(t, err)
		return plentyGas - remM, plentyGas - remB, plentyGas - remC
	}
	narrow := func(t *testing.T) (uint64, uint64, uint64) {
		e := fundedEnv(new(big.Int).Lsh(big.NewInt(1), 220))
		_, remM, err := e.callRaw(trader, inMint(stdPool, -60, 60, big.NewInt(1000)), plentyGas, false)
		require.NoError(t, err)
		_, remB, err := e.callRaw(trader, inBurn(stdPool, -60, 60, big.NewInt(1000)), plentyGas, false)
		require.NoError(t, err)
		_, remC, err := e.callRaw(trader, inCollect(stdPool, -60, 60, maxU, maxU), plentyGas, false)
		require.NoError(t, err)
		return plentyGas - remM, plentyGas - remB, plentyGas - remC
	}

	wm, wb, wc := wide(t)
	nm, nb, nc := narrow(t)
	require.Equal(t, GasMint, wm)
	require.Equal(t, GasMint, nm)
	require.Equal(t, GasBurn, wb)
	require.Equal(t, GasBurn, nb)
	require.Equal(t, GasCollect, wc)
	require.Equal(t, GasCollect, nc)

	// initialize likewise: the extreme end of the price band costs the flat fee.
	e := newEnv()
	_, rem, err := e.callRaw(trader, inInitialize(stdPool, dex.MinSqrtRatio), plentyGas, false)
	require.NoError(t, err)
	require.Equal(t, GasInitialize, plentyGas-rem)
}
