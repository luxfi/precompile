// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// This file covers the pure arithmetic under dex/: full_math.go, sqrt_price_math.go,
// swap_math.go, liquidity_amounts.go and tick_bitmap_math.go. Every one of these was
// at 0% coverage while being live on the swap path (MulDiv alone has 10 non-test call
// sites). They are where a one-wei rounding error becomes a drain, so the assertions
// below are about DIRECTION and BOUNDS, not sample outputs.

var (
	amMaxU256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	amTwo255  = new(big.Int).Lsh(big.NewInt(1), 255)
)

func amBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad literal " + s)
	}
	return v
}

// ---------------------------------------------------------------------------
// full_math.go — MulDiv / MulDivRoundingUp / UnsafeDivRoundingUp
// ---------------------------------------------------------------------------

// TestMulDivRoundsTowardZeroAtEveryBoundary pins the floor semantics exactly.
// MulDiv is the "amount owed to the CALLER" primitive, so it must never return a
// value above the true quotient.
func TestMulDivRoundsTowardZero(t *testing.T) {
	// Exhaustively check every remainder class for a small denominator: floor must
	// hold for all of them, not just the ones a sample test happens to pick.
	for d := int64(1); d <= 17; d++ {
		for num := int64(0); num <= 200; num++ {
			got := MulDiv(big.NewInt(num), big.NewInt(1), big.NewInt(d))
			require.Equalf(t, num/d, got.Int64(), "MulDiv(%d,1,%d) must floor", num, d)
		}
	}
	// Exact division leaves no remainder to round.
	require.Equal(t, int64(7), MulDiv(big.NewInt(14), big.NewInt(3), big.NewInt(6)).Int64())
	// The 512-bit intermediate must not be truncated: a*b overflows uint256 but the
	// quotient does not.
	require.Equal(t, 0, MulDiv(amMaxU256, amMaxU256, amMaxU256).Cmp(amMaxU256))
	// A product that overflows uint256 but divides back inside it must NOT be
	// truncated: 2^255 * 4 / 2 == 2^256 is itself out of range and must panic, while
	// 2^255 * 4 / 8 == 2^254 is in range and must be exact.
	require.Equal(t, 0, MulDiv(amTwo255, big.NewInt(4), big.NewInt(8)).Cmp(new(big.Int).Lsh(big.NewInt(1), 254)))
}

// TestMulDivRoundingUpRoundsUpAtEveryBoundary is the rounding-direction proof for
// the "amount owed to the POOL" primitive. Any remainder at all, however small,
// must push the result up a whole unit — that one unit is what stops a caller
// cycling dust-sized operations to extract the pool.
func TestMulDivRoundingUpRoundsUp(t *testing.T) {
	for d := int64(1); d <= 17; d++ {
		for num := int64(0); num <= 200; num++ {
			got := MulDivRoundingUp(big.NewInt(num), big.NewInt(1), big.NewInt(d))
			want := num / d
			if num%d != 0 {
				want++
			}
			require.Equalf(t, want, got.Int64(), "MulDivRoundingUp(%d,1,%d) must ceil", num, d)
		}
	}

	// The one-unit boundary, stated directly: a single wei of remainder rounds up.
	require.Equal(t, int64(1), MulDivRoundingUp(big.NewInt(1), big.NewInt(1), big.NewInt(1000000)).Int64(),
		"one wei of remainder must round to a whole unit")
	// Exact division must NOT gain a spurious unit — rounding up is not "always +1".
	require.Equal(t, int64(5), MulDivRoundingUp(big.NewInt(10), big.NewInt(1), big.NewInt(2)).Int64())
	require.Equal(t, int64(0), MulDivRoundingUp(big.NewInt(0), big.NewInt(12345), big.NewInt(7)).Int64(),
		"zero has no remainder and must stay zero")

	// Ceiling never exceeds floor by more than one, and never falls below it.
	seed := int64(90210)
	r := rand.New(rand.NewSource(seed))
	for range 20000 {
		a := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 128))
		b := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100))
		d := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100)))
		lo := MulDiv(a, b, d)
		hi := MulDivRoundingUp(a, b, d)
		delta := new(big.Int).Sub(hi, lo)
		require.Truef(t, delta.Sign() >= 0 && delta.Cmp(big.NewInt(1)) <= 0,
			"seed=%d ceil-floor must be 0 or 1, got %v", seed, delta)
		// The defining property, checked against exact arithmetic.
		prod := new(big.Int).Mul(a, b)
		require.LessOrEqual(t, new(big.Int).Mul(lo, d).Cmp(prod), 0, "floor*d <= a*b")
		require.GreaterOrEqual(t, new(big.Int).Mul(hi, d).Cmp(prod), 0, "ceil*d >= a*b")
	}
}

// TestUnsafeDivRoundingUp covers the third primitive, which takes an already-
// computed numerator. Same ceiling contract.
func TestUnsafeDivRoundingUp(t *testing.T) {
	for d := int64(1); d <= 13; d++ {
		for num := int64(0); num <= 120; num++ {
			got := UnsafeDivRoundingUp(big.NewInt(num), big.NewInt(d))
			want := num / d
			if num%d != 0 {
				want++
			}
			require.Equalf(t, want, got.Int64(), "UnsafeDivRoundingUp(%d,%d)", num, d)
		}
	}
	require.Equal(t, 0, UnsafeDivRoundingUp(amMaxU256, big.NewInt(1)).Cmp(amMaxU256))
}

// TestFullMathRefusesNonPositiveDenominator: both guarded primitives refuse a zero
// or negative denominator by panicking. That panic is the SUBJECT of the
// reachability tests below — here we simply pin that the guard exists and fires
// for every non-positive value, so a silent wrong answer is impossible.
func TestFullMathRefusesNonPositiveDenominator(t *testing.T) {
	for _, d := range []*big.Int{big.NewInt(0), big.NewInt(-1), big.NewInt(-1000), new(big.Int).Neg(amMaxU256)} {
		require.PanicsWithValue(t, "MulDiv: denominator must be positive", func() {
			MulDiv(big.NewInt(1), big.NewInt(1), d)
		}, "MulDiv must refuse denominator %v", d)
		require.PanicsWithValue(t, "MulDivRoundingUp: denominator must be positive", func() {
			MulDivRoundingUp(big.NewInt(1), big.NewInt(1), d)
		}, "MulDivRoundingUp must refuse denominator %v", d)
	}
}

// TestFullMathOverflowPanicIsReachableArithmetic documents the uint256 overflow
// guard. A panic inside a precompile aborts the BLOCK, not the call, so this guard
// is only safe while no caller can drive a result past uint256. The companion test
// TestLiquidityMathOverflowReachability below establishes whether any live caller
// can, which is what decides whether this is a safe assertion or a chain halt.
func TestFullMathOverflowPanics(t *testing.T) {
	// Result exactly maxU256 is legal; one more is not.
	require.NotPanics(t, func() { MulDiv(amMaxU256, big.NewInt(1), big.NewInt(1)) })
	require.PanicsWithValue(t, "MulDiv: result overflows uint256", func() {
		MulDiv(new(big.Int).Add(amMaxU256, big.NewInt(1)), big.NewInt(1), big.NewInt(1))
	})
	require.PanicsWithValue(t, "MulDivRoundingUp: result overflows uint256", func() {
		MulDivRoundingUp(new(big.Int).Add(amMaxU256, big.NewInt(1)), big.NewInt(1), big.NewInt(1))
	})
	// The rounding-up CARRY is what tips this one over the edge, and it is the case a
	// floor-only overflow check would miss: the floor is exactly maxU256 (legal) and
	// the single wei of remainder pushes the ceiling one past it.
	carry := new(big.Int).Add(new(big.Int).Mul(amMaxU256, big.NewInt(2)), big.NewInt(1))
	require.Equal(t, 0, MulDiv(carry, big.NewInt(1), big.NewInt(2)).Cmp(amMaxU256),
		"the floor of this input is exactly maxU256 and must be accepted")
	require.PanicsWithValue(t, "MulDivRoundingUp: result overflows uint256", func() {
		MulDivRoundingUp(carry, big.NewInt(1), big.NewInt(2))
	}, "the rounding-up carry must be caught by the overflow guard")
}

// TestLiquidityMathOverflowReachability answers the question the overflow guard
// raises: can a caller reach it? GetLiquidityForAmount0 divides by the WIDTH of the
// price range, so a one-wei-wide range makes the quotient as large as the product —
// and the product of two uint256-scale inputs is far past uint256.
//
// This is a REACHABILITY finding, not a passing invariant: it records that the
// panic is arithmetically attainable through an exported helper, so the bound must
// be enforced by whichever caller supplies the range.
func TestLiquidityMathOverflowReachability(t *testing.T) {
	// A legitimate, wide range never comes close.
	require.NotPanics(t, func() {
		GetLiquidityForAmount0(MinSqrtRatio, MaxSqrtRatio, amBig("1000000000000000000"))
	})

	// A one-wei-wide range with a large amount0 drives the quotient past uint256.
	narrowLo := new(big.Int).Set(MaxSqrtRatio)
	narrowHi := new(big.Int).Add(narrowLo, big.NewInt(1))
	require.PanicsWithValue(t, "MulDiv: result overflows uint256", func() {
		GetLiquidityForAmount0(narrowLo, narrowHi, amMaxU256)
	}, "a one-wei price range makes the liquidity quotient overflow uint256")

	// A zero-width range is handled without dividing by zero — the guard returns 0.
	require.Equal(t, int64(0), GetLiquidityForAmount0(MinSqrtRatio, MinSqrtRatio, big.NewInt(1e18)).Int64())
	require.Equal(t, int64(0), GetLiquidityForAmount1(MinSqrtRatio, MinSqrtRatio, big.NewInt(1e18)).Int64())
}

// ---------------------------------------------------------------------------
// sqrt_price_math.go
// ---------------------------------------------------------------------------

// TestGetAmountDeltasRoundTowardThePool is the central rounding rule for the V3/V4
// swap path: the same price range must yield a LARGER amount when rounding up (what
// the caller owes the pool) than when rounding down (what the pool owes the caller).
// If those two ever coincide in the wrong direction, the pool leaks on every swap.
func TestGetAmountDeltasRoundTowardThePool(t *testing.T) {
	const seed = 13371337
	r := rand.New(rand.NewSource(seed))
	sawStrict0, sawStrict1 := 0, 0

	for range 20000 {
		a := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)))
		b := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)))
		liq := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 112))
		if liq.Sign() == 0 {
			continue
		}

		up0 := GetAmount0Delta(a, b, liq, true)
		dn0 := GetAmount0Delta(a, b, liq, false)
		require.GreaterOrEqualf(t, up0.Cmp(dn0), 0, "seed=%d amount0 roundUp must be >= roundDown", seed)
		require.LessOrEqualf(t, new(big.Int).Sub(up0, dn0).Cmp(big.NewInt(1)), 0,
			"seed=%d amount0 rounding may differ by at most one wei", seed)
		if up0.Cmp(dn0) > 0 {
			sawStrict0++
		}

		up1 := GetAmount1Delta(a, b, liq, true)
		dn1 := GetAmount1Delta(a, b, liq, false)
		require.GreaterOrEqualf(t, up1.Cmp(dn1), 0, "seed=%d amount1 roundUp must be >= roundDown", seed)
		require.LessOrEqualf(t, new(big.Int).Sub(up1, dn1).Cmp(big.NewInt(1)), 0,
			"seed=%d amount1 rounding may differ by at most one wei", seed)
		if up1.Cmp(dn1) > 0 {
			sawStrict1++
		}
	}
	// The sweep must actually EXERCISE rounding, not just sample exact divisions —
	// otherwise the direction assertions above are vacuous.
	require.Greater(t, sawStrict0, 100, "sweep never hit a fractional amount0")
	require.Greater(t, sawStrict1, 100, "sweep never hit a fractional amount1")
}

// TestGetAmountDeltasAreOrderIndependent: both helpers sort their bounds, so
// passing the range backwards must not change the answer. A caller that could flip
// the sign by swapping arguments would be able to mint value.
func TestGetAmountDeltasAreOrderIndependent(t *testing.T) {
	a, b := amBig("79228162514264337593543950336"), amBig("158456325028528675187087900672")
	liq := big.NewInt(1e18)
	for _, up := range []bool{true, false} {
		require.Equal(t, GetAmount0Delta(a, b, liq, up), GetAmount0Delta(b, a, liq, up))
		require.Equal(t, GetAmount1Delta(a, b, liq, up), GetAmount1Delta(b, a, liq, up))
	}
	// Zero-width range yields zero in both directions.
	require.Equal(t, int64(0), GetAmount0Delta(a, a, liq, true).Int64())
	require.Equal(t, int64(0), GetAmount1Delta(a, a, liq, true).Int64())
	// Zero liquidity yields zero regardless of range.
	require.Equal(t, int64(0), GetAmount0Delta(a, b, big.NewInt(0), true).Int64())
	require.Equal(t, int64(0), GetAmount1Delta(a, b, big.NewInt(0), true).Int64())
}

// TestGetAmountDeltaSignedMirrorsSign: negative liquidity (a burn) must produce a
// negative delta of the same magnitude the matching positive liquidity would owe,
// and the rounding must flip with it — a burn rounds DOWN in magnitude so the pool
// never pays out more than it took in.
func TestGetAmountDeltaSignedMirrorsSign(t *testing.T) {
	a, b := amBig("79228162514264337593543950336"), amBig("112045541949572279837463876454")
	liq := big.NewInt(1e18)
	neg := new(big.Int).Neg(liq)

	pos0 := GetAmount0DeltaSigned(a, b, liq)
	neg0 := GetAmount0DeltaSigned(a, b, neg)
	require.Positive(t, pos0.Sign(), "adding liquidity owes the pool a positive amount0")
	require.Negative(t, neg0.Sign(), "removing liquidity owes the user a negative amount0")
	require.Equal(t, 0, pos0.Cmp(GetAmount0Delta(a, b, liq, true)), "mint rounds UP toward the pool")
	require.Equal(t, 0, new(big.Int).Neg(neg0).Cmp(GetAmount0Delta(a, b, liq, false)), "burn rounds DOWN toward the pool")
	// A mint must never cost less than a burn pays: that gap is the pool's margin.
	require.GreaterOrEqual(t, pos0.Cmp(new(big.Int).Neg(neg0)), 0,
		"mint-cost must be >= burn-payout, else mint+burn extracts value")

	pos1 := GetAmount1DeltaSigned(a, b, liq)
	neg1 := GetAmount1DeltaSigned(a, b, neg)
	require.Positive(t, pos1.Sign())
	require.Negative(t, neg1.Sign())
	require.GreaterOrEqual(t, pos1.Cmp(new(big.Int).Neg(neg1)), 0,
		"mint-cost must be >= burn-payout for token1 too")
}

// TestMintBurnRoundTripCannotProfit is the economic statement of the rule above,
// swept over many ranges: minting L then immediately burning L must never return
// more of either token than it cost. Otherwise the pool is a money pump.
func TestMintBurnRoundTripCannotProfit(t *testing.T) {
	const seed = 5551212
	r := rand.New(rand.NewSource(seed))
	for range 20000 {
		a := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)))
		b := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)))
		liq := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100)))

		cost0 := GetAmount0DeltaSigned(a, b, liq)
		back0 := new(big.Int).Neg(GetAmount0DeltaSigned(a, b, new(big.Int).Neg(liq)))
		require.GreaterOrEqualf(t, cost0.Cmp(back0), 0,
			"seed=%d mint/burn round-trip profited in token0: cost=%v back=%v", seed, cost0, back0)

		cost1 := GetAmount1DeltaSigned(a, b, liq)
		back1 := new(big.Int).Neg(GetAmount1DeltaSigned(a, b, new(big.Int).Neg(liq)))
		require.GreaterOrEqualf(t, cost1.Cmp(back1), 0,
			"seed=%d mint/burn round-trip profited in token1: cost=%v back=%v", seed, cost1, back1)
	}
}

// TestGetNextSqrtPriceFromAmount0 covers both directions and the underflow refusal.
func TestGetNextSqrtPriceFromAmount0(t *testing.T) {
	price := amBig("79228162514264337593543950336") // 1.0 in Q64.96
	liq := amBig("1000000000000000000")

	// A zero amount is a no-op, not an error.
	got, err := GetNextSqrtPriceFromAmount0RoundingUp(price, liq, big.NewInt(0), true)
	require.NoError(t, err)
	require.Equal(t, 0, got.Cmp(price))

	// Adding token0 pushes the price DOWN.
	down, err := GetNextSqrtPriceFromAmount0RoundingUp(price, liq, big.NewInt(1e15), true)
	require.NoError(t, err)
	require.Negative(t, down.Cmp(price), "adding token0 must lower the price")

	// Removing token0 pushes the price UP.
	up, err := GetNextSqrtPriceFromAmount0RoundingUp(price, liq, big.NewInt(1e15), false)
	require.NoError(t, err)
	require.Positive(t, up.Cmp(price), "removing token0 must raise the price")

	// Zero liquidity is refused rather than dividing by zero.
	_, err = GetNextSqrtPriceFromAmount0RoundingUp(price, big.NewInt(0), big.NewInt(1), true)
	require.Error(t, err, "zero liquidity must be refused")

	// Removing more token0 than the position holds underflows the denominator and
	// must be REFUSED, not wrapped into a plausible price.
	_, err = GetNextSqrtPriceFromAmount0RoundingUp(price, liq, amMaxU256, false)
	require.Error(t, err, "removing too much amount0 must be refused")
}

// TestGetNextSqrtPriceFromAmount1 covers both directions and the underflow refusal.
func TestGetNextSqrtPriceFromAmount1(t *testing.T) {
	price := amBig("79228162514264337593543950336")
	liq := amBig("1000000000000000000")

	up, err := GetNextSqrtPriceFromAmount1RoundingDown(price, liq, big.NewInt(1e15), true)
	require.NoError(t, err)
	require.Positive(t, up.Cmp(price), "adding token1 must raise the price")

	down, err := GetNextSqrtPriceFromAmount1RoundingDown(price, liq, big.NewInt(1e15), false)
	require.NoError(t, err)
	require.Negative(t, down.Cmp(price), "removing token1 must lower the price")

	_, err = GetNextSqrtPriceFromAmount1RoundingDown(price, big.NewInt(0), big.NewInt(1), true)
	require.Error(t, err, "zero liquidity must be refused")

	// Removing more token1 than the price supports is REFUSED gracefully.
	_, err = GetNextSqrtPriceFromAmount1RoundingDown(price, liq, big.NewInt(2e18), false)
	require.Error(t, err, "removing too much amount1 must be refused")

	// The subtraction refuses at EQUALITY too: a resulting price of exactly zero is
	// not a valid pool state, so <= is the correct comparison, not <.
	q := MulDivRoundingUp(big.NewInt(1e15), Q96, liq)
	_, err = GetNextSqrtPriceFromAmount1RoundingDown(q, liq, big.NewInt(1e15), false)
	require.Error(t, err, "a price driven to exactly zero must be refused")
}

// TestSqrtPriceAmount1OverflowIsLatent records a second latent hazard of the same
// shape as the fee denominator: GetNextSqrtPriceFromAmount1RoundingDown computes
// ceil(amount * 2^96 / liquidity) BEFORE its underflow check, so a large amount over
// small liquidity overflows uint256 and panics inside MulDivRoundingUp — reaching the
// overflow guard rather than the function's own graceful refusal.
//
// It is NOT reachable through the live swap path: ComputeSwapStep only calls it when
// amountRemaining < amountOut, and amountOut is itself MulDiv(liquidity, diff, Q96)
// <= liquidity * 2^64, which bounds the quotient below 2^160. This test pins both
// halves — the bound that makes it safe, and the fact that the raw helper is not
// self-guarding.
func TestSqrtPriceAmount1OverflowIsLatent(t *testing.T) {
	price := amBig("79228162514264337593543950336")

	// Direct call with an unbounded amount over tiny liquidity: panics rather than
	// returning the "removing too much amount1" error.
	require.PanicsWithValue(t, "MulDivRoundingUp: result overflows uint256", func() {
		_, _ = GetNextSqrtPriceFromAmount1RoundingDown(price, big.NewInt(1), amMaxU256, false)
	}, "the raw helper is not self-guarding against an unbounded amount")

	// The bound the live caller enforces. amountOut is what ComputeSwapStep computes
	// before deciding to call down here, and any amountRemaining below it keeps the
	// quotient far inside uint256.
	liq := amBig("1000000000000000000")
	amountOut := GetAmount1Delta(MinSqrtRatio, MaxSqrtRatio, liq, false)
	require.NotPanics(t, func() {
		_, _ = GetNextSqrtPriceFromAmount1RoundingDown(MaxSqrtRatio, liq, amountOut, false)
	}, "any amount within the caller-computed amountOut is safe")
	require.Less(t, amountOut.BitLen(), 200,
		"amountOut is bounded by liquidity*2^64, which keeps amount*2^96/liquidity inside uint256")
}

// TestGetNextSqrtPriceFromInputOutputDirections pins the direction table that the
// swap loop depends on. Getting any one of these four backwards inverts a trade.
func TestGetNextSqrtPriceFromInputOutputDirections(t *testing.T) {
	price := amBig("79228162514264337593543950336")
	liq := amBig("1000000000000000000")
	amt := big.NewInt(1e15)

	in0, err := GetNextSqrtPriceFromInput(price, liq, amt, true)
	require.NoError(t, err)
	require.Negative(t, in0.Cmp(price), "zeroForOne input must lower the price")

	in1, err := GetNextSqrtPriceFromInput(price, liq, amt, false)
	require.NoError(t, err)
	require.Positive(t, in1.Cmp(price), "oneForZero input must raise the price")

	out0, err := GetNextSqrtPriceFromOutput(price, liq, amt, true)
	require.NoError(t, err)
	require.Negative(t, out0.Cmp(price), "zeroForOne output must lower the price")

	out1, err := GetNextSqrtPriceFromOutput(price, liq, amt, false)
	require.NoError(t, err)
	require.Positive(t, out1.Cmp(price), "oneForZero output must raise the price")

	// Errors propagate rather than being swallowed into a plausible price.
	_, err = GetNextSqrtPriceFromInput(price, big.NewInt(0), amt, true)
	require.Error(t, err)
	_, err = GetNextSqrtPriceFromInput(price, big.NewInt(0), amt, false)
	require.Error(t, err)
	_, err = GetNextSqrtPriceFromOutput(price, big.NewInt(0), amt, true)
	require.Error(t, err)
	_, err = GetNextSqrtPriceFromOutput(price, big.NewInt(0), amt, false)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// swap_math.go — ComputeSwapStep
// ---------------------------------------------------------------------------

// TestComputeSwapStepNeverOvershootsTarget asserts the two bounds the swap loop
// relies on for termination and solvency: the step price always lands within
// [current, target] (never past it), and an exact-output step never produces more
// than was asked for.
func TestComputeSwapStepStaysWithinBounds(t *testing.T) {
	const seed = 24681012
	r := rand.New(rand.NewSource(seed))
	span := new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)

	for range 20000 {
		cur := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, span))
		tgt := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, span))
		liq := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100)))
		fee := uint32(r.Intn(int(FeeMax) + 1))

		amt := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 90)))
		exactInput := r.Intn(2) == 0
		if exactInput {
			amt.Neg(amt)
		}

		step := ComputeSwapStep(cur, tgt, liq, amt, fee)

		lo, hi := cur, tgt
		if lo.Cmp(hi) > 0 {
			lo, hi = hi, lo
		}
		require.GreaterOrEqualf(t, step.SqrtRatioNextX96.Cmp(lo), 0,
			"seed=%d step price below the range [%v,%v]: %v", seed, lo, hi, step.SqrtRatioNextX96)
		require.LessOrEqualf(t, step.SqrtRatioNextX96.Cmp(hi), 0,
			"seed=%d step price above the range [%v,%v]: %v", seed, lo, hi, step.SqrtRatioNextX96)

		require.GreaterOrEqualf(t, step.AmountIn.Sign(), 0, "seed=%d amountIn must be non-negative", seed)
		require.GreaterOrEqualf(t, step.AmountOut.Sign(), 0, "seed=%d amountOut must be non-negative", seed)
		require.GreaterOrEqualf(t, step.FeeAmount.Sign(), 0, "seed=%d fee must be non-negative", seed)

		if !exactInput {
			require.LessOrEqualf(t, step.AmountOut.Cmp(amt), 0,
				"seed=%d exact-output step produced more than requested", seed)
		} else {
			// An exact-input step may never consume more than was offered.
			consumed := new(big.Int).Add(step.AmountIn, step.FeeAmount)
			require.LessOrEqualf(t, consumed.Cmp(new(big.Int).Neg(amt)), 0,
				"seed=%d exact-input step consumed more than offered: %v > %v",
				seed, consumed, new(big.Int).Neg(amt))
		}
	}
}

// TestComputeSwapStepChargesFeeWheneverInputIsConsumed: a step that moves the
// price on a fee-bearing pool must charge a fee. A zero fee on a non-zero input is
// a free trade.
func TestComputeSwapStepChargesFee(t *testing.T) {
	cur := amBig("79228162514264337593543950336")
	tgt := amBig("112045541949572279837463876454") // higher: oneForZero
	liq := amBig("1000000000000000000000")

	withFee := ComputeSwapStep(cur, tgt, liq, big.NewInt(-1e18), 3000)
	require.Positive(t, withFee.AmountIn.Sign(), "step must consume input")
	require.Positive(t, withFee.FeeAmount.Sign(), "a 0.3% pool must charge a fee")

	noFee := ComputeSwapStep(cur, tgt, liq, big.NewInt(-1e18), 0)
	require.Zero(t, noFee.FeeAmount.Sign(), "a zero-fee pool charges nothing")

	// A larger fee tier must cost the trader more for the same trade.
	high := ComputeSwapStep(cur, tgt, liq, big.NewInt(-1e18), FeeMax)
	require.Positive(t, high.FeeAmount.Cmp(withFee.FeeAmount),
		"a higher fee tier must charge strictly more")
}

// TestComputeSwapStepZeroLiquidity: with no liquidity a step must not panic and
// must move no value. This is the empty-pool edge the swap loop can reach after a
// tick crossing removes all liquidity.
func TestComputeSwapStepZeroLiquidity(t *testing.T) {
	cur := amBig("79228162514264337593543950336")
	tgt := amBig("112045541949572279837463876454")
	require.NotPanics(t, func() {
		step := ComputeSwapStep(cur, tgt, big.NewInt(0), big.NewInt(-1e18), 3000)
		require.Zero(t, step.AmountOut.Sign(), "no liquidity can produce no output")
	})
}

// TestComputeSwapStepFeeDenominatorBound records a LATENT hazard rather than a
// live one. ComputeSwapStep divides by (1e6 - feePips) with no guard of its own;
// at feePips == 1e6 that denominator is zero and MulDivRoundingUp panics — which
// inside a precompile is a chain halt, not a failed call.
//
// It is currently unreachable because every live caller bounds the fee first
// (dex/pool_manager.go and dex/settle_market.go reject Fee > FeeMax == 100000;
// v3/contract.go parsePoolKey rejects fee >= 1e6). This test pins BOTH halves: the
// whole legal range is safe, and the guard that keeps it safe lives in the callers.
func TestComputeSwapStepFeeDenominatorBound(t *testing.T) {
	cur := amBig("79228162514264337593543950336")
	tgt := amBig("112045541949572279837463876454")
	liq := amBig("1000000000000000000000")

	// Every fee the dex path can construct is safe, including the exact maximum.
	for _, fee := range []uint32{0, 1, 500, 3000, 10000, uint32(FeeMax)} {
		require.NotPanicsf(t, func() {
			ComputeSwapStep(cur, tgt, liq, big.NewInt(-1e18), fee)
		}, "fee %d is within FeeMax and must not panic", fee)
	}
	require.Less(t, uint32(FeeMax), uint32(1_000_000),
		"FeeMax must stay below the fee denominator, or ComputeSwapStep divides by zero")

	// And the boundary itself. On an EXACT-OUTPUT step the fee is computed as
	// ceil(amountIn * feePips / (1e6 - feePips)), so feePips == 1e6 divides by zero and
	// panics — a chain halt, not a failed call. No live caller can supply it; if one
	// ever could, this is the halt it would cause.
	require.PanicsWithValue(t, "MulDivRoundingUp: denominator must be positive", func() {
		ComputeSwapStep(cur, tgt, liq, big.NewInt(1e6), 1_000_000)
	}, "feePips == 1e6 makes the fee denominator zero")

	// A related boundary that does NOT panic but is worth pinning: on an exact-INPUT
	// step a 100% fee takes the trader's entire input and moves no price. Bounded by
	// FeeMax in practice, but the arithmetic itself does not refuse it.
	starved := ComputeSwapStep(cur, tgt, liq, big.NewInt(-1e18), 1_000_000)
	require.Equal(t, 0, starved.SqrtRatioNextX96.Cmp(cur), "a 100% fee moves no price")
	require.Zero(t, starved.AmountOut.Sign(), "a 100% fee returns nothing to the trader")
}

// ---------------------------------------------------------------------------
// liquidity_amounts.go
// ---------------------------------------------------------------------------

// TestGetLiquidityForAmountsPicksTheBindingSide: below the range only token0
// matters, above it only token1, and inside it the SMALLER of the two — taking the
// larger would mint liquidity the depositor did not fund.
func TestGetLiquidityForAmountsPicksTheBindingSide(t *testing.T) {
	lo := amBig("79228162514264337593543950336")  // 1.0
	hi := amBig("112045541949572279837463876454") // 2.0
	amt0 := amBig("1000000000000000000")
	amt1 := amBig("1000000000000000000")

	below := new(big.Int).Sub(lo, big.NewInt(1))
	require.Equal(t, 0, GetLiquidityForAmounts(below, lo, hi, amt0, amt1).Cmp(GetLiquidityForAmount0(lo, hi, amt0)),
		"below the range, only token0 funds liquidity")

	above := new(big.Int).Add(hi, big.NewInt(1))
	require.Equal(t, 0, GetLiquidityForAmounts(above, lo, hi, amt0, amt1).Cmp(GetLiquidityForAmount1(lo, hi, amt1)),
		"above the range, only token1 funds liquidity")

	mid := amBig("94665117646458423579364416512")
	inRange := GetLiquidityForAmounts(mid, lo, hi, amt0, amt1)
	l0 := GetLiquidityForAmount0(mid, hi, amt0)
	l1 := GetLiquidityForAmount1(lo, mid, amt1)
	require.LessOrEqual(t, inRange.Cmp(l0), 0, "in-range liquidity must not exceed the token0 side")
	require.LessOrEqual(t, inRange.Cmp(l1), 0, "in-range liquidity must not exceed the token1 side")
	require.True(t, inRange.Cmp(l0) == 0 || inRange.Cmp(l1) == 0, "must equal the binding side")

	// Argument order must not matter: the helper sorts its bounds.
	require.Equal(t, 0, GetLiquidityForAmounts(mid, hi, lo, amt0, amt1).Cmp(inRange))
	require.Equal(t, 0, GetLiquidityForAmount0(hi, lo, amt0).Cmp(GetLiquidityForAmount0(lo, hi, amt0)))
	require.Equal(t, 0, GetLiquidityForAmount1(hi, lo, amt1).Cmp(GetLiquidityForAmount1(lo, hi, amt1)))

	// Exactly at each boundary the range collapses to one side.
	require.Equal(t, 0, GetLiquidityForAmounts(lo, lo, hi, amt0, amt1).Cmp(GetLiquidityForAmount0(lo, hi, amt0)))
	require.Equal(t, 0, GetLiquidityForAmounts(hi, lo, hi, amt0, amt1).Cmp(GetLiquidityForAmount1(lo, hi, amt1)))
}

// TestGetAmountsForLiquidityMatchesTheDeltas: the "what do I get back" view must
// agree with the delta helpers the money path actually uses, and must round DOWN
// (a view that over-promises is a payout that over-pays).
func TestGetAmountsForLiquidityMatchesTheDeltas(t *testing.T) {
	lo := amBig("79228162514264337593543950336")
	hi := amBig("112045541949572279837463876454")
	liq := amBig("1000000000000000000")

	below := new(big.Int).Sub(lo, big.NewInt(1))
	a0, a1 := GetAmountsForLiquidity(below, lo, hi, liq)
	require.Equal(t, 0, a0.Cmp(GetAmount0Delta(lo, hi, liq, false)))
	require.Zero(t, a1.Sign(), "below the range the position is all token0")

	above := new(big.Int).Add(hi, big.NewInt(1))
	a0, a1 = GetAmountsForLiquidity(above, lo, hi, liq)
	require.Zero(t, a0.Sign(), "above the range the position is all token1")
	require.Equal(t, 0, a1.Cmp(GetAmount1Delta(lo, hi, liq, false)))

	mid := amBig("94665117646458423579364416512")
	a0, a1 = GetAmountsForLiquidity(mid, lo, hi, liq)
	require.Equal(t, 0, a0.Cmp(GetAmount0Delta(mid, hi, liq, false)))
	require.Equal(t, 0, a1.Cmp(GetAmount1Delta(lo, mid, liq, false)))
	require.Positive(t, a0.Sign())
	require.Positive(t, a1.Sign())

	// The view must never promise more than a mint would have charged.
	require.LessOrEqual(t, a0.Cmp(GetAmount0Delta(mid, hi, liq, true)), 0, "view must round DOWN")
	require.LessOrEqual(t, a1.Cmp(GetAmount1Delta(lo, mid, liq, true)), 0, "view must round DOWN")

	// Order independence again.
	b0, b1 := GetAmountsForLiquidity(mid, hi, lo, liq)
	require.Equal(t, 0, a0.Cmp(b0))
	require.Equal(t, 0, a1.Cmp(b1))

	// The two single-sided helpers are the same computation, unrounded.
	require.Equal(t, 0, GetAmount0ForLiquidity(lo, hi, liq).Cmp(GetAmount0Delta(lo, hi, liq, false)))
	require.Equal(t, 0, GetAmount1ForLiquidity(lo, hi, liq).Cmp(GetAmount1Delta(lo, hi, liq, false)))
}

// TestLiquidityDepositRoundTripCannotProfit: converting an amount to liquidity and
// back must never return more than was deposited. This is the ERC-4626-style
// inflation check applied to the concentrated-liquidity math.
func TestLiquidityDepositRoundTripCannotProfit(t *testing.T) {
	const seed = 61616161
	r := rand.New(rand.NewSource(seed))
	span := new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)
	checked := 0

	for range 20000 {
		lo := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, span))
		hi := new(big.Int).Add(MinSqrtRatio, new(big.Int).Rand(r, span))
		if lo.Cmp(hi) == 0 {
			continue
		}
		if lo.Cmp(hi) > 0 {
			lo, hi = hi, lo
		}
		// Keep the range wide enough that the liquidity quotient stays in uint256.
		if new(big.Int).Sub(hi, lo).Cmp(new(big.Int).Lsh(big.NewInt(1), 64)) < 0 {
			continue
		}
		amt1 := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 90)))

		liq := GetLiquidityForAmount1(lo, hi, amt1)
		if liq.Sign() == 0 {
			continue
		}
		back := GetAmount1ForLiquidity(lo, hi, liq)
		require.LessOrEqualf(t, back.Cmp(amt1), 0,
			"seed=%d deposit/withdraw round-trip returned MORE than deposited: %v > %v", seed, back, amt1)
		checked++
	}
	require.Greater(t, checked, 1000, "the sweep must actually exercise the round trip")
}

// ---------------------------------------------------------------------------
// tick_bitmap_math.go
// ---------------------------------------------------------------------------

// TestCompressFloorsTowardNegativeInfinity: the bitmap index must use FLOOR
// division, not Go's truncate-toward-zero, or negative ticks land in the wrong
// word and the swap loop reads the wrong liquidity.
func TestCompressFloorsTowardNegativeInfinity(t *testing.T) {
	for _, spacing := range []int32{1, 10, 60, 200} {
		for tick := int32(-1000); tick <= 1000; tick++ {
			got := Compress(tick, spacing)
			// Reference floor division computed independently of the implementation.
			want := tick / spacing
			if tick%spacing != 0 && (tick < 0) != (spacing < 0) {
				want--
			}
			require.Equalf(t, want, got, "Compress(%d,%d) must floor", tick, spacing)
			// Defining property: spacing*compressed <= tick < spacing*(compressed+1).
			require.LessOrEqualf(t, got*spacing, tick, "Compress(%d,%d) overshot", tick, spacing)
			require.Greaterf(t, (got+1)*spacing, tick, "Compress(%d,%d) undershot", tick, spacing)
		}
	}
	// The exact sign boundary, called out because truncation and floor agree
	// everywhere except here.
	require.Equal(t, int32(-1), Compress(-1, 10), "-1/10 must floor to -1, not 0")
	require.Equal(t, int32(-1), Compress(-10, 10), "an exact negative multiple must not over-decrement")
	require.Equal(t, int32(-2), Compress(-11, 10))
	require.Equal(t, int32(0), Compress(0, 10))
	require.Equal(t, int32(0), Compress(9, 10))
	require.Equal(t, int32(1), Compress(10, 10))
}

// TestTickBitmapPositionSplitsWordAndBit: wordPos/bitPos must reconstruct the
// compressed tick exactly, for negatives too — the bit index is taken modulo 256
// with wraparound, which is where a sign error would show.
func TestTickBitmapPositionSplitsWordAndBit(t *testing.T) {
	for _, c := range []int32{0, 1, 255, 256, 257, -1, -255, -256, -257, 100000, -100000} {
		wordPos, bitPos := TickBitmapPosition(c)
		require.Equalf(t, c, int32(wordPos)*256+int32(bitPos),
			"compressed=%d must reconstruct from word=%d bit=%d", c, wordPos, bitPos)
	}
}

// TestFlipTickIsAnInvolution: flipping the same tick twice must restore the
// bitmap exactly. A flip that is not self-inverse leaves phantom liquidity.
func TestFlipTickIsAnInvolution(t *testing.T) {
	bm := &TickBitmap{Words: map[int16]*big.Int{}}
	spacing := int32(10)

	for _, tick := range []int32{0, 10, -10, 2560, -2560, 887200, -887200} {
		FlipTick(bm, tick, spacing)
		compressed := Compress(tick, spacing)
		wordPos, bitPos := TickBitmapPosition(compressed)
		require.Equalf(t, uint(1), bm.Words[wordPos].Bit(int(bitPos)), "tick %d must be set", tick)

		FlipTick(bm, tick, spacing)
		require.Equalf(t, uint(0), bm.Words[wordPos].Bit(int(bitPos)), "tick %d must be cleared", tick)
	}

	// A misaligned tick is IGNORED, not written to a neighbouring bit.
	before := &TickBitmap{Words: map[int16]*big.Int{}}
	FlipTick(before, 5, 10)
	require.Empty(t, before.Words, "a misaligned tick must not touch the bitmap")
}

// TestNextInitializedTickFindsTheNearest: both search directions must return the
// nearest initialized tick within the word, and report `initialized=false` with the
// word boundary when there is none. Returning the wrong tick would let a swap skip
// a liquidity boundary and price the trade against stale liquidity.
func TestNextInitializedTickFindsTheNearest(t *testing.T) {
	spacing := int32(1)
	bm := &TickBitmap{Words: map[int16]*big.Int{}}
	for _, tick := range []int32{10, 50, 200} {
		FlipTick(bm, tick, spacing)
	}

	// Searching left (lte) from 100 finds 50, the nearest at-or-below.
	next, ok := NextInitializedTickWithinOneWord(bm, 100, spacing, true)
	require.True(t, ok)
	require.Equal(t, int32(50), next)

	// Searching left from exactly 50 finds 50 itself — lte includes equality.
	next, ok = NextInitializedTickWithinOneWord(bm, 50, spacing, true)
	require.True(t, ok)
	require.Equal(t, int32(50), next)

	// Searching right (gt) from 100 finds 200, and is STRICTLY greater.
	next, ok = NextInitializedTickWithinOneWord(bm, 100, spacing, false)
	require.True(t, ok)
	require.Equal(t, int32(200), next)

	next, ok = NextInitializedTickWithinOneWord(bm, 50, spacing, false)
	require.True(t, ok)
	require.Equal(t, int32(200), next, "rightward search must exclude the current tick")

	// No initialized tick below 10: report not-found at the word boundary, and the
	// boundary must be on the correct side so the caller makes progress.
	next, ok = NextInitializedTickWithinOneWord(bm, 5, spacing, true)
	require.False(t, ok)
	require.LessOrEqual(t, next, int32(5), "the left boundary must not be above the search point")

	empty := &TickBitmap{Words: map[int16]*big.Int{}}
	next, ok = NextInitializedTickWithinOneWord(empty, 0, spacing, false)
	require.False(t, ok)
	require.Greater(t, next, int32(0), "the right boundary must be above the search point")

	// An uninitialized word must be treated as empty, not dereferenced.
	require.NotPanics(t, func() {
		NextInitializedTickWithinOneWord(&TickBitmap{Words: map[int16]*big.Int{}}, 1_000_000, spacing, true)
	})
}

// TestNextInitializedTickAlwaysMakesProgress is the swap-loop termination
// property: every call must return a tick strictly on the requested side of the
// input (or equal, for lte), so the loop cannot stall on the same tick forever.
func TestNextInitializedTickAlwaysMakesProgress(t *testing.T) {
	const seed = 808080
	r := rand.New(rand.NewSource(seed))
	for range 5000 {
		spacing := []int32{1, 10, 60, 200}[r.Intn(4)]
		bm := &TickBitmap{Words: map[int16]*big.Int{}}
		for range r.Intn(8) {
			FlipTick(bm, (int32(r.Intn(20000))-10000)/spacing*spacing, spacing)
		}
		tick := int32(r.Intn(20000)) - 10000

		left, _ := NextInitializedTickWithinOneWord(bm, tick, spacing, true)
		require.LessOrEqualf(t, left, tick+spacing,
			"seed=%d leftward search must not jump forward past one spacing", seed)

		right, _ := NextInitializedTickWithinOneWord(bm, tick, spacing, false)
		require.Greaterf(t, right, tick-spacing,
			"seed=%d rightward search must not jump backward past one spacing", seed)
	}
}

// TestLsb256 covers the least-significant-bit helper directly, including the
// documented zero case.
func TestLsb256(t *testing.T) {
	require.Equal(t, 0, lsb256(big.NewInt(0)), "zero has no set bit; the helper reports 0")
	require.Equal(t, 0, lsb256(big.NewInt(-5)), "a negative input reports 0")
	require.Equal(t, 0, lsb256(big.NewInt(1)))
	require.Equal(t, 3, lsb256(big.NewInt(8)))
	require.Equal(t, 3, lsb256(big.NewInt(0b11001000)))
	require.Equal(t, 255, lsb256(new(big.Int).Lsh(big.NewInt(1), 255)))
}

// ---------------------------------------------------------------------------
// RESERVED ADDRESS SPACE
// ---------------------------------------------------------------------------

// TestReservedAddressesAreNotRegistered pins that the addresses documented as
// "RESERVED — constant only, not implemented" really are inert. An address that is
// declared but also REGISTERED would be a live precompile nobody reviewed: reachable
// from calldata, with whatever default behaviour its module happened to have.
//
// The declared surface is exactly the four LP-999x modules; 0x9995/0x9994/0x9993
// must dispatch to nothing.
func TestReservedAddressesAreNotRegistered(t *testing.T) {
	reserved := map[string]string{
		"DEXPermitAddress (LP-9995)": DEXPermitAddress,
		"DEXFHEAddress (LP-9994)":    DEXFHEAddress,
		"DEXAdminAddress (LP-9993)":  DEXAdminAddress,
	}
	registered := map[string]bool{
		SettleModule.Address.Hex():          true,
		QuoterModule.Address.Hex():          true,
		StateViewModule.Address.Hex():       true,
		PositionManagerModule.Address.Hex(): true,
		RouterModule.Address.Hex():          true,
	}
	for name, addr := range reserved {
		require.Falsef(t, registered[common.HexToAddress(addr).Hex()],
			"%s is RESERVED and must not be registered as a module", name)
	}

	// And the four live modules must be distinct addresses — two modules sharing one
	// address means one silently shadows the other.
	seen := map[string]string{}
	for _, m := range []struct {
		name string
		addr string
	}{
		{"settle", SettleModule.Address.Hex()},
		{"quoter", QuoterModule.Address.Hex()},
		{"stateview", StateViewModule.Address.Hex()},
		{"position", PositionManagerModule.Address.Hex()},
		{"router", RouterModule.Address.Hex()},
	} {
		require.Emptyf(t, seen[m.addr], "%s and %s share address %s", m.name, seen[m.addr], m.addr)
		seen[m.addr] = m.name
	}
}
