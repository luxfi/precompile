// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// This file PROVES that the AMM math the v3 precompile composes from package dex
// matches the canonical Uniswap v3-core reference values. Every literal below is a
// published Uniswap fixture or a value derived directly from the Uniswap formula,
// cited inline. If any of these drift, the precompile's swaps/mints are wrong and
// these tests go red — they are the math gate.
package v3

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad bigint: " + s)
	}
	return v
}

// TestVector_GetSqrtRatioAtTick checks the tick→sqrtPrice magic-constant ladder
// against Uniswap v3-core TickMath.sol constants and TickMath.spec.ts fixtures.
func TestVector_GetSqrtRatioAtTick(t *testing.T) {
	// tick 0 → 2^96 (sqrt of price 1.0). Uniswap TickMath: getSqrtRatioAtTick(0).
	got, err := dex.GetSqrtRatioAtTick(0)
	require.NoError(t, err)
	eqBig(t, mustBig("79228162514264337593543950336"), got) // == 2^96

	// MIN_TICK → MIN_SQRT_RATIO. Uniswap TickMath.MIN_SQRT_RATIO.
	got, err = dex.GetSqrtRatioAtTick(dex.MinTick)
	require.NoError(t, err)
	eqBig(t, mustBig("4295128739"), got)

	// MAX_TICK → MAX_SQRT_RATIO. Uniswap TickMath.MAX_SQRT_RATIO.
	got, err = dex.GetSqrtRatioAtTick(dex.MaxTick)
	require.NoError(t, err)
	eqBig(t, mustBig("1461446703485210103287273052203988822378723970342"), got)

	// tick ±1. Uniswap v3-core TickMath.spec.ts "getSqrtRatioAtTick" fixtures.
	got, err = dex.GetSqrtRatioAtTick(1)
	require.NoError(t, err)
	eqBig(t, mustBig("79232123823359799118286999568"), got)

	got, err = dex.GetSqrtRatioAtTick(-1)
	require.NoError(t, err)
	eqBig(t, mustBig("79224201403219477170569942574"), got)
}

// TestVector_TickRoundTrip checks the TickMath inverse: for a spread of ticks,
// getTickAtSqrtRatio(getSqrtRatioAtTick(t)) == t (Uniswap TickMath property), plus
// the two boundary fixtures from TickMath.spec.ts.
func TestVector_TickRoundTrip(t *testing.T) {
	// getTickAtSqrtRatio is defined on [MIN_SQRT_RATIO, MAX_SQRT_RATIO), so the
	// round-trippable ticks are [MinTick, MaxTick-1].
	for _, tick := range []int32{dex.MinTick, -100000, -5000, -60, -1, 0, 1, 60, 5000, 100000, dex.MaxTick - 1} {
		sp, err := dex.GetSqrtRatioAtTick(tick)
		require.NoError(t, err)
		back, err := dex.GetTickAtSqrtRatio(sp)
		require.NoError(t, err)
		require.Equalf(t, tick, back, "round-trip tick %d", tick)
	}

	// Uniswap v3-core TickMath.spec.ts: getTickAtSqrtRatio(MIN_SQRT_RATIO) == MIN_TICK.
	got, err := dex.GetTickAtSqrtRatio(dex.MinSqrtRatio)
	require.NoError(t, err)
	require.Equal(t, dex.MinTick, got)

	// Uniswap v3-core TickMath.spec.ts: getTickAtSqrtRatio(MAX_SQRT_RATIO-1) == MAX_TICK-1.
	got, err = dex.GetTickAtSqrtRatio(new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1)))
	require.NoError(t, err)
	require.Equal(t, dex.MaxTick-1, got)
}

// TestVector_AmountDeltas checks SqrtPriceMath.getAmount{0,1}Delta against values
// derived directly from the Uniswap v3-core formulas:
//
//	amount1 = L · (√P_b − √P_a) / 2^96
//	amount0 = L · 2^96 · (√P_b − √P_a) / (√P_a · √P_b)
//
// With √P_a = 2^96 (price 1) and √P_b = 2^97 (price 4) and L = 1e18 these are exact:
//
//	amount1 = 1e18 · (2^97 − 2^96)/2^96 = 1e18
//	amount0 = 1e18 · 2^96 · 2^96 / (2^96 · 2^97) = 1e18 / 2 = 5e17
func TestVector_AmountDeltas(t *testing.T) {
	q96 := mustBig("79228162514264337593543950336") // 2^96
	q97 := new(big.Int).Lsh(big.NewInt(1), 97)      // 2^97
	L := mustBig("1000000000000000000")             // 1e18

	a0 := dex.GetAmount0Delta(q96, q97, L, false)
	eqBig(t, mustBig("500000000000000000"), a0) // 5e17

	a1 := dex.GetAmount1Delta(q96, q97, L, false)
	eqBig(t, mustBig("1000000000000000000"), a1) // 1e18

	// roundUp=true is pool-favourable (the swap-in convention): never less than roundDown.
	require.True(t, dex.GetAmount0Delta(q96, q97, L, true).Cmp(a0) >= 0)
	require.True(t, dex.GetAmount1Delta(q96, q97, L, true).Cmp(a1) >= 0)
}

// TestVector_LiquidityAmountsConsistency checks the LiquidityAmounts round trip for
// an in-range position: amounts computed from the liquidity derived from amounts are
// never MORE than the originals (round-down), and the liquidity is positive. This is
// the Uniswap LiquidityAmounts.sol GetLiquidityForAmounts ↔ GetAmountsForLiquidity
// consistency property.
func TestVector_LiquidityAmountsConsistency(t *testing.T) {
	price := mustBig("79228162514264337593543950336") // 2^96, price 1, in range
	lo, err := dex.GetSqrtRatioAtTick(-600)
	require.NoError(t, err)
	hi, err := dex.GetSqrtRatioAtTick(600)
	require.NoError(t, err)

	want0 := mustBig("1000000000000000000") // 1e18
	want1 := mustBig("1000000000000000000") // 1e18

	L := dex.GetLiquidityForAmounts(price, lo, hi, want0, want1)
	require.True(t, L.Sign() > 0, "liquidity must be positive")

	a0, a1 := dex.GetAmountsForLiquidity(price, lo, hi, L)
	require.Truef(t, a0.Cmp(want0) <= 0, "amount0 %s must be <= %s", a0, want0)
	require.Truef(t, a1.Cmp(want1) <= 0, "amount1 %s must be <= %s", a1, want1)
	// Round-down loses at most 1 wei per side here.
	require.True(t, new(big.Int).Sub(want0, a0).Cmp(big.NewInt(2)) < 0)
	require.True(t, new(big.Int).Sub(want1, a1).Cmp(big.NewInt(2)) < 0)
}

// TestVector_ComputeSwapStep_ReachesTarget is the Uniswap v3-core SwapMath.spec.ts
// case "exact amount in that gets capped at price target in one for zero":
//
//	price=encodePriceSqrt(1,1)=2^96, target=encodePriceSqrt(101,100),
//	liquidity=2e18, amount=1e18 exact-in, fee=600 pips.
//
// Expected (published fixture): amountIn=9975124224178055,
// amountOut=9925619580021728, feeAmount=5988667735148, sqrtQ == target (reached).
func TestVector_ComputeSwapStep_ReachesTarget(t *testing.T) {
	price := mustBig("79228162514264337593543950336")  // encodePriceSqrt(1,1) = 2^96
	target := mustBig("79623317895830914510639640423") // encodePriceSqrt(101,100)
	liquidity := mustBig("2000000000000000000")        // 2e18
	amountRemaining := mustBig("-1000000000000000000") // -1e18 (V4: negative = exact input)

	step := dex.ComputeSwapStep(price, target, liquidity, amountRemaining, 600)

	eqBig(t, target, step.SqrtRatioNextX96) // reached the target price
	eqBig(t, mustBig("9975124224178055"), step.AmountIn)
	eqBig(t, mustBig("9925619580021728"), step.AmountOut)
	eqBig(t, mustBig("5988667735148"), step.FeeAmount)

	// Sanity: not all 1e18 was consumed (we reached the target first).
	consumed := new(big.Int).Add(step.AmountIn, step.FeeAmount)
	require.True(t, consumed.Cmp(mustBig("1000000000000000000")) < 0)
}

// TestVector_ComputeSwapStep_NotCapped is the Uniswap v3-core SwapMath.spec.ts case
// "exact amount in that is fully spent in one for zero":
//
//	price=encodePriceSqrt(1,1)=2^96, target=encodePriceSqrt(1000,100) (far),
//	liquidity=2e18, amount=1e18 exact-in, fee=600 pips.
//
// The price does NOT reach the target; the full 1e18 is spent. Expected (published
// fixture): amountIn=999400000000000000, feeAmount=600000000000000,
// amountOut=666399946655997866, and amountIn+feeAmount == 1e18, sqrtQ < target.
func TestVector_ComputeSwapStep_NotCapped(t *testing.T) {
	price := mustBig("79228162514264337593543950336")   // 2^96
	target := mustBig("250541448375047931186413801569") // encodePriceSqrt(1000,100)
	liquidity := mustBig("2000000000000000000")         // 2e18
	amountRemaining := mustBig("-1000000000000000000")  // -1e18 exact input

	step := dex.ComputeSwapStep(price, target, liquidity, amountRemaining, 600)

	require.Truef(t, step.SqrtRatioNextX96.Cmp(target) < 0, "must not reach the far target")
	eqBig(t, mustBig("999400000000000000"), step.AmountIn)
	eqBig(t, mustBig("600000000000000"), step.FeeAmount)
	eqBig(t, mustBig("666399946655997866"), step.AmountOut)

	// "Fully spent": the fee is the remainder (everything left minus what was consumed).
	consumed := new(big.Int).Add(step.AmountIn, step.FeeAmount)
	eqBig(t, mustBig("1000000000000000000"), consumed)
}

// TestVector_Constants pins the exported dex constants the precompile relies on.
func TestVector_Constants(t *testing.T) {
	eqBig(t, new(big.Int).Lsh(big.NewInt(1), 96), dex.Q96)
	eqBig(t, new(big.Int).Lsh(big.NewInt(1), 128), dex.Q128)
	require.Equal(t, int32(-887272), dex.MinTick)
	require.Equal(t, int32(887272), dex.MaxTick)
	eqBig(t, mustBig("4295128739"), dex.MinSqrtRatio)
	eqBig(t, mustBig("1461446703485210103287273052203988822378723970342"), dex.MaxSqrtRatio)
}

// TestSelectors asserts the derived 4-byte selectors match their published values,
// proving the ABI surface is stable. Values are DERIVED from the signature strings
// (methodSelector), never hand-entered, so this guards against signature drift.
func TestSelectors(t *testing.T) {
	require.Equal(t, uint32(0x3df54ad7), selInitialize)
	require.Equal(t, uint32(0xb26b3066), selMint)
	require.Equal(t, uint32(0x418c5e35), selBurn)
	require.Equal(t, uint32(0x1b1cd92d), selCollect)
	require.Equal(t, uint32(0xf4bec049), selSwap)
	require.Equal(t, uint32(0xe3f6e2b1), selSlot0)
	require.Equal(t, uint32(0xc6e7cadb), selLiquidity)
	require.Equal(t, uint32(0xebba9138), selTicks)
	require.Equal(t, uint32(0x01aed3f4), selPositions)
}

// TestModuleRegistered confirms the module registered itself at 0x…90A1 with the
// v3Config key, in the reserved DEX range. (init() panics on a bad/colliding
// address, so the test binary loading at all already proves registration.)
func TestModuleRegistered(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x00000000000000000000000000000000000090A1"), v3Addr)
	require.Equal(t, "v3Config", ConfigKey)
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, v3Addr, Module.Address)
}
