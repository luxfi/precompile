// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
)

// LiquidityAmounts implements Uniswap V4's LiquidityAmounts.sol helper library.
// These are view functions used to compute optimal liquidity from desired token amounts,
// and to compute token amounts from a given liquidity position.

// GetLiquidityForAmount0 computes the liquidity amount that corresponds to
// a given amount of token0 and price range [sqrtRatioAX96, sqrtRatioBX96].
//
//	liquidity = amount0 * sqrtRatioA * sqrtRatioB / (sqrtRatioB - sqrtRatioA)
func GetLiquidityForAmount0(sqrtRatioAX96, sqrtRatioBX96, amount0 *big.Int) *big.Int {
	a, b := sqrtRatioAX96, sqrtRatioBX96
	if a.Cmp(b) > 0 {
		a, b = b, a
	}

	intermediate := MulDiv(a, b, Q96)
	diff := new(big.Int).Sub(b, a)
	if diff.Sign() <= 0 {
		return big.NewInt(0)
	}
	return MulDiv(amount0, intermediate, diff)
}

// GetLiquidityForAmount1 computes the liquidity amount that corresponds to
// a given amount of token1 and price range [sqrtRatioAX96, sqrtRatioBX96].
//
//	liquidity = amount1 * Q96 / (sqrtRatioB - sqrtRatioA)
func GetLiquidityForAmount1(sqrtRatioAX96, sqrtRatioBX96, amount1 *big.Int) *big.Int {
	a, b := sqrtRatioAX96, sqrtRatioBX96
	if a.Cmp(b) > 0 {
		a, b = b, a
	}

	diff := new(big.Int).Sub(b, a)
	if diff.Sign() <= 0 {
		return big.NewInt(0)
	}
	return MulDiv(amount1, Q96, diff)
}

// GetLiquidityForAmounts computes the maximum liquidity that can be minted
// from the given token amounts at the current price, within the given price range.
//
// If current price is below the range, all liquidity comes from token0.
// If current price is above the range, all liquidity comes from token1.
// If current price is within the range, use the minimum of both.
func GetLiquidityForAmounts(
	sqrtRatioX96, sqrtRatioAX96, sqrtRatioBX96, amount0, amount1 *big.Int,
) *big.Int {
	a, b := sqrtRatioAX96, sqrtRatioBX96
	if a.Cmp(b) > 0 {
		a, b = b, a
	}

	if sqrtRatioX96.Cmp(a) <= 0 {
		// Current price below range: only token0 needed
		return GetLiquidityForAmount0(a, b, amount0)
	}
	if sqrtRatioX96.Cmp(b) >= 0 {
		// Current price above range: only token1 needed
		return GetLiquidityForAmount1(a, b, amount1)
	}
	// Current price within range: use min of both
	liq0 := GetLiquidityForAmount0(sqrtRatioX96, b, amount0)
	liq1 := GetLiquidityForAmount1(a, sqrtRatioX96, amount1)
	if liq0.Cmp(liq1) < 0 {
		return liq0
	}
	return liq1
}

// GetAmount0ForLiquidity computes the amount of token0 for a given liquidity
// and price range. Does not round up (used for view functions).
func GetAmount0ForLiquidity(sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int) *big.Int {
	return GetAmount0Delta(sqrtRatioAX96, sqrtRatioBX96, liquidity, false)
}

// GetAmount1ForLiquidity computes the amount of token1 for a given liquidity
// and price range. Does not round up (used for view functions).
func GetAmount1ForLiquidity(sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int) *big.Int {
	return GetAmount1Delta(sqrtRatioAX96, sqrtRatioBX96, liquidity, false)
}

// GetAmountsForLiquidity computes both token amounts for a given liquidity
// position at the current price.
func GetAmountsForLiquidity(
	sqrtRatioX96, sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int,
) (amount0, amount1 *big.Int) {
	a, b := sqrtRatioAX96, sqrtRatioBX96
	if a.Cmp(b) > 0 {
		a, b = b, a
	}

	if sqrtRatioX96.Cmp(a) <= 0 {
		// Below range: only token0
		amount0 = GetAmount0ForLiquidity(a, b, liquidity)
		amount1 = big.NewInt(0)
	} else if sqrtRatioX96.Cmp(b) >= 0 {
		// Above range: only token1
		amount0 = big.NewInt(0)
		amount1 = GetAmount1ForLiquidity(a, b, liquidity)
	} else {
		// Within range: both tokens
		amount0 = GetAmount0ForLiquidity(sqrtRatioX96, b, liquidity)
		amount1 = GetAmount1ForLiquidity(a, sqrtRatioX96, liquidity)
	}
	return
}
