// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"fmt"
	"math/big"
)

// SqrtPriceMath implements the core price/amount conversion functions
// matching Uniswap V4's SqrtPriceMath.sol.
//
// All functions operate on sqrtPriceX96 values (Q64.96 fixed-point),
// and use big.Int for uint256 arithmetic with 512-bit intermediates via MulDiv.
//
// Key invariants:
//   - amount0 = liquidity * (1/sqrtPriceA - 1/sqrtPriceB) = L * (sqrtPriceB - sqrtPriceA) / (sqrtPriceA * sqrtPriceB)
//   - amount1 = liquidity * (sqrtPriceB - sqrtPriceA)

// GetNextSqrtPriceFromAmount0RoundingUp computes the next sqrt price after
// adding/removing amount0 (token0).
//
// For exact input (add = true):  sqrtPriceNext = L * sqrtPriceCurrent / (L + amount * sqrtPriceCurrent)
// For exact output (add = false): sqrtPriceNext = L * sqrtPriceCurrent / (L - amount * sqrtPriceCurrent)
//
// Always rounds up because in the exact output case, we want to move the price
// less (to get a more conservative amount out).
func GetNextSqrtPriceFromAmount0RoundingUp(sqrtPriceX96, liquidity, amount *big.Int, add bool) (*big.Int, error) {
	if amount.Sign() == 0 {
		return new(big.Int).Set(sqrtPriceX96), nil
	}
	if liquidity.Sign() == 0 {
		return nil, fmt.Errorf("liquidity must be positive")
	}

	// numerator1 = liquidity << 96
	numerator1 := new(big.Int).Lsh(liquidity, 96)

	if add {
		// product = amount * sqrtPriceX96
		product := new(big.Int).Mul(amount, sqrtPriceX96)
		// denominator = numerator1 + product
		denominator := new(big.Int).Add(numerator1, product)
		// result = MulDivRoundingUp(numerator1, sqrtPriceX96, denominator)
		return MulDivRoundingUp(numerator1, sqrtPriceX96, denominator), nil
	}

	// Removing amount0: price goes UP
	// product = amount * sqrtPriceX96
	product := new(big.Int).Mul(amount, sqrtPriceX96)
	// denominator = numerator1 - product
	denominator := new(big.Int).Sub(numerator1, product)
	if denominator.Sign() <= 0 {
		return nil, fmt.Errorf("denominator underflow: removing too much amount0")
	}
	return MulDivRoundingUp(numerator1, sqrtPriceX96, denominator), nil
}

// GetNextSqrtPriceFromAmount1RoundingDown computes the next sqrt price after
// adding/removing amount1 (token1).
//
// For exact input (add = true):  sqrtPriceNext = sqrtPriceCurrent + amount / liquidity
// For exact output (add = false): sqrtPriceNext = sqrtPriceCurrent - amount / liquidity
//
// Always rounds down for the same conservative reasoning.
func GetNextSqrtPriceFromAmount1RoundingDown(sqrtPriceX96, liquidity, amount *big.Int, add bool) (*big.Int, error) {
	if liquidity.Sign() == 0 {
		return nil, fmt.Errorf("liquidity must be positive")
	}

	if add {
		// quotient = amount << 96 / liquidity (round down)
		quotient := MulDiv(amount, Q96, liquidity)
		result := new(big.Int).Add(sqrtPriceX96, quotient)
		return result, nil
	}

	// quotient = ceil(amount << 96 / liquidity)
	quotient := MulDivRoundingUp(amount, Q96, liquidity)
	if sqrtPriceX96.Cmp(quotient) <= 0 {
		return nil, fmt.Errorf("sqrt price underflow: removing too much amount1")
	}
	result := new(big.Int).Sub(sqrtPriceX96, quotient)
	return result, nil
}

// GetNextSqrtPriceFromInput determines the sqrt price after consuming
// `amountIn` tokens. Direction depends on zeroForOne.
func GetNextSqrtPriceFromInput(sqrtPriceX96, liquidity, amountIn *big.Int, zeroForOne bool) (*big.Int, error) {
	if zeroForOne {
		// Adding token0 → price decreases
		return GetNextSqrtPriceFromAmount0RoundingUp(sqrtPriceX96, liquidity, amountIn, true)
	}
	// Adding token1 → price increases
	return GetNextSqrtPriceFromAmount1RoundingDown(sqrtPriceX96, liquidity, amountIn, true)
}

// GetNextSqrtPriceFromOutput determines the sqrt price after producing
// `amountOut` tokens. Direction depends on zeroForOne.
func GetNextSqrtPriceFromOutput(sqrtPriceX96, liquidity, amountOut *big.Int, zeroForOne bool) (*big.Int, error) {
	if zeroForOne {
		// Getting token1 out → removing token1 → price decreases
		return GetNextSqrtPriceFromAmount1RoundingDown(sqrtPriceX96, liquidity, amountOut, false)
	}
	// Getting token0 out → removing token0 → price increases
	return GetNextSqrtPriceFromAmount0RoundingUp(sqrtPriceX96, liquidity, amountOut, false)
}

// GetAmount0Delta computes the amount of token0 between two sqrt prices.
//
//	amount0 = liquidity * (sqrtPriceUpper - sqrtPriceLower) / (sqrtPriceLower * sqrtPriceUpper)
//
// Rounding: roundUp = true for amounts owed to the pool.
func GetAmount0Delta(sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int, roundUp bool) *big.Int {
	// Ensure A < B
	a, b := sqrtRatioAX96, sqrtRatioBX96
	if a.Cmp(b) > 0 {
		a, b = b, a
	}

	numerator := new(big.Int).Sub(b, a)
	numerator.Mul(new(big.Int).Lsh(liquidity, 96), numerator)

	denominator := new(big.Int).Mul(a, b)

	if roundUp {
		return UnsafeDivRoundingUp(numerator, denominator)
	}
	return new(big.Int).Div(numerator, denominator)
}

// GetAmount1Delta computes the amount of token1 between two sqrt prices.
//
//	amount1 = liquidity * (sqrtPriceUpper - sqrtPriceLower)
//
// Rounding: roundUp = true for amounts owed to the pool.
func GetAmount1Delta(sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int, roundUp bool) *big.Int {
	// Ensure A < B
	a, b := sqrtRatioAX96, sqrtRatioBX96
	if a.Cmp(b) > 0 {
		a, b = b, a
	}

	diff := new(big.Int).Sub(b, a)

	if roundUp {
		return MulDivRoundingUp(liquidity, diff, Q96)
	}
	return MulDiv(liquidity, diff, Q96)
}

// GetAmount0DeltaSigned computes signed amount0 delta based on liquidity direction.
// Positive liquidity = positive delta (user owes pool).
// Negative liquidity = negative delta (pool owes user).
func GetAmount0DeltaSigned(sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int) *big.Int {
	if liquidity.Sign() < 0 {
		absLiq := new(big.Int).Neg(liquidity)
		return new(big.Int).Neg(GetAmount0Delta(sqrtRatioAX96, sqrtRatioBX96, absLiq, false))
	}
	return GetAmount0Delta(sqrtRatioAX96, sqrtRatioBX96, liquidity, true)
}

// GetAmount1DeltaSigned computes signed amount1 delta based on liquidity direction.
func GetAmount1DeltaSigned(sqrtRatioAX96, sqrtRatioBX96, liquidity *big.Int) *big.Int {
	if liquidity.Sign() < 0 {
		absLiq := new(big.Int).Neg(liquidity)
		return new(big.Int).Neg(GetAmount1Delta(sqrtRatioAX96, sqrtRatioBX96, absLiq, false))
	}
	return GetAmount1Delta(sqrtRatioAX96, sqrtRatioBX96, liquidity, true)
}
