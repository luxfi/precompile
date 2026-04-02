// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import "math/big"

// FullMath implements 512-bit intermediate precision multiplication and division,
// matching Uniswap V4's FullMath.sol library.

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
	maxU256 = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 256), bigOne)
)

// MulDiv computes (a * b) / denominator with full 512-bit intermediate precision.
// Rounds toward zero. Panics if denominator is zero or result overflows uint256.
func MulDiv(a, b, denominator *big.Int) *big.Int {
	if denominator.Sign() <= 0 {
		panic("MulDiv: denominator must be positive")
	}
	// big.Int handles arbitrary precision natively, no overflow possible in intermediate.
	product := new(big.Int).Mul(a, b)
	result := new(big.Int).Div(product, denominator)
	if result.Cmp(maxU256) > 0 {
		panic("MulDiv: result overflows uint256")
	}
	return result
}

// MulDivRoundingUp computes ceil(a * b / denominator) with full precision.
func MulDivRoundingUp(a, b, denominator *big.Int) *big.Int {
	if denominator.Sign() <= 0 {
		panic("MulDivRoundingUp: denominator must be positive")
	}
	product := new(big.Int).Mul(a, b)
	result := new(big.Int).Div(product, denominator)
	// If there is a remainder, round up.
	remainder := new(big.Int).Mod(product, denominator)
	if remainder.Sign() > 0 {
		result.Add(result, bigOne)
	}
	if result.Cmp(maxU256) > 0 {
		panic("MulDivRoundingUp: result overflows uint256")
	}
	return result
}

// UnsafeDivRoundingUp computes ceil(x / y). Caller must ensure y > 0.
func UnsafeDivRoundingUp(x, y *big.Int) *big.Int {
	result := new(big.Int).Div(x, y)
	remainder := new(big.Int).Mod(x, y)
	if remainder.Sign() > 0 {
		result.Add(result, bigOne)
	}
	return result
}
