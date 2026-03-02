// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
)

// SwapMath implements the core per-step swap computation matching
// Uniswap V4's SwapMath.sol.
//
// computeSwapStep is called once per tick-crossing step in the swap loop.
// It determines how far the price moves within one tick range and computes
// the amounts consumed/produced plus fees.

// SwapStepResult contains the output of a single swap step computation.
type SwapStepResult struct {
	SqrtRatioNextX96 *big.Int // New sqrt price after this step
	AmountIn         *big.Int // Amount of input token consumed (excluding fee)
	AmountOut        *big.Int // Amount of output token produced
	FeeAmount        *big.Int // Fee charged on input
}

// feeDenominator is 1e6 (fees are in pips: 1 pip = 0.0001% = 1/1_000_000).
var feeDenominator = big.NewInt(1_000_000)

// ComputeSwapStep computes the result of swapping within a single tick range.
//
// Parameters:
//   - sqrtRatioCurrentX96: current sqrt price
//   - sqrtRatioTargetX96: target sqrt price (the next initialized tick boundary)
//   - liquidity: active liquidity in the current tick range
//   - amountRemaining: how much input/output is left to consume (signed like V4)
//   - feePips: fee rate in pips (e.g., 3000 = 0.3%)
//
// V4 convention: amountRemaining < 0 means exact input, > 0 means exact output.
//
// Returns the step result.
func ComputeSwapStep(
	sqrtRatioCurrentX96, sqrtRatioTargetX96, liquidity, amountRemaining *big.Int,
	feePips uint32,
) SwapStepResult {
	zeroForOne := sqrtRatioCurrentX96.Cmp(sqrtRatioTargetX96) >= 0
	exactInput := amountRemaining.Sign() < 0

	var sqrtRatioNextX96, amountIn, amountOut, feeAmount *big.Int

	if exactInput {
		// Exact input: amountRemaining is negative, use absolute value
		amountRemainingAbs := new(big.Int).Neg(amountRemaining)

		// Deduct fee from input to get effective input amount
		amountRemainingLessFee := MulDiv(
			amountRemainingAbs,
			new(big.Int).Sub(feeDenominator, big.NewInt(int64(feePips))),
			feeDenominator,
		)

		// Compute how much input is needed to reach the target price
		if zeroForOne {
			amountIn = GetAmount0Delta(sqrtRatioTargetX96, sqrtRatioCurrentX96, liquidity, true)
		} else {
			amountIn = GetAmount1Delta(sqrtRatioCurrentX96, sqrtRatioTargetX96, liquidity, true)
		}

		// If we have enough input to reach the target, we reach it.
		// Otherwise, compute the price we can reach with available input.
		if amountRemainingLessFee.Cmp(amountIn) >= 0 {
			sqrtRatioNextX96 = new(big.Int).Set(sqrtRatioTargetX96)
		} else {
			// Can't reach target — compute next price from available input
			var err error
			sqrtRatioNextX96, err = GetNextSqrtPriceFromInput(
				sqrtRatioCurrentX96, liquidity, amountRemainingLessFee, zeroForOne,
			)
			if err != nil {
				// If computation fails (shouldn't with valid liquidity), clamp to target
				sqrtRatioNextX96 = new(big.Int).Set(sqrtRatioTargetX96)
			}
		}
	} else {
		// Exact output: amountRemaining is positive
		if zeroForOne {
			amountOut = GetAmount1Delta(sqrtRatioTargetX96, sqrtRatioCurrentX96, liquidity, false)
		} else {
			amountOut = GetAmount0Delta(sqrtRatioCurrentX96, sqrtRatioTargetX96, liquidity, false)
		}

		if amountRemaining.Cmp(amountOut) >= 0 {
			sqrtRatioNextX96 = new(big.Int).Set(sqrtRatioTargetX96)
		} else {
			var err error
			sqrtRatioNextX96, err = GetNextSqrtPriceFromOutput(
				sqrtRatioCurrentX96, liquidity, amountRemaining, zeroForOne,
			)
			if err != nil {
				sqrtRatioNextX96 = new(big.Int).Set(sqrtRatioTargetX96)
			}
		}
	}

	reachedTarget := sqrtRatioNextX96.Cmp(sqrtRatioTargetX96) == 0

	// Compute actual amounts in and out based on the price movement
	if zeroForOne {
		if !(reachedTarget && exactInput) {
			amountIn = GetAmount0Delta(sqrtRatioNextX96, sqrtRatioCurrentX96, liquidity, true)
		}
		if !(reachedTarget && !exactInput) {
			amountOut = GetAmount1Delta(sqrtRatioNextX96, sqrtRatioCurrentX96, liquidity, false)
		}
	} else {
		if !(reachedTarget && exactInput) {
			amountIn = GetAmount1Delta(sqrtRatioCurrentX96, sqrtRatioNextX96, liquidity, true)
		}
		if !(reachedTarget && !exactInput) {
			amountOut = GetAmount0Delta(sqrtRatioCurrentX96, sqrtRatioNextX96, liquidity, false)
		}
	}

	// Cap output to amountRemaining for exact output
	if !exactInput && amountOut.Cmp(amountRemaining) > 0 {
		amountOut = new(big.Int).Set(amountRemaining)
	}

	// Compute fee
	if exactInput && sqrtRatioNextX96.Cmp(sqrtRatioTargetX96) != 0 {
		// Didn't reach target: fee is everything remaining minus what was consumed
		amountRemainingAbs := new(big.Int).Neg(amountRemaining)
		feeAmount = new(big.Int).Sub(amountRemainingAbs, amountIn)
	} else {
		// Reached target or exact output: compute fee as percentage of input
		feeAmount = MulDivRoundingUp(
			amountIn,
			big.NewInt(int64(feePips)),
			new(big.Int).Sub(feeDenominator, big.NewInt(int64(feePips))),
		)
	}

	return SwapStepResult{
		SqrtRatioNextX96: sqrtRatioNextX96,
		AmountIn:         amountIn,
		AmountOut:        amountOut,
		FeeAmount:        feeAmount,
	}
}
