// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
)

// EmbeddedEngine implements Engine using the V4 math libraries directly in Go.
// This provides a standalone concentrated liquidity AMM without requiring an
// external DEX process. Uses the same math as Uniswap V4:
//   - SwapMath.computeSwapStep for per-tick step computation
//   - SqrtPriceMath for price/amount conversions
//   - TickBitmap for initialized tick discovery
//   - TickMath for tick <-> sqrtPrice conversions
//
// The swap loop iterates through initialized ticks, crossing them when the price
// reaches a tick boundary, updating liquidity net and fee growth.
type EmbeddedEngine struct{}

var _ Engine = (*EmbeddedEngine)(nil)

// NewEmbeddedEngine creates a new embedded engine.
func NewEmbeddedEngine() *EmbeddedEngine {
	return &EmbeddedEngine{}
}

// Brand returns the OSS backend identity. White-label EVMs that wrap this
// engine and want their brand to surface to users MUST construct their own
// Engine — typically by wrapping EmbeddedEngine and overriding Brand() —
// rather than mutating this default. See the LiquidDEXBackend reference
// wrapper in the Liquidity tree for an example.
func (e *EmbeddedEngine) Brand() string { return "Lux DEX" }

// Initialize computes the tick from sqrtPriceX96.
func (e *EmbeddedEngine) Initialize(sqrtPriceX96 *big.Int) (int24, error) {
	tick, err := GetTickAtSqrtRatio(sqrtPriceX96)
	if err != nil {
		return 0, fmt.Errorf("initialize: %w", err)
	}
	return tick, nil
}

// Swap executes the full V4 tick-crossing swap loop on a PoolState.
// Mutates pool state: sqrtPriceX96, tick, liquidity, feeGrowthGlobal.
func (e *EmbeddedEngine) Swap(pool *PoolState, params SwapParams) (BalanceDelta, error) {
	if pool.Liquidity.Sign() == 0 && params.AmountSpecified.Sign() != 0 {
		// Check if there's any liquidity at all (bitmap might have initialized ticks)
		// Allow the swap to proceed - it will naturally fail if there's no liquidity
	}

	zeroForOne := params.ZeroForOne
	exactInput := params.AmountSpecified.Sign() < 0

	// Validate price limit
	sqrtPriceLimitX96 := params.SqrtPriceLimitX96
	if sqrtPriceLimitX96 == nil || sqrtPriceLimitX96.Sign() == 0 {
		if zeroForOne {
			sqrtPriceLimitX96 = new(big.Int).Add(MinSqrtRatio, bigOne)
		} else {
			sqrtPriceLimitX96 = new(big.Int).Sub(MaxSqrtRatio, bigOne)
		}
	}

	if zeroForOne {
		if sqrtPriceLimitX96.Cmp(pool.SqrtPriceX96) >= 0 {
			return ZeroBalanceDelta(), ErrPriceLimitReached
		}
		if sqrtPriceLimitX96.Cmp(MinSqrtRatio) <= 0 {
			return ZeroBalanceDelta(), ErrInvalidSqrtPrice
		}
	} else {
		if sqrtPriceLimitX96.Cmp(pool.SqrtPriceX96) <= 0 {
			return ZeroBalanceDelta(), ErrPriceLimitReached
		}
		if sqrtPriceLimitX96.Cmp(MaxSqrtRatio) >= 0 {
			return ZeroBalanceDelta(), ErrInvalidSqrtPrice
		}
	}

	// Swap state
	amountSpecifiedRemaining := new(big.Int).Set(params.AmountSpecified)
	amountCalculated := big.NewInt(0)
	sqrtPriceX96 := new(big.Int).Set(pool.SqrtPriceX96)
	tick := pool.Tick
	liquidity := new(big.Int).Set(pool.Liquidity)
	feeGrowthGlobal := new(big.Int)
	if zeroForOne {
		feeGrowthGlobal.Set(pool.FeeGrowth0X128)
	} else {
		feeGrowthGlobal.Set(pool.FeeGrowth1X128)
	}

	// Swap loop: iterate through ticks until amount is exhausted or price limit hit
	maxIterations := 500 // Safety bound to prevent infinite loops
	for i := 0; amountSpecifiedRemaining.Sign() != 0 && sqrtPriceX96.Cmp(sqrtPriceLimitX96) != 0 && i < maxIterations; i++ {
		// Find the next initialized tick in the swap direction
		tickNext, initialized := NextInitializedTickWithinOneWord(
			pool.TickBitmap, tick, pool.TickSpacing, zeroForOne,
		)

		// Clamp tick to valid range
		if tickNext < MinTick {
			tickNext = MinTick
		}
		if tickNext > MaxTick {
			tickNext = MaxTick
		}

		// Get the sqrt price at the next tick
		sqrtPriceNextX96, err := GetSqrtRatioAtTick(tickNext)
		if err != nil {
			return ZeroBalanceDelta(), fmt.Errorf("swap: getSqrtRatioAtTick(%d): %w", tickNext, err)
		}

		// Determine the target price for this step: either the next tick or the limit
		sqrtRatioTargetX96 := sqrtPriceNextX96
		if zeroForOne {
			if sqrtPriceNextX96.Cmp(sqrtPriceLimitX96) < 0 {
				sqrtRatioTargetX96 = sqrtPriceLimitX96
			}
		} else {
			if sqrtPriceNextX96.Cmp(sqrtPriceLimitX96) > 0 {
				sqrtRatioTargetX96 = sqrtPriceLimitX96
			}
		}

		// Compute this swap step
		step := ComputeSwapStep(
			sqrtPriceX96,
			sqrtRatioTargetX96,
			liquidity,
			amountSpecifiedRemaining,
			pool.LPFee,
		)

		// Update running amounts
		if exactInput {
			// amountSpecifiedRemaining is negative (exact input consumed)
			consumed := new(big.Int).Add(step.AmountIn, step.FeeAmount)
			amountSpecifiedRemaining.Add(amountSpecifiedRemaining, consumed) // becomes less negative
			amountCalculated.Sub(amountCalculated, step.AmountOut)           // output is negative (owed to user)
		} else {
			amountSpecifiedRemaining.Sub(amountSpecifiedRemaining, step.AmountOut) // exact output consumed
			consumed := new(big.Int).Add(step.AmountIn, step.FeeAmount)
			amountCalculated.Add(amountCalculated, consumed) // input owed to pool
		}

		// Update fee growth global
		if step.FeeAmount.Sign() > 0 && liquidity.Sign() > 0 {
			// feeGrowthGlobal += (feeAmount << 128) / liquidity
			feeGrowthDelta := MulDiv(step.FeeAmount, Q128, liquidity)
			feeGrowthGlobal.Add(feeGrowthGlobal, feeGrowthDelta)
		}

		// Update price
		sqrtPriceX96 = step.SqrtRatioNextX96

		// Cross tick if we reached the next initialized tick
		if sqrtPriceX96.Cmp(sqrtPriceNextX96) == 0 {
			if initialized {
				// Cross the tick: update liquidity from tick's net liquidity
				tickInfo := pool.Ticks[tickNext]
				if tickInfo != nil {
					liquidityNet := new(big.Int).Set(tickInfo.LiquidityNet)

					// When moving left (zeroForOne), negate liquidityNet
					if zeroForOne {
						liquidityNet.Neg(liquidityNet)
					}

					liquidity.Add(liquidity, liquidityNet)

					// Update tick's fee growth outside
					// When crossing a tick, the fee growth outside flips:
					// feeGrowthOutside = feeGrowthGlobal - feeGrowthOutside
					if tickInfo.FeeGrowthOutside0X128 != nil {
						if zeroForOne {
							tickInfo.FeeGrowthOutside0X128 = new(big.Int).Sub(feeGrowthGlobal, tickInfo.FeeGrowthOutside0X128)
							tickInfo.FeeGrowthOutside1X128 = new(big.Int).Sub(pool.FeeGrowth1X128, tickInfo.FeeGrowthOutside1X128)
						} else {
							tickInfo.FeeGrowthOutside0X128 = new(big.Int).Sub(pool.FeeGrowth0X128, tickInfo.FeeGrowthOutside0X128)
							tickInfo.FeeGrowthOutside1X128 = new(big.Int).Sub(feeGrowthGlobal, tickInfo.FeeGrowthOutside1X128)
						}
					}
				}
			}

			// Update tick: when zeroForOne, we just crossed the tick going left
			if zeroForOne {
				tick = tickNext - 1
			} else {
				tick = tickNext
			}
		} else {
			// Didn't reach the tick — recompute tick from price
			newTick, err := GetTickAtSqrtRatio(sqrtPriceX96)
			if err == nil {
				tick = newTick
			}
		}
	}

	// Update pool state
	pool.SqrtPriceX96 = sqrtPriceX96
	pool.Tick = tick
	pool.Liquidity = liquidity

	if zeroForOne {
		pool.FeeGrowth0X128 = feeGrowthGlobal
	} else {
		pool.FeeGrowth1X128 = feeGrowthGlobal
	}

	// Compute balance delta in V4 internal convention:
	// V4 Solidity: negative = user spent (paying), positive = user received
	var v4amount0, v4amount1 *big.Int
	if zeroForOne == exactInput {
		v4amount0 = new(big.Int).Sub(params.AmountSpecified, amountSpecifiedRemaining)
		v4amount1 = amountCalculated
	} else {
		v4amount0 = amountCalculated
		v4amount1 = new(big.Int).Sub(params.AmountSpecified, amountSpecifiedRemaining)
	}

	// Convert to Go BalanceDelta convention: positive = user owes pool, negative = pool owes user.
	// V4 Solidity uses opposite signs: negative = user paid, positive = user received.
	// Negate both to convert.
	amount0 := new(big.Int).Neg(v4amount0)
	amount1 := new(big.Int).Neg(v4amount1)
	return NewBalanceDelta(amount0, amount1), nil
}

// ModifyLiquidity adds or removes concentrated liquidity.
// Handles tick updates, bitmap flips, position tracking, fee accrual.
func (e *EmbeddedEngine) ModifyLiquidity(pool *PoolState, owner common.Address, params ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	tickLower := params.TickLower
	tickUpper := params.TickUpper
	liquidityDelta := params.LiquidityDelta

	// Get or create position
	posKey := PositionKey(owner, tickLower, tickUpper, params.Salt)
	pos, ok := pool.Positions[posKey]
	if !ok {
		pos = &Position{
			Owner:                    owner,
			TickLower:                tickLower,
			TickUpper:                tickUpper,
			Liquidity:                big.NewInt(0),
			FeeGrowthInside0LastX128: big.NewInt(0),
			FeeGrowthInside1LastX128: big.NewInt(0),
			TokensOwed0:              big.NewInt(0),
			TokensOwed1:              big.NewInt(0),
		}
		pool.Positions[posKey] = pos
	}

	// Compute fee growth inside the tick range
	feeGrowthInside0X128, feeGrowthInside1X128 := e.getFeeGrowthInside(
		pool, tickLower, tickUpper,
	)

	// Compute fees owed to the position
	feesOwed0 := big.NewInt(0)
	feesOwed1 := big.NewInt(0)
	if pos.Liquidity.Sign() > 0 {
		feeGrowthDelta0 := new(big.Int).Sub(feeGrowthInside0X128, pos.FeeGrowthInside0LastX128)
		if feeGrowthDelta0.Sign() < 0 {
			// Handle underflow (modular arithmetic)
			feeGrowthDelta0.Add(feeGrowthDelta0, new(big.Int).Lsh(bigOne, 256))
		}
		feesOwed0 = MulDiv(feeGrowthDelta0, pos.Liquidity, Q128)

		feeGrowthDelta1 := new(big.Int).Sub(feeGrowthInside1X128, pos.FeeGrowthInside1LastX128)
		if feeGrowthDelta1.Sign() < 0 {
			feeGrowthDelta1.Add(feeGrowthDelta1, new(big.Int).Lsh(bigOne, 256))
		}
		feesOwed1 = MulDiv(feeGrowthDelta1, pos.Liquidity, Q128)
	}

	// Update position
	pos.FeeGrowthInside0LastX128 = new(big.Int).Set(feeGrowthInside0X128)
	pos.FeeGrowthInside1LastX128 = new(big.Int).Set(feeGrowthInside1X128)
	pos.TokensOwed0 = new(big.Int).Add(pos.TokensOwed0, feesOwed0)
	pos.TokensOwed1 = new(big.Int).Add(pos.TokensOwed1, feesOwed1)

	// Update liquidity delta on ticks
	if liquidityDelta.Sign() != 0 {
		// Update lower tick
		e.updateTick(pool, tickLower, liquidityDelta, false)
		// Update upper tick
		e.updateTick(pool, tickUpper, liquidityDelta, true)

		// Update position liquidity
		newLiq := new(big.Int).Add(pos.Liquidity, liquidityDelta)
		if newLiq.Sign() < 0 {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("insufficient position liquidity")
		}
		pos.Liquidity = newLiq

		// Update active liquidity if current tick is in range
		currentTick := pool.Tick
		if currentTick >= tickLower && currentTick < tickUpper {
			pool.Liquidity = new(big.Int).Add(pool.Liquidity, liquidityDelta)
			if pool.Liquidity.Sign() < 0 {
				pool.Liquidity = big.NewInt(0)
			}
		}
	}

	// Compute token amounts required/returned for this liquidity change
	var amount0, amount1 *big.Int

	sqrtPriceLowerX96, _ := GetSqrtRatioAtTick(tickLower)
	sqrtPriceUpperX96, _ := GetSqrtRatioAtTick(tickUpper)

	amount0 = GetAmount0DeltaSigned(pool.SqrtPriceX96, sqrtPriceUpperX96, liquidityDelta)
	amount1 = GetAmount1DeltaSigned(sqrtPriceLowerX96, pool.SqrtPriceX96, liquidityDelta)

	// If current tick is below the range, only token0 is needed
	if pool.Tick < tickLower {
		amount0 = GetAmount0DeltaSigned(sqrtPriceLowerX96, sqrtPriceUpperX96, liquidityDelta)
		amount1 = big.NewInt(0)
	} else if pool.Tick >= tickUpper {
		// Above range: only token1
		amount0 = big.NewInt(0)
		amount1 = GetAmount1DeltaSigned(sqrtPriceLowerX96, sqrtPriceUpperX96, liquidityDelta)
	}

	callerDelta := NewBalanceDelta(amount0, amount1)
	feesAccrued := NewBalanceDelta(
		new(big.Int).Neg(feesOwed0), // Fees are owed to user (negative from pool perspective)
		new(big.Int).Neg(feesOwed1),
	)

	return callerDelta, feesAccrued, nil
}

// Donate distributes tokens to LPs via fee growth updates.
func (e *EmbeddedEngine) Donate(pool *PoolState, amount0, amount1 *big.Int) (BalanceDelta, error) {
	if pool.Liquidity == nil || pool.Liquidity.Sign() <= 0 {
		return ZeroBalanceDelta(), ErrNoLiquidity
	}

	if amount0 != nil && amount0.Sign() > 0 {
		feeGrowthDelta := MulDiv(amount0, Q128, pool.Liquidity)
		pool.FeeGrowth0X128 = new(big.Int).Add(pool.FeeGrowth0X128, feeGrowthDelta)
	}
	if amount1 != nil && amount1.Sign() > 0 {
		feeGrowthDelta := MulDiv(amount1, Q128, pool.Liquidity)
		pool.FeeGrowth1X128 = new(big.Int).Add(pool.FeeGrowth1X128, feeGrowthDelta)
	}

	a0 := amount0
	a1 := amount1
	if a0 == nil {
		a0 = big.NewInt(0)
	}
	if a1 == nil {
		a1 = big.NewInt(0)
	}
	return NewBalanceDelta(a0, a1), nil
}

// Quote estimates swap output without mutating state.
func (e *EmbeddedEngine) Quote(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int {
	if pool.Liquidity.Sign() == 0 || amountIn.Sign() <= 0 {
		return big.NewInt(0)
	}

	// Simple single-step quote using current liquidity (no tick crossing).
	// For a more accurate quote, callers should use the full Swap path.
	var sqrtPriceLimitX96 *big.Int
	if zeroForOne {
		sqrtPriceLimitX96 = new(big.Int).Add(MinSqrtRatio, bigOne)
	} else {
		sqrtPriceLimitX96 = new(big.Int).Sub(MaxSqrtRatio, bigOne)
	}

	step := ComputeSwapStep(
		pool.SqrtPriceX96,
		sqrtPriceLimitX96,
		pool.Liquidity,
		new(big.Int).Neg(amountIn), // exact input convention
		3000,                       // default fee
	)
	return new(big.Int).Abs(step.AmountOut)
}

// updateTick updates tick state when liquidity is added/removed.
func (e *EmbeddedEngine) updateTick(pool *PoolState, tick int32, liquidityDelta *big.Int, upper bool) {
	ti := pool.getOrCreateTick(tick)

	liquidityGrossBefore := new(big.Int).Set(ti.LiquidityGross)
	liquidityGrossAfter := new(big.Int).Add(liquidityGrossBefore, liquidityDelta)

	// Handle flip: when a tick goes from 0 to nonzero liquidity or vice versa
	flipped := (liquidityGrossAfter.Sign() == 0) != (liquidityGrossBefore.Sign() == 0)

	if flipped {
		FlipTick(pool.TickBitmap, tick, pool.TickSpacing)
	}

	ti.LiquidityGross = liquidityGrossAfter

	if upper {
		// Upper tick: subtract liquidity net
		ti.LiquidityNet = new(big.Int).Sub(ti.LiquidityNet, liquidityDelta)
	} else {
		// Lower tick: add liquidity net
		ti.LiquidityNet = new(big.Int).Add(ti.LiquidityNet, liquidityDelta)
	}

	// Initialize fee growth outside for new ticks below the current tick
	if flipped && liquidityGrossAfter.Sign() > 0 {
		if tick <= pool.Tick {
			ti.FeeGrowthOutside0X128 = new(big.Int).Set(pool.FeeGrowth0X128)
			ti.FeeGrowthOutside1X128 = new(big.Int).Set(pool.FeeGrowth1X128)
		}
	}

	// Clean up tick if all liquidity removed
	if liquidityGrossAfter.Sign() == 0 {
		ti.LiquidityNet = big.NewInt(0)
		ti.FeeGrowthOutside0X128 = big.NewInt(0)
		ti.FeeGrowthOutside1X128 = big.NewInt(0)
	}
}

// getFeeGrowthInside computes fee growth accumulated within a tick range.
func (e *EmbeddedEngine) getFeeGrowthInside(pool *PoolState, tickLower, tickUpper int32) (*big.Int, *big.Int) {
	tiLower := pool.Ticks[tickLower]
	tiUpper := pool.Ticks[tickUpper]

	var feeGrowthBelow0, feeGrowthBelow1, feeGrowthAbove0, feeGrowthAbove1 *big.Int

	if tiLower != nil {
		if pool.Tick >= tickLower {
			feeGrowthBelow0 = tiLower.FeeGrowthOutside0X128
			feeGrowthBelow1 = tiLower.FeeGrowthOutside1X128
		} else {
			feeGrowthBelow0 = new(big.Int).Sub(pool.FeeGrowth0X128, tiLower.FeeGrowthOutside0X128)
			feeGrowthBelow1 = new(big.Int).Sub(pool.FeeGrowth1X128, tiLower.FeeGrowthOutside1X128)
		}
	} else {
		feeGrowthBelow0 = big.NewInt(0)
		feeGrowthBelow1 = big.NewInt(0)
	}

	if tiUpper != nil {
		if pool.Tick < tickUpper {
			feeGrowthAbove0 = tiUpper.FeeGrowthOutside0X128
			feeGrowthAbove1 = tiUpper.FeeGrowthOutside1X128
		} else {
			feeGrowthAbove0 = new(big.Int).Sub(pool.FeeGrowth0X128, tiUpper.FeeGrowthOutside0X128)
			feeGrowthAbove1 = new(big.Int).Sub(pool.FeeGrowth1X128, tiUpper.FeeGrowthOutside1X128)
		}
	} else {
		feeGrowthAbove0 = big.NewInt(0)
		feeGrowthAbove1 = big.NewInt(0)
	}

	feeGrowthInside0 := new(big.Int).Sub(pool.FeeGrowth0X128, feeGrowthBelow0)
	feeGrowthInside0.Sub(feeGrowthInside0, feeGrowthAbove0)

	feeGrowthInside1 := new(big.Int).Sub(pool.FeeGrowth1X128, feeGrowthBelow1)
	feeGrowthInside1.Sub(feeGrowthInside1, feeGrowthAbove1)

	return feeGrowthInside0, feeGrowthInside1
}
