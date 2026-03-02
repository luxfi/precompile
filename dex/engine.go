// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/geth/common"
)

// Engine abstracts the DEX computation backend.
// The precompile is a thin ABI shim -- all AMM math, tick crossing,
// fee growth, matching, and position management happen in the engine.
// Production: ZAP binary protocol to ~/work/lux/dex process.
// Embedded: Direct Go call to DEX engine linked in-process.
type Engine interface {
	// Initialize computes the initial tick from sqrtPriceX96 and creates pool state.
	Initialize(sqrtPriceX96 *big.Int) (int24, error)

	// Swap executes the full V4 tick-crossing swap loop.
	// All math happens in the engine (ComputeSwapStep, tick bitmap, fee growth).
	// Returns balance delta (amount0, amount1).
	Swap(pool *PoolState, params SwapParams) (BalanceDelta, error)

	// ModifyLiquidity adds/removes concentrated liquidity.
	// Engine handles tick updates, bitmap flips, position tracking, fee accrual.
	// Returns callerDelta and feesAccrued.
	ModifyLiquidity(pool *PoolState, owner common.Address, params ModifyLiquidityParams) (callerDelta BalanceDelta, feesAccrued BalanceDelta, err error)

	// Donate distributes tokens to LPs via fee growth updates.
	Donate(pool *PoolState, amount0, amount1 *big.Int) (BalanceDelta, error)

	// Quote estimates swap output without mutating state. Used by router.
	Quote(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int
}

// Production: use ZAPEngine (engine_zap.go) pointing to the DEX process.
// Testing: provide any Engine implementation.
