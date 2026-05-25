// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/geth/common"
)

// Engine abstracts the DEX computation backend.
// The precompile is a thin ABI shim — all AMM math, tick crossing,
// fee growth, matching, and position management happen in the engine.
//
// Backends ship in their own packages. Two canonical implementations live
// in-tree:
//
//   - EmbeddedEngine (engine_embedded.go) — pure-Go V4 math, default for
//     upstream Lux EVM and any chain that wants a self-contained build.
//   - ZAPEngine (engine_zap.go) — binary protocol shim to an external DEX
//     process. The external process can be the upstream Lux DEX or a
//     white-label DEX such as Liquid DEX; the precompile does not care.
//
// Adding a new backend is purely additive: implement Engine, ship it in
// its own package, and have the host EVM call dex.SetBackend() before the
// chain bootstraps. The on-chain ABI (selectors at LP-9010) is invariant
// across backends — a contract compiled against the precompile address
// runs unchanged on every chain.
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

	// Brand returns the human-readable identity of the backend. The precompile
	// uses this in log lines and error wrapping so user-facing strings on a
	// regulated EVM L1 chain say "Liquid DEX", on Lux say "Lux DEX", etc. Implementations
	// MUST return a non-empty constant; an empty value trips a sanity check at
	// SetBackend() time.
	Brand() string
}
