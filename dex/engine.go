// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/geth/common"
)

// Engine abstracts the DEX computation backend.
// The precompile is a thin ABI shim — it holds NO canonical DEX state and runs
// NO matching itself. Matching, the resting book, fills, and value conservation
// all live on the d-chain, reached over ZAP. The precompile only translates the
// V4 PoolManager (CLOB facade) ABI into engine operations and commits the
// server-returned BalanceDelta.
//
// Two implementations live in-tree:
//
//   - inertEngine (engine_inert.go) — the package DEFAULT. No backend wired:
//     every call reverts ErrDEXBackendNotConfigured. The public EVM ships this
//     so an unconfigured chain's LP-9010 cleanly reverts instead of running a
//     wrong, second matcher.
//   - ZAPEngine (engine_zap.go) — the stateless V4->CLOB adapter that forwards
//     every operation to the d-chain CLOB gateway over ZAP. The venue installs
//     it via dex.SetBackend(NewZAPEngine(...)) when dex-zap-endpoint is set.
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
	// downstream L1 chain say e.g. "Hanzo DEX", on Lux say "Lux DEX", etc.
	// Implementations MUST return a non-empty constant; an empty value trips
	// a sanity check at SetBackend() time.
	Brand() string
}

// poolRouter is the OPTIONAL seam a backend implements when its canonical pool
// state lives elsewhere (e.g. ZAPEngine, whose pools live on the D-Chain DEX
// server). The PoolManager, which alone knows the V4 poolId, threads it to the
// backend so operations route to the right canonical pool.
//
// The inertEngine does NOT implement this: it has no backend to route to. The
// PoolManager type-asserts for poolRouter and only calls it when present, so a
// backend that holds its own state (none in-tree today) needs no routing.
type poolRouter interface {
	// InitializePool creates the canonical pool on the backend keyed by poolID
	// and records the route for ps. Returns the authoritative initial tick.
	InitializePool(ps *PoolState, poolID [32]byte, sqrtPriceX96 *big.Int, tickSpacing int32, lpFee uint32) (int24, error)

	// SetPoolID records the canonical poolID for ps so a later swap / modify /
	// donate / quote forwards to the correct server-side pool. Idempotent.
	SetPoolID(ps *PoolState, poolID [32]byte)
}

// Replay-idempotency for a marketable order (Swap) is NOT a backend concern: it
// lives in the PoolManager against StateDB, keyed by (txHash, poolId, params).
// That key is durable (survives a node restart) and consensus-shared (identical
// on every validator replaying the same block), so it maps a re-executed / reorg
// / retried tx to EXACTLY ONE d-chain match — properties an in-process backend
// cache cannot provide (RED H1). See PoolManager.swapBindKey / loadSwapBinding.
