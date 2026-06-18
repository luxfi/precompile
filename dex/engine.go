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

	// Swap submits a marketable order to the CLOB and returns the fills' net
	// BalanceDelta. The taker identity (caller) is bound so the order's spend is
	// locked + settled against the caller's D-Chain ledger account (the funds the
	// caller DEPOSITED via Deposit). Returns balance delta (amount0, amount1).
	Swap(pool *PoolState, caller common.Address, params SwapParams) (BalanceDelta, error)

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

// custodyEngine is the OPTIONAL seam a backend implements when it carries a
// per-account balance ledger that funds and settles orders — i.e. the CLOB
// custody model where "the money lives in the order book". The PoolManager calls
// it to move value INTO the ledger (Deposit, after locking the asset in the 0x9010
// vault) and OUT of it (Withdraw, before releasing the asset), and to bind a
// market's assets (OpenMarket) so the ledger value-checks orders.
//
// The inertEngine does NOT implement this (no ledger to fund). The PoolManager
// type-asserts for custodyEngine and a deposit/withdraw selector reverts cleanly
// when the backend is not custody-capable. ZAPEngine implements it by relaying
// clob_deposit / clob_withdraw / clob_open_market to the D-Chain.
//
// asset handles: a Currency's 20-byte address folds to the 8-byte D-Chain asset
// handle (assetHandle in engine_zap.go); native LUX (address(0)) folds to 0.
type custodyEngine interface {
	// OpenMarket binds (base=currency0, quote=currency1) asset handles for poolID
	// so the D-Chain custody gate value-checks orders. Idempotent.
	OpenMarket(poolID [32]byte, base, quote Currency) error
	// Deposit credits exactly amount of asset into account's available D-Chain
	// balance. Called AFTER the vault lock leg. Refuses a short credit.
	Deposit(account common.Address, asset Currency, amount uint64) error
	// Withdraw debits up to want of asset from account's available balance and
	// returns the realized amount (clamped). The caller releases exactly realized
	// from the vault. realized > want is refused (mint guard).
	Withdraw(account common.Address, asset Currency, want uint64) (uint64, error)
	// Balance returns account's AVAILABLE balance for asset (read-only, no
	// mutation). Used by the balanceOf view selector.
	Balance(account common.Address, asset Currency) (uint64, error)
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

// cancelAuthority is the OPTIONAL seam a backend exposes when it resolves a maker's
// resting order through an in-process handle map (e.g. ZAPEngine.orderRef). The
// AUTHORITATIVE owner<->order binding lives in the PoolManager's durable StateDB
// (cancelAuthKey / loadCancelAuth); the backend map is only a read-through cache,
// exactly like the pool/positions caches. The PoolManager uses this seam to:
//
//   - OrderHandle: read the orderID the backend bound at place time, so the
//     PoolManager can persist it to StateDB durably.
//   - SeedOrderHandle: prime the backend cache from the durable orderID before a
//     cancel, so the backend resolves the same order across the EVM's repeated
//     executions of the cancel tx (the place's in-memory binding does not survive
//     to a later tx / a node restart).
//
// The inertEngine does NOT implement this (no resting book). The PoolManager type-
// asserts and only drives the durable binding when the backend is cancelAuthority-
// capable, so a stateless backend needs no seam.
type cancelAuthority interface {
	// OrderHandle returns the server orderID the backend currently has bound to the
	// (maker, poolId, salt) handle, or ok=false if none. Read straight after a
	// successful place so the PoolManager can store it durably.
	OrderHandle(maker common.Address, poolID [32]byte, salt [32]byte) (orderID uint64, ok bool)

	// SeedOrderHandle primes the backend's read-through cache with the durable
	// (maker, poolId, salt) -> orderID binding so a later cancel resolves it even
	// when the backend's process memory never saw the place (different tx / restart).
	SeedOrderHandle(maker common.Address, poolID [32]byte, salt [32]byte, orderID uint64)
}
