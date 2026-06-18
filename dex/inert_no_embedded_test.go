// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// TestUnconfiguredPrecompileRevertsNoEmbeddedFallback pins the one-way engine
// model: the precompile has EXACTLY ONE configured backend (ZAP -> D-Chain) and
// ONE default (inert). There is NO embedded matcher and NO local-quote path. An
// unconfigured precompile must revert cleanly on every state-moving operation
// and must never fabricate a fill, a delta, or a local AMM quote off
// precompile-held pool state.
//
// Production constructs the singleton as newDEXContract(newInertEngine()), so
// the unconfigured backend is the inertEngine (never nil). This test exercises
// that exact engine through the PoolManager surface.
func TestUnconfiguredPrecompileRevertsNoEmbeddedFallback(t *testing.T) {
	pm := NewPoolManager(newInertEngine())
	stateDB := NewMockStateDB()

	key := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}

	// Initialize reverts with the backend sentinel: no backend, no market.
	if _, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil); !errors.Is(err, ErrDEXBackendNotConfigured) {
		t.Fatalf("Initialize err = %v, want ErrDEXBackendNotConfigured", err)
	}

	// Because Initialize reverted, the pool was never created — Swap reverts
	// cleanly (ErrPoolNotInitialized) and fabricates no delta. There is no
	// embedded engine that would create the pool and self-match.
	if d, err := pm.Swap(stateDB, testTokenA, key, SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000),
		SqrtPriceLimitX96: MinSqrtRatio,
	}, nil); err == nil || !d.IsZero() {
		t.Fatalf("Swap on unconfigured precompile = (%v, %v), want (zero delta, error)", d, err)
	}

	// The inert engine itself reverts EVERY value-moving op with the sentinel
	// and returns zero deltas — the proof that no embedded fallback fabricates
	// value. (Hit directly so the not-initialized gate above can't mask it.)
	e := pm.engine
	if d, err := e.Swap(&PoolState{}, common.Address{}, SwapParams{AmountSpecified: big.NewInt(-1)}); !errors.Is(err, ErrDEXBackendNotConfigured) || !d.IsZero() {
		t.Fatalf("inert Swap = (%v, %v), want (zero, ErrDEXBackendNotConfigured)", d, err)
	}
	cd, fd, err := e.ModifyLiquidity(&PoolState{}, common.Address{}, ModifyLiquidityParams{TickLower: -60, TickUpper: 60, LiquidityDelta: big.NewInt(1)})
	if !errors.Is(err, ErrDEXBackendNotConfigured) || !cd.IsZero() || !fd.IsZero() {
		t.Fatalf("inert ModifyLiquidity = (%v, %v, %v), want (zero, zero, ErrDEXBackendNotConfigured)", cd, fd, err)
	}
	if d, err := e.Donate(&PoolState{}, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrDEXBackendNotConfigured) || !d.IsZero() {
		t.Fatalf("inert Donate = (%v, %v), want (zero, ErrDEXBackendNotConfigured)", d, err)
	}
}

// TestNoLocalQuotePath proves the embedded local-quote path is gone. It commits
// a fully-liquid pool to StateDB WITHOUT any backend wired, then drives the
// single consolidated quote path (PoolManager.calculateSwapOutput). A surviving
// embedded AMM would compute a positive output from that liquidity; the inert
// engine returns zero (no book to price). One quote path only: ZAP reads its
// canonical D-Chain pool, inert returns zero, nothing quotes locally.
func TestNoLocalQuotePath(t *testing.T) {
	pm := NewPoolManager(newInertEngine())
	stateDB := NewMockStateDB()

	key := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}
	poolId := key.ID()

	// Commit a liquid pool directly to StateDB (bypassing Initialize, which the
	// inert engine refuses). This is the precompile-held *Pool state that the
	// dead embedded path would have quoted against locally.
	liquidPool := &Pool{
		SqrtPriceX96:   new(big.Int).Set(Q96),
		Tick:           0,
		Liquidity:      big.NewInt(1_000_000_000),
		FeeGrowth0X128: big.NewInt(0),
		FeeGrowth1X128: big.NewInt(0),
	}
	pm.setPool(stateDB, poolId, liquidPool)
	if !pm.getPool(stateDB, poolId).IsInitialized() {
		t.Fatalf("test setup: committed pool must read back initialized")
	}

	// The single routed quote path: inert backend => zero, no local AMM math.
	if q := pm.calculateSwapOutput(stateDB, key, poolId, big.NewInt(10_000), true); q.Sign() != 0 {
		t.Fatalf("calculateSwapOutput on inert backend = %s, want 0 (no local-quote path)", q)
	}

	// And directly: the inert engine never quotes a liquid pool locally.
	if q := pm.engine.Quote(liquidPool, big.NewInt(10_000), true); q.Sign() != 0 {
		t.Fatalf("inert Quote of a liquid pool = %s, want 0", q)
	}

	// The inert engine is NOT a poolRouter (no canonical pool to route to) and
	// NOT a custodyEngine (no ledger). These negative assertions lock the
	// two-state model: only the configured ZAP backend implements those seams.
	if _, ok := pm.engine.(poolRouter); ok {
		t.Fatalf("inert engine must NOT implement poolRouter (would imply local pool state)")
	}
	if _, ok := pm.engine.(custodyEngine); ok {
		t.Fatalf("inert engine must NOT implement custodyEngine (would imply a local ledger)")
	}
}
