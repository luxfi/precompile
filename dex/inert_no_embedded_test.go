// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"
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

	// The inert engine itself is the sentinel: no stateful seam and every value op
	// reverts with ErrDEXBackendNotConfigured + zero delta — the proof that no
	// embedded fallback fabricates value. (Hit directly so the not-initialized gate
	// above can't mask it. Shared definition — see assertInertEngineSentinel.)
	assertInertEngineSentinel(t, pm.engine)
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
	// Sanity: the committed liquid pool reads back initialized — so a surviving
	// embedded AMM WOULD have priced it (this is what makes the zero-quote
	// assertion below meaningful, not vacuous).
	poolId := key.ID()
	pm.setPool(stateDB, poolId, &Pool{
		SqrtPriceX96:   new(big.Int).Set(Q96),
		Tick:           0,
		Liquidity:      big.NewInt(1_000_000_000),
		FeeGrowth0X128: big.NewInt(0),
		FeeGrowth1X128: big.NewInt(0),
	})
	if !pm.getPool(stateDB, poolId).IsInitialized() {
		t.Fatalf("test setup: committed pool must read back initialized")
	}

	// No local-quote path: the consolidated quote path and the raw engine BOTH
	// return zero for that liquid pool, and the inert engine exposes no stateful
	// seam. (Shared definitions — assertNoLocalQuotePath + assertInertEngineSentinel.)
	assertNoLocalQuotePath(t, pm, stateDB, key)
	assertInertEngineSentinel(t, pm.engine)
}
