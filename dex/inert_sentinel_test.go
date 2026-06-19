// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// inert_sentinel_test.go is the ONE shared helper for the inert-engine sentinel /
// negative-seam assertions. Both route_not_simulate_test.go and
// inert_no_embedded_test.go pin the SAME two-state engine model — inert default
// refuses every value op and exposes no stateful seam, ZAP is the only configured
// backend — and both previously re-implemented the ~40-line negative-seam +
// behavioral-revert block. This consolidates that into one place (DRY): the seam
// assertions and the per-op revert assertions live here, and each test file calls
// the helper instead of repeating the block. There is exactly one definition of
// "this engine is the inert sentinel".

// assertInertEngineSentinel is the executable definition of the inert default: it
// holds NO stateful seam (poolRouter / custodyEngine / cancelAuthority — having any
// would imply an embedded pool / ledger / order map = a second matcher) AND every
// value-moving op refuses with ErrDEXBackendNotConfigured and a ZERO delta (it
// fabricates no fill, delta, or quote). This is the tripwire: if an embedded engine
// ever creeps back in, one of these assertions flips.
func assertInertEngineSentinel(t *testing.T, e Engine) {
	t.Helper()

	// Structural: no stateful seam => cannot embed a matcher/book/ledger/order-map.
	if _, ok := e.(poolRouter); ok {
		t.Fatal("inert engine implements poolRouter — implies embedded canonical pool state (second matcher)")
	}
	if _, ok := e.(custodyEngine); ok {
		t.Fatal("inert engine implements custodyEngine — implies an embedded balance ledger")
	}
	if _, ok := e.(cancelAuthority); ok {
		t.Fatal("inert engine implements cancelAuthority — implies an embedded resting-order map")
	}

	// Behavioral: every value-moving op refuses with the backend sentinel + zero
	// delta. No op fabricates a fill, a delta, or a quote.
	if d, err := e.Swap(&PoolState{}, common.Address{}, SwapParams{AmountSpecified: big.NewInt(-1)}); !errors.Is(err, ErrDEXBackendNotConfigured) || !d.IsZero() {
		t.Fatalf("inert Swap = (%v,%v), want (zero, ErrDEXBackendNotConfigured)", d, err)
	}
	if cd, fd, err := e.ModifyLiquidity(&PoolState{}, common.Address{}, ModifyLiquidityParams{TickLower: -60, TickUpper: 60, LiquidityDelta: big.NewInt(1)}); !errors.Is(err, ErrDEXBackendNotConfigured) || !cd.IsZero() || !fd.IsZero() {
		t.Fatalf("inert ModifyLiquidity = (%v,%v,%v), want (zero,zero,ErrDEXBackendNotConfigured)", cd, fd, err)
	}
	if d, err := e.Donate(&PoolState{}, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrDEXBackendNotConfigured) || !d.IsZero() {
		t.Fatalf("inert Donate = (%v,%v), want (zero, ErrDEXBackendNotConfigured)", d, err)
	}
}

// assertNoLocalQuotePath pins that NO embedded AMM prices precompile-held pool
// state: it commits a fully-liquid pool DIRECTLY to StateDB (bypassing Initialize,
// which the inert backend refuses) and asserts BOTH the consolidated quote path
// (calculateSwapOutput) and the raw engine Quote return ZERO — there is no book to
// read and nothing computes locally. One quote path only: ZAP reads its canonical
// D-Chain pool, inert returns zero.
func assertNoLocalQuotePath(t *testing.T, pm *PoolManager, stateDB StateDB, key PoolKey) {
	t.Helper()
	poolId := key.ID()
	liquid := &Pool{
		SqrtPriceX96:   new(big.Int).Set(Q96),
		Tick:           0,
		Liquidity:      big.NewInt(1_000_000_000),
		FeeGrowth0X128: big.NewInt(0),
		FeeGrowth1X128: big.NewInt(0),
	}
	pm.setPool(stateDB, poolId, liquid)
	if q := pm.calculateSwapOutput(stateDB, key, poolId, big.NewInt(10_000), true); q.Sign() != 0 {
		t.Fatalf("calculateSwapOutput on inert backend = %s, want 0 (NO local-quote path)", q)
	}
	if q := pm.engine.Quote(liquid, big.NewInt(10_000), true); q.Sign() != 0 {
		t.Fatalf("inert Quote of a liquid pool = %s, want 0 (NO embedded AMM)", q)
	}
}
