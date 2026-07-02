// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	lx "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
)

// router_v2_wire_test.go proves the LXRouter's V2 venue resolves to the NATIVE
// constant-product AMM (swap_amm_pool.go reserves + lx.ConstantProductOut), not the
// dead STATICCALL stub it used to be. When the V2 facade address is configured to the
// native DEX precompile (0x9999, exactly as the brand upgrade configs do) and a pool's
// reserves are bound, quoteV2 returns the canonical xy=k curve output for the correctly
// oriented (rx, ry). With no pool bound it falls through (returns 0, error).

// withV2Configured points the V2 facade at the native DEX precompile for the duration
// of a test and restores the prior package var on exit, so tests stay self-contained
// and order-independent.
func withV2Configured(t *testing.T) {
	t.Helper()
	prev := v2RouterAddr
	v2RouterAddr = common.HexToAddress(DEXPoolManagerAddress)
	t.Cleanup(func() { v2RouterAddr = prev })
}

func TestRouterQuoteV2ResolvesNativeAMM(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)
	withV2Configured(t)

	// Unbound pair: quoteV2 must fall through (no native liquidity), returning 0 + error.
	if out, err := router.quoteV2(stateDB, testTokenA, testTokenB, big.NewInt(1000)); err == nil || out.Sign() != 0 {
		t.Fatalf("unbound quoteV2 = (%s, %v), want (0, error) fall-through", out, err)
	}

	// Bind the canonical V2 pool (0.30% constant-product) for the A/B pair.
	// base = reserve of currency0, quote = reserve of currency1.
	const (
		baseReserve  = uint64(1_000_000)
		quoteReserve = uint64(2_000_000)
		feeBps       = uint32(30)
	)
	poolID := sortedPoolKey(testTokenA, testTokenB, Fee030, TickSpacing030, common.Address{}).ID()
	if err := BindAMMPool(newEVMStore(stateDB), poolID, baseReserve, quoteReserve, feeBps); err != nil {
		t.Fatalf("BindAMMPool: %v", err)
	}

	// FORWARD A->B: testTokenA (0x10..01) < testTokenB (0x20..02) so zeroForOne ⇒
	// rx = base (1_000_000), ry = quote (2_000_000).
	// lx.ConstantProductOut = 1000*2_000_000 / (1_000_000+1000)
	//                       = 2_000_000_000 / 1_001_000 = 1998 (floor).
	wantFwd := lx.ConstantProductOut(baseReserve, quoteReserve, 1000)
	if wantFwd != 1998 {
		t.Fatalf("forward curve output drifted: got %d, want 1998", wantFwd)
	}
	gotFwd, err := router.quoteV2(stateDB, testTokenA, testTokenB, big.NewInt(1000))
	if err != nil {
		t.Fatalf("bound quoteV2 A->B: %v", err)
	}
	if gotFwd.Cmp(new(big.Int).SetUint64(wantFwd)) != 0 {
		t.Fatalf("quoteV2 A->B = %s, want %d (lx.ConstantProductOut)", gotFwd, wantFwd)
	}
	t.Logf("quoteV2 A->B: 1000 in -> %s out (native xy=k, rx=%d ry=%d)", gotFwd, baseReserve, quoteReserve)

	// REVERSE B->A: !zeroForOne ⇒ reserves flip: rx = quote (2_000_000), ry = base
	// (1_000_000). lx.ConstantProductOut = 1000*1_000_000 / (2_000_000+1000)
	//                                    = 1_000_000_000 / 2_001_000 = 499 (floor).
	// Proves orientation is handled (the curve is NOT symmetric in direction).
	wantRev := lx.ConstantProductOut(quoteReserve, baseReserve, 1000)
	if wantRev != 499 {
		t.Fatalf("reverse curve output drifted: got %d, want 499", wantRev)
	}
	gotRev, err := router.quoteV2(stateDB, testTokenB, testTokenA, big.NewInt(1000))
	if err != nil {
		t.Fatalf("bound quoteV2 B->A: %v", err)
	}
	if gotRev.Cmp(new(big.Int).SetUint64(wantRev)) != 0 {
		t.Fatalf("quoteV2 B->A = %s, want %d (lx.ConstantProductOut)", gotRev, wantRev)
	}
	t.Logf("quoteV2 B->A: 1000 in -> %s out (native xy=k, rx=%d ry=%d)", gotRev, quoteReserve, baseReserve)
}

// TestRouterQuoteV2AmountOutOfUint64Domain proves an amountIn beyond the native AMM's
// uint64 domain falls through (0, error) rather than truncating.
func TestRouterQuoteV2AmountOutOfUint64Domain(t *testing.T) {
	stateDB := NewMockStateDB()
	router := NewLXRouter(NewPoolManager(&mockEngine{}))
	withV2Configured(t)

	poolID := sortedPoolKey(testTokenA, testTokenB, Fee030, TickSpacing030, common.Address{}).ID()
	if err := BindAMMPool(newEVMStore(stateDB), poolID, 1_000_000, 2_000_000, 30); err != nil {
		t.Fatalf("BindAMMPool: %v", err)
	}

	overUint64 := new(big.Int).Add(new(big.Int).SetUint64(^uint64(0)), big.NewInt(1)) // 2^64
	out, err := router.quoteV2(stateDB, testTokenA, testTokenB, overUint64)
	if err == nil || out.Sign() != 0 {
		t.Fatalf("out-of-domain quoteV2 = (%s, %v), want (0, error) fall-through", out, err)
	}
}

// TestRouterQuoteExactInputSingleSelectsV2 proves the full QuoteExactInputSingle path
// surfaces a VenueV2 result carrying the exact native-AMM curve output when V2 is the
// only bound venue (no V4 pool, V3 unconfigured).
func TestRouterQuoteExactInputSingleSelectsV2(t *testing.T) {
	stateDB := NewMockStateDB()
	router := NewLXRouter(NewPoolManager(&mockEngine{}))
	withV2Configured(t)

	const baseReserve, quoteReserve = uint64(1_000_000), uint64(2_000_000)
	poolID := sortedPoolKey(testTokenA, testTokenB, Fee030, TickSpacing030, common.Address{}).ID()
	if err := BindAMMPool(newEVMStore(stateDB), poolID, baseReserve, quoteReserve, 30); err != nil {
		t.Fatalf("BindAMMPool: %v", err)
	}

	results, err := router.QuoteExactInputSingle(stateDB, testTokenA, testTokenB, big.NewInt(1000), 0)
	if err != nil {
		t.Fatalf("QuoteExactInputSingle: %v", err)
	}

	want := lx.ConstantProductOut(baseReserve, quoteReserve, 1000) // 1998, as derived above
	var sawV2 bool
	for _, q := range results {
		if q.Venue == VenueV2 {
			sawV2 = true
			if q.AmountOut.Cmp(new(big.Int).SetUint64(want)) != 0 {
				t.Fatalf("VenueV2 AmountOut = %s, want %d (lx.ConstantProductOut)", q.AmountOut, want)
			}
		}
	}
	if !sawV2 {
		t.Fatalf("QuoteExactInputSingle results missing VenueV2 (got %d results)", len(results))
	}
	t.Logf("QuoteExactInputSingle surfaced VenueV2: 1000 in -> %d out", want)
}
