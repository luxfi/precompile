// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/dex/pkg/dexcore"
)

// swap_sync_mevfloor_redteam_test.go is the RED suite for the SYNCHRONOUS 0x9999 router's
// SELL-side MEV floor (H3). The pre-existing native_swap_mevfloor_redteam_test.go covers
// the TAKER-AUTHENTICATED floor on the ASYNC intent/settlement rail (ImportSettlement);
// this suite covers the SYNCHRONOUS in-process router, which before this fix had NO SELL
// floor at all: minAmountOutU64 always returned 0, so a no-limit market SELL swept the
// resting book at any price with zero slippage protection (the BUY side was guarded by
// dexcore.ErrBuyRequiresLimit; the SELL side was not).
//
// THE ATTACK. A sandwich attacker brackets the taker's tx: they cancel/withdraw the fair
// resting bids and leave only a LOW bid, so the taker's no-limit market SELL fills at the
// attacker's price; the attacker buys the spread back. With no floor the taker eats it.
//
// THE FIX (two layers, both proven here):
//  1. A market SELL (no price limit) with NO declared min-out is REFUSED outright
//     (ErrSellRequiresProtection) — an unprotected market sell never executes on the
//     public value surface.
//  2. A market SELL that DOES declare a min-out (via the DM01 hookData) reverts when the
//     realized proceeds fall BELOW that floor (dexcore.enforceProceedsPriceFloor / the
//     MinOut check bites), so the sandwich cannot fill the taker at the attacker's price.

// TestRED_SyncSell_NoLimitNoMinOut_Refused proves layer 1: an exact-input market SELL with
// neither a price limit nor a min-out floor is refused before it can sweep the book.
func TestRED_SyncSell_NoLimitNoMinOut_Refused(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// A fair resting bid exists (100 LETH @ 50). The taker, however, submits a market SELL
	// with NO price limit and NO min-out — the unprotected market sell.
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, uint64(50)*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	// Build a market SELL with EMPTY hookData (no min-out) and zero sqrt limit (no price
	// limit). This must be refused at request-build (ErrSellRequiresProtection).
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, nil) // no DM01 -> no floor
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err == nil {
		t.Fatal("an unprotected market SELL (no limit, no min-out) MUST be refused")
	}
	if !errors.Is(err, ErrSellRequiresProtection) {
		t.Fatalf("expected ErrSellRequiresProtection, got: %v", err)
	}
	// Fail-closed: the taker kept their LETH (the swap never executed).
	if got := h.ercBal(e2eLETH, taker); got != 80 {
		t.Fatalf("a refused swap must leave the taker's LETH untouched, got %d want 80", got)
	}
}

// TestRED_SyncSell_SandwichedBelowFloor_Reverts proves layer 2: a market SELL that
// declares a min-out floor reverts when the only available (sandwich) liquidity would fill
// it BELOW that floor. The taker is not sold at the attacker's price.
func TestRED_SyncSell_SandwichedBelowFloor_Reverts(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// THE SANDWICH: the only resting bid is a LOW one — 80 LETH @ 30 (the attacker's
	// price). A fair price would be ~50. The maker locks 80*30 = 2400 LUSD.
	h.mint(e2eLUSD, maker, 2400)
	h.deposit(t, maker, e2eLUSD, 2400)
	h.placeArgs(t, maker, true, uint64(30)*uint64(priceMultiplierConst), 80)

	// The taker sells 80 LETH and declares a min-out floor of 4000 LUSD (they expect ~50/
	// base; "I will not accept less than 4000 for 80"). The only fill available is 80@30 =
	// 2400 < 4000, so the swap MUST revert (the floor bites).
	h.mint(e2eLETH, taker, 80)
	_, err := h.swapMinOut(t, taker, 80, 4000)
	if err == nil {
		t.Fatal("a market SELL whose realized proceeds fall below the declared min-out MUST revert")
	}
	if !errors.Is(err, dexcore.ErrPriceLimit) {
		t.Fatalf("expected dexcore.ErrPriceLimit (min-out floor breach), got: %v", err)
	}
	// Fail-closed atomicity: the taker keeps their LETH; the attacker's bid is untouched.
	if got := h.ercBal(e2eLETH, taker); got != 80 {
		t.Fatalf("a reverted swap must leave the taker's LETH untouched, got %d want 80", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != 2400 {
		t.Fatalf("the maker's resting bid must be untouched by the reverted swap, locked=%d want 2400", got)
	}
}

// TestRED_SyncSell_MinOutMet_Succeeds proves the floor does not over-reject: a market SELL
// whose realized proceeds MEET the declared min-out fills normally.
func TestRED_SyncSell_MinOutMet_Succeeds(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// A fair resting bid: 100 LETH @ 50. The taker sells 80 and declares a min-out of 4000
	// (== 80 * 50). The fill realizes exactly 4000, which MEETS the floor, so it succeeds.
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, uint64(50)*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	out, err := h.swapMinOut(t, taker, 80, 4000)
	if err != nil {
		t.Fatalf("a market SELL whose proceeds meet the min-out must succeed: %v", err)
	}
	_, a1 := UnpackBalanceDelta(out)
	if a1.Int64() != 4000 {
		t.Fatalf("realized proceeds = %s, want 4000 (floor exactly met)", a1)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker real LUSD proceeds = %d, want 4000", got)
	}
}
