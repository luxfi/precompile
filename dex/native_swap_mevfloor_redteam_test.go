// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/ids"
)

// native_swap_mevfloor_redteam_test.go is the RED suite for the TAKER-AUTHENTICATED MEV
// floor on the swap rail's PROCEEDS leg. It pins the property that ImportSettlement enforces
// the taker's OWN recorded slippage limit (order.PriceLimit, recorded at SubmitSwapOrder
// from the taker's V4 SqrtPriceLimitX96) against the realized fill price (out/spent),
// INDEPENDENTLY of any keeper-relayed RelayOrderTx.PriceLimit.
//
// THE ATTACK (the gap this closes). Before the fix the slippage limit was KEEPER-asserted:
// settleFromFills (D) enforced RelayOrderTx.PriceLimit, but swapOrderRecord DROPPED the
// taker's PriceLimit at submit. So a malicious keeper that set priceLimit=0 in the relay
// removed the D-side floor and could sandwich the taker — D would settle a bad-price fill and
// export a proceeds object, and C credited it blindly. Now C records the taker's limit at
// submit and re-checks the realized proceeds price against THAT limit, so the keeper's relay
// value is irrelevant: a proceeds object whose realized price violates the recorded limit is
// refused (ErrSettlePriceLimit), the order stays Open, and the principal stays reclaimable.
//
// THE WITNESS. The realized price is reconstructed from the venue-ATTESTED object the keeper
// cannot forge: spent = matched input, out = proceeds output (the 69-byte wire's trailing
// spent word, byte-identical with chains/dexvm). quote-per-base realized price is out/spent
// on a SELL (zeroForOne) and spent/out on a BUY (!zeroForOne).

// priceUnits returns a quote-per-base price as a uint64 FIXED-POINT ×priceScale value —
// the PriceInt grid the order records and the floor compares in (priceLimitToCLOB's
// output domain). No float on the wire.
func priceUnits(price float64) uint64 { return uint64(price * priceScale) }

// TestRED_MEVFloor_KeeperZeroedLimit_StillRejected is the DECISIVE proof: even if the keeper
// drops the relay limit entirely (so D imposes NO floor and settles a sandwiched fill), C
// refuses the bad-price PROCEEDS credit because it binds the TAKER's recorded limit, not the
// keeper's. A SELL taker who recorded "at least 2.0 quote per base" is not credited a fill
// realized at 1.5 — the keeper cannot sandwich them.
func TestRED_MEVFloor_KeeperZeroedLimit_StillRejected(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000_000) // back the proceeds.
	out := h.outAssetID()
	in := h.inAssetID()

	// The taker SELLS base for quote (zeroForOne) and recorded a FLOOR of 2.0 quote/base
	// (limitIsUpper=false). They locked 100 base. The keeper relayed priceLimit=0 to D (the
	// sandwich), so D settled a fill realized at 1.5 quote/base: 100 base in -> 150 quote out.
	orderID := h.seedSwapOrderLimit(h.caller, in, 100, 0, priceUnits(2.0), false, ids.ID{0x3E, 0x00, 0x01})

	// D exports the sandwiched proceeds object: out=150 quote, spent=100 base -> realized 1.5,
	// WORSE than the taker's recorded floor of 2.0.
	badObj := ids.ID{0x3E, 0x00, 0x02}
	h.putDtoCObjectRailSpent(t, railSwap, h.caller, badObj, out, 150, 100)

	db := newPoolStateAdapter(h.state)
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: badObj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObjectSpent(railSwap, h.caller, out, 150, 100),
	}); err != ErrSettlePriceLimit {
		t.Fatalf("MEV: a proceeds fill realized at 1.5 (< the taker's recorded floor 2.0) MUST revert "+
			"ErrSettlePriceLimit even with a keeper-zeroed relay limit, got: %v", err)
	}
	// Fail-secure: the refused settle did NOT consume the object, did NOT credit, and left the
	// order Open with its principal intact (reclaimable after deadline).
	if isSettlementConsumed(db, badObj) {
		t.Fatal("MEV: a refused price-floor settle must NOT mark the object consumed")
	}
	if rec := loadSwapOrderRecord(db, orderID); rec.Status != swapOrderOpen || rec.Remaining != 100 {
		t.Fatalf("MEV: a refused price-floor settle must leave the order Open with principal intact (status=%d remaining=%d)",
			rec.Status, rec.Remaining)
	}

	// CONTRAST: an HONEST fill that MEETS the recorded floor (2.0 quote/base: 100 base ->
	// 200 quote) is credited. The floor refuses ONLY the bad price, never an honest one.
	okObj := ids.ID{0x3E, 0x00, 0x03}
	h.putDtoCObjectRailSpent(t, railSwap, h.caller, okObj, out, 200, 100)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: okObj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObjectSpent(railSwap, h.caller, out, 200, 100),
	})
	if err != nil || credited != 200 {
		t.Fatalf("MEV: an honest proceeds fill AT the recorded floor (200 quote for 100 base = 2.0) MUST be credited: credited=%d err=%v", credited, err)
	}
}

// TestRED_MEVFloor_BuyCeiling_Rejected pins the BUY direction: a !zeroForOne taker who
// recorded a CEILING of 2.0 quote/base (never pay more than 2 per base) is not credited a
// fill realized at 2.5 (200 quote in -> 80 base out => 2.5 quote/base). The ceiling is the
// limitIsUpper=true side.
func TestRED_MEVFloor_BuyCeiling_Rejected(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000_000)
	// BUY: input = quote (currency1), output = base (currency0). For the harness pool
	// currency0 is native (the inAssetID) and currency1 is the token; on a BUY the taker
	// locks the token (quote) and receives native (base). The order's AssetIn is the LOCKED
	// asset = quote = the token's asset id; the proceeds asset = base = native.
	quote := h.outAssetID() // the token (currency1) — locked on a BUY
	base := h.inAssetID()   // native (currency0) — received on a BUY
	h.fundVaultNativeOut(1_000_000)

	// Taker recorded a CEILING of 2.0 quote/base (limitIsUpper=true). Locked 1000 quote.
	orderID := h.seedSwapOrderLimit(h.caller, quote, 1000, 0, priceUnits(2.0), true, ids.ID{0x4B, 0x00, 0x01})

	// D exports a proceeds object realized at 2.5 quote/base (WORSE for a buyer than the 2.0
	// ceiling): spent=200 quote in, out=80 base -> 200/80 = 2.5.
	badObj := ids.ID{0x4B, 0x00, 0x02}
	h.putDtoCObjectRailSpent(t, railSwap, h.caller, badObj, base, 80, 200)
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: badObj, Asset: base, AssetAddr: assetAddress(base), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObjectSpent(railSwap, h.caller, base, 80, 200),
	}); err != ErrSettlePriceLimit {
		t.Fatalf("MEV: a BUY fill realized at 2.5 (> the taker's recorded ceiling 2.0) MUST revert ErrSettlePriceLimit, got: %v", err)
	}

	// An honest BUY AT the ceiling (2.0: 200 quote in -> 100 base out) is credited.
	okObj := ids.ID{0x4B, 0x00, 0x03}
	h.putDtoCObjectRailSpent(t, railSwap, h.caller, okObj, base, 100, 200)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: okObj, Asset: base, AssetAddr: assetAddress(base), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObjectSpent(railSwap, h.caller, base, 100, 200),
	})
	if err != nil || credited != 100 {
		t.Fatalf("MEV: an honest BUY at the recorded ceiling (200 quote -> 100 base = 2.0) MUST be credited: credited=%d err=%v", credited, err)
	}
}

// TestRED_MEVFloor_ZeroSpentFailsSecure pins the fail-secure edge: a proceeds object under a
// REAL recorded limit but carrying spent=0 (a malformed / hostile object whose realized price
// is unprovable) is REJECTED, never credited on an unverifiable price.
func TestRED_MEVFloor_ZeroSpentFailsSecure(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000_000)
	out := h.outAssetID()
	in := h.inAssetID()

	orderID := h.seedSwapOrderLimit(h.caller, in, 100, 0, priceUnits(2.0), false, ids.ID{0x5C, 0x00, 0x01})

	// Proceeds object with spent=0 (price unprovable) under a non-zero limit -> fail secure.
	obj := ids.ID{0x5C, 0x00, 0x02}
	h.putDtoCObjectRailSpent(t, railSwap, h.caller, obj, out, 200, 0)
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObjectSpent(railSwap, h.caller, out, 200, 0),
	}); err != ErrSettlePriceLimit {
		t.Fatalf("MEV: a proceeds object with spent=0 under a real limit MUST fail secure (ErrSettlePriceLimit), got: %v", err)
	}
}

// TestRED_MEVFloor_NoLimitIsUnbounded pins that a taker who recorded NO limit (PriceLimit=0,
// the V4-sentinel / unset case) is unbounded: ANY proceeds price is credited, preserving the
// pre-existing behavior for limitless swaps. (This is also why TestRED_Swap_ProceedsNotCapped
// — which seeds no limit — still passes.)
func TestRED_MEVFloor_NoLimitIsUnbounded(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000_000)
	out := h.outAssetID()
	in := h.inAssetID()

	// No limit recorded (PriceLimit=0). Even a wildly bad realized price (1 quote for 100
	// base) is credited — the taker accepted any price by setting none.
	orderID := h.seedSwapOrderLimit(h.caller, in, 100, 0, 0, false, ids.ID{0x6D, 0x00, 0x01})
	obj := ids.ID{0x6D, 0x00, 0x02}
	h.putDtoCObjectRailSpent(t, railSwap, h.caller, obj, out, 1, 100)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObjectSpent(railSwap, h.caller, out, 1, 100),
	})
	if err != nil || credited != 1 {
		t.Fatalf("MEV: with NO recorded limit any proceeds price must be credited (unbounded), got credited=%d err=%v", credited, err)
	}
}

// TestRED_MEVFloor_RecordedLimitSurvivesSubmit is the PLUMBING proof: the taker's V4
// SqrtPriceLimitX96 actually lands in the persisted swapOrderRecord through the REAL submit
// path (SubmitSwapOrder), not just when a test hand-seeds it. Before the fix swapOrderRecord
// dropped PriceLimit, so the floor had nothing to enforce.
func TestRED_MEVFloor_RecordedLimitSurvivesSubmit(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(10_000)

	// A real exact-input SELL (zeroForOne) carrying a V4 SqrtPriceLimitX96 for ~2.0 quote/base.
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000), // exact input
		SqrtPriceLimitX96: sqrtX96For(2.0),
	}
	limitBits, limitIsUpper := priceLimitToCLOB(params)
	if limitBits == 0 {
		t.Fatal("precondition: the test's V4 limit must convert to a non-zero CLOB limit")
	}
	req, err := buildOrderRequest(h.key, params, h.caller, 0, 42)
	if err != nil {
		t.Fatalf("buildOrderRequest: %v", err)
	}
	orderID, serr := nativeClient.SubmitSwapOrder(h.state, h.state, req)
	if serr != nil {
		t.Fatalf("SubmitSwapOrder: %v", serr)
	}

	// The persisted record must carry the taker's limit (the gap this fix closes).
	rec := loadSwapOrderRecord(newPoolStateAdapter(h.state), orderID)
	if rec.Status != swapOrderOpen {
		t.Fatalf("submit must persist an Open order, got status=%d", rec.Status)
	}
	if rec.PriceLimit != limitBits || rec.LimitIsUpper != limitIsUpper {
		t.Fatalf("PLUMBING: submit dropped the taker's recorded limit — record has (bits=%d upper=%v), want (bits=%d upper=%v)",
			rec.PriceLimit, rec.LimitIsUpper, limitBits, limitIsUpper)
	}
}
