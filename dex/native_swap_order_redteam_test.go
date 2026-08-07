// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_swap_order_redteam_test.go is the RED suite for the swap rail's per-order
// escrow record — the shared record that closes BOTH the MEDIUM per-taker cap and the
// HIGH deadline reclaim. It is the swap-rail analog of native_rail_redteam_test.go
// (the LP per-position bound) and pins:
//
//	MEDIUM — a swap settlement credit is bounded by the taker's OWN order's remaining
//	         locked principal, so an over-export for taker X can NEVER draw on other
//	         takers' pooled tokenIn in the shared seam reserve.
//	HIGH   — locked swap input can ALWAYS exit: once an order's deadline passes and D
//	         has not settled, the locker reclaims the remaining principal; a late
//	         settlement and a reclaim can never BOTH pay out (conservation).

// TestRED_Swap_RefundBoundToOwnOrderPrincipal — MEDIUM CLOSED. The swap-rail analog
// of TestRED_LP_CollectBoundToOwnPositionPrincipal, on the SAME-ASSET return (the
// refund of unfilled tokenIn — the leg whose dimension matches the locked principal,
// exactly as the LP collects the same asset it committed). Two takers lock equal
// principal of the same input asset; the seam reserve of THAT input asset pools their
// backing. D over-exports a REFUND object (input asset) for X beyond X's own locked
// principal; X's settle (naming X's order) is bounded to X's own principal and the
// over-export is REFUSED — the other taker's pooled tokenIn is safe.
func TestRED_Swap_RefundBoundToOwnOrderPrincipal(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	db := newPoolStateAdapter(h.state)
	in := h.inAssetID() // the LOCKED asset — the refund leg's asset (== the cap dimension).

	x := h.caller
	y := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Seed the INPUT-asset seam reserve fat enough that an over-refund COULD physically
	// pay out (making the cap's refusal meaningful) — this models other takers' pooled
	// tokenIn of the input asset (X's refund draws this shared pot).
	h.fundVaultNativeOut(1_000)
	seamBefore := loadSeamReserve(db, in)

	// X holds an order with 100 remaining locked principal; Y holds one with 100.
	orderX := h.seedSwapOrder(x, in, 100, 0, ids.ID{0x1A, 0x00, 0x01})
	_ = h.seedSwapOrder(y, in, 100, 0, ids.ID{0x1A, 0x00, 0x02})

	// D OVER-EXPORTS a railSwap REFUND object (input asset) for X with amount 150 (a
	// bug/malice on D): more than X's own locked principal (100). The seam reserve (1000)
	// COULD back it — exactly the cross-taker drain the per-taker cap prevents.
	overObj := ids.ID{0x0F, 0xE0, 0x01}
	h.putDtoCObjectRail(t, railSwap, x, overObj, in, 150)

	// X settles naming X's order. The per-taker bound (recAmount <= orderX.Remaining
	// = 100) REFUSES the 150 over-refund — X cannot reach the pooled tokenIn beyond its
	// own 100 stake.
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: overObj, Asset: in, AssetAddr: assetAddress(in), Recipient: x, OrderID: orderX,
		Object: encodeAtomicObject(railSwap, x, in, 150),
	}); err != ErrSettleExceedsOrder {
		t.Fatalf("MEDIUM: an over-refund (150) beyond X's own locked principal (100) MUST revert ErrSettleExceedsOrder, got: %v", err)
	}

	// The seam reserve is untouched by the refused over-refund — no pooled tokenIn drained.
	if loadSeamReserve(db, in).Cmp(seamBefore) != 0 {
		t.Fatalf("MEDIUM: seamReserve must be untouched by a refused over-refund (was %s, now %s)",
			seamBefore, loadSeamReserve(db, in))
	}
	if isSettlementConsumed(db, overObj) {
		t.Fatal("MEDIUM: a refused over-refund settle must NOT mark the object consumed")
	}

	// X can still settle its OWN 100 (the legitimate amount) — the bound is exact, not blanket.
	okObj := ids.ID{0x0F, 0xE0, 0x02}
	h.putDtoCObjectRail(t, railSwap, x, okObj, in, 100)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: okObj, Asset: in, AssetAddr: assetAddress(in), Recipient: x, OrderID: orderX,
		Object: encodeAtomicObject(railSwap, x, in, 100),
	})
	if err != nil || credited != 100 {
		t.Fatalf("MEDIUM: X's legitimate refund of its OWN 100 must succeed: credited=%d err=%v", credited, err)
	}
	// X's order is now drained to 0; a further same-asset settle naming it is capped to 0.
	if rec := loadSwapOrderRecord(db, orderX); rec.Remaining != 0 {
		t.Fatalf("MEDIUM: X's order remaining must be 0 after a full refund, got %d", rec.Remaining)
	}
	moreObj := ids.ID{0x0F, 0xE0, 0x03}
	h.putDtoCObjectRail(t, railSwap, x, moreObj, in, 1)
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: moreObj, Asset: in, AssetAddr: assetAddress(in), Recipient: x, OrderID: orderX,
		Object: encodeAtomicObject(railSwap, x, in, 1),
	}); err != ErrSettleExceedsOrder {
		t.Fatalf("MEDIUM: refunding a drained order (remaining 0) must revert ErrSettleExceedsOrder, got: %v", err)
	}
}

// TestRED_Swap_ProceedsNotCappedByInputPrincipal is the CORRECTNESS guard for the
// per-taker cap's DIMENSION: the cap bounds the SAME-ASSET refund leg by the locked
// principal, but the PROCEEDS leg (the OPPOSITE asset the taker receives) must NOT be
// bounded by the input-unit count — output units legitimately differ from input units
// at any price != 1 (e.g. an expensive tokenIn buying many cheap tokenOut, or simply a
// decimals mismatch). A naive input-unit cap on proceeds would wrongly refuse honest
// swaps; this proves it does not.
func TestRED_Swap_ProceedsNotCappedByInputPrincipal(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000_000) // back the (large) output proceeds.
	out := h.outAssetID()

	// The taker locked only 100 units of the INPUT asset...
	orderID := h.seedSwapOrder(h.caller, h.inAssetID(), 100, 0, ids.ID{0x9A, 0x00, 0x01})

	// ...but legitimately RECEIVES 60_000 units of the OUTPUT asset (price ~600, or a
	// decimals gap). The proceeds (60_000) hugely exceed the input-unit count (100); an
	// input-unit cap would wrongly refuse this honest fill.
	proceedsObj := ids.ID{0x9A, 0x00, 0x02}
	h.putDtoCObjectRail(t, railSwap, h.caller, proceedsObj, out, 60_000)
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: proceedsObj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObject(railSwap, h.caller, out, 60_000),
	})
	if err != nil || credited != 60_000 {
		t.Fatalf("CORRECTNESS: an honest proceeds credit (60000 out) for a 100-in order MUST succeed "+
			"(the cap is same-asset only, never an input-unit ceiling on output): credited=%d err=%v", credited, err)
	}
	// The proceeds credit did NOT touch the input principal (different dimension).
	if rec := loadSwapOrderRecord(newPoolStateAdapter(h.state), orderID); rec.Remaining != 100 {
		t.Fatalf("CORRECTNESS: a proceeds (opposite-asset) credit must not decrement the input principal; remaining=%d want 100", rec.Remaining)
	}
}

// TestRED_Swap_SettleMustNameAnOpenOrder — the per-order gate also refuses a
// settlement that names NO live order for the recorded owner: a claim naming a zero /
// unknown order, or one owned by someone else, reverts (ErrSettleNoOrder) — the
// credit cannot float free of the taker's own order.
func TestRED_Swap_SettleMustNameAnOpenOrder(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000)
	out := h.outAssetID()

	obj := ids.ID{0x0A, 0x0B, 0x0C}
	h.putDtoCObjectRail(t, railSwap, h.caller, obj, out, 200)

	// These exercise the order gate directly via the client (the test shim auto-binds a
	// standing order for a zero OrderID, which is exactly what we must AVOID here).
	imp := func(orderID [32]byte) error {
		_, err := nativeClient.ImportSettlement(h.state, h.state, SettlementClaim{
			OutputID: obj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
			Object: encodeAtomicObject(railSwap, h.caller, out, 200),
		})
		return err
	}

	// (a) ZERO order id => no such record => refused.
	if err := imp([32]byte{}); err != ErrSettleNoOrder {
		t.Fatalf("a settle naming no order must revert ErrSettleNoOrder, got: %v", err)
	}
	// (b) UNKNOWN order id => refused.
	if err := imp([32]byte{0xDE, 0xAD}); err != ErrSettleNoOrder {
		t.Fatalf("a settle naming an unknown order must revert ErrSettleNoOrder, got: %v", err)
	}
	// (c) order owned by SOMEONE ELSE => refused (cannot bind a victim's order).
	foreign := h.seedSwapOrder(common.HexToAddress("0x3333333333333333333333333333333333333333"),
		h.inAssetID(), 1000, 0, ids.ID{0xF0, 0x01})
	if err := imp(foreign); err != ErrSettleNoOrder {
		t.Fatalf("a settle naming another owner's order must revert ErrSettleNoOrder, got: %v", err)
	}
	// (d) the caller's OWN live order => succeeds.
	mine := h.seedSwapOrder(h.caller, h.inAssetID(), 1000, 0, ids.ID{0xF0, 0x02})
	if err := imp(mine); err != nil {
		t.Fatalf("a settle naming the caller's live order must succeed, got: %v", err)
	}
}

// TestRED_Swap_ReclaimRefundsStrandedPrincipal — HIGH CLOSED (the headline liveness
// fix). A swap order with a deadline is never settled by D; once the deadline passes,
// the locker reclaims the full remaining principal from the seam reserve. Funds always
// exit.
func TestRED_Swap_ReclaimRefundsStrandedPrincipal(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	// Seed seamReserve[native] with the locker's locked principal (what SubmitSwapOrder
	// would have credited on the lock) so the reclaim refund is backed (no mint).
	h.fundVaultNativeOut(1_000)

	const deadline uint64 = 100
	const principal uint64 = 400
	orderID := h.seedSwapOrder(h.caller, native, principal, deadline, ids.ID{0xDE, 0xAD, 0x71})

	// Before the deadline, reclaim is REFUSED (a settlement may still land).
	h.state.blockTimestamp = deadline // == deadline, not strictly past => refused
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(orderID)), 5_000_000, false); err != ErrReclaimBeforeDeadline {
		t.Fatalf("reclaim at/<= deadline must revert ErrReclaimBeforeDeadline, got: %v", err)
	}

	// Past the deadline, the locker reclaims the full remaining principal.
	h.state.blockTimestamp = deadline + 1
	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	seamBefore := loadSeamReserve(db, native)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(orderID)), 5_000_000, false)
	if err != nil {
		t.Fatalf("reclaim past deadline must succeed, got: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Uint64(); got != principal {
		t.Fatalf("reclaim must refund the full remaining principal %d, got %d", principal, got)
	}
	// The native principal is credited back to the locker and debited from the seam reserve.
	if d := new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), callerBefore); d.Uint64() != principal {
		t.Fatalf("reclaim must credit the locker %d native, credited %s", principal, d)
	}
	if d := new(big.Int).Sub(seamBefore, loadSeamReserve(db, native)); d.Uint64() != principal {
		t.Fatalf("reclaim must debit seamReserve by %d, debited %s", principal, d)
	}
	// The order is terminal (Reclaimed) and a second reclaim is a replay no-op (refused).
	if rec := loadSwapOrderRecord(db, orderID); rec.Status != swapOrderReclaimed || rec.Remaining != 0 {
		t.Fatalf("reclaimed order must be terminal Reclaimed/0, got status=%d remaining=%d", rec.Status, rec.Remaining)
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(orderID)), 5_000_000, false); err == nil {
		t.Fatal("a second reclaim of the same order must revert (one-time)")
	}
}

// TestRED_Swap_SettleRefusedPastDeadline — a Phase-B settlement that arrives AFTER the
// order's deadline is refused (ErrSettlePastDeadline), keeping settlement and reclaim
// mutually exclusive by the deadline boundary.
func TestRED_Swap_SettleRefusedPastDeadline(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(1_000)
	out := h.outAssetID()

	const deadline uint64 = 100
	orderID := h.seedSwapOrder(h.caller, h.inAssetID(), 500, deadline, ids.ID{0xDD, 0x01})
	obj := ids.ID{0xDD, 0x02}
	h.putDtoCObjectRail(t, railSwap, h.caller, obj, out, 200)

	// Past the deadline => settlement refused.
	h.state.blockTimestamp = deadline + 1
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObject(railSwap, h.caller, out, 200),
	}); err != ErrSettlePastDeadline {
		t.Fatalf("a settlement past the order deadline must revert ErrSettlePastDeadline, got: %v", err)
	}

	// At/<= the deadline => settlement allowed (the bound is the boundary, not blanket).
	h.state.blockTimestamp = deadline
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObject(railSwap, h.caller, out, 200),
	}); err != nil {
		t.Fatalf("a settlement at the deadline boundary must succeed, got: %v", err)
	}
}

// TestRED_Swap_ReclaimAndSettleAreMutuallyExclusive — CONSERVATION. After a reclaim
// drains an order's principal, a late settlement naming that order is capped to 0 and
// refused — the principal exits EXACTLY ONCE (never reclaim refund + settlement credit).
func TestRED_Swap_ReclaimAndSettleAreMutuallyExclusive(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	out := h.outAssetID()
	db := newPoolStateAdapter(h.state)
	h.fundVaultNativeOut(1_000) // backs the reclaim refund (input asset)
	h.fundVaultOut(1_000)       // would back a settlement credit (output asset)

	const deadline uint64 = 100
	const principal uint64 = 300
	orderID := h.seedSwapOrder(h.caller, native, principal, deadline, ids.ID{0xCE, 0x01})

	// Reclaim past the deadline (drains the order to 0, terminal Reclaimed).
	h.state.blockTimestamp = deadline + 1
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(orderID)), 5_000_000, false); err != nil {
		t.Fatalf("reclaim: %v", err)
	}

	// A D->C settlement object for the SAME order now lands (D settled after the
	// deadline). It MUST be refused: the order is terminal (Reclaimed) => ErrSettleNoOrder
	// (the status gate fires first), so the principal can never be paid twice.
	obj := ids.ID{0xCE, 0x02}
	h.putDtoCObjectRail(t, railSwap, h.caller, obj, out, 200)
	h.state.blockTimestamp = deadline // even at a settle-valid timestamp, the reclaimed order is terminal
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: out, AssetAddr: assetAddress(out), Recipient: h.caller, OrderID: orderID,
		Object: encodeAtomicObject(railSwap, h.caller, out, 200),
	}); err != ErrSettleNoOrder {
		t.Fatalf("CONSERVATION: a settlement naming a reclaimed order MUST revert (no double payout), got: %v", err)
	}
	if isSettlementConsumed(db, obj) {
		t.Fatal("CONSERVATION: a refused post-reclaim settlement must NOT consume the object")
	}
}

// TestRED_Swap_ReclaimGuards pins the remaining reclaim guards: only the locker may
// reclaim, an order with no deadline cannot be reclaimed (it relies on settlement),
// and a fully-settled order has nothing to refund.
func TestRED_Swap_ReclaimGuards(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	h.fundVaultNativeOut(1_000)

	// (a) NON-owner cannot reclaim.
	const deadline uint64 = 100
	orderID := h.seedSwapOrder(h.caller, native, 200, deadline, ids.ID{0xAA, 0x01})
	h.state.blockTimestamp = deadline + 1
	stranger := common.HexToAddress("0x4444444444444444444444444444444444444444")
	if _, _, err := h.c.Run(h.state, stranger, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(orderID)), 5_000_000, false); err != ErrReclaimNotOwner {
		t.Fatalf("a non-owner reclaim must revert ErrReclaimNotOwner, got: %v", err)
	}

	// (b) an order with NO deadline cannot be reclaimed (it must settle).
	noDeadline := h.seedSwapOrder(h.caller, native, 200, 0, ids.ID{0xAA, 0x02})
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(noDeadline)), 5_000_000, false); err != ErrReclaimNoDeadline {
		t.Fatalf("a no-deadline order reclaim must revert ErrReclaimNoDeadline, got: %v", err)
	}

	// (c) a fully-settled order (remaining 0) has nothing to refund.
	drained := h.seedSwapOrder(h.caller, native, 0, deadline, ids.ID{0xAA, 0x03})
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(drained)), 5_000_000, false); err != ErrReclaimNothingLocked {
		t.Fatalf("a drained order reclaim must revert ErrReclaimNothingLocked, got: %v", err)
	}

	// (d) an UNKNOWN order reclaim is refused.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimOrder, EncodeReclaimOrderInput(ids.ID{0xBB, 0xBB})), 5_000_000, false); err != ErrReclaimNoOrder {
		t.Fatalf("an unknown order reclaim must revert ErrReclaimNoOrder, got: %v", err)
	}
}

// TestRED_Swap_DeadlinePlumbedFromOrderBody — the deadline is no longer hardcoded 0:
// a Phase-A order with an explicit DI01 deadline body persists that deadline in the
// per-order record (so reclaim/late-settle gating works end-to-end from calldata).
func TestRED_Swap_DeadlinePlumbedFromOrderBody(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1_000)

	const deadline uint64 = 4242
	out, err := h.runSwap(t, h.orderCalldataWithDeadline(deadline), false)
	if err != nil {
		t.Fatalf("order-with-deadline swap: %v", err)
	}
	var orderID ids.ID
	copy(orderID[:], out[0:32])

	rec := loadSwapOrderRecord(newPoolStateAdapter(h.state), orderID)
	if rec.Status != swapOrderOpen {
		t.Fatalf("order record must be Open after submission, got status=%d", rec.Status)
	}
	if rec.Deadline != deadline {
		t.Fatalf("DEADLINE PLUMBING BROKEN: order record deadline=%d, want %d (no longer hardcoded 0)", rec.Deadline, deadline)
	}
	if rec.Owner != h.caller {
		t.Fatalf("order record owner=%s, want caller %s", rec.Owner.Hex(), h.caller.Hex())
	}
}
