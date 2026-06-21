// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_rail_redteam_test.go is the H1 (cross-rail D->C object consumption) RED
// suite. It proves the FIXED ship rule in BOTH directions:
//
//	a C credit comes ONLY from consuming a D->C object OF THE MATCHING RAIL;
//	a unit is CSpendable XOR DCommitted across BOTH rails (swap seamReserve and LP
//	committedPositions are disjoint pots, each fed only by its own rail's objects).
//
// The pre-fix exploits (proven CLOSED here):
//   H1-A: an LP feeds their own railLP collect object into swap-Phase-B and calls swap
//         -> ImportSettlement would credit from seamReserve, draining the SWAP pot and
//         stranding real swap settlements. Now ImportSettlement requires railSwap.
//   H1-B: a taker holding an open position routes their railSwap swap-fill object
//         through collectPosition -> ImportPositionCollect would credit from
//         committedPositions, draining the LP pot. Now ImportPositionCollect requires
//         railLP AND binds the credit to a specific position record (per-object gate).

// TestRED_LP_SwapObjectCannotBeCollected — H1-B CLOSED. A railSwap D->C object (a
// swap fill the taker is entitled to on the SWAP rail) CANNOT be consumed via
// collectPosition to drain the LP rail's committedPositions pot — even when the
// attacker holds a live LP position (the old per-owner-any-position gate would have
// passed). The rail tag refuses it; committedPositions is untouched.
func TestRED_LP_SwapObjectCannotBeCollected(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	// The attacker is a legitimate LP: they hold an open position (so the OLD gate
	// "owner has any open position" would have armed) and committedPositions is fat.
	recordID, _ := h.commitNativePosition(t, -60, 60, 1000, lpSalt(0x21))
	committedBefore := loadCommittedPositions(db, native)

	// D exported a SWAP-rail (railSwap) D->C object for the attacker (a swap fill they
	// are owed on the swap rail). It is a perfectly valid object — owner, asset, amount
	// all bind — but it is on the WRONG rail for collectPosition.
	swapObj := ids.ID{0x5A, 0x00, 0x01}
	h.putDtoCObjectRail(t, railSwap, h.caller, swapObj, native, 250)

	// Route it through collectPosition (the LP rail). It MUST be refused on the rail
	// gate — a swap-fill object can never reach committedPositions.
	if _, err := h.collectNative(swapObj, 250, recordID); err != ErrLPCollectWrongRail {
		t.Fatalf("H1-B: a railSwap object consumed via collectPosition MUST revert ErrLPCollectWrongRail, got: %v", err)
	}

	// committedPositions UNTOUCHED — the LP pot was not drained.
	if loadCommittedPositions(db, native).Cmp(committedBefore) != 0 {
		t.Fatalf("H1-B: committedPositions must be untouched by a refused cross-rail collect (was %s, now %s)",
			committedBefore, loadCommittedPositions(db, native))
	}
	// And the object is NOT consumed (the swap rail can still legitimately settle it).
	if isSettlementConsumed(db, swapObj) {
		t.Fatal("H1-B: a refused cross-rail collect must NOT mark the object consumed")
	}
}

// TestRED_LP_CollectObjectCannotBeSwapSettled — H1-A CLOSED. A railLP D->C object (an
// LP collect/withdraw the LP is entitled to on the LP rail) CANNOT be consumed via the
// swap settlement path (ImportSettlement) to drain the swap rail's seamReserve pot.
// The rail tag refuses it; seamReserve is untouched, so real swap settlements are not
// stranded.
func TestRED_LP_CollectObjectCannotBeSwapSettled(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	// Seed the swap rail's seamReserve so that IF the cross-rail consume were allowed,
	// it COULD physically pay out (the pot can back it) — making the refusal meaningful.
	h.fundVaultNativeOut(1000)
	seamBefore := loadSeamReserve(db, native)

	// D exported an LP-rail (railLP) D->C object for the attacker (an LP collect they
	// are owed on the LP rail). Valid object, WRONG rail for swap settlement.
	lpObj := ids.ID{0x1B, 0x00, 0x01}
	h.putDtoCLPObject(t, h.caller, lpObj, native, 250)

	// (a) directly via ImportSettlement (the swap credit path) — MUST refuse on rail.
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: lpObj, Asset: native, AssetAddr: common.Address{}, Amount: 250, Recipient: h.caller,
	}); err != ErrSettleWrongRail {
		t.Fatalf("H1-A: a railLP object consumed via ImportSettlement MUST revert ErrSettleWrongRail, got: %v", err)
	}

	// (b) via the 0x9999 swap selector's Phase-B settlement hookData (the calldata path
	// an LP would actually use to smuggle the object) — also refused; no credit.
	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	if _, err := h.runSwap(t, h.settlementCalldata(lpObj, 250), false); err == nil {
		t.Fatal("H1-A: a railLP object smuggled through swap Phase-B settlement MUST revert")
	}

	// seamReserve UNTOUCHED — the swap pot was not drained, real swap settlements safe.
	if loadSeamReserve(db, native).Cmp(seamBefore) != 0 {
		t.Fatalf("H1-A: seamReserve must be untouched by a refused cross-rail settle (was %s, now %s)",
			seamBefore, loadSeamReserve(db, native))
	}
	if h.state.stateDB.GetBalance(h.caller).ToBig().Cmp(callerBefore) > 0 {
		t.Fatal("H1-A: a refused cross-rail settle must not credit the caller")
	}
	if isSettlementConsumed(db, lpObj) {
		t.Fatal("H1-A: a refused cross-rail settle must NOT mark the object consumed")
	}
}

// TestRED_LP_CollectBoundToOwnPositionPrincipal — FIX-2 CLOSED. The collect credit is
// bounded by the recorded owner's OWN named position record, so an over-export for
// owner X can never draw on owner Y's committed principal in the shared
// committedPositions pot. Two LPs commit equal principal of the same asset; D
// over-exports a railLP object for X; X's collect (naming X's record) is bounded to
// X's own backing and the over-export is REFUSED — Y's principal is safe.
func TestRED_LP_CollectBoundToOwnPositionPrincipal(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	x := h.caller
	y := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// X commits 100 (record_X.LockedAmt = 100, committedPositions = 100).
	recordX, _ := h.commitNativePosition(t, -60, 60, 100, lpSalt(0x31))

	// Y commits 100 of the SAME asset (committedPositions = 200). Y's principal now
	// shares the pot with X's. Drive Y's commit directly (Y is not h.caller).
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	saltY := lpSalt(0x32)
	h.state.stateDB.AddBalance(y, uint256.NewInt(100))
	yArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(100), saltY, hookData)
	if _, _, err := h.c.Run(h.state, y, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, yArgs), 5_000_000, false); err != nil {
		t.Fatalf("Y commit: %v", err)
	}
	h.flushStaged(t)
	if loadCommittedPositions(db, native).Int64() != 200 {
		t.Fatalf("pot must be 200 (X 100 + Y 100), got %s", loadCommittedPositions(db, native))
	}
	yReserveBefore := loadLockedReserve(db, y, native)

	// D OVER-EXPORTS a railLP object for X with amount 150 (a bug/malice on D): more
	// than X's own committed principal (100). The pot (200) COULD back it, which is
	// exactly the cross-owner drain FIX-2 prevents.
	overObj := ids.ID{0x07, 0xE0, 0x01}
	h.putDtoCLPObject(t, x, overObj, native, 150)

	// X collects naming X's record. The per-object bound (recAmount <= record_X.LockedAmt
	// = 100) REFUSES the 150 over-export — X cannot reach Y's 100.
	if _, err := h.collectNative(overObj, 150, recordX); err != ErrLPCollectExceedsPosition {
		t.Fatalf("FIX-2: an over-export (150) beyond X's own committed principal (100) MUST revert ErrLPCollectExceedsPosition, got: %v", err)
	}

	// Y's committed principal is intact — it was never reachable by X's over-export.
	if loadLockedReserve(db, y, native).Cmp(yReserveBefore) != 0 {
		t.Fatal("FIX-2: Y's committed reserve must be untouched by X's refused over-export")
	}
	if loadCommittedPositions(db, native).Int64() != 200 {
		t.Fatalf("FIX-2: the pot must be untouched by the refused over-export, got %s", loadCommittedPositions(db, native))
	}

	// X can still collect its OWN 100 (the legitimate amount) — the bound is exact, not
	// a blanket refusal.
	okObj := ids.ID{0x07, 0xE0, 0x02}
	h.putDtoCLPObject(t, x, okObj, native, 100)
	if _, err := h.collectNative(okObj, 100, recordX); err != nil {
		t.Fatalf("FIX-2: X's legitimate collect of its OWN 100 must succeed, got: %v", err)
	}
	// After X drains its own 100, the pot is 100 (Y's), and Y can collect it.
	if loadCommittedPositions(db, native).Int64() != 100 {
		t.Fatalf("FIX-2: pot must be 100 (Y's) after X's full collect, got %s", loadCommittedPositions(db, native))
	}
}

// TestRED_FIX5_CreditTokenDerivedFromRecordedAsset — FIX-5 CLOSED. The ERC-20 transfer
// token is DERIVED from the recorded object's asset INSIDE creditSettlementOutput, not
// taken from the caller-supplied claim.AssetAddr. A claim that names a DIFFERENT token
// in AssetAddr (while the asset id still matches the recorded object — the equality
// check passes) credits the CORRECT (recorded-asset-derived) token, never the
// caller's named one. This removes the latent trust on claim.AssetAddr.
func TestRED_FIX5_CreditTokenDerivedFromRecordedAsset(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	// Seed the seam reserve of the REAL output token (so a swap credit is backed).
	h.fundVaultOut(10_000)

	outTok := h.outToken() // the correct token (== assetAddress(outAssetID)).
	wrongTok := common.HexToAddress("0x00000000000000000000000000000000DeadBeef")
	// Pre-seed the wrong token's vault balance so that IF the credit wrongly used
	// AssetAddr, it COULD physically transfer it (making the negative meaningful).
	h.wrapper().mintTestToken(wrongTok, poolManagerAddr9999, big.NewInt(10_000))

	// D exported a railSwap object for the OUTPUT token (asset == outAssetID).
	obj := ids.ID{0xF5, 0x00, 0x01}
	h.putDtoCObjectRail(t, railSwap, h.caller, obj, h.outAssetID(), 300)

	wrongBefore := h.tokenBal(wrongTok, h.caller)
	rightBefore := h.tokenBal(outTok, h.caller)

	// The claim's asset id is the recorded one (so the asset-bind passes), but AssetAddr
	// names the WRONG token. FIX-5: the credit derives the token from recAsset, so the
	// CORRECT token is credited and the wrong one is untouched.
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID:  obj,
		Asset:     h.outAssetID(),
		AssetAddr: wrongTok, // attacker-supplied; MUST be ignored for the transfer.
		Amount:    300,
		Recipient: h.caller,
	})
	if err != nil || credited != 300 {
		t.Fatalf("FIX-5: a bound claim must credit 300: credited=%d err=%v", credited, err)
	}
	if new(big.Int).Sub(h.tokenBal(outTok, h.caller), rightBefore).Int64() != 300 {
		t.Fatal("FIX-5: the credit must go to the token DERIVED from the recorded asset (the correct output token)")
	}
	if h.tokenBal(wrongTok, h.caller).Cmp(wrongBefore) != 0 {
		t.Fatal("FIX-5: the credit must NOT touch the token named by the caller's AssetAddr")
	}
}

// TestRED_LP_CollectMustNameAnOpenPosition — the per-object gate also refuses a collect
// that names NO live position for the recorded owner: a railLP object whose owner holds
// the named record only if it exists Open/Closing. A claim naming a zero / unknown /
// already-closed record reverts (ErrLPCollectNoPosition) — the credit cannot float free
// of a specific position.
func TestRED_LP_CollectMustNameAnOpenPosition(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()

	// A live position + a valid railLP object for the owner.
	recordID, _ := h.commitNativePosition(t, -60, 60, 500, lpSalt(0x41))
	obj := ids.ID{0x0A, 0x0B, 0x0C}
	h.putDtoCLPObject(t, h.caller, obj, native, 200)

	// (a) naming the ZERO position id => no such record => refused.
	if _, err := h.collectNative(obj, 200, [32]byte{}); err != ErrLPCollectNoPosition {
		t.Fatalf("a collect naming no position must revert ErrLPCollectNoPosition, got: %v", err)
	}
	// (b) naming an UNKNOWN (never-committed) record id => refused.
	if _, err := h.collectNative(obj, 200, [32]byte{0xDE, 0xAD, 0xBE, 0xEF}); err != ErrLPCollectNoPosition {
		t.Fatalf("a collect naming an unknown position must revert ErrLPCollectNoPosition, got: %v", err)
	}
	// (c) naming the CORRECT live record => succeeds (the gate is bind, not blanket-deny).
	if _, err := h.collectNative(obj, 200, recordID); err != nil {
		t.Fatalf("a collect naming the owner's live position must succeed, got: %v", err)
	}
}

// TestRED_LP_LifecycleClosedOnFullCollect — FIX-3 CLOSED. A position drives
// Open -> Closing -> Closed by remaining LockedAmt on collect (Closed when 0), and a
// re-commit while Closing is FORBIDDEN (cannot flip a withdraw-in-flight back to Open,
// the lifecycle hole that permanently armed the old H1-B). A fully-collected (Closed)
// slot can host a brand-new commit.
func TestRED_LP_LifecycleClosedOnFullCollect(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x51)

	// COMMIT 600 -> Open.
	recordID, _ := h.commitNativePosition(t, -60, 60, 600, salt)
	if loadRestingOrder(db, recordID).Status != OrderStatusOpen {
		t.Fatal("commit must open the position")
	}

	// DECREASE (REMOVE) -> Closing (a withdraw is requested).
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	decArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(-600), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, decArgs), 5_000_000, false); err != nil {
		t.Fatalf("decrease: %v", err)
	}
	if loadRestingOrder(db, recordID).Status != OrderStatusClosing {
		t.Fatal("decrease must mark the position Closing")
	}

	// RE-COMMIT while Closing is FORBIDDEN (FIX-3): cannot re-arm an in-flight withdraw.
	h.fundCallerNative(100)
	reArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(100), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, reArgs), 5_000_000, false); err != ErrLPCommitWhileClosing {
		t.Fatalf("re-commit while Closing must revert ErrLPCommitWhileClosing, got: %v", err)
	}

	// PARTIAL collect 200 -> still Closing (400 left), LockedAmt = 400.
	obj1 := ids.ID{0xC1, 0x01}
	h.putDtoCLPObject(t, h.caller, obj1, native, 200)
	if _, err := h.collectNative(obj1, 200, recordID); err != nil {
		t.Fatalf("partial collect: %v", err)
	}
	if o := loadRestingOrder(db, recordID); o.Status != OrderStatusClosing || o.LockedAmt.Int64() != 400 {
		t.Fatalf("after partial collect: status=%d LockedAmt=%s (want Closing/400)", o.Status, o.LockedAmt)
	}

	// FULL collect of the remaining 400 -> Closed (terminal), LockedAmt = 0.
	obj2 := ids.ID{0xC1, 0x02}
	h.putDtoCLPObject(t, h.caller, obj2, native, 400)
	if _, err := h.collectNative(obj2, 400, recordID); err != nil {
		t.Fatalf("full collect: %v", err)
	}
	if o := loadRestingOrder(db, recordID); o.Status != OrderStatusCancelled || o.LockedAmt.Sign() != 0 {
		t.Fatalf("after full collect: status=%d LockedAmt=%s (want Closed/0)", o.Status, o.LockedAmt)
	}

	// A Closed slot can host a BRAND-NEW commit (reuse the same coordinates).
	h.fundCallerNative(300)
	freshArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(300), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, freshArgs), 5_000_000, false); err != nil {
		t.Fatalf("a fresh commit on a Closed slot must succeed, got: %v", err)
	}
	if o := loadRestingOrder(db, recordID); o.Status != OrderStatusOpen || o.LockedAmt.Int64() != 300 {
		t.Fatalf("fresh commit must reopen at 300, got status=%d LockedAmt=%s", o.Status, o.LockedAmt)
	}
}
