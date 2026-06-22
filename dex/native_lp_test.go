// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_lp_test.go — the LP D-COMMITTED LIQUIDITY tests. Each asserts a leg of the
// CTO-locked LP ship rule:
//
//	A D position is funded ONLY by consuming a C->D commit object (DL01);
//	a C balance is credited (collect/withdraw) ONLY by consuming a D->C object;
//	a unit of value is CSpendable XOR DCommitted, NEVER both.
//
// They drive the REAL 0x9999 modifyLiquidity (commit) + collectPosition (collect)
// over the genuine atomic shared-memory channel (the same harness the swap tests use),
// and the dexvm-side seam tests (chains/dexvm) prove the D side consumes/produces the
// identical wire.

// lpSalt builds a distinct position salt per test.
func lpSalt(b byte) [32]byte {
	var s [32]byte
	s[31] = b
	return s
}

// TestLP_ModifyLiquidityCommitsCToD — COMMIT moves funds OUT of CSpendable into
// DCommitted (committedPositions) and stages a C->D commit object D will import. It
// returns a positionID; it credits NO output. The C->D object records the LP's
// (owner, asset, amount) — the funding D consumes.
func TestLP_ModifyLiquidityCommitsCToD(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	committedBefore := loadCommittedPositions(db, native)

	salt := lpSalt(0x01)
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	args := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(400), salt, hookData)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, args), 5_000_000, false)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(out) < 32 {
		t.Fatal("commit must return (positionID, committed)")
	}
	var recordID [32]byte
	copy(recordID[:], out[0:32])

	// Funds LEFT CSpendable and BECAME DCommitted.
	callerAfter := h.state.stateDB.GetBalance(h.caller).ToBig()
	if new(big.Int).Sub(callerBefore, callerAfter).Int64() != 400 {
		t.Fatalf("commit must debit caller CSpendable by 400, got %s", new(big.Int).Sub(callerBefore, callerAfter))
	}
	if new(big.Int).Sub(loadCommittedPositions(db, native), committedBefore).Int64() != 400 {
		t.Fatalf("commit must add 400 to committedPositions (DCommitted), got %s", loadCommittedPositions(db, native))
	}
	if loadRestingOrder(db, recordID).Status != OrderStatusOpen {
		t.Fatal("position must be OPEN (Committed)")
	}
	h.vaultInvariantNative(t, "after commit")

	// The commit STAGED a C->D object (DL01) keyed by the commit object id; flush it
	// and assert D can read it (the funding D consumes — D funded ONLY by this object).
	h.flushStaged(t)
	commitObjID := ids.ID(db.GetState(poolManagerAddr9999, orderSlot(recordID, orderCommitObjSuffix)))
	if commitObjID == ids.Empty {
		t.Fatal("commit must record the C->D commit object id on the position")
	}
	raw, ok := h.readCtoDObject(t, commitObjID)
	if !ok {
		t.Fatal("C->D commit object not found in shared memory after commit")
	}
	rail, owner, asset, amount, _, decOK := decodeAtomicObject(raw)
	if !decOK || rail != railLP || owner != h.caller || asset != native || amount != 400 {
		t.Fatalf("C->D commit object mismatch: ok=%v rail=%d owner=%s asset=%x amount=%d", decOK, rail, owner.Hex(), asset, amount)
	}
}

// TestLP_CollectImportsDToCCredit — COLLECT consumes a D->C object ONCE and credits
// the LP out of committedPositions (DPendingCollect -> CSettled). The committed pot
// falls by exactly the credited amount; the LP's CSpendable balance rises by it.
func TestLP_CollectImportsDToCCredit(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	// Commit 400 (committedPositions = 400, the C-side backing of the live position).
	recordID, _ := h.commitNativePosition(t, -60, 60, 400, lpSalt(0x02))
	if loadCommittedPositions(db, native).Int64() != 400 {
		t.Fatalf("committedPositions must be 400 after commit, got %s", loadCommittedPositions(db, native))
	}

	// D exported a railLP D->C collect object for the LP (principal withdraw of 250).
	outputID := ids.ID{0xC0, 0x11}
	h.putDtoCLPObject(t, h.caller, outputID, native, 250)

	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	out, err := h.collectNative(outputID, 250, recordID)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if new(big.Int).SetBytes(out).Int64() != 250 {
		t.Fatalf("collect must credit 250, returned %s", new(big.Int).SetBytes(out))
	}
	// CSpendable rose by 250; committedPositions fell by 250.
	if new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), callerBefore).Int64() != 250 {
		t.Fatal("collect must credit the LP's CSpendable balance by 250")
	}
	if loadCommittedPositions(db, native).Int64() != 150 {
		t.Fatalf("committedPositions must be 150 after collecting 250, got %s", loadCommittedPositions(db, native))
	}
	// The position record's backing fell to 150 too (still Open).
	if loadRestingOrder(db, recordID).LockedAmt.Int64() != 150 {
		t.Fatalf("position record LockedAmt must be 150 after collecting 250, got %s", loadRestingOrder(db, recordID).LockedAmt)
	}
	h.vaultInvariantNative(t, "after collect")

	// Replay: consuming the SAME object again reverts (one-time D->C).
	if _, err := h.collectNative(outputID, 250, recordID); err != ErrNativeSettleReplay {
		t.Fatalf("re-collecting the same D->C object must revert ErrNativeSettleReplay, got: %v", err)
	}
}

// TestLP_DecreaseLiquidityReturnsFundsToC — a DECREASE (REMOVE) marks the position
// Closing and emits the withdraw request; the funds return when the LP consumes the
// resulting D->C object via collectPosition (the full decrease->collect path).
func TestLP_DecreaseLiquidityReturnsFundsToC(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x03)

	recordID, _ := h.commitNativePosition(t, -60, 60, 600, salt)

	// DECREASE 200 (a partial withdraw request). Marks the position Closing; moves NO
	// C value here.
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	args := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(-200), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, args), 5_000_000, false); err != nil {
		t.Fatalf("decrease (withdraw request): %v", err)
	}
	if loadRestingOrder(db, recordID).Status != OrderStatusClosing {
		t.Fatal("decrease must mark the position CLOSING")
	}
	if loadCommittedPositions(db, native).Int64() != 600 {
		t.Fatal("the withdraw request alone must NOT change committedPositions")
	}

	// D exports the railLP D->C object for the 200 principal; the LP collects it.
	outputID := ids.ID{0xDE, 0xC0}
	h.putDtoCLPObject(t, h.caller, outputID, native, 200)
	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	if _, err := h.collectNative(outputID, 200, recordID); err != nil {
		t.Fatalf("collect of decreased principal: %v", err)
	}
	if new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), callerBefore).Int64() != 200 {
		t.Fatal("decrease->collect must return 200 to the LP's CSpendable balance")
	}
	if loadCommittedPositions(db, native).Int64() != 400 {
		t.Fatalf("committedPositions must be 400 after withdrawing 200 of 600, got %s", loadCommittedPositions(db, native))
	}
	h.vaultInvariantNative(t, "after decrease->collect")
}

// TestLP_BurnClosesPositionAndWithdraws — BURN (full REMOVE) marks the position
// Closing; the full principal returns via the D->C collect object; positionsOf drops
// the position (only OPEN listed).
func TestLP_BurnClosesPositionAndWithdraws(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x04)

	recordID, _ := h.commitNativePosition(t, -60, 60, 500, salt)

	// BURN: route a full REMOVE through 0x9996 burn (delta forced negative).
	burnArgs := pmLifecycleCalldata(SelectorPMBurn, h.key, -60, 60, big.NewInt(500), salt, MakerSideBid)
	if _, _, err := PositionManagerPrecompile.Run(h.state, h.caller, positionManagerAddr, burnArgs, 5_000_000, false); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if loadRestingOrder(db, recordID).Status != OrderStatusClosing {
		t.Fatal("burn must mark the position CLOSING")
	}
	// positionsOf drops the closing position (only OPEN listed).
	pOut, _, _ := PositionManagerPrecompile.Run(h.state, h.caller, positionManagerAddr,
		prependSelector(SelectorPMPositionsOf, leftPad32(h.caller.Bytes())), 5_000_000, true)
	if new(big.Int).SetBytes(pOut[32:64]).Int64() != 0 {
		t.Fatal("positionsOf must be empty after burn")
	}

	// D exports the full principal; the LP collects it.
	outputID := ids.ID{0xB0, 0x12}
	h.putDtoCLPObject(t, h.caller, outputID, native, 500)
	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	if _, err := h.collectNative(outputID, 500, recordID); err != nil {
		t.Fatalf("collect of burned principal: %v", err)
	}
	if new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), callerBefore).Int64() != 500 {
		t.Fatal("burn->collect must return the full 500 to the LP")
	}
	if loadCommittedPositions(db, native).Sign() != 0 {
		t.Fatalf("committedPositions must be 0 after the full withdraw, got %s", loadCommittedPositions(db, native))
	}
	// FIX-3: a fully-collected position is Closed (terminal).
	if loadRestingOrder(db, recordID).Status != OrderStatusCancelled {
		t.Fatalf("burn->full-collect must leave the position Closed, got status %d", loadRestingOrder(db, recordID).Status)
	}
	h.vaultInvariantNative(t, "after burn->collect")
}

// TestLP_CancelRefundsViaDToC — a CANCEL (REMOVE) refunds the LP's committed
// principal ONLY through a consumed D->C object; the cancel itself moves no C value.
func TestLP_CancelRefundsViaDToC(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x05)

	recordID, _ := h.commitNativePosition(t, -120, 120, 300, salt)
	callerAfterCommit := h.state.stateDB.GetBalance(h.caller).ToBig()

	// CANCEL via 0x9996 cancelLimit (REMOVE). No C credit here.
	cancelArgs := pmLifecycleCalldata(SelectorPMCancelLimit, h.key, -120, 120, big.NewInt(300), salt, MakerSideBid)
	if _, _, err := PositionManagerPrecompile.Run(h.state, h.caller, positionManagerAddr, cancelArgs, 5_000_000, false); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if h.state.stateDB.GetBalance(h.caller).ToBig().Cmp(callerAfterCommit) != 0 {
		t.Fatal("cancel alone must NOT credit the LP (funds are on D)")
	}
	if loadCommittedPositions(db, native).Int64() != 300 {
		t.Fatal("cancel alone must NOT change committedPositions")
	}

	// The refund returns ONLY by consuming the railLP D->C object.
	outputID := ids.ID{0xCA, 0x11}
	h.putDtoCLPObject(t, h.caller, outputID, native, 300)
	if _, err := h.collectNative(outputID, 300, recordID); err != nil {
		t.Fatalf("cancel refund collect: %v", err)
	}
	if new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), callerAfterCommit).Int64() != 300 {
		t.Fatal("cancel->collect must refund the full 300")
	}
	h.vaultInvariantNative(t, "after cancel->collect")
}

// TestLP_NeverCSpendableAndDCommitted — the state-machine invariant: at every step a
// unit is EITHER in the LP's CSpendable EVM balance OR in committedPositions backing a
// D position, NEVER both. The conserved total (caller balance + committedPositions +
// the vault's other pots) is constant across commit and collect; the vault-account
// invariant holds throughout.
func TestLP_NeverCSpendableAndDCommitted(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	h.fundCallerNative(1000)
	// The conserved system total for native = caller CSpendable + the vault's real
	// native holding (which == settleVault+makerLocked+seam+committedPositions).
	systemTotal := func() *big.Int {
		caller := h.state.stateDB.GetBalance(h.caller).ToBig()
		vault := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig()
		return new(big.Int).Add(caller, vault)
	}
	total0 := systemTotal()

	// A unit is in exactly ONE place: assert caller_balance and committedPositions are
	// disjoint and their movement is balanced at each step.
	assertNeverBoth := func(where string, prevCaller, prevCommitted *big.Int) (*big.Int, *big.Int) {
		caller := h.state.stateDB.GetBalance(h.caller).ToBig()
		committed := loadCommittedPositions(db, native)
		dCaller := new(big.Int).Sub(caller, prevCaller)          // change in CSpendable
		dCommitted := new(big.Int).Sub(committed, prevCommitted) // change in DCommitted
		// Every unit that left CSpendable entered DCommitted (and vice-versa): the two
		// deltas are exact negatives — a unit is never created in both nor lost from both.
		if new(big.Int).Add(dCaller, dCommitted).Sign() != 0 {
			t.Fatalf("%s: NEVER-BOTH violated: dCSpendable=%s + dDCommitted=%s != 0", where, dCaller, dCommitted)
		}
		if systemTotal().Cmp(total0) != 0 {
			t.Fatalf("%s: system total drifted (mint/burn): %s != %s", where, systemTotal(), total0)
		}
		h.vaultInvariantNative(t, where)
		return caller, committed
	}

	c, cm := h.state.stateDB.GetBalance(h.caller).ToBig(), loadCommittedPositions(db, native)
	salt := lpSalt(0x06)
	recordID := MakerOrderID(h.caller, h.key.ID(), salt, -60, 60)

	// COMMIT 400: 400 units move CSpendable -> DCommitted.
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	addArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(400), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, addArgs), 5_000_000, false); err != nil {
		t.Fatalf("commit: %v", err)
	}
	h.flushStaged(t)
	c, cm = assertNeverBoth("after commit 400", c, cm)
	if cm.Int64() != 400 {
		t.Fatalf("committed must be 400, got %s", cm)
	}

	// COMMIT another 100 (same range, re-commit): 100 more move CSpendable -> DCommitted.
	h.fundCallerNative(0) // no-op; balance already present
	addArgs2 := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(100), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, addArgs2), 5_000_000, false); err != nil {
		t.Fatalf("commit 2: %v", err)
	}
	h.flushStaged(t)
	c, cm = assertNeverBoth("after commit +100", c, cm)
	if cm.Int64() != 500 {
		t.Fatalf("committed must be 500, got %s", cm)
	}

	// COLLECT 300: 300 units move DCommitted -> CSpendable.
	outputID := ids.ID{0x6A, 0x33}
	h.putDtoCLPObject(t, h.caller, outputID, native, 300)
	if _, err := h.collectNative(outputID, 300, recordID); err != nil {
		t.Fatalf("collect: %v", err)
	}
	_, cm = assertNeverBoth("after collect 300", c, cm)
	if cm.Int64() != 200 {
		t.Fatalf("committed must be 200 after collecting 300 of 500, got %s", cm)
	}
}

// TestLP_FeeAccrualCollectableOnlyViaDToCObject — fees (value earned on D beyond the
// LP's principal) are collectable ONLY by consuming a railLP D->C object, and only up
// to the LP's OWN recorded backing. The keeper reflects the D-Chain maker-fee credit
// onto the LP's position via creditPositionFee (raising THAT record's withdrawable +
// the pot together), so a principal+fees collect succeeds against a real object; once
// the record is fully collected (Closed) a further collect reverts (no mint, no raid,
// no per-object backing).
func TestLP_FeeAccrualCollectableOnlyViaDToCObject(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x07)

	// LP commits 1000 principal; the keeper credits 50 of earned fees to THIS position
	// (raises the record's withdrawable to 1050 AND the LP pot to 1050).
	recordID, _ := h.commitNativePosition(t, -60, 60, 1000, salt)
	h.creditPositionFeeNative(t, recordID, 50)
	if loadCommittedPositions(db, native).Int64() != 1050 {
		t.Fatalf("committedPositions must be 1000 principal + 50 fee backing, got %s", loadCommittedPositions(db, native))
	}
	if loadRestingOrder(db, recordID).LockedAmt.Int64() != 1050 {
		t.Fatalf("the position's withdrawable must rise to 1050 with the fee credit, got %s", loadRestingOrder(db, recordID).LockedAmt)
	}
	h.vaultInvariantNative(t, "after commit + fee credit")

	// D exports a railLP D->C collect object for principal+fees = 1050. The LP collects.
	outputID := ids.ID{0xFE, 0xE5}
	h.putDtoCLPObject(t, h.caller, outputID, native, 1050)
	callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	if _, err := h.collectNative(outputID, 1050, recordID); err != nil {
		t.Fatalf("fee+principal collect via D->C object: %v", err)
	}
	if new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), callerBefore).Int64() != 1050 {
		t.Fatal("collect must credit principal+fees = 1050 to the LP")
	}
	if loadCommittedPositions(db, native).Sign() != 0 {
		t.Fatalf("committedPositions must be 0 after collecting 1050, got %s", loadCommittedPositions(db, native))
	}

	// A SECOND collect now reverts: the record is fully collected (Closed, LockedAmt=0),
	// so the per-object gate refuses it (no mint, no raid). The position no longer
	// satisfies the Open/Closing gate.
	outputID2 := ids.ID{0xFE, 0xE6}
	h.putDtoCLPObject(t, h.caller, outputID2, native, 10)
	if _, err := h.collectNative(outputID2, 10, recordID); err != ErrLPCollectNoPosition {
		t.Fatalf("a collect against a fully-collected (Closed) position must revert ErrLPCollectNoPosition, got: %v", err)
	}
}

// TestRED_LP_PositionFundableOnlyByConsumingCToDObject — the ship rule (C->D leg): a
// position's funding exists ONLY as a consumable C->D commit object. There is no
// path that funds a D position without a commit object: the commit BOTH debits C AND
// stages the object atomically; a reverting commit leaves neither. The object D
// imports binds the recorded (owner, asset, amount) — D cannot be funded beyond what
// C committed.
func TestRED_LP_PositionFundableOnlyByConsumingCToDObject(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x08)

	// A commit with INSUFFICIENT balance reverts — NO object is staged (no unbacked
	// funding). Fund only 100, try to commit 400.
	h.fundCallerNative(100)
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	badArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(400), salt, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, badArgs), 5_000_000, false); err != ErrNativeFundsShort {
		t.Fatalf("an unbacked commit must revert ErrNativeFundsShort, got: %v", err)
	}
	// committedPositions unchanged; no position recorded; staging seq unmoved => no
	// C->D object was staged for an unbacked commit.
	if loadCommittedPositions(db, native).Sign() != 0 {
		t.Fatal("a reverted commit must not add to committedPositions")
	}
	if stageSeq(db) != 0 {
		t.Fatal("a reverted commit must stage NO C->D object (no unbacked funding)")
	}

	// A SUCCESSFUL commit stages EXACTLY ONE C->D object whose amount == the C debit.
	h.fundCallerNative(300) // now 400 total
	goodArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(400), salt, hookData)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, goodArgs), 5_000_000, false)
	if err != nil {
		t.Fatalf("backed commit: %v", err)
	}
	var recordID [32]byte
	copy(recordID[:], out[0:32])
	h.flushStaged(t)
	commitObjID := ids.ID(db.GetState(poolManagerAddr9999, orderSlot(recordID, orderCommitObjSuffix)))
	raw, ok := h.readCtoDObject(t, commitObjID)
	if !ok {
		t.Fatal("a backed commit must stage a C->D object D can consume")
	}
	rail, _, _, amount, _, _ := decodeAtomicObject(raw)
	if rail != railLP {
		t.Fatalf("the C->D commit object must be stamped railLP, got rail=%d", rail)
	}
	if amount != 400 {
		t.Fatalf("the C->D object amount must equal the C debit (400), got %d", amount)
	}
}

// TestRED_LP_CollectCannotCreditWithoutDToCObject — the ship rule (D->C leg): a
// collect CANNOT credit C without a real D->C object in shared memory. A collect that
// names a non-existent object reverts (ErrNativeNoSettlement); a collect whose claim
// amount/owner does not match the recorded object reverts (bind failure). No declared
// amount can drive a credit.
func TestRED_LP_CollectCannotCreditWithoutDToCObject(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	// Give the LP a live position (so the per-object gate has a record to name) and a
	// fat committed pot.
	recordID, _ := h.commitNativePosition(t, -60, 60, 1000, lpSalt(0x09))
	committedBefore := loadCommittedPositions(db, native)

	// (a) collect with NO object in shared memory => revert, NO credit.
	phantom := ids.ID{0x00, 0xDE, 0xAD}
	if _, err := h.collectNative(phantom, 500, recordID); err != ErrNativeNoSettlement {
		t.Fatalf("collect with no D->C object must revert ErrNativeNoSettlement, got: %v", err)
	}

	// (b) a real railLP object exists for 250, but the claim DECLARES 500 => amount-bind
	// failure, NO credit (the credit is the RECORDED amount, not the declared one).
	realObj := ids.ID{0x00, 0xC0, 0x01}
	h.putDtoCLPObject(t, h.caller, realObj, native, 250)
	if _, err := h.collectNative(realObj, 500, recordID); err != ErrNativeSettleAmount {
		t.Fatalf("collect declaring 500 against a 250 object must revert ErrNativeSettleAmount, got: %v", err)
	}

	// (c) a railLP object owned by a DIFFERENT account => owner-bind failure when this
	// caller claims it (recipient=caller != recorded owner).
	other := common.HexToAddress("0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")
	victimObj := ids.ID{0x00, 0x71, 0x71}
	h.putDtoCLPObject(t, other, victimObj, native, 250)
	if _, err := h.collectNative(victimObj, 250, recordID); err != ErrNativeSettleOwner {
		t.Fatalf("collect of another account's object must revert ErrNativeSettleOwner, got: %v", err)
	}

	// Through all the refused collects, committedPositions is UNTOUCHED (no credit).
	if loadCommittedPositions(db, native).Cmp(committedBefore) != 0 {
		t.Fatal("refused collects must not move committedPositions (no credit without a bound D->C object)")
	}
}

// TestLP_ConservationAcrossCommitMatchCollect — end-to-end conservation: an LP
// commits, a position is funded on D (the C->D object), value is matched/earned on D
// (modeled as the operator fee backing the LP rail), and the LP collects via a D->C
// object. After the full cycle, the LP's net CSpendable change equals (collected −
// committed), the committedPositions pot returns to its post-fee-seed baseline minus
// what was collected, and the vault-account invariant holds at every step.
func TestLP_ConservationAcrossCommitMatchCollect(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)
	salt := lpSalt(0x0A)

	h.fundCallerNative(2000)
	startCaller := h.state.stateDB.GetBalance(h.caller).ToBig()
	h.vaultInvariantNative(t, "genesis")

	// 1) COMMIT 1200: CSpendable -> DCommitted.
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	addArgs := buildModifyLiquidityArgs(h.key, -60, 60, big.NewInt(1200), salt, hookData)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, addArgs), 5_000_000, false)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	var recordID [32]byte
	copy(recordID[:], out[0:32])
	h.flushStaged(t)
	if loadCommittedPositions(db, native).Int64() != 1200 {
		t.Fatalf("committed must be 1200, got %s", loadCommittedPositions(db, native))
	}
	h.vaultInvariantNative(t, "after commit")

	// 2) D imports the C->D object and matches (modeled): the LP earns 80 fees. The
	// keeper reflects the 80 onto THIS position (raises its withdrawable + the LP pot),
	// the cross-rail settlement of taker flow into the maker's collectable balance.
	h.creditPositionFeeNative(t, recordID, 80)
	h.vaultInvariantNative(t, "after match (fee backing)")

	// 3) COLLECT the full withdrawable: principal 1200 + fees 80 = 1280, via a railLP object.
	outputID := ids.ID{0x0A, 0xCC}
	h.putDtoCLPObject(t, h.caller, outputID, native, 1280)
	if _, err := h.collectNative(outputID, 1280, recordID); err != nil {
		t.Fatalf("collect principal+fees: %v", err)
	}
	h.vaultInvariantNative(t, "after collect")

	// Net CSpendable change = collected(1280) − committed(1200) = +80 (the earned fee).
	netCaller := new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), startCaller)
	if netCaller.Int64() != 80 {
		t.Fatalf("LP net CSpendable change must equal earned fees (+80), got %s", netCaller)
	}
	// committedPositions fully drained (1200 principal + 80 fee backing − 1280 collect).
	if loadCommittedPositions(db, native).Sign() != 0 {
		t.Fatalf("committedPositions must be 0 after full collect, got %s", loadCommittedPositions(db, native))
	}
}
