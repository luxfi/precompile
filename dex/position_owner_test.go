// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// position_owner_test.go pins the one fact collectPosition's calldata cannot be trusted
// about: WHOSE position record a collect applies to.
//
// The credit itself is sound — Import binds the object's recorded beneficiary to the
// caller, so a claim can only ever pay the party it names. The positionID rode in beside
// it unchecked, and the record it names is someone's property: a stranger holding a
// legitimate one-wei claim of their own could name any LP's record and drive it to a
// TERMINAL status. The victim's value stays on D, and the record that says how to bring
// it back is closed, so requestPositionWithdraw refuses it. Cheap for the attacker,
// unrecoverable for the victim except by committing new money.

// TestPosition_CollectCannotTouchAnotherPartysRecord is the regression. Mallory's claim
// is entirely legitimate and pays only Mallory; the record she names is Alice's, and
// that is the part that must fail.
func TestPosition_CollectCannotTouchAnotherPartysRecord(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	alice := h.caller
	mallory := common.HexToAddress("0x6666666666666666666666666666666666666666")

	var salt [32]byte
	salt[31] = 1
	recordID, _ := h.commitNativePosition(t, -120, 120, 1_000_000, salt)

	db := newPoolStateAdapter(h.state)
	before := loadRestingOrder(db, [32]byte(recordID))
	if before.Owner != alice {
		t.Fatalf("setup: expected alice to own the record, got %s", before.Owner.Hex())
	}

	// Mallory's own D->C claim, for value that is genuinely hers.
	claim := ids.ID{0x4D, 0x31}
	h.putDtoCObject(t, mallory, claim, [32]byte{}, 1_000_000)

	input := EncodeCollectPositionInput(claim, [32]byte{}, [32]byte(recordID), h.recordedObject(claim))
	_, _, err := h.c.Run(h.state, mallory, poolManagerAddr9999,
		prependSelector(SelectorCollectPosition, input), 5_000_000, false)
	if err == nil {
		t.Error("a collect naming another party's position record was accepted; the record is " +
			"the owner's property and a claim says nothing about it")
	}

	after := loadRestingOrder(db, [32]byte(recordID))
	if after.Status != before.Status || after.LockedAmt.Cmp(before.LockedAmt) != 0 {
		t.Fatalf("alice's record moved under a stranger's collect: status %d -> %d, locked %s -> %s",
			before.Status, after.Status, before.LockedAmt, after.LockedAmt)
	}
	if after.Status == OrderStatusCancelled {
		t.Fatal("alice's record was driven to a terminal status; her value is on D and the " +
			"record that brings it back is now closed")
	}
}

// TestPosition_CollectStillWorksForTheOwner is the other half: binding the record to the
// caller must not cost an LP their own collect. Alice draws against her own record and
// the bookkeeping follows the value exactly as before.
func TestPosition_CollectStillWorksForTheOwner(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	var salt [32]byte
	salt[31] = 2
	recordID, _ := h.commitNativePosition(t, -120, 120, 1_000_000, salt)

	db := newPoolStateAdapter(h.state)
	before := loadRestingOrder(db, [32]byte(recordID))

	const collected uint64 = 400_000
	claim := ids.ID{0xA1, 0xA2}
	h.putDtoCObject(t, h.caller, claim, [32]byte{}, collected)

	out, err := h.collectNative(claim, collected, [32]byte(recordID))
	if err != nil {
		t.Fatalf("the owner's own collect was refused: %v", err)
	}
	if got := new(big.Int).SetBytes(out).Uint64(); got != collected {
		t.Fatalf("collected %d, want %d", got, collected)
	}

	after := loadRestingOrder(db, [32]byte(recordID))
	want := new(big.Int).Sub(before.LockedAmt, new(big.Int).SetUint64(collected))
	if after.LockedAmt.Cmp(want) != 0 {
		t.Fatalf("the record's withdrawable is %s after collecting %d, want %s",
			after.LockedAmt, collected, want)
	}
}
