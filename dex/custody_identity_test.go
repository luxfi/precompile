// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/ids"
)

// custody_identity_test.go pins the sentence native_state.go opens with:
//
//	custody[a] = operator seed of a
//	           + Σ value exported to D (C->D claims written)
//	           − Σ value imported from D (D->C claims consumed)
//
// One pot per asset is only defensible while that identity holds, because a single pot
// means every claim draws on the same number. The identity is what makes the number
// exactly "value C holds because D owns it" — no more, so a claim cannot draw on
// backing nobody on D is owed, and no less, so every D holder can be paid.
//
// It had a fourth term. creditPositionFee raised custody with no D-side crossing, which
// put real value in the shared pot that no D account owned and wrote an LP a
// withdrawable the rail could not deliver.

// TestCustody_HasNoTermBesidesSeedAndCrossings walks the identity through a full LP
// cycle and asserts custody equals it at every step.
func TestCustody_HasNoTermBesidesSeedAndCrossings(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	var seed, exported, imported int64

	identity := func(where string) {
		t.Helper()
		want := big.NewInt(seed + exported - imported)
		if got := loadCustody(db, native); got.Cmp(want) != 0 {
			t.Fatalf("%s: custody[native] = %s, want seed(%d) + exported(%d) - imported(%d) = %s",
				where, got, seed, exported, imported, want)
		}
		h.vaultInvariantNative(t, where)
	}

	identity("genesis")

	// A COMMIT is a C->D export: it debits the LP on C and writes a claim D consumes.
	var salt [32]byte
	salt[31] = 0x1D
	recordID, _ := h.commitNativePosition(t, -60, 60, 1_000, salt)
	exported += 1_000
	identity("after commit")

	// A COLLECT is a D->C import: it consumes a claim D exported and pays out of custody.
	claim := ids.ID{0xC0, 0x1D}
	h.putDtoCObject(t, h.caller, claim, [32]byte{}, 400)
	if _, err := h.collectNative(claim, 400, [32]byte(recordID)); err != nil {
		t.Fatalf("collect: %v", err)
	}
	imported += 400
	identity("after collect")

	// A SEED is the one other term, and it is in the identity by name.
	h.fundVaultNativeOut(250)
	seed += 250
	identity("after seed")

	// Nothing else on the whole 0x9999 surface can move custody. If a new term is ever
	// added, it lands here as a mismatch rather than as an LP who cannot collect.
	remaining := loadCustody(db, native).Int64()
	if remaining != seed+exported-imported {
		t.Fatalf("custody drifted to %d", remaining)
	}
}

// TestCustody_RetiredFeeCreditIsUnreachable pins the deletion. creditPositionFee was a
// live, governance-gated selector on every network — it needed no atomic capability, so
// unlike the rest of the rail it was reachable today. Its calldata must now be an
// unknown selector rather than a path that quietly still exists.
func TestCustody_RetiredFeeCreditIsUnreachable(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	var salt [32]byte
	salt[31] = 0x2D
	recordID, _ := h.commitNativePosition(t, -60, 60, 500, salt)

	// creditPositionFee(bytes32,address,uint256) — the retired selector, called by the
	// one account that was ever allowed to call it.
	retired := keccak4("creditPositionFee(bytes32,address,uint256)")
	data := make([]byte, 96)
	copy(data[0:32], recordID[:])
	big.NewInt(50).FillBytes(data[64:96])

	// The operator ALSO delivers the value, so the call fails for the only reason left:
	// there is no such selector. (Without this, an undelivered-value revert would let
	// the test pass while the path still existed.)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(50))

	before := loadCustody(newPoolStateAdapter(h.state), h.inAssetID())
	_, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(retired, data), 5_000_000, false)
	if err == nil {
		t.Fatal("the retired fee credit still executes")
	}
	if !strings.Contains(err.Error(), "unknown 0x9999 selector") {
		t.Fatalf("the retired call failed for an incidental reason (%v); it must be an "+
			"unknown selector, or the path is still there", err)
	}
	after := loadCustody(newPoolStateAdapter(h.state), h.inAssetID())
	if after.Cmp(before) != 0 {
		t.Fatalf("the retired call moved custody %s -> %s", before, after)
	}
}
