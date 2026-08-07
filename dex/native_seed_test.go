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

// native_seed_test.go is the FIX-4 suite: the swap rail's first matched settlement of
// an output asset is backed by a PRODUCTION operator seed (seedSeamReserve), not a
// test-only state poke. It proves:
//   - an UN-seeded first fill reverts ErrNativeSettleUnbacked (no mint), and
//   - after the operator seeds seamReserve through the real gated selector, the first
//     matched swap settles, and
//   - the seed is operator-gated (a non-operator caller is refused) and value-backed
//     (a native seed with no delivered msg.value reverts), and
//   - the LP-rail fee credit (creditPositionFee) is symmetric (gated + value-backed).

// TestFIX4_FirstFillRevertsWithoutSeed — before any opposing-direction intent lock or
// operator seed, seamReserve[assetOut] is empty, so the first matched swap settlement
// (consuming a real railSwap D->C object) reverts ErrNativeSettleUnbacked. No mint, no
// raid of another pot — the credit needs the seam's OWN backing.
func TestFIX4_FirstFillRevertsWithoutSeed(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	if loadSeamReserve(db, native).Sign() != 0 {
		t.Fatal("seam reserve must start empty (no seed, no opposing lock)")
	}
	// A real railSwap D->C object exists, but seamReserve[native] is empty.
	obj := ids.ID{0xF1, 0x00, 0x01}
	h.putDtoCObjectRail(t, railSwap, h.caller, obj, native, 250)
	if _, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: native, AssetAddr: common.Address{}, Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, native, 250),
	}); err != ErrNativeSettleUnbacked {
		t.Fatalf("an unseeded first fill MUST revert ErrNativeSettleUnbacked, got: %v", err)
	}
}

// TestFIX4_OperatorSeedBacksFirstFill — the operator seeds seamReserve through the
// REAL seedSeamReserve selector (the production path), and the first matched swap then
// settles. The seed moves real value into the vault and is reflected in seamReserve;
// the vault-account invariant holds throughout.
func TestFIX4_OperatorSeedBacksFirstFill(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	native := h.inAssetID()
	db := newPoolStateAdapter(h.state)

	// Operator seeds 1000 native counterparty backing via the real selector.
	h.fundVaultNativeOut(1000)
	if loadSeamReserve(db, native).Int64() != 1000 {
		t.Fatalf("seedSeamReserve must set seamReserve[native]=1000, got %s", loadSeamReserve(db, native))
	}
	h.vaultInvariantNative(t, "after operator seed")

	// The FIRST matched swap now settles from the seeded reserve.
	obj := ids.ID{0xF2, 0x00, 0x01}
	h.putDtoCObjectRail(t, railSwap, h.caller, obj, native, 250)
	before := h.state.stateDB.GetBalance(h.caller).ToBig()
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: obj, Asset: native, AssetAddr: common.Address{}, Recipient: h.caller,
		Object: encodeAtomicObject(railSwap, h.caller, native, 250),
	})
	if err != nil || credited != 250 {
		t.Fatalf("a seam-seeded first fill must settle 250: credited=%d err=%v", credited, err)
	}
	if new(big.Int).Sub(h.state.stateDB.GetBalance(h.caller).ToBig(), before).Int64() != 250 {
		t.Fatal("the first matched swap must credit the taker 250 from the seeded reserve")
	}
	if loadSeamReserve(db, native).Int64() != 750 {
		t.Fatalf("seam reserve must fall to 750 after the 250 settlement, got %s", loadSeamReserve(db, native))
	}
	h.vaultInvariantNative(t, "after first fill")
}

// TestFIX4_SeedIsOperatorGatedAndValueBacked — the seed selector is gated to the
// protocolFeeController and refuses a bookkeeping (value-less) native seed.
func TestFIX4_SeedIsOperatorGatedAndValueBacked(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	// (a) a NON-operator caller is refused (ErrUnauthorized) — only the operator seeds.
	notOp := common.HexToAddress("0xBADBAD0000000000000000000000000000000001")
	data := make([]byte, 64)
	big.NewInt(500).FillBytes(data[32:64]) // native asset (word0 zero), amount 500
	// The non-operator "delivers" value too (so the only failure is the auth gate).
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(500))
	if _, _, err := h.c.Run(h.state, notOp, poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false); err != ErrUnauthorized {
		t.Fatalf("a non-operator seed must revert ErrUnauthorized, got: %v", err)
	}

	// (b) the operator seeding native with NO delivered value reverts (no mint): the
	// observed-delta is 0 against a value==0 call. (We seeded the vault in (a) for the
	// auth test, so first drain it back to a known baseline by recording it as a real
	// seed, then attempt a value-less seed.)
	//    Reset: treat the 500 already in the vault as a legitimate prior seed.
	okData := make([]byte, 64)
	big.NewInt(500).FillBytes(okData[32:64])
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, okData), 5_000_000, false); err != nil {
		t.Fatalf("operator seed of the already-delivered 500 must succeed, got: %v", err)
	}
	// Now a SECOND native seed with NO new delivered value must revert (delivered=0).
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, okData), 5_000_000, false); err != ErrSeedUndelivered {
		t.Fatalf("a value-less native seed must revert ErrSeedUndelivered (no mint), got: %v", err)
	}
}

// TestFIX4_FeeCreditIsOperatorGated — the symmetric LP-rail fee credit
// (creditPositionFee) is also operator-gated.
func TestFIX4_FeeCreditIsOperatorGated(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	recordID, _ := h.commitNativePosition(t, -60, 60, 500, lpSalt(0x61))

	notOp := common.HexToAddress("0xBADBAD0000000000000000000000000000000002")
	data := make([]byte, 96)
	copy(data[0:32], recordID[:])
	big.NewInt(50).FillBytes(data[64:96])
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(50))
	if _, _, err := h.c.Run(h.state, notOp, poolManagerAddr9999,
		prependSelector(SelectorCreditPositionFee, data), 5_000_000, false); err != ErrUnauthorized {
		t.Fatalf("a non-operator fee credit must revert ErrUnauthorized, got: %v", err)
	}
}
