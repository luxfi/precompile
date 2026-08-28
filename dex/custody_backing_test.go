// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// custody_backing_test.go pins the one question every native funding path asks:
// how much native did THIS call deliver?
//
// 0x9999 holds one native balance backing three pots — settleVault (depositor
// claims), seamReserve (swap-rail input locks) and committedPositions (LP
// commits). The precompile cannot read msg.value, so it answers by difference:
// delivered = balance(0x9999) - Σ pots. Subtract fewer pots than exist and the
// difference reports somebody else's locked funds as value this caller carried,
// which is a claim over the whole seam.

var backingStranger = common.HexToAddress("0x00000000000000000000000000000000000000BA")

// backingPots is the three-pot decomposition the invariant names, so a test can
// exercise each independently and a new pot cannot be added without appearing here.
var backingPots = []struct {
	name string
	lock func(stateKV, [32]byte, uint64)
}{
	{"seamReserve", recordSeamLock},
	{"committedPositions", recordCommittedLock},
}

// TestDepositCannotClaimAnotherPot is the theft. Value locked in the seam or LP
// pot raises the vault's real balance; a deposit that measures itself against
// settleVault alone reads that value as its own delivery and mints a claim over
// it, which withdraw then pays out — draining the backing for every open intent
// and every committed position.
func TestDepositCannotClaimAnotherPot(t *testing.T) {
	for _, pot := range backingPots {
		t.Run(pot.name, func(t *testing.T) {
			h := newSettleHarness(t)
			db := zzmpDB(h)
			aid := h.inAssetID() // native

			// Somebody else locks 1_000 native: the vault's real balance rises and
			// this pot — never settleVault — accounts for it.
			h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1_000))
			pot.lock(db, aid, 1_000)

			// A stranger delivers NOTHING and asks for a claim over the whole pot.
			_, _, err := zzmpRun(h, backingStranger, SelectorDeposit,
				zzmpAssetAmountData(common.Address{}, big.NewInt(1_000)), 5_000_000, false)
			if !errors.Is(err, ErrSettleDepositShort) {
				t.Fatalf("a zero-value deposit against a funded %s: want ErrSettleDepositShort, got %v", pot.name, err)
			}
			if got := loadDepositorClaim(db, backingStranger, aid); got.Sign() != 0 {
				t.Fatalf("a refused deposit minted a claim of %s over the %s", got, pot.name)
			}
			if got := loadSettleVault(db, aid); got.Sign() != 0 {
				t.Fatalf("a refused deposit credited settleVault %s from the %s", got, pot.name)
			}
			// The pot is untouched, so the funds it backs are still payable.
			if got := deliveredNative(db, aid); got.Sign() != 0 {
				t.Fatalf("delivered native = %s with every pot accounted, want 0", got)
			}
		})
	}
}

// TestDepositCreditsOnlyWhatThisCallDelivered pins the other side: a real
// deposit alongside a funded pot still works, and credits exactly what it
// carried — the refusal above must not be bought by refusing everything.
func TestDepositCreditsOnlyWhatThisCallDelivered(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	aid := h.inAssetID()

	// 1_000 already locked in the seam, then this call carries 300.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1_000))
	recordSeamLock(db, aid, 1_000)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(300))

	if got := deliveredNative(db, aid); got.Int64() != 300 {
		t.Fatalf("delivered native = %s, want the 300 this call carried", got)
	}
	// One wei above what was carried is short.
	if _, _, err := zzmpRun(h, backingStranger, SelectorDeposit,
		zzmpAssetAmountData(common.Address{}, big.NewInt(301)), 5_000_000, false); !errors.Is(err, ErrSettleDepositShort) {
		t.Fatalf("a deposit one wei above the delivery: want ErrSettleDepositShort, got %v", err)
	}
	// Exactly what was carried is accepted.
	if _, _, err := zzmpRun(h, backingStranger, SelectorDeposit,
		zzmpAssetAmountData(common.Address{}, big.NewInt(300)), 5_000_000, false); err != nil {
		t.Fatalf("a deposit of exactly the delivered amount: %v", err)
	}
	if got := loadDepositorClaim(db, backingStranger, aid); got.Int64() != 300 {
		t.Fatalf("claim = %s, want 300", got)
	}
	if got := loadSettleVault(db, aid); got.Int64() != 300 {
		t.Fatalf("settleVault = %s, want 300", got)
	}
	// Every pot is now accounted for, so nothing further is claimable.
	if got := deliveredNative(db, aid); got.Sign() != 0 {
		t.Fatalf("delivered native = %s after the deposit settled, want 0", got)
	}
}

// TestDeliveredNativeIsTheOneAnswer pins that the deposit and the operator seed
// ask the same question of the same state. Two spellings of "what did this call
// carry" is how they came to disagree, and the disagreement was the theft.
func TestDeliveredNativeIsTheOneAnswer(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	aid := h.inAssetID()

	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(900))
	recordSeamLock(db, aid, 200)
	recordCommittedLock(db, aid, 300)
	storeSettleVault(db, aid, big.NewInt(400))

	if got := deliveredNative(db, aid); got.Sign() != 0 {
		t.Fatalf("with 200+300+400 accounted against a balance of 900, delivered = %s, want 0", got)
	}

	// The seed path reaches the same answer through receiveOperatorValue: it must
	// refuse for the same reason, not credit the pots it already counted.
	if _, err := receiveOperatorValue(db, backingStranger, Currency{}, aid, big.NewInt(1),
		func(*big.Int) error { return nil }); !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("seed of 1 with nothing delivered: want ErrSeedUndelivered, got %v", err)
	}

	// A real delivery is seen identically by both.
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(75))
	if got := deliveredNative(db, aid); got.Int64() != 75 {
		t.Fatalf("delivered = %s, want 75", got)
	}
	if _, err := receiveOperatorValue(db, backingStranger, Currency{}, aid, big.NewInt(75),
		func(*big.Int) error { return nil }); err != nil {
		t.Fatalf("seed of the delivered 75: %v", err)
	}
}

// TestDeliveredNativeNeverReportsMoreThanTheBalance pins the sign: an
// over-accounted vault (more tracked than held) must report zero delivery, never
// a negative that a Cmp against a positive amount would read as short-but-close.
func TestDeliveredNativeNeverReportsMoreThanTheBalance(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	aid := h.inAssetID()

	storeSettleVault(db, aid, big.NewInt(10))
	if got := deliveredNative(db, aid); got.Sign() >= 0 {
		t.Fatalf("tracked above held must report a negative delivery so callers refuse, got %s", got)
	}
	if _, _, err := zzmpRun(h, backingStranger, SelectorDeposit,
		zzmpAssetAmountData(common.Address{}, big.NewInt(1)), 5_000_000, false); !errors.Is(err, ErrSettleDepositShort) {
		t.Fatalf("a deposit against an over-accounted vault: want ErrSettleDepositShort, got %v", err)
	}
}
