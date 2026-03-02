// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

func TestFillAttestationAttest(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	// Set attester (first time, anyone can set)
	if err := mgr.SetAttester(stateDB, common.Address{}, attester); err != nil {
		t.Fatalf("SetAttester failed: %v", err)
	}

	// Set ceiling to $10M (18 decimals)
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	if err := mgr.SetCeiling(stateDB, attester, ceiling); err != nil {
		t.Fatalf("SetCeiling failed: %v", err)
	}

	orderID := OrderIDFromString("alpaca-order-12345")
	symbol := SymbolToBytes32("AAPL")
	amount := big.NewInt(100)                                       // 100 shares
	price := new(big.Int).Mul(big.NewInt(175), big.NewInt(1e18))    // $175/share

	// Attest
	err := mgr.Attest(stateDB, attester, orderID, symbol, amount, price, user, 1711036800)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Verify attestation exists
	att := mgr.GetAttestation(stateDB, orderID)
	if att == nil {
		t.Fatal("attestation not found after Attest")
	}
	if att.Status != FillPending {
		t.Fatalf("expected FillPending, got %d", att.Status)
	}
	if att.Amount.Cmp(amount) != 0 {
		t.Fatalf("amount mismatch: got %s, want %s", att.Amount, amount)
	}
	if att.User != user {
		t.Fatalf("user mismatch: got %s, want %s", att.User, user)
	}
	if att.Attester != attester {
		t.Fatalf("attester mismatch: got %s, want %s", att.Attester, attester)
	}
}

func TestFillAttestationDuplicate(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	mgr.SetCeiling(stateDB, attester, ceiling)

	orderID := OrderIDFromString("alpaca-order-dup")
	symbol := SymbolToBytes32("BTC")
	amount := big.NewInt(1)
	price := new(big.Int).Mul(big.NewInt(60000), big.NewInt(1e18))

	// First attest succeeds
	if err := mgr.Attest(stateDB, attester, orderID, symbol, amount, price, user, 1711036800); err != nil {
		t.Fatalf("first Attest failed: %v", err)
	}

	// Second attest for same order fails
	err := mgr.Attest(stateDB, attester, orderID, symbol, amount, price, user, 1711036800)
	if err != ErrDuplicateAttestation {
		t.Fatalf("expected ErrDuplicateAttestation, got %v", err)
	}
}

func TestFillAttestationUnauthorized(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	rando := common.HexToAddress("0xCC00000000000000000000000000000000000003")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	mgr.SetCeiling(stateDB, attester, ceiling)

	orderID := OrderIDFromString("alpaca-order-unauth")
	symbol := SymbolToBytes32("ETH")
	amount := big.NewInt(10)
	price := new(big.Int).Mul(big.NewInt(3500), big.NewInt(1e18))

	// Random address cannot attest
	err := mgr.Attest(stateDB, rando, orderID, symbol, amount, price, user, 1711036800)
	if err != ErrUnauthorizedAttester {
		t.Fatalf("expected ErrUnauthorizedAttester, got %v", err)
	}
}

func TestFillAttestationPrefundCeiling(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)

	// Set ceiling to $100 (very low for testing)
	ceiling := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	mgr.SetCeiling(stateDB, attester, ceiling)

	symbol := SymbolToBytes32("AAPL")
	price := new(big.Int).Mul(big.NewInt(175), big.NewInt(1e18)) // $175/share

	// First order: 1 share = $175 > $100 ceiling
	orderID := OrderIDFromString("ceiling-test-1")
	err := mgr.Attest(stateDB, attester, orderID, symbol, big.NewInt(1), price, user, 1711036800)
	if err != ErrPrefundCeilingExceeded {
		t.Fatalf("expected ErrPrefundCeilingExceeded, got %v", err)
	}
}

func TestFillAttestationChallenge(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	mgr.SetCeiling(stateDB, attester, ceiling)

	orderID := OrderIDFromString("alpaca-order-challenge")
	symbol := SymbolToBytes32("NVDA")
	amount := big.NewInt(50)
	price := new(big.Int).Mul(big.NewInt(800), big.NewInt(1e18))

	// Attest
	if err := mgr.Attest(stateDB, attester, orderID, symbol, amount, price, user, 1711036800); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Outstanding should be 50 * 800e18 = 40000e18
	outstanding := mgr.GetOutstanding(stateDB)
	expected := new(big.Int).Mul(big.NewInt(50), new(big.Int).Mul(big.NewInt(800), big.NewInt(1e18)))
	if outstanding.Cmp(expected) != 0 {
		t.Fatalf("outstanding mismatch: got %s, want %s", outstanding, expected)
	}

	// Challenge
	reversalProof := []byte("alpaca-reversal-confirmation-12345")
	if err := mgr.Challenge(stateDB, attester, orderID, reversalProof); err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}

	// Verify status
	att := mgr.GetAttestation(stateDB, orderID)
	if att.Status != FillReversed {
		t.Fatalf("expected FillReversed, got %d", att.Status)
	}

	// Outstanding should be 0
	outstanding = mgr.GetOutstanding(stateDB)
	if outstanding.Sign() != 0 {
		t.Fatalf("outstanding should be 0 after challenge, got %s", outstanding)
	}
}

func TestFillAttestationFinalize(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	mgr.SetCeiling(stateDB, attester, ceiling)

	// Set fraud window to 10 blocks (short for testing)
	if err := mgr.SetFraudWindow(stateDB, attester, 10); err != nil {
		t.Fatalf("SetFraudWindow failed: %v", err)
	}

	orderID := OrderIDFromString("alpaca-order-finalize")
	symbol := SymbolToBytes32("MSFT")
	amount := big.NewInt(25)
	price := new(big.Int).Mul(big.NewInt(400), big.NewInt(1e18))

	// Attest at block 1
	if err := mgr.Attest(stateDB, attester, orderID, symbol, amount, price, user, 1711036800); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Finalize too early should fail
	err := mgr.Finalize(stateDB, orderID)
	if err != ErrFraudWindowActive {
		t.Fatalf("expected ErrFraudWindowActive, got %v", err)
	}

	// Advance block to past fraud window
	// Set block number to 12 (attestation at block 1, window 10, so block 11 should work)
	blockKey := makeStorageKey(fillConfigPrefix, []byte("block"))
	var blockData common.Hash
	blockData[31] = 12
	stateDB.SetState(fillAttestAddr, blockKey, blockData)

	// Clear cache so getCurrentBlock reads from state
	mgr2 := NewFillAttestationManager()
	// Re-read attestation from state
	mgr2.SetAttester(stateDB, common.Address{}, attester)
	mgr2.SetFraudWindow(stateDB, attester, 10)

	err = mgr2.Finalize(stateDB, orderID)
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	att := mgr2.GetAttestation(stateDB, orderID)
	if att.Status != FillFinalized {
		t.Fatalf("expected FillFinalized, got %d", att.Status)
	}
}

func TestFillAttestationChallengeAfterFinalize(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	mgr.SetCeiling(stateDB, attester, ceiling)
	mgr.SetFraudWindow(stateDB, attester, 0) // instant finalization for test

	orderID := OrderIDFromString("alpaca-order-post-finalize")
	symbol := SymbolToBytes32("GOOG")
	amount := big.NewInt(10)
	price := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))

	mgr.Attest(stateDB, attester, orderID, symbol, amount, price, user, 1711036800)
	mgr.Finalize(stateDB, orderID)

	// Challenge after finalize should fail
	err := mgr.Challenge(stateDB, attester, orderID, []byte("proof"))
	if err != ErrAttestationFinalized {
		t.Fatalf("expected ErrAttestationFinalized, got %v", err)
	}
}

func TestOrderIDFromString(t *testing.T) {
	id1 := OrderIDFromString("order-1")
	id2 := OrderIDFromString("order-2")
	id1dup := OrderIDFromString("order-1")

	if id1 == id2 {
		t.Fatal("different inputs should produce different IDs")
	}
	if id1 != id1dup {
		t.Fatal("same input should produce same ID")
	}
}

func TestSymbolToBytes32(t *testing.T) {
	s := SymbolToBytes32("AAPL")
	if s[0] != 'A' || s[1] != 'A' || s[2] != 'P' || s[3] != 'L' {
		t.Fatalf("SymbolToBytes32 mismatch: got %v", s[:4])
	}
	// Rest should be zero
	for i := 4; i < 32; i++ {
		if s[i] != 0 {
			t.Fatalf("expected zero at position %d, got %d", i, s[i])
		}
	}
}

func TestFillAttestationInvalidParams(t *testing.T) {
	stateDB := NewMockStateDB()
	mgr := NewFillAttestationManager()

	attester := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	user := common.HexToAddress("0xBB00000000000000000000000000000000000002")

	mgr.SetAttester(stateDB, common.Address{}, attester)

	orderID := OrderIDFromString("invalid-params")
	symbol := SymbolToBytes32("TEST")

	// Zero amount
	err := mgr.Attest(stateDB, attester, orderID, symbol, big.NewInt(0), big.NewInt(100), user, 0)
	if err != ErrInvalidAttestationParam {
		t.Fatalf("expected ErrInvalidAttestationParam for zero amount, got %v", err)
	}

	// Nil amount
	err = mgr.Attest(stateDB, attester, orderID, symbol, nil, big.NewInt(100), user, 0)
	if err != ErrInvalidAttestationParam {
		t.Fatalf("expected ErrInvalidAttestationParam for nil amount, got %v", err)
	}

	// Zero price
	err = mgr.Attest(stateDB, attester, orderID, symbol, big.NewInt(1), big.NewInt(0), user, 0)
	if err != ErrInvalidAttestationParam {
		t.Fatalf("expected ErrInvalidAttestationParam for zero price, got %v", err)
	}

	// Zero address user
	err = mgr.Attest(stateDB, attester, orderID, symbol, big.NewInt(1), big.NewInt(100), common.Address{}, 0)
	if err != ErrInvalidAttestationParam {
		t.Fatalf("expected ErrInvalidAttestationParam for zero user, got %v", err)
	}
}
