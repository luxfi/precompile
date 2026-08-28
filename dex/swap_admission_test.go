// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// swap_admission_test.go pins WHERE the market-admission question is asked.
//
// A market becomes real at initialize (settle_market.go), which resolves both
// assets through the installed AssetResolver and requires live on-chain code at
// each. Several surfaces re-read that record and require it Active before they
// act: the LP commit, the quoter, the stateview reads. The swap money path does
// not, and this file records that as a measured fact rather than an assumption.

// admissionKey is a well-formed PoolKey over two addresses that initialize never
// registered as a market.
func admissionKey() PoolKey {
	return PoolKey{
		Currency0:   Currency{Address: common.Address{}},
		Currency1:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000FE")},
		Fee:         3000,
		TickSpacing: 60,
	}
}

// TestMarketAdmissionHasOnePredicate pins the question itself: MarketExists and an
// Active status are the same answer, and an uninitialized key answers no to both.
func TestMarketAdmissionHasOnePredicate(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)

	key := admissionKey()
	if MarketExists(db, key) {
		t.Fatal("an uninitialized key must not read as a market")
	}
	if loadMarket(db, key.ID()).Status == MarketStatusActive {
		t.Fatal("an uninitialized key must not load as Active")
	}

	h.registerMarket(t)
	if !MarketExists(db, h.key) {
		t.Fatal("the registered harness market must read as a market")
	}
	if loadMarket(db, h.key.ID()).Status != MarketStatusActive {
		t.Fatal("the registered harness market must load as Active")
	}
}

// TestTheViewSurfacesRequireARegisteredMarket pins the surfaces that DO ask. Each
// refuses an uninitialized key rather than answering over it.
func TestTheViewSurfacesRequireARegisteredMarket(t *testing.T) {
	h := newSettleHarness(t)
	key := admissionKey()

	q := &QuoterContract{}
	if _, _, err := q.Run(h.state, h.caller, common.HexToAddress(DEXQuoterAddress),
		quoteCalldata(SelQExactInput, key, big.NewInt(1_000), true), 5_000_000, true); !errors.Is(err, ErrQuoteNoMarket) {
		t.Fatalf("quote on an unregistered market: want ErrQuoteNoMarket, got %v", err)
	}

	v := &StateViewContract{}
	poolID := key.ID()
	if _, _, err := v.Run(h.state, h.caller, common.HexToAddress(DEXStateViewAddress),
		prependSelector(SelectorGetMarket, poolID[:]), 5_000_000, true); err == nil {
		t.Fatal("getMarket on an unregistered market must be refused")
	}
}

// TestSwapDoesNotAskWhereItsSiblingsDo records the gap. A Phase-A swap against an
// uninitialized key is accepted: it locks the caller's asset into the seam and
// stages a cross-chain object carrying a market id nothing admitted.
//
// Closing it is a one-line status check identical to the LP commit's in
// position_commit.go, but it changes which calls a chain accepts, so it is a
// coordinated upgrade rather than a patch — and adding it fails eighteen existing
// tests, every one of which swaps against a key it never registered. When the check
// lands, this test asserts the refusal instead of the acceptance.
func TestSwapDoesNotAskWhereItsSiblingsDo(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(10_000)
	key := admissionKey()
	if MarketExists(zzmpDB(h), key) {
		t.Fatal("fixture: the key under test must not be a registered market")
	}
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-1_000)}

	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, buildSwapCalldata(key, params, nil)), 5_000_000, false); err != nil {
		t.Fatalf("swap against an unregistered market now returns %v — the admission check "+
			"was added; assert the refusal here instead of the acceptance", err)
	}
	// And it is not free: the accepted swap locked the caller's asset against a
	// market that does not exist, and staged a cross-chain record naming its id.
	aid := assetID(key.Currency0)
	if got := loadSeamReserve(zzmpDB(h), aid); got.Sign() == 0 {
		t.Fatal("the accepted swap locked nothing — re-read what this test characterises")
	}
	if got := stageSeq(zzmpDB(h)); got == 0 {
		t.Fatal("the accepted swap staged nothing — re-read what this test characterises")
	}
}
