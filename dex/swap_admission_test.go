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
// each. Every surface that acts on a pool identity re-reads that record and
// requires it Active first: the LP commit, the quoter, the stateview reads, and
// the swap money path. marketID is the one predicate all of them ask.

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

// TestSwapAsksWhereItsSiblingsDo. A Phase-A swap against an uninitialized key is
// refused before it locks anything: no asset enters custody and no cross-chain
// object is staged naming an id nothing admitted.
func TestSwapAsksWhereItsSiblingsDo(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(10_000)
	key := admissionKey()
	if MarketExists(zzmpDB(h), key) {
		t.Fatal("fixture: the key under test must not be a registered market")
	}
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-1_000)}

	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, buildSwapCalldata(key, params, nil)), 5_000_000, false); !errors.Is(err, ErrSwapNoMarket) {
		t.Fatalf("swap against an unregistered market: want ErrSwapNoMarket, got %v", err)
	}
	if got := loadCustody(zzmpDB(h), assetID(key.Currency0)); got.Sign() != 0 {
		t.Fatalf("a refused swap locked %s into custody", got)
	}
	if got := stageSeq(zzmpDB(h)); got != 0 {
		t.Fatalf("a refused swap staged %d cross-chain objects", got)
	}
}

// TestHaltBindsTheRegisteredMarketNotTheSuppliedKey moves the axis the halt suite
// never moved. Every halt test varies the HALT and holds the PoolKey fixed, so none
// of them can tell "the halt binds a registered market" from "the halt binds a
// number the caller supplied". Here the halt is fixed on the real market and the KEY
// varies by one calldata field.
//
// The forged key keeps both currencies, so the asset-halt scope is byte-identical
// and the swap direction resolves to the same pair; only the fee tier differs, which
// is enough to move key.ID() to a slot governance never set. Without the registry
// resolution that key settles around the halt.
func TestHaltBindsTheRegisteredMarketNotTheSuppliedKey(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(10_000)

	// Governance halts the REAL market. Global and asset halts stay off.
	if err := haltMarket(h, h.operator(), h.key.ID(), true); err != nil {
		t.Fatalf("governance setHaltMarket: %v", err)
	}
	if _, err := h.runSwap(t, h.crossCalldata(), false); !errors.Is(err, ErrMarketHalted) {
		t.Fatalf("the halted market must refuse its own key: got %v", err)
	}

	// One field of the tuple changes. Same currencies, same direction, same amount.
	forged := h.key
	forged.Fee = 500
	forgedID := forged.ID()
	if forgedID == h.key.ID() {
		t.Fatal("fixture: the forged key must hash to a different pool id")
	}
	in0, out0 := swapAssetDirection(h.key, h.params)
	in1, out1 := swapAssetDirection(forged, h.params)
	if in0 != in1 || out0 != out1 {
		t.Fatal("fixture: the forged key must move the pool id and nothing else")
	}
	if isHalted(zzmpDB(h), makeStorageKey(haltMarketPrefix, forgedID[:])) {
		t.Fatal("fixture: governance never set a halt at the forged pool id")
	}

	if _, err := h.runSwap(t, buildSwapCalldata(forged, h.params, nil), false); !errors.Is(err, ErrSwapNoMarket) {
		t.Fatalf("a fabricated pool key settled around a market halt: want ErrSwapNoMarket, got %v", err)
	}
	if got := loadCustody(zzmpDB(h), in1); got.Sign() != 0 {
		t.Fatalf("the fabricated key locked %s into custody past a halted market", got)
	}
}
