// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"
)

// swap_views_test.go proves the 0x9999 READ surface the maker/trader depend on:
// getBestBidAsk(bytes32) and getOpenOrders(address), served over the SAME live
// resting book swapPlace writes. It reuses the real *state.StateDB harness
// (native_zap_realstate_test.go) so the reads run against the production money path,
// not a mock. Before this surface existed the maker could place but never enumerate
// (→ never cancel) its resting orders; the round-trip below is that gap closed.

// getBestBidAsk9999 calls getBestBidAsk(poolID) at 0x9999 and decodes the 96-byte
// (bestBid, bestAsk, fromBook) the maker/trader expect (prices in the PriceInt grid).
func (h *rsHarness) getBestBidAsk9999(poolID [32]byte) (bid, ask uint64, fromBook bool) {
	h.t.Helper()
	out, err := h.callDex(h.maker, prependSelector(SelectorGetBestBidAsk, poolID[:]))
	if err != nil {
		h.t.Fatalf("getBestBidAsk: %v", err)
	}
	if len(out) < 96 {
		h.t.Fatalf("getBestBidAsk short return: %d bytes", len(out))
	}
	return new(big.Int).SetBytes(out[0:32]).Uint64(),
		new(big.Int).SetBytes(out[32:64]).Uint64(),
		out[95] == 1
}

// openOrders9999 calls getOpenOrders(owner) at 0x9999 and decodes the bytes32[] as
// the maker does (each element's low 8 bytes = a uint64 order id).
func (h *rsHarness) openOrders9999(owner [20]byte) []uint64 {
	h.t.Helper()
	body := make([]byte, 32)
	copy(body[12:32], owner[:])
	out, err := h.callDex(h.maker, prependSelector(SelectorGetOpenOrders, body))
	if err != nil {
		h.t.Fatalf("getOpenOrders: %v", err)
	}
	if len(out) < 64 {
		h.t.Fatalf("getOpenOrders short return: %d bytes", len(out))
	}
	n := int(new(big.Int).SetBytes(out[32:64]).Uint64())
	ids := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		w := out[64+i*32 : 64+i*32+32]
		ids = append(ids, new(big.Int).SetBytes(w).Uint64())
	}
	return ids
}

// swapCancel9999 cancels a resting order via swapCancel(key, orderID) at 0x9999.
func (h *rsHarness) swapCancel9999(caller [20]byte, orderID uint64) uint64 {
	h.t.Helper()
	data := make([]byte, 192)
	copy(data[0:160], EncodePoolKeyABI(h.market()))
	new(big.Int).SetUint64(orderID).FillBytes(data[160:192])
	out, err := h.callDex(caller, prependSelector(SelectorSwapCancel, data))
	if err != nil {
		h.t.Fatalf("swapCancel(%d): %v", orderID, err)
	}
	return new(big.Int).SetBytes(out).Uint64()
}

func contains(ids []uint64, want uint64) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestSwapViews_On9999_EnumerateReadBestCancel is the maker-lifecycle proof: place
// resting orders, READ them back through 0x9999 (getBestBidAsk / getOpenOrders), then
// CANCEL by an enumerated id and re-read — the exact place→read→cancel loop the maker
// runs and previously could not (getOpenOrders returned "unknown 0x9999 selector").
func TestSwapViews_On9999_EnumerateReadBestCancel(t *testing.T) {
	h := newRSHarness(t)
	mult := uint64(priceMultiplierConst)

	// Fund the maker on BOTH sides: it already holds quote (for bids); give it base so
	// it can also rest an ask (sell base).
	h.tokenTransfer(h.deployer, h.base, h.maker, big.NewInt(1000))
	h.approve9999(h.maker, h.quote, big.NewInt(100_000))
	h.swapDeposit(h.maker, h.quote, 100_000)
	h.approve9999(h.maker, h.base, big.NewInt(1000))
	h.swapDeposit(h.maker, h.base, 1000)
	h.commit()

	// Rest two bids (49, 50) and one ask (60). swapPlace returns each order id.
	bid49 := h.swapPlace(h.maker, true, 49*mult, 100)
	bid50 := h.swapPlace(h.maker, true, 50*mult, 100)
	ask60 := h.swapPlace(h.maker, false, 60*mult, 100)
	h.commit()

	poolID := h.market().ID()

	// getBestBidAsk over the LIVE book: best bid = 50 (highest), best ask = 60 (lowest),
	// fromBook set. Prices are the exact PriceInt grid the maker placed.
	bid, ask, fromBook := h.getBestBidAsk9999(poolID)
	if !fromBook {
		t.Fatalf("getBestBidAsk fromBook=false, want true (there ARE resting orders)")
	}
	if bid != 50*mult {
		t.Fatalf("bestBid = %d, want %d (the 50 bid)", bid, 50*mult)
	}
	if ask != 60*mult {
		t.Fatalf("bestAsk = %d, want %d (the 60 ask)", ask, 60*mult)
	}

	// getOpenOrders(maker) enumerates all three — the ids the maker needs to cancel.
	ids := h.openOrders9999(h.maker)
	if len(ids) != 3 {
		t.Fatalf("getOpenOrders(maker) = %v (%d), want 3 ids", ids, len(ids))
	}
	for _, want := range []uint64{bid49, bid50, ask60} {
		if !contains(ids, want) {
			t.Fatalf("getOpenOrders missing placed id %d: got %v", want, ids)
		}
	}

	// A DIFFERENT account has no resting orders — the owner filter is real.
	if other := h.openOrders9999(h.taker); len(other) != 0 {
		t.Fatalf("getOpenOrders(taker) = %v, want empty (taker rested nothing)", other)
	}

	// CANCEL the top bid by an enumerated id → it settles (returns 1) and the book updates:
	// best bid falls to 49, and getOpenOrders no longer lists it.
	if got := h.swapCancel9999(h.maker, bid50); got != 1 {
		t.Fatalf("swapCancel(bid50=%d) = %d, want 1 (cancelled)", bid50, got)
	}
	h.commit()

	bid, _, _ = h.getBestBidAsk9999(poolID)
	if bid != 49*mult {
		t.Fatalf("after cancel of top bid, bestBid = %d, want %d (the 49 bid)", bid, 49*mult)
	}
	ids = h.openOrders9999(h.maker)
	if len(ids) != 2 || contains(ids, bid50) {
		t.Fatalf("after cancel, getOpenOrders(maker) = %v, want 2 ids without %d", ids, bid50)
	}
}
