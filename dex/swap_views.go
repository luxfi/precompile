// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// swap_views.go is the READ counterpart to swap_custody.go: the deterministic,
// write-incapable getters over the SYNCHRONOUS 0x9999 order book — the dexcore
// resting book that swapPlace writes and swapCancel / a maker fill removes. They
// live at 0x9999, the SAME address that holds the book, so the maker and the
// off-chain readers see the exact liquidity swapPlace rested with no cross-
// precompile hop. (0x9997 StateView answers the SAME two signatures over the
// registry/position rail; these answer them over the live CLOB book. Same ABI,
// different rail — the maker targets 0x9999 because that is where its orders live.)
//
// DETERMINISM: both are pure functions of (input, 0x9999 StateDB). getBestBidAsk
// folds the market's persisted rows through the ONE rebuild path
// (dexcore.RebuildBook) and reads the top of book; getOpenOrders walks the append-
// only markets index and each market's order index (the SAME indices core_store
// maintains for the rebuild) in insertion order, filtering to the owner's resting
// orders. No engine probe and no map iteration — every validator computes the
// identical bytes.

// runGetBestBidAsk answers getBestBidAsk(bytes32 poolID) -> (uint256 bestBid,
// uint256 bestAsk, bool fromBook) over the LIVE resting book. Prices are the
// integer PriceInt grid (quote-per-base * dexcore.PriceMultiplier) — the SAME grid
// swapPlace consumes, so a read round-trips a placed price. A side with no resting
// order returns 0 for that side; fromBook is 1 iff either side has a resting order
// (this is the book, never a registry spot). Read-only by construction (GetState
// only), matching the 96-byte layout the maker/trader decode.
func (s *SettleContract) runGetBestBidAsk(state contract.AccessibleState, input []byte, gas uint64) ([]byte, uint64, error) {
	if len(input) < 32 {
		return nil, gas, ErrViewBadInput
	}
	if gas < GasStateView {
		return nil, 0, errors.New("dex: out of gas")
	}
	var poolID [32]byte
	copy(poolID[:], input[:32])
	store := newEVMStore(newPoolStateAdapter(state))

	// Per-order gas: RebuildBook folds every resting row in this market.
	extra := GasStateView * uint64(len(store.indexIDs(poolID)))
	if gas < GasStateView+extra {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasStateView - extra

	ob, err := dexcore.RebuildBook(store, poolID, dexcore.PoolSymbol(poolID))
	if err != nil {
		return nil, gasLeft, err
	}
	bid := int64(dexcore.PriceToInt(ob.GetBestBid()))
	ask := int64(dexcore.PriceToInt(ob.GetBestAsk()))
	out := make([]byte, 96)
	if bid > 0 {
		new(big.Int).SetInt64(bid).FillBytes(out[0:32])
	}
	if ask > 0 {
		new(big.Int).SetInt64(ask).FillBytes(out[32:64])
	}
	if bid > 0 || ask > 0 {
		out[95] = 1
	}
	return out, gasLeft, nil
}

// runGetOpenOrders answers getOpenOrders(address owner) -> bytes32[] orderIDs over
// the LIVE resting book, MARKET-AGNOSTIC: every order the owner has resting on ANY
// market, each as its uint64 id left-padded into a bytes32 word (the maker decodes
// the low 8 bytes and feeds each straight back into swapCancel(key, orderID),
// brute-forcing its configured markets). The scan walks the append-only markets
// index and each market's order index — the SAME indices the book rebuild uses —
// keeping only orders whose FULL settlement identity (GetOrderUser) is the owner, so
// it reports exactly the owner's cancellable orders and nothing else. A resting-order
// index entry IS an open order (fills and cancels de-index the row), so no per-order
// status re-check is needed. Deterministic order: markets then per-market ids, both
// insertion-ordered.
func (s *SettleContract) runGetOpenOrders(state contract.AccessibleState, input []byte, gas uint64) ([]byte, uint64, error) {
	if len(input) < 32 {
		return nil, gas, ErrViewBadInput
	}
	if gas < GasStateView {
		return nil, 0, errors.New("dex: out of gas")
	}
	owner := common.BytesToAddress(input[12:32])
	want := accountFromAddress(owner)
	store := newEVMStore(newPoolStateAdapter(state))

	gasLeft := gas - GasStateView
	var open [][32]byte
	for _, poolID := range store.marketsList() {
		for _, id := range store.indexIDs(poolID) {
			// One SLOAD-equivalent per scanned order (the GetOrderUser read).
			if gasLeft < GasStateView {
				return nil, 0, errors.New("dex: out of gas")
			}
			gasLeft -= GasStateView
			u, ok, uerr := dexcore.GetOrderUser(store, poolID, id)
			if uerr != nil {
				return nil, gasLeft, uerr
			}
			if !ok || u != want {
				continue
			}
			var w [32]byte
			putU64(w[24:32], id)
			open = append(open, w)
		}
	}
	return encodeBytes32Array(open), gasLeft, nil
}
