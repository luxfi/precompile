// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_callindex_test.go is the intent-id regression suite for the CHAIN-OBSERVABLE id
// model (the watch-correlation fix). DeriveIntentID now binds (networkID, cChainID,
// dChainID, account, assetIn, amountIn, marketID, NONCE) — NO txID. The nonce is the
// taker's own disambiguator, carried in the swap's DI01 hookData, so:
//   - the id derives ONLY from values knowable BEFORE the tx lands (no post-landing
//     txID), so the off-chain keeper derives the IDENTICAL id from the IDENTICAL calldata
//     (watch correlation against a live chain);
//   - two distinct invocations in one tx get distinct ids by carrying distinct nonces
//     (replacing the former callIndex axis), even with identical account/asset/amount/
//     market;
//   - a deterministic re-execution reproduces BYTE-IDENTICAL ids (the consensus property)
//     because the nonce is in the calldata, not a per-node value.
//
// (The host's per-tx precompileCallIndex still exists for other precompiles; the swap id
// no longer consumes it — the user nonce is the disambiguator.)

// invokeSwapNonce drives ONE Phase-A SettleSwap invocation carrying `nonce` in its DI01
// hookData. It returns the raw output (a 32-byte intent id for Phase A) and the error.
func (h *settleHarness) invokeSwapNonce(t testing.TB, nonce uint64, readOnly bool) ([]byte, error) {
	t.Helper()
	return h.runSwap(t, h.intentCalldataWithNonce(0, nonce), readOnly)
}

// TestIntentID_DeterministicAndCollisionFreeAcrossNonces — two real Phase-A swaps in ONE
// tx with the SAME account/asset/amount/market but DISTINCT nonces must produce DISTINCT
// intent ids (collision-free), and re-executing the identical calls reproduces
// BYTE-IDENTICAL ids (deterministic, txID-independent).
func TestIntentID_DeterministicAndCollisionFreeAcrossNonces(t *testing.T) {
	// run executes both swaps once over a fresh harness with a given txID and returns the
	// two intent ids in order. The txID is varied across runs to PROVE the id no longer
	// depends on it (the watch-correlation fix).
	run := func(txID ids.ID) (ids.ID, ids.ID) {
		h := newSettleHarness(t)
		h.state.txID = txID
		h.registerMarket(t)
		h.fundCallerNative(10_000)

		out1, err := h.invokeSwapNonce(t, 1, false)
		if err != nil {
			t.Fatalf("swap1 (nonce 1): %v", err)
		}
		// A read-only (STATICCALL) settle must still refuse — it stages no value and does
		// not consume a nonce (the nonce lives in calldata, not a host counter).
		if _, serr := h.invokeSwapNonce(t, 1, true); serr == nil {
			t.Fatal("a read-only (STATICCALL) settle must refuse, not move value")
		}
		out2, err := h.invokeSwapNonce(t, 2, false)
		if err != nil {
			t.Fatalf("swap2 (nonce 2): %v", err)
		}
		var id1, id2 ids.ID
		copy(id1[:], out1)
		copy(id2[:], out2)
		return id1, id2
	}

	a1, a2 := run(ids.ID{0xAB, 0xCD})

	// COLLISION-FREE on the nonce axis: same params, nonces 1 vs 2 => distinct ids.
	if a1 == a2 {
		t.Fatal("COLLISION: two same-params swaps with distinct nonces must have distinct intent ids")
	}
	if a1 == (ids.ID{}) || a2 == (ids.ID{}) {
		t.Fatal("intent ids must be non-empty")
	}

	// TXID-INDEPENDENT + DETERMINISTIC: re-run with a DIFFERENT txID. The ids MUST be
	// byte-identical to the first run — proving the id no longer binds the txID (so the
	// off-chain side, which cannot know the txID before signing, derives the same id).
	b1, b2 := run(ids.ID{0xEF, 0x01})
	if a1 != b1 || a2 != b2 {
		t.Fatalf("INTENT ID MUST BE TXID-INDEPENDENT (watch-correlation fix): the same (account,asset,"+
			"amount,market,nonce) produced (%x,%x) under one txID but (%x,%x) under another — the id must "+
			"derive only from chain-observable, pre-signing values.", a1, a2, b1, b2)
	}
}

// TestIntentID_OffChainEqualsOnChain is the DECISIVE watch-correlation proof: the id the
// off-chain keeper derives (from the economic tuple + nonce, with NO txID) EQUALS the id
// the on-chain SubmitSwapIntent mints. Pre-fix the off-chain side substituted a zero txID
// while the chain used the real txID, so the two never matched and the watch could not
// correlate. Now both call DeriveIntentID with the SAME chain-observable inputs.
func TestIntentID_OffChainEqualsOnChain(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(10_000)
	h.state.txID = ids.ID{0xDE, 0xAD, 0xBE, 0xEF} // some real landing txID, unknown off-chain

	const nonce uint64 = 42

	// ON-CHAIN: run the real Phase-A swap; it returns the minted intent id.
	out, err := h.invokeSwapNonce(t, nonce, false)
	if err != nil {
		t.Fatalf("on-chain swap: %v", err)
	}
	var onChain ids.ID
	copy(onChain[:], out)

	// OFF-CHAIN: derive the id the way the keeper/SDK does — from the SAME (networkID,
	// cChainID, dChainID, account, assetIn, amountIn, marketID, nonce), WITHOUT the txID.
	in, _ := swapAssetDirection(h.key, h.params)
	amountIn := new(big.Int).Abs(h.params.AmountSpecified).Uint64()
	offChain := DeriveIntentID(
		h.state.NetworkID(), h.state.CChainID(), h.state.DChainID(),
		h.caller, in, amountIn, h.key.ID(), nonce,
	)

	if offChain != onChain {
		t.Fatalf("WATCH CORRELATION BROKEN: off-chain-derived id %x != on-chain id %x for the same intent. "+
			"The keeper's watch keys on the off-chain id; if it differs from the chain's id, the watch never "+
			"correlates against the live chain.", offChain, onChain)
	}
	t.Logf("WATCH CORRELATION OK: off-chain id == on-chain id == %x (txID-independent)", onChain)
}

// TestDeriveIntentID_PureOnNonce — DeriveIntentID is collision-free purely on the nonce
// axis: holding every other field fixed, distinct nonces yield distinct ids and the same
// nonce reproduces the same id. This is the algebraic core the disambiguation relies on.
func TestDeriveIntentID_PureOnNonce(t *testing.T) {
	net := uint32(1)
	c := ids.ID{0xCC}
	d := ids.ID{0xDD}
	acct := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var asset, market [32]byte
	market[0] = 0xAA

	seen := make(map[ids.ID]uint64)
	for i := uint64(0); i < 256; i++ {
		id := DeriveIntentID(net, c, d, acct, asset, 100, market, i)
		if prev, dup := seen[id]; dup {
			t.Fatalf("COLLISION: nonce %d and %d derived the same intent id", prev, i)
		}
		seen[id] = i
		if id != DeriveIntentID(net, c, d, acct, asset, 100, market, i) {
			t.Fatalf("NON-DETERMINISTIC: nonce %d re-derivation differs", i)
		}
	}
	if len(seen) != 256 {
		t.Fatalf("expected 256 distinct ids across 256 nonces, got %d", len(seen))
	}
}

// TestFIX4_SettleSwapIsNonReentrant — SettleSwap takes the SAME single custody guard
// slot as deposit/withdraw/modifyLiquidity. With the guard already held (a custody op
// in progress on the same 0x9999 surface), a re-entrant SettleSwap refuses with
// ErrCustodyReentrant before moving any value — uniform defense-in-depth across the
// money surface, so a malicious token's transfer callback cannot re-enter the seam.
func TestFIX4_SettleSwapIsNonReentrant(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	db := newPoolStateAdapter(h.state)

	// Simulate an in-flight custody op holding the guard (what a deposit/withdraw/
	// modifyLiquidity does for the duration of its sub-call).
	if !enterCustodyKV(db) {
		t.Fatal("guard must be free initially")
	}
	defer exitCustodyKV(db)

	// A SettleSwap entering while the guard is held must refuse — no lock, no object.
	seqBefore := ReadStagedAtomicSeq(h.state.stateDB)
	_, err := h.runSwap(t, h.intentCalldata(), false)
	if err != ErrCustodyReentrant {
		t.Fatalf("re-entrant SettleSwap must refuse with ErrCustodyReentrant, got: %v", err)
	}
	if ReadStagedAtomicSeq(h.state.stateDB) != seqBefore {
		t.Fatal("a refused re-entrant settle must stage NO atomic op (no value moved)")
	}
}

// TestFIX4_SettleSwapReleasesGuardForSequentialCalls — the guard is per-call (released
// on exit), so SEQUENTIAL settles in distinct frames both succeed. Proves the FIX-4
// guard does not wedge the normal two-phase flow (intent then settlement).
func TestFIX4_SettleSwapReleasesGuardForSequentialCalls(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(10_000)

	// First settle (Phase A) succeeds and RELEASES the guard via its deferred exit.
	if _, err := h.invokeSwapNonce(t, 1, false); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	// The guard is free again — a second settle in a fresh frame succeeds. It carries a
	// DISTINCT nonce so it is a distinct intent (the same nonce would be a replay of the
	// first intent, correctly rejected — that is the intent-id one-time guard, not the
	// custody guard this test exercises).
	if _, err := h.invokeSwapNonce(t, 2, false); err != nil {
		t.Fatalf("second sequential settle must succeed (guard released after the first): %v", err)
	}
}
