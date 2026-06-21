// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_callindex_test.go is the FIX-4 regression suite: callIndex determinism and
// intent-id collision-freedom across a non-trivial in-tx call tree (two swaps + a
// precompile call inside a REVERTED sub-frame + a STATICCALL), plus the reentrancy
// guard on SettleSwap.
//
// DETERMINISM MODEL (matches geth core/vm/precompile_env.go): the host increments a
// per-tx precompileCallIndex once per precompile invocation — for EVERY invocation,
// including those in reverted sub-frames and STATICCALLs — and resets it to 0 at tx
// start. So a precompile's CallIndex() is a pure function of (txID, ordinal-within-tx).
// DeriveIntentID binds (networkID, cChainID, dChainID, txID, callIndex, account,
// assetIn, amountIn, marketID), so:
//   - two distinct invocations in one tx get distinct callIndexes -> distinct ids,
//     even when account/asset/amount/market are identical;
//   - a deterministic re-execution reproduces the IDENTICAL call tree, hence the
//     IDENTICAL callIndex for each invocation, hence BYTE-IDENTICAL intent ids
//     network-wide (the consensus property).
//
// txCallCounter mirrors the host's per-tx counter so this unit test sequences
// callIndexes exactly as the geth EVM would. The full live EVM call-tree test (real
// revert frames + STATICCALL opcodes) is CI-only (needs CGO + LUXCPP); this proves the
// id-derivation contract the host's counter feeds.

// txCallCounter is the per-tx precompile call-index counter (the unit-test twin of
// evm.precompileCallIndex). next() returns the current index and advances — exactly
// what NewPrecompileEnvironment does per invocation.
type txCallCounter struct{ idx uint32 }

func (c *txCallCounter) next() uint32 { i := c.idx; c.idx++; return i }

// invokeSwap drives ONE SettleSwap invocation at the NEXT call index of the current tx
// (the host would have advanced the counter at frame entry). It returns the raw output
// (a 32-byte intent id for Phase A) and the error.
func (h *settleHarness) invokeSwap(t testing.TB, ctr *txCallCounter, readOnly bool) ([]byte, error) {
	t.Helper()
	h.state.callIndex = ctr.next()
	return h.runSwap(t, h.intentCalldata(), readOnly)
}

// TestFIX4_IntentIDDeterministicAndCollisionFreeAcrossCallTree — two real Phase-A
// swaps in ONE tx, separated by a precompile call inside a REVERTED sub-frame and a
// STATICCALL, all consuming call indices as the host would. The two real swaps must
// produce DISTINCT intent ids (collision-free), and re-executing the IDENTICAL call
// tree must reproduce BYTE-IDENTICAL ids for each (deterministic replay).
func TestFIX4_IntentIDDeterministicAndCollisionFreeAcrossCallTree(t *testing.T) {
	// run executes the full call tree once over a fresh harness with a fixed txID and
	// returns the two real-swap intent ids in order.
	run := func(txID ids.ID) (ids.ID, ids.ID) {
		h := newSettleHarness(t)
		h.state.txID = txID
		h.registerMarket(t)
		h.fundCallerNative(10_000)
		ctr := &txCallCounter{}

		// (idx 0) FIRST real swap -> stages a C->D intent, returns intent id.
		out1, err := h.invokeSwap(t, ctr, false)
		if err != nil {
			t.Fatalf("swap1: %v", err)
		}

		// (idx 1) A precompile call inside a REVERTED sub-frame. The host advanced the
		// counter at frame entry; on revert the StateDB writes roll back, but the index
		// was consumed (re-execution reproduces this same consumed index). We model the
		// revert by discarding its staging (no durable effect) while still consuming idx.
		seqBefore := ReadStagedAtomicSeq(h.state.stateDB)
		h.state.callIndex = ctr.next()
		if _, rerr := h.runSwap(t, h.intentCalldata(), false); rerr != nil {
			t.Fatalf("reverted-frame swap pre-revert: %v", rerr)
		}
		// REVERT: roll the staged seq back to before this sub-frame (EVM snapshot/revert
		// discards the sub-frame's StateDB writes).
		setStageSeq(newPoolStateAdapter(h.state), seqBefore)

		// (idx 2) A STATICCALL (read-only): the host advanced the counter; the call is
		// read-only so SettleSwap short-circuits (cannot settle in read-only mode) and
		// stages NO value — but the index is still consumed.
		if _, serr := h.invokeSwap(t, ctr, true); serr == nil {
			t.Fatal("a read-only (STATICCALL) settle must refuse, not move value")
		}

		// (idx 3) SECOND real swap. Same account/asset/amount/market as swap1 — only the
		// callIndex differs (3 vs 0). It must still produce a DISTINCT intent id.
		out2, err := h.invokeSwap(t, ctr, false)
		if err != nil {
			t.Fatalf("swap2: %v", err)
		}

		var id1, id2 ids.ID
		copy(id1[:], out1)
		copy(id2[:], out2)
		return id1, id2
	}

	tx := ids.ID{0xAB, 0xCD}
	a1, a2 := run(tx)

	// COLLISION-FREE: the two real swaps differ only by callIndex (0 vs 3) yet must have
	// distinct intent ids — the reverted-frame and STATICCALL indices in between do NOT
	// let two real swaps alias.
	if a1 == a2 {
		t.Fatal("COLLISION: two same-params swaps in one tx must have distinct intent ids (callIndex disambiguation)")
	}
	if a1 == (ids.ID{}) || a2 == (ids.ID{}) {
		t.Fatal("intent ids must be non-empty")
	}

	// DETERMINISTIC REPLAY: re-execute the IDENTICAL call tree (same txID, same frame
	// structure). Every invocation gets the same callIndex, so the ids are byte-identical.
	b1, b2 := run(tx)
	if a1 != b1 || a2 != b2 {
		t.Fatalf("NON-DETERMINISTIC: re-executing the identical call tree must reproduce identical intent ids; got (%x,%x) then (%x,%x)", a1, a2, b1, b2)
	}

	// A DIFFERENT txID must yield different ids (the tx binding is part of the identity).
	c1, c2 := run(ids.ID{0xEF, 0x01})
	if c1 == a1 || c2 == a2 {
		t.Fatal("a different txID must produce different intent ids (tx binding)")
	}
}

// TestFIX4_DeriveIntentIDPureOnCallIndex — DeriveIntentID is collision-free purely on
// the callIndex axis: holding every other field fixed, distinct call indices yield
// distinct ids, and the same call index reproduces the same id. This is the algebraic
// core the host's per-tx counter relies on.
func TestFIX4_DeriveIntentIDPureOnCallIndex(t *testing.T) {
	net := uint32(1)
	c := ids.ID{0xCC}
	d := ids.ID{0xDD}
	tx := ids.ID{0x7A}
	acct := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var asset, market [32]byte
	market[0] = 0xAA

	seen := make(map[ids.ID]uint32)
	for i := uint32(0); i < 256; i++ {
		id := DeriveIntentID(net, c, d, tx, i, acct, asset, 100, market)
		if prev, dup := seen[id]; dup {
			t.Fatalf("COLLISION: callIndex %d and %d derived the same intent id", prev, i)
		}
		seen[id] = i
		// Re-derivation with the same callIndex is byte-identical (determinism).
		if id != DeriveIntentID(net, c, d, tx, i, acct, asset, 100, market) {
			t.Fatalf("NON-DETERMINISTIC: callIndex %d re-derivation differs", i)
		}
	}
	if len(seen) != 256 {
		t.Fatalf("expected 256 distinct ids across 256 call indices, got %d", len(seen))
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
	if _, err := h.runSwap(t, h.intentCalldata(), false); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	// The guard is free again — a second settle in a fresh frame succeeds.
	h.state.callIndex = 1
	if _, err := h.runSwap(t, h.intentCalldata(), false); err != nil {
		t.Fatalf("second sequential settle must succeed (guard released after the first): %v", err)
	}
}
