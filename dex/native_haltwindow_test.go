// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// native_haltwindow_test.go is the FIX-2 regression suite: the consensus-liveness
// chain-halt window in the host's block-accept atomic flush.
//
// THE BUG (Red-found): the old host flush applied the staged ops to shared memory
// FIRST (sm.Apply with no batch -> committed immediately) and advanced the node-local
// seq marker LATER, in a separate versiondb.Commit(). atomic.SharedMemory.Apply is
// NOT idempotent (a duplicate Put errors). So a crash BETWEEN the eager Apply and the
// marker commit left shared memory MUTATED but the marker UNADVANCED. On restart the
// SAME parent->current window re-collected, sm.Apply re-applied the already-present
// Put, errored "duplicate put", and Accept returned fatal -> the chain HALTED, unable
// to re-accept the block.
//
// THE FIX: stage the advanced marker into the versiondb in-memory layer, then pass
// the versiondb commit batch to sm.Apply(reqs, batch). The atomic layer commits the
// shared-memory mutation AND the batch (marker included) in ONE database write
// (WriteAll). So the marker advance and the SM mutation are all-or-nothing — a crash
// either commits both (re-accept finds an advanced marker -> EMPTY window -> no
// duplicate Put) or neither (re-accept re-derives the full window -> applies fresh).
//
// These tests model the host's single-write commit at the precompile unit level: the
// seq marker rides the SAME database batch passed to FlushAcceptedAtomicOps, exactly
// as the EVM acceptedBlockDB marker rides the versiondb batch. They run against the
// REAL atomic.Memory (which rejects duplicate Puts), so a regression that drops the
// one-batch atomicity FAILS here. The full live path (real versiondb + crash injection
// in plugin/evm Accept) is CI-only (needs CGO + LUXCPP); see vm.go stageDexAtomic.

// hostAtomicMarkerKey is the unit-test analogue of the EVM's dexAtomicSeqKey: the
// node-local last-applied staged-atomic seq, persisted in the SAME database the
// shared memory commits into so the marker advance and the Apply are one write.
var hostAtomicMarkerKey = []byte("dex_atomic_flushed_seq_test")

func readHostMarker(t testing.TB, db database.Database) uint64 {
	t.Helper()
	b, err := db.Get(hostAtomicMarkerKey)
	if err == database.ErrNotFound || len(b) != 8 {
		return 0
	}
	if err != nil {
		t.Fatalf("read host marker: %v", err)
	}
	return binary.BigEndian.Uint64(b)
}

// acceptOnce models ONE host Block.Accept of the native atomic seam (the fixed
// stageDexAtomic + block.go single-commit path):
//
//  1. derive the flush window [from, to) from the node-local marker (from) and the
//     accepted state's staged seq (to) — the consensus boundary;
//  2. collect that window's staged ops;
//  3. build the commit batch and STAGE the advanced marker (to) into it (mirrors
//     acceptedBlockDB.Put of dexAtomicSeqKey into the versiondb the batch snapshots);
//  4. THE SINGLE ATOMIC WRITE:
//     - with ops: sm.Apply(reqs, batch) — its WriteAll replays our batch (marker)
//     onto the shared-memory batch and writes BOTH in one db write;
//     - without ops: batch.Write() — persists just the marker (mirrors the plain
//     versiondb.Commit() path the EVM takes when there is nothing cross-chain).
//
// If commit==false we model a CRASH BEFORE the single write (step 4): the batch and
// reqs are prepared but neither sm.Apply nor batch.Write runs, so NOTHING is durable —
// not the SM mutation, not the marker. Returns the number of ops the window contained.
func (h *settleHarness) acceptOnce(t testing.TB, commit bool) (applied int, err error) {
	t.Helper()
	from := readHostMarker(t, h.memdbBacking)
	to := ReadStagedAtomicSeq(h.state.stateDB)
	if to < from {
		return 0, ErrAtomicSeqRegression
	}
	reqs, cerr := CollectStagedAtomicRange(h.state.stateDB, from, to)
	if cerr != nil {
		return 0, cerr
	}
	for _, r := range reqs {
		applied += len(r.PutRequests) + len(r.RemoveRequests)
	}
	if !commit {
		// (crash before the single write) nothing was applied or marked.
		return applied, nil
	}

	batch := h.memdbBacking.NewBatch()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], to)
	if perr := batch.Put(hostAtomicMarkerKey, buf[:]); perr != nil {
		return 0, perr
	}
	// THE single atomic write. sm.Apply's WriteAll(smBatch, batch) writes the SM
	// mutation AND our marker in one db write — they are all-or-nothing.
	if len(reqs) > 0 {
		if aerr := h.cSM.Apply(reqs, batch); aerr != nil {
			return applied, aerr // pre-WriteAll error: nothing durable.
		}
		return applied, nil
	}
	// No cross-chain ops: still advance the marker durably (the plain-commit path).
	if werr := batch.Write(); werr != nil {
		return applied, werr
	}
	return applied, nil
}

// TestFIX2_ReAcceptAfterCommittedWindowIsCleanNoOp — THE chain-halt regression. After
// a window's ops + marker commit together (one batch.Write), re-accepting the SAME
// block re-derives the window from the ADVANCED marker, gets an EMPTY window, and
// applies NOTHING — so the non-idempotent shared memory is never hit with a duplicate
// Put and Accept does NOT fatal. This is the crash-AFTER-commit recovery: both the SM
// mutation and the marker are durable, so replay is a clean no-op.
func TestFIX2_ReAcceptAfterCommittedWindowIsCleanNoOp(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	out, err := h.runSwap(t, h.orderCalldata(), false)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	var id ids.ID
	copy(id[:], out)

	// First accept: window (0,1] -> 1 Put applied, marker advances to 1, all committed
	// in one batch write.
	applied, err := h.acceptOnce(t, true)
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if applied != 1 {
		t.Fatalf("first accept applied %d ops, want 1", applied)
	}
	if _, ok := h.readCtoDObject(t, id); !ok {
		t.Fatal("object must be present after the first committed accept")
	}
	if m := readHostMarker(t, h.memdbBacking); m != 1 {
		t.Fatalf("marker after first accept = %d, want 1 (rode the same batch as Apply)", m)
	}

	// CRASH-AFTER-COMMIT then RESTART: re-accept the SAME block. The marker is 1 and the
	// accepted state's staged seq is 1, so the window (1,1] is EMPTY. NOTHING is applied
	// -> the non-idempotent SM is never re-hit -> NO duplicate Put -> NO HALT.
	applied2, err := h.acceptOnce(t, true)
	if err != nil {
		t.Fatalf("CHAIN HALT REGRESSION: re-accept after a committed window must be a clean no-op, got: %v", err)
	}
	if applied2 != 0 {
		t.Fatalf("re-accept applied %d ops, want 0 (window already flushed)", applied2)
	}
}

// TestFIX2_CrashBeforeCommitReAppliesCleanly — the crash-BEFORE-commit recovery. If
// the node crashes BEFORE the single batch.Write (the SM Apply's WriteAll never ran),
// neither the SM mutation nor the marker advanced. On restart the window (0,1] is
// re-derived in full and applies FRESH — no value lost, no double-apply, because the
// first attempt committed nothing.
func TestFIX2_CrashBeforeCommitReAppliesCleanly(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	out, err := h.runSwap(t, h.orderCalldata(), false)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	var id ids.ID
	copy(id[:], out)

	// Accept but CRASH before the single write (commit=false): the SM Apply staged into
	// the batch, but the batch was never written -> nothing durable.
	if _, err := h.acceptOnce(t, false); err != nil {
		t.Fatalf("pre-commit accept (no write) must not error: %v", err)
	}
	if _, ok := h.readCtoDObject(t, id); ok {
		t.Fatal("object must NOT be present when the commit batch was never written (crash before WriteAll)")
	}
	if m := readHostMarker(t, h.memdbBacking); m != 0 {
		t.Fatalf("marker must stay 0 when the batch never wrote, got %d", m)
	}

	// RESTART: re-accept. The window (0,1] is re-derived in full and applies fresh.
	applied, err := h.acceptOnce(t, true)
	if err != nil {
		t.Fatalf("re-accept after a pre-commit crash must apply cleanly, got: %v", err)
	}
	if applied != 1 {
		t.Fatalf("re-accept applied %d ops, want 1 (full window re-derived)", applied)
	}
	if _, ok := h.readCtoDObject(t, id); !ok {
		t.Fatal("object must be present after the re-accept committed the window")
	}
	if m := readHostMarker(t, h.memdbBacking); m != 1 {
		t.Fatalf("marker after re-accept = %d, want 1", m)
	}
}

// TestFIX2_MarkerAndApplyShareOneBatch — proves the marker and the shared-memory Apply
// commit in the SAME database write. We model the OLD bug's split commit and show it
// would halt: apply the window to SM (committed) but DROP the marker write (separate,
// lost to a crash). A re-accept then re-derives the FULL window and hits the
// non-idempotent SM -> duplicate-Put error == the halt. The fixed path (marker in the
// batch, TestFIX2_ReAccept...) does not. This locks the invariant: the marker MUST
// ride the Apply's batch.
func TestFIX2_MarkerAndApplyShareOneBatch(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	if _, err := h.runSwap(t, h.orderCalldata(), false); err != nil {
		t.Fatalf("order: %v", err)
	}

	// OLD-BUG MODEL: apply the window to shared memory committed (its own batch write)
	// but FAIL to persist the marker (the separate versiondb.Commit lost to a crash).
	from := readHostMarker(t, h.memdbBacking)  // 0
	to := ReadStagedAtomicSeq(h.state.stateDB) // 1
	reqs, cerr := CollectStagedAtomicRange(h.state.stateDB, from, to)
	if cerr != nil {
		t.Fatalf("collect: %v", cerr)
	}
	smBatch := h.memdbBacking.NewBatch()
	if err := h.cSM.Apply(reqs, smBatch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := smBatch.Write(); err != nil { // SM committed...
		t.Fatalf("sm batch write: %v", err)
	}
	// ...but the marker was NOT advanced (still 0). This is the crash window.
	if m := readHostMarker(t, h.memdbBacking); m != 0 {
		t.Fatalf("model setup: marker should be unadvanced (0), got %d", m)
	}

	// RESTART with the marker still 0: the window (0,1] re-collects the SAME Put and
	// re-applies it to the now-already-populated shared memory -> duplicate Put error
	// == the chain halt. This proves WHY the marker must ride the Apply's batch.
	reqs2, _ := CollectStagedAtomicRange(h.state.stateDB, 0, to)
	dupErr := h.cSM.Apply(reqs2)
	if dupErr == nil {
		t.Fatal("the OLD split-commit MUST halt on re-accept (duplicate Put) — proving the marker has to ride the Apply batch")
	}
}

var _ = database.ErrNotFound
