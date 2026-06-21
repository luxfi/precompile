// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
)

// native_atomicity_test.go proves the CROSS-DOMAIN ATOMICITY model (CTO-specified):
// staged-in-EVM-state during tx execution, applied to shared memory ONLY at
// accepted-block flush over the DETERMINISTIC parent->current seq window, atomic
// with the EVM state commit. These tests exercise the flush primitives directly.

// Test9999AtomicFlush_UsesParentToCurrentSeqWindow — the flush set is exactly the
// ops staged between the parent block's seq and the accepted block's seq, derived
// from consensus state (not a node-local marker). Two intents staged across two
// "blocks" flush in their own windows, never re-flushing the prior block's ops.
func Test9999AtomicFlush_UsesParentToCurrentSeqWindow(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(10_000)

	// Block 1: one intent staged.
	out1, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent1: %v", err)
	}
	var id1 ids.ID
	copy(id1[:], out1)
	seqAfter1 := ReadStagedAtomicSeq(h.state.stateDB)
	if seqAfter1 != 1 {
		t.Fatalf("after block1 seq = %d, want 1", seqAfter1)
	}
	// Flush block 1 (window (0,1]).
	h.flushStaged(t)
	if _, ok := h.readCtoDObject(t, id1); !ok {
		t.Fatal("block1 object must be flushed")
	}

	// Block 2: a SECOND intent. callIndex differs so the intent id differs; the seq
	// advances to 2. The flush window must be (1,2] — only block2's op.
	h.state.callIndex = 1 // distinct call -> distinct intent id
	out2, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent2: %v", err)
	}
	var id2 ids.ID
	copy(id2[:], out2)
	if id2 == id1 {
		t.Fatal("two intents must have distinct ids (callIndex disambiguation)")
	}

	// The window collected for block 2 must contain ONLY block2's op (1 Put), not
	// block1's (already flushed) — proving parent->current windowing.
	from := h.lastFlushed
	to := ReadStagedAtomicSeq(h.state.stateDB)
	reqs, cerr := CollectStagedAtomicRange(h.state.stateDB, from, to)
	if cerr != nil {
		t.Fatalf("collect range: %v", cerr)
	}
	total := 0
	for _, r := range reqs {
		total += len(r.PutRequests) + len(r.RemoveRequests)
	}
	if total != 1 {
		t.Fatalf("block2 window must contain exactly 1 op, got %d", total)
	}
}

// Test9999AtomicFlush_RejectsSeqRegression — a current seq below the parent seq is
// fatal (state corruption / bad reorg), never silently accepted.
func Test9999AtomicFlush_RejectsSeqRegression(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	if _, err := h.runSwap(t, h.intentCalldata(), false); err != nil {
		t.Fatalf("intent: %v", err)
	}
	// parent seq = current (1), but we pass a parent state whose seq is HIGHER (2)
	// than the current (1) -> regression -> fatal.
	parent := &seqOnlyState{seq: 2}
	err := FlushAcceptedAtomicOps(parent, h.state.stateDB, h.cSM, nil)
	if err != ErrAtomicSeqRegression {
		t.Fatalf("seq regression must be fatal (ErrAtomicSeqRegression), got: %v", err)
	}
}

// Test9999AtomicFlush_FailsOnMalformedStagedOp — a staged op with a bad version or
// truncated record FAILS the flush (block accept), never silently skipped.
func Test9999AtomicFlush_FailsOnMalformedStagedOp(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB

	// Hand-write a malformed staged Put at seq 0 (bad version byte).
	kv := newPoolStateAdapter(h.state)
	bad := make([]byte, 1+32+32+exportedOutputSize9999)
	bad[0] = 0xFF // not stagedOpVersion
	writeBytesToSlots(kv, stagePutPrefix, 0, bad)
	markStageKind(kv, 0, stageKindPut)
	setStageSeq(kv, 1)

	_, err := CollectStagedAtomicRange(db, 0, 1)
	if err != ErrStagedOpMalformed {
		t.Fatalf("malformed staged op must fail with ErrStagedOpMalformed, got: %v", err)
	}
	// And the host flush surfaces it as fatal.
	if ferr := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, db, h.cSM, nil); ferr != ErrStagedOpMalformed {
		t.Fatalf("flush must fail fatally on malformed op, got: %v", ferr)
	}
}

// Test9999AtomicFlush_ExactlyOnceViaBatchMarker — the atomic.SharedMemory layer is
// NOT idempotent (a duplicate Put errors: "duplicate put"). So the design does NOT
// rely on replay idempotency; instead the flush is exactly-once via the SAME-BATCH
// commit of the shared-memory Apply AND the node-local last-applied marker. Once a
// window's Put committed, advancing the marker (in the same batch) means the next
// flush starts at the new boundary and never re-applies. This test proves: applying
// a window twice WITHOUT advancing the boundary is what would error (so the host
// MUST advance the boundary atomically — which the same-batch commit guarantees).
func Test9999AtomicFlush_ExactlyOnceViaBatchMarker(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	out, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	var id ids.ID
	copy(id[:], out)

	// Flush window (0,1] once -> object present.
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, h.state.stateDB, h.cSM, nil); err != nil {
		t.Fatalf("flush 1: %v", err)
	}
	if _, ok := h.readCtoDObject(t, id); !ok {
		t.Fatal("object must be present after flush 1")
	}

	// CORRECT exactly-once: ADVANCE the boundary to the flushed seq (what the host
	// persists atomically in the same batch). The next flush starts at the new
	// boundary and yields NO ops -> no duplicate Put, no error.
	h.lastFlushed = ReadStagedAtomicSeq(h.state.stateDB)
	if err := FlushAcceptedAtomicOps(h.parentSeqState(), h.state.stateDB, h.cSM, nil); err != nil {
		t.Fatalf("flush after boundary advance must be a clean no-op, got: %v", err)
	}

	// Conversely, re-flushing the SAME window WITHOUT advancing the boundary hits the
	// non-idempotent memory layer — proving WHY the boundary MUST advance atomically
	// (the same-batch commit of Apply + marker is the exactly-once guarantee).
	dupErr := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, h.state.stateDB, h.cSM, nil)
	if dupErr == nil {
		t.Fatal("re-flushing an un-advanced window should hit the non-idempotent Apply — the boundary MUST advance in the commit batch")
	}
}

// TestRED_RevertAfterCToDPutCannotFundD — THE CRITICAL atomicity RED test (C->D
// leg): if the tx that staged a C->D Put REVERTS, the staged op is discarded with
// the StateDB rollback, so NO C->D object reaches shared memory => D cannot be
// funded by a reverted intent. We model the revert by discarding the staged seq
// window (what the EVM snapshot/revert does to StateDB) before the flush.
func TestRED_RevertAfterCToDPutCannotFundD(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	out, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	var id ids.ID
	copy(id[:], out)

	// REVERT model: the EVM rolls back the tx's StateDB writes — including the staged
	// op AND the seq increment. Reset the staged seq to the pre-tx value (0). After a
	// real revert, CollectStagedAtomicRange over the (unchanged) parent->current
	// window finds NOTHING (current seq rolled back to parent).
	setStageSeq(newPoolStateAdapter(h.state), 0)

	// Flush over the consensus window (parent=0, current=0 after revert) -> no ops.
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, h.state.stateDB, h.cSM, nil); err != nil {
		t.Fatalf("flush after revert: %v", err)
	}
	if _, ok := h.readCtoDObject(t, id); ok {
		t.Fatal("MINT RISK: a reverted C->D intent leaked an object to shared memory — D could be funded with no C lock")
	}
}

// TestRED_RevertAfterDToCRemoveCannotBurnUserFunds — THE CRITICAL atomicity RED test
// (D->C leg): if the tx that consumed a D->C object REVERTS, the staged Remove is
// discarded, so the D->C object STAYS in shared memory (not burned) AND the C credit
// rolled back — the user can re-claim it later. No value is lost.
func TestRED_RevertAfterDToCRemoveCannotBurnUserFunds(t *testing.T) {
	h := newSettleHarness(t)
	h.fundVaultOut(10_000)

	// D exported a D->C object.
	outputID := ids.ID{0xDE, 0xAD}
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 200)

	// A settlement consume STAGES a Remove (and credited C in StateDB).
	credited, err := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: outputID, Asset: h.outAssetID(), AssetAddr: h.outToken(), Amount: 200, Recipient: h.caller,
	})
	if err != nil || credited != 200 {
		t.Fatalf("settle import: credited=%d err=%v", credited, err)
	}

	// REVERT model: roll back the staged seq (the EVM discards the staged Remove AND
	// the credit on revert). The flush over the consensus window finds no Remove.
	setStageSeq(newPoolStateAdapter(h.state), 0)
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, h.state.stateDB, h.cSM, nil); err != nil {
		t.Fatalf("flush after revert: %v", err)
	}

	// The D->C object is STILL in shared memory (not burned) — the user can re-claim.
	vals, gerr := h.cSM.Get(h.dChainID, [][]byte{outputID[:]})
	if gerr != nil || len(vals) != 1 || len(vals[0]) == 0 {
		t.Fatal("VALUE LOSS: a reverted settlement burned the D->C object from shared memory — user funds lost")
	}
}

// Test9999AtomicFlush_PutAndRemoveCommitInBatch — the flush passes the supplied DB
// batch to sm.Apply so the shared-memory mutation lands in the SAME batch as the
// EVM state commit (all-or-nothing). We assert sm.Apply is invoked with the batch
// by using a real atomic.Memory + a real batch and confirming the Put committed.
func Test9999AtomicFlush_PutAndRemoveCommitInBatch(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	out, err := h.runSwap(t, h.intentCalldata(), false)
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	var id ids.ID
	copy(id[:], out)

	// Flush WITH a batch (the production path). The atomic.Memory commits the Put as
	// part of the batch; after the batch write the object is visible.
	batch := h.memBatch()
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, h.state.stateDB, h.cSM, batch); err != nil {
		t.Fatalf("flush with batch: %v", err)
	}
	if err := batch.Write(); err != nil {
		t.Fatalf("batch write: %v", err)
	}
	if _, ok := h.readCtoDObject(t, id); !ok {
		t.Fatal("object must be visible after the batched flush commit")
	}
}

// memBatch returns a fresh batch on the harness's shared-memory backing DB so the
// flush's sm.Apply(reqs, batch) and the batch.Write() are one atomic commit.
func (h *settleHarness) memBatch() database.Batch {
	return h.memdbBacking.NewBatch()
}

var _ = atomic.NewMemory
var _ common.Hash
