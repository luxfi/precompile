// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
)

// settle_import_test.go pins the property the whole change exists for: a settled
// swap must RE-EXECUTE to the same result on a node that no longer has the object
// in shared memory. That is what a bootstrapping node does, and it is what the old
// shape could not do — it read the object during execution while the consuming
// Remove landed at accept, so a syncing node computed a reverted receipt where the
// network had computed a successful one and died on the receipt root.

// TestSettlementReExecutesWithoutSharedMemory is THE bootstrap-replay test.
//
// It runs the SAME Phase-B settlement calldata twice against two independent
// harnesses that differ in exactly one way: the first has the D->C object present in
// shared memory (the live proposer's view), the second has shared memory COMPLETELY
// EMPTY (a node replaying history after the object was consumed and removed). Both
// must credit the same amount and leave the same balances.
//
// Under the old shape the second case returned ErrNativeNoSettlement — a reverted
// receipt — which is precisely the divergence that made a settled swap unsyncable.
func TestSettlementReExecutesWithoutSharedMemory(t *testing.T) {
	const settled uint64 = 40

	outputID := ids.ID{0x51, 0x99}

	// --- Node 1: the live view. The object IS in shared memory. -----------------
	live := newSettleHarness(t)
	live.installDefaultMarketResolver(t)
	live.fundVaultOut(int64(settled))
	orderID := live.standingOrder(settled)
	live.putDtoCObject(t, live.caller, outputID, live.outAssetID(), settled)

	object := live.recordedObject(outputID)
	if len(object) != exportedOutputSize9999 {
		t.Fatalf("harness produced a %d-byte object, want %d", len(object), exportedOutputSize9999)
	}
	calldata := buildSwapCalldata(live.key, live.params,
		EncodeSettlementHookData(outputID, orderID, object))

	liveRet, _, liveErr := SettleSwap(live.state, live.caller, calldata, 1_000_000, false)
	if liveErr != nil {
		t.Fatalf("live settlement failed: %v", liveErr)
	}
	liveBal := live.state.stateDB.GetBalance(live.caller)

	// --- Node 2: the REPLAY view. Shared memory is empty. -----------------------
	// Same order, same vault backing, same calldata — but nothing was ever put
	// into shared memory, exactly as a bootstrapping node sees it after the object
	// has been consumed and removed by the accept that this block already caused.
	replay := newSettleHarness(t)
	replay.installDefaultMarketResolver(t)
	replay.fundVaultOut(int64(settled))
	if got := replay.seedSwapOrder(replay.caller, replay.inAssetID(), settled, 0, orderID); got != orderID {
		t.Fatalf("replay harness seeded order %s, want %s", got, orderID)
	}
	if _, err := replay.cSM.Get(replay.dChainID, [][]byte{outputID[:]}); err == nil {
		t.Fatal("replay harness must start with the object ABSENT from shared memory")
	}

	replayRet, _, replayErr := SettleSwap(replay.state, replay.caller, calldata, 1_000_000, false)
	if replayErr != nil {
		t.Fatalf("REPLAY DIVERGED: settlement failed on a node without the object: %v "+
			"(this is the bug that made a settled swap unsyncable)", replayErr)
	}

	if !bytes.Equal(liveRet, replayRet) {
		t.Fatalf("REPLAY DIVERGED: return value differs\n live:   %x\n replay: %x", liveRet, replayRet)
	}
	if replayBal := replay.state.stateDB.GetBalance(replay.caller); liveBal.Cmp(replayBal) != 0 {
		t.Fatalf("REPLAY DIVERGED: credited balance differs: live %s, replay %s", liveBal, replayBal)
	}
}

// TestSettlementDeclarationAuthenticatesTheObject proves the relocated ship rule is
// enforceable: the block's declaration commits to the exact object bytes execution
// used, so a host reading the real object out of shared memory can prove or disprove
// it. This is the host-side check in evm/plugin/evm/dex_atomic_verify.go, exercised
// here at the precompile boundary where the commitment is produced.
func TestSettlementDeclarationAuthenticatesTheObject(t *testing.T) {
	const settled uint64 = 25
	outputID := ids.ID{0x51, 0xAA}

	h := newSettleHarness(t)
	h.installDefaultMarketResolver(t)
	h.fundVaultOut(int64(settled))
	orderID := h.standingOrder(settled)
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), settled)
	object := h.recordedObject(outputID)

	calldata := buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, orderID, object))
	if _, _, err := SettleSwap(h.state, h.caller, calldata, 1_000_000, false); err != nil {
		t.Fatalf("settlement failed: %v", err)
	}

	imports := DecodeSettleImports(h.state.stateDB.Logs())
	if len(imports) != 1 {
		t.Fatalf("expected exactly 1 declared import, got %d", len(imports))
	}
	imp := imports[0]
	if imp.OutputID != outputID {
		t.Fatalf("declared outputID %s, want %s", imp.OutputID, outputID)
	}
	if imp.SourceChainID != h.dChainID {
		t.Fatalf("declared sourceChainID %s, want %s", imp.SourceChainID, h.dChainID)
	}

	// THE HOST CHECK: the declaration must match what shared memory really holds.
	recorded, err := h.cSM.Get(h.dChainID, [][]byte{outputID[:]})
	if err != nil || len(recorded) != 1 {
		t.Fatalf("could not read the recorded object back: %v", err)
	}
	if got := SettleObjectHash(recorded[0]); got != imp.ObjectHash {
		t.Fatalf("declaration does not authenticate: declared %s, shared memory holds %s", imp.ObjectHash, got)
	}

	// And a FORGED object must NOT authenticate — otherwise the relocated rule is
	// vacuous. One flipped amount byte is enough.
	forged := append([]byte(nil), object...)
	forged[len(forged)-9] ^= 0x01 // last byte of amount(8) at [53:61]
	if SettleObjectHash(forged) == imp.ObjectHash {
		t.Fatal("a forged object produced the SAME commitment — the block rule would be unenforceable")
	}
}

// TestForgedObjectIsDeclaredAndThereforeRejectable proves the forgery path end to
// end at this layer: a transaction CAN supply fabricated bytes (execution must not
// consult shared memory, so it cannot tell), but it necessarily declares them, and
// the declaration provably disagrees with shared memory. That disagreement is what
// the host turns into a rejected block.
func TestForgedObjectIsDeclaredAndThereforeRejectable(t *testing.T) {
	const real uint64 = 10
	const inflated uint64 = 1_000_000
	outputID := ids.ID{0x51, 0xBB}

	h := newSettleHarness(t)
	h.installDefaultMarketResolver(t)
	h.fundVaultOut(int64(inflated))
	orderID := h.standingOrder(inflated)
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), real)

	// Fabricate an object claiming 1e6 where D exported 10.
	forged := encodeAtomicObjectSpent(railSwap, h.caller, h.outAssetID(), inflated, 0)
	calldata := buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, orderID, forged))

	if _, _, err := SettleSwap(h.state, h.caller, calldata, 1_000_000, false); err != nil {
		t.Fatalf("execution should bind the carried bytes without consulting shared memory: %v", err)
	}

	imports := DecodeSettleImports(h.state.stateDB.Logs())
	if len(imports) != 1 {
		t.Fatalf("expected 1 declared import, got %d", len(imports))
	}
	recorded, err := h.cSM.Get(h.dChainID, [][]byte{outputID[:]})
	if err != nil || len(recorded) != 1 {
		t.Fatalf("could not read the recorded object: %v", err)
	}
	if SettleObjectHash(recorded[0]) == imports[0].ObjectHash {
		t.Fatal("the forgery authenticated against shared memory — the block rule is broken")
	}
	// A host running verifyDexAtomicImports over these logs rejects the block here.
}

// TestMalformedObjectRefusedAtExecution pins the one object check execution KEEPS:
// a blob that is not exactly the canonical width is refused outright, so a caller
// can never steer the decode into a different (rail, owner, asset, amount) reading.
func TestMalformedObjectRefusedAtExecution(t *testing.T) {
	outputID := ids.ID{0x51, 0xCC}
	h := newSettleHarness(t)
	h.installDefaultMarketResolver(t)
	h.fundVaultOut(100)
	orderID := h.standingOrder(50)

	short := make([]byte, exportedOutputSize9999-1)
	calldata := buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, orderID, short))
	_, _, err := SettleSwap(h.state, h.caller, calldata, 1_000_000, false)
	// A short object shortens the whole hookData body, so the fixed-width body gate
	// catches it first; either refusal is correct and both are hard errors.
	if !errors.Is(err, ErrImportObjectMalformed) && !errors.Is(err, ErrSettleBodyMalformed) {
		t.Fatalf("a malformed object must be refused, got %v", err)
	}
	if len(DecodeSettleImports(h.state.stateDB.Logs())) != 0 {
		t.Fatal("a refused settlement must declare nothing")
	}
}

// TestRetiredDS01NeverBecomesAnOrder is the MIXED-FLEET safety test, and it guards
// the one outcome worse than a revert.
//
// decodeSwapPhase's fallback for unrecognized hookData is PHASE A. So a stale DS01
// settlement arriving at a node running this build would, without an explicit
// refusal, be silently re-read as an ORDER and LOCK the sender's input instead of
// settling it. Refusing the retired tag by name is what keeps a rolling upgrade from
// converting stale settle traffic into locked funds.
func TestRetiredDS01NeverBecomesAnOrder(t *testing.T) {
	// A DS01-tagged body of the old width: outputID | amount | orderID.
	old := make([]byte, 0, 4+96)
	old = append(old, 'D', 'S', '0', '1')
	old = append(old, make([]byte, 96)...)

	phase, body, tagged, err := decodeSwapPhase(old)
	if !errors.Is(err, ErrRetiredSwapPhase) {
		t.Fatalf("retired DS01 must be refused by name, got phase=%v body=%d tagged=%v err=%v",
			phase, len(body), tagged, err)
	}

	// And it must not settle or lock through the live entrypoint either.
	h := newSettleHarness(t)
	h.installDefaultMarketResolver(t)
	h.fundCallerNative(1_000_000)
	before := h.state.stateDB.GetBalance(h.caller)

	calldata := buildSwapCalldata(h.key, h.params, old)
	if _, _, serr := SettleSwap(h.state, h.caller, calldata, 1_000_000, false); !errors.Is(serr, ErrRetiredSwapPhase) {
		t.Fatalf("SettleSwap must refuse a retired DS01 hookData, got %v", serr)
	}
	if after := h.state.stateDB.GetBalance(h.caller); before.Cmp(after) != 0 {
		t.Fatalf("a refused DS01 swap moved value: %s -> %s (it was re-read as an order and locked funds)", before, after)
	}
}

// TestDeclarationIsAddressBound proves a contract cannot forge a declaration: the
// EVM stamps the emitting address on every log, and only the precompile executes at
// 0x9999, so a log carrying the declaration topic from any other address is ignored.
func TestDeclarationIsAddressBound(t *testing.T) {
	outputID := ids.ID{0x51, 0xDD}
	object := encodeAtomicObjectSpent(railSwap, common.HexToAddress("0xdead"), [32]byte{}, 99, 0)
	h := SettleObjectHash(object)

	data := make([]byte, 0, settleImportDataLen)
	src := ids.ID{0xDD}
	data = append(data, src[:]...)
	data = append(data, h[:]...)

	impostor := &ethtypes.Log{
		Address: common.HexToAddress("0xC0FFEE0000000000000000000000000000000001"),
		Topics:  []common.Hash{settleImportEventSig, common.BytesToHash(outputID[:])},
		Data:    data,
	}
	genuine := &ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics:  []common.Hash{settleImportEventSig, common.BytesToHash(outputID[:])},
		Data:    data,
	}

	if got := DecodeSettleImports([]*ethtypes.Log{impostor}); len(got) != 0 {
		t.Fatalf("a declaration from a non-0x9999 address must be ignored, got %d", len(got))
	}
	if got := DecodeSettleImports([]*ethtypes.Log{genuine}); len(got) != 1 {
		t.Fatalf("the genuine declaration must decode, got %d", len(got))
	}
}
