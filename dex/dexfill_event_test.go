// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// TestDEXFillEvent_EmittedOnPhaseBCredit proves the 0x9999 settlement money path
// emits an indexable DEXFill log on a Phase-B credit — the signal the graph
// indexer ingests into the DEX (CLOB) schema. Without this log, settled native
// fills are invisible to eth_getLogs and the explorer DEX graph stays empty.
func TestDEXFillEvent_EmittedOnPhaseBCredit(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundVaultOut(10_000) // vault backs the output credit (no mint).

	// D exported a D->C object: owner=caller, asset=outToken, amount=250.
	outputID := ids.ID{0xDE, 0x42}
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 250)

	// Phase-B settle consumes the object and credits 250.
	if _, err := h.runSwap(t, h.settlementCalldata(outputID, 250), false); err != nil {
		t.Fatalf("phase-B settle: %v", err)
	}

	// Exactly one DEXFill log must be present, at 0x9999, with the right topics.
	wantSig := common.BytesToHash(crypto.Keccak256([]byte("DEXFill(bytes32,address,uint256,uint256)")))
	var found int
	for _, lg := range h.state.stateDB.Logs() {
		if len(lg.Topics) == 0 || lg.Topics[0] != wantSig {
			continue
		}
		found++
		if lg.Address != poolManagerAddr9999 {
			t.Errorf("DEXFill emitted at %s, want 0x9999", lg.Address.Hex())
		}
		// topic[1] = poolId (the market id).
		poolID := h.key.ID()
		if lg.Topics[1] != common.BytesToHash(poolID[:]) {
			t.Errorf("DEXFill poolId topic = %s, want %x", lg.Topics[1].Hex(), poolID)
		}
		// topic[2] = taker (the caller), right-aligned address.
		if lg.Topics[2] != common.BytesToHash(h.caller.Bytes()) {
			t.Errorf("DEXFill taker topic = %s, want %s", lg.Topics[2].Hex(), h.caller.Hex())
		}
		// data word 0 = amountOut = 250.
		if len(lg.Data) < 32 {
			t.Fatalf("DEXFill data too short: %d bytes", len(lg.Data))
		}
		amountOut := new(big.Int).SetBytes(lg.Data[:32])
		if amountOut.Cmp(big.NewInt(250)) != 0 {
			t.Errorf("DEXFill amountOut = %s, want 250", amountOut)
		}
	}
	if found != 1 {
		t.Fatalf("want exactly 1 DEXFill log on a settled fill, got %d", found)
	}
}

// TestDEXFillEvent_NotEmittedOnPhaseAOrder proves a Phase-A order (which only
// LOCKS input and creates a C->D object — no output credited) does NOT emit a
// DEXFill. A fill log must correspond to an actual settled output, never to an
// unmatched order.
func TestDEXFillEvent_NotEmittedOnPhaseAOrder(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	if _, err := h.runSwap(t, h.crossCalldata(), false); err != nil {
		t.Fatalf("phase-A order: %v", err)
	}

	wantSig := common.BytesToHash(crypto.Keccak256([]byte("DEXFill(bytes32,address,uint256,uint256)")))
	for _, lg := range h.state.stateDB.Logs() {
		if len(lg.Topics) > 0 && lg.Topics[0] == wantSig {
			t.Fatal("Phase-A order must NOT emit a DEXFill (no output credited)")
		}
	}
}

// countDEXFill returns how many DEXFill logs are present in the harness state.
func (h *settleHarness) countDEXFill() int {
	sig := common.BytesToHash(crypto.Keccak256([]byte("DEXFill(bytes32,address,uint256,uint256)")))
	n := 0
	for _, lg := range h.state.stateDB.Logs() {
		if len(lg.Topics) > 0 && lg.Topics[0] == sig {
			n++
		}
	}
	return n
}

// TestDEXFillEvent_EmittedAtGenesis proves the consensus-visible DEXFill log is AlwaysOn
// (active from genesis, no dated fork): a Phase-B credit executed at genesis (block
// timestamp 0) BOTH credits the output AND emits the DEXFill log — there is no
// pre-activation suppression. Every settlement that executes emits its log, from block 0.
func TestDEXFillEvent_EmittedAtGenesis(t *testing.T) {
	h := newSettleHarness(t)
	h.state.blockTimestamp = 0 // genesis — the earliest possible block
	h.registerMarket(t)
	h.fundVaultOut(10_000)

	outputID := ids.ID{0xDE, 0x43}
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 250)

	before := h.tokenBal(h.outToken(), h.caller)
	if _, err := h.runSwap(t, h.settlementCalldata(outputID, 250), false); err != nil {
		t.Fatalf("phase-B settle (genesis): %v", err)
	}
	// The credit happened — the output token (currency1) is credited from the seam reserve.
	after := h.tokenBal(h.outToken(), h.caller)
	if new(big.Int).Sub(after, before).Int64() != 250 {
		t.Fatalf("genesis settle must credit 250, got delta %s", new(big.Int).Sub(after, before))
	}
	// ... and the DEXFill log WAS written, from genesis.
	if n := h.countDEXFill(); n != 1 {
		t.Fatalf("DEXFill must be emitted from genesis (AlwaysOn), got %d", n)
	}
}

// TestDEXFillEvent_EmittedOnCredit proves a Phase-B credit at a normal block time emits
// exactly one DEXFill — the standard indexable settlement signal on the money path.
func TestDEXFillEvent_EmittedOnCredit(t *testing.T) {
	h := newSettleHarness(t) // harness default block time
	h.registerMarket(t)
	h.fundVaultOut(10_000)

	outputID := ids.ID{0xDE, 0x44}
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 250)
	if _, err := h.runSwap(t, h.settlementCalldata(outputID, 250), false); err != nil {
		t.Fatalf("phase-B settle: %v", err)
	}
	if n := h.countDEXFill(); n != 1 {
		t.Fatalf("DEXFill must be emitted on a Phase-B credit, got %d", n)
	}
}

// TestInitializeEvent_EmittedAt9999WithPairAndFee proves the native market registry
// (runSettleInitialize, exercised by registerMarket) emits the canonical V4 Initialize
// log AT 0x9999 carrying the pool id, BOTH currencies, and the fee tier — exactly the
// fields the graph's handleInitializeV4 reads to build a rich DEX Market (FIX B(a)).
// Asserting against the REAL emitter output (not a fabricated log) is the point: the
// graph test mirrors this exact shape.
func TestInitializeEvent_EmittedAt9999WithPairAndFee(t *testing.T) {
	h := newSettleHarness(t) // harness default block time (logs AlwaysOn)
	h.registerMarket(t)

	initSig := common.BytesToHash(crypto.Keccak256([]byte("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")))
	var found int
	for _, lg := range h.state.stateDB.Logs() {
		if len(lg.Topics) == 0 || lg.Topics[0] != initSig {
			continue
		}
		found++
		if lg.Address != poolManagerAddr9999 {
			t.Errorf("Initialize emitted at %s, want 0x9999 (so the graph's isPoolManager makes a Market)", lg.Address.Hex())
		}
		if len(lg.Topics) != 4 {
			t.Fatalf("Initialize must have 4 topics (sig, poolId, cur0, cur1), got %d", len(lg.Topics))
		}
		poolID := h.key.ID()
		if lg.Topics[1] != common.BytesToHash(poolID[:]) {
			t.Errorf("Initialize poolId topic = %s, want %x", lg.Topics[1].Hex(), poolID)
		}
		if lg.Topics[2] != common.BytesToHash(h.key.Currency0.Address.Bytes()) {
			t.Errorf("Initialize currency0 topic = %s, want %s", lg.Topics[2].Hex(), h.key.Currency0.Address.Hex())
		}
		if lg.Topics[3] != common.BytesToHash(h.key.Currency1.Address.Bytes()) {
			t.Errorf("Initialize currency1 topic = %s, want %s", lg.Topics[3].Hex(), h.key.Currency1.Address.Hex())
		}
		// data word 0 = fee (uint24, right-aligned). Harness fee = 3000.
		if len(lg.Data) < 32 {
			t.Fatalf("Initialize data too short: %d bytes", len(lg.Data))
		}
		fee := new(big.Int).SetBytes(lg.Data[:32])
		if fee.Cmp(big.NewInt(int64(h.key.Fee))) != 0 {
			t.Errorf("Initialize fee = %s, want %d", fee, h.key.Fee)
		}
	}
	if found != 1 {
		t.Fatalf("native initialize must emit exactly 1 V4 Initialize log at 0x9999, got %d", found)
	}
}

// TestInitializeEvent_EmittedAtGenesis proves the Initialize log is AlwaysOn (active from
// genesis): registering a market at genesis (block timestamp 0) BOTH writes the
// C-authoritative state record AND emits the Initialize log — no pre-activation suppression.
func TestInitializeEvent_EmittedAtGenesis(t *testing.T) {
	h := newSettleHarness(t)
	h.state.blockTimestamp = 0 // genesis
	h.registerMarket(t)

	initSig := common.BytesToHash(crypto.Keccak256([]byte("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")))
	found := 0
	for _, lg := range h.state.stateDB.Logs() {
		if len(lg.Topics) > 0 && lg.Topics[0] == initSig {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("Initialize must be emitted from genesis (AlwaysOn), got %d", found)
	}
	// The registry write IS present (idempotent re-init reverts → proves it registered).
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false); err == nil {
		t.Fatal("re-init should revert ErrPoolAlreadyInitialized — registry must have been written")
	}
}
