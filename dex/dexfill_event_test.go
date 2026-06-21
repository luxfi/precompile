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

// TestDEXFillEvent_NotEmittedOnPhaseAIntent proves a Phase-A intent (which only
// LOCKS input and creates a C->D object — no output credited) does NOT emit a
// DEXFill. A fill log must correspond to an actual settled output, never to an
// unmatched intent.
func TestDEXFillEvent_NotEmittedOnPhaseAIntent(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)

	if _, err := h.runSwap(t, h.intentCalldata(), false); err != nil {
		t.Fatalf("phase-A intent: %v", err)
	}

	wantSig := common.BytesToHash(crypto.Keccak256([]byte("DEXFill(bytes32,address,uint256,uint256)")))
	for _, lg := range h.state.stateDB.Logs() {
		if len(lg.Topics) > 0 && lg.Topics[0] == wantSig {
			t.Fatal("Phase-A intent must NOT emit a DEXFill (no output credited)")
		}
	}
}
