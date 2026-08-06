// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/luxfi/ids"
)

// seam_pending_trait_test.go pins the C->D intent DISCOVERY trait against the
// D-Chain's own constant, and pins that the flush actually attaches it.
//
// WHY A GOLDEN. The D-Chain proposer enumerates pending intents with
// atomic.SharedMemory.Indexed under a trait it derives itself (dex/pkg/dchain
// drive.go SeamPendingTrait). The two repos cannot import each other — the same
// module-cycle constraint that already forced a golden vector for the 69-byte
// object wire — so nothing but a shared vector keeps them equal.
//
// Drift here is silent in the worst way. D would query a trait C never writes,
// enumerate nothing, and every swap intent would sit unmatched forever with no
// error logged on either side. That is indistinguishable from "nobody is
// trading", which is precisely how it went unnoticed: the constant existed on
// the D side with a comment naming this exact companion change, and the C side
// never made it.
//
// The golden is sha256("lux.dex.native.intent.pending.v1") — the same domain
// string dex/pkg/dchain hashes.
const seamPendingTraitGoldenHex = "6d4307f9774ca9f016f890486262e504f06bb756fae621fffe99876a569348f2"

func TestSeamPendingTrait_MatchesDChainGolden(t *testing.T) {
	want, err := hex.DecodeString(seamPendingTraitGoldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if len(SeamPendingTrait) != 32 {
		t.Fatalf("trait width %d, want 32 — a 20-byte trait could collide with an owner trait", len(SeamPendingTrait))
	}
	if !bytes.Equal(SeamPendingTrait, want) {
		t.Fatalf("SeamPendingTrait = %x\nwant                %x\n"+
			"the discovery trait drifted from the D-Chain's constant: D would enumerate "+
			"nothing and every swap would sit unmatched with no error anywhere",
			SeamPendingTrait, want)
	}
}

// TestCollectStaged_SwapIntentCarriesDiscoveryTrait proves the FLUSH attaches
// the trait to a real staged swap-rail export. The constant existing is worth
// nothing if collectRange does not write it — that omission is the actual defect.
func TestCollectStaged_SwapIntentCarriesDiscoveryTrait(t *testing.T) {
	db := NewMockStateDB()
	dChainID := ids.ID{0xD1}
	key := ids.ID{0x1A}
	owner := parityOwner()
	obj := encodeAtomicObject(railSwap, owner, parityAsset(), 100)

	stageAtomicPut(db, dChainID, key, obj)

	reqs, err := collectRange(db, 0, stageSeq(db))
	if err != nil {
		t.Fatalf("collectRange: %v", err)
	}
	ops := reqs[dChainID]
	if ops == nil || len(ops.PutRequests) != 1 {
		t.Fatalf("puts for D = %v, want exactly 1", ops)
	}

	var haveOwner, haveDiscovery bool
	for _, tr := range ops.PutRequests[0].Traits {
		if bytes.Equal(tr, owner[:]) {
			haveOwner = true
		}
		if bytes.Equal(tr, SeamPendingTrait) {
			haveDiscovery = true
		}
	}
	if !haveOwner {
		t.Error("owner trait missing — the per-recipient index broke")
	}
	if !haveDiscovery {
		t.Error("discovery trait missing — the D-Chain import drive cannot enumerate this intent, so it is never matched and no fill is ever produced")
	}
}

// TestCollectStaged_LPObjectHasNoDiscoveryTrait: the LP rail's lifecycle is
// driven by its position record, not by enumeration. Tagging it would inject LP
// objects into the swap import drive's queue.
func TestCollectStaged_LPObjectHasNoDiscoveryTrait(t *testing.T) {
	db := NewMockStateDB()
	dChainID := ids.ID{0xD1}
	key := ids.ID{0x2B}
	obj := encodeAtomicObject(railLP, parityOwner(), parityAsset(), 100)

	stageAtomicPut(db, dChainID, key, obj)

	reqs, err := collectRange(db, 0, stageSeq(db))
	if err != nil {
		t.Fatalf("collectRange: %v", err)
	}
	for _, tr := range reqs[dChainID].PutRequests[0].Traits {
		if bytes.Equal(tr, SeamPendingTrait) {
			t.Fatal("LP-rail object carries the swap discovery trait — it would enter the swap import drive")
		}
	}
}
