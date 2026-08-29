// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/ids"
)

// callindex_test.go covers the second argument nothing was watching.
//
// A C->D claim id is SHA-256(domain | source | dest | sourceTx | index), and the index
// is the precompile invocation's position within the transaction. It is what makes the
// derivation injective for a transaction that crosses more than once — a contract that
// commits two positions, or commits and swaps, in one call frame.
//
// Every harness in the package ran at call index 0 and never moved it, so nothing
// distinguished CallIndex() from the literal 0. With a constant, both crossings in a
// transaction derive the SAME claim id, the export replay guard fires on the second, and
// the transaction reverts — a live rail would refuse every multi-crossing transaction
// while every test stayed green.

// TestCallIndex_SecondCrossingInOneTransactionGetsItsOwnClaim varies only the call
// index — same transaction, same chains — and requires two distinct, both-accepted
// claims.
func TestCallIndex_SecondCrossingInOneTransactionGetsItsOwnClaim(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	var saltA, saltB [32]byte
	saltA[31] = 0xA1
	saltB[31] = 0xB2

	// Crossing one, at the transaction's first invocation.
	h.state.callIndex = 0
	_, claimA := h.commitNativePosition(t, -60, 60, 500, saltA)

	// Crossing two, SAME transaction, next invocation — the only thing that changed.
	h.state.callIndex = 1
	_, claimB := h.commitNativePosition(t, -120, 120, 500, saltB)

	if claimA == claimB {
		t.Fatal("two crossings in one transaction derived the SAME claim id: the derivation " +
			"ignores the call index, so the export replay guard refuses the second and no " +
			"transaction can ever cross twice")
	}

	// Both are real, distinct, spendable claims on D's side.
	for name, id := range map[string]ids.ID{"first": claimA, "second": claimB} {
		vals, err := h.dSM.Get(h.state.cChainID, [][]byte{id[:]})
		if err != nil || len(vals) != 1 || len(vals[0]) == 0 {
			t.Fatalf("the %s crossing left no claim D can consume (err=%v)", name, err)
		}
		if _, _, amount, ok := decodeClaim(vals[0]); !ok || amount != 500 {
			t.Fatalf("the %s crossing wrote {ok=%v amount=%d}, want {true 500}", name, ok, amount)
		}
	}
}

// TestCallIndex_RepeatingAnIndexIsRefused is the other side of the same fact: the index
// is what makes the id injective, so reusing one inside a transaction must be caught by
// the replay guard rather than overwrite a staged claim. Together the two tests say the
// derivation depends on the index and on nothing else that moved.
func TestCallIndex_RepeatingAnIndexIsRefused(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	var salt [32]byte
	salt[31] = 0xC3
	h.state.callIndex = 0
	h.commitNativePosition(t, -60, 60, 500, salt)

	// The same transaction, the same invocation index, a different position: the claim
	// id collides with the one already staged.
	h.fundCallerNative(500)
	var salt2 [32]byte
	salt2[31] = 0xC4
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	args := buildModifyLiquidityArgs(h.key, -120, 120, big.NewInt(500), salt2, hookData)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorModifyLiquidity, args), 5_000_000, false); err != ErrExportReplay {
		t.Fatalf("a repeated call index must be refused as an export replay, got: %v", err)
	}
}
