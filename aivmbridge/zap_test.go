// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// zap_test.go — the ZAP transport is OFF the consensus-critical path. Asserts:
//   - a ZAP failure does NOT fail the consensus tx and the committed intent is STILL
//     written (transport ≠ consensus; the committed C outbox is the source of truth);
//   - the notifier fires exactly once, AFTER the committed write, with the right id;
//   - a ZAP message ALONE never credits C — only a committed receipt+proof does (i.e.
//     submitting an intent and "notifying" A does not consume the intent; verification
//     is still required).

package aivmbridge

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/geth/common"
)

// recordingNotifier captures Notify calls and can be made to fail.
type recordingNotifier struct {
	calls    int
	lastID   [32]byte
	failWith error
}

func (n *recordingNotifier) Notify(ctx context.Context, intentID [32]byte, in InferenceIntent) error {
	n.calls++
	n.lastID = intentID
	return n.failWith
}

func TestZAP_FailureDoesNotFailConsensusTxAndIntentStillWritten(t *testing.T) {
	notifier := &recordingNotifier{failWith: errors.New("transport down")}
	installNative(t, h32(0xA0), notifier)

	st := newMockState(common.HexToHash("0x42"))
	caller := common.HexToAddress("0x5555555555555555555555555555555555555555")
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)

	ret, _, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas, false)
	// A transport failure MUST NOT surface as a consensus-tx error.
	if err != nil {
		t.Fatalf("ZAP failure leaked into the consensus tx: %v", err)
	}
	intentID := toArr(ret)

	// The committed intent MUST still be written despite the transport failure.
	store := newStateKVStore(st.db, st.blockNumber)
	if store.IntentStatus(intentID) != OutboxPending {
		t.Fatal("intent not committed when ZAP failed (committed state must be source of truth)")
	}
	// The notifier fired exactly once with the committed id.
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.calls)
	}
	if notifier.lastID != intentID {
		t.Fatalf("notifier id mismatch")
	}
}

func TestZAP_AloneDoesNotCreditWithoutProof(t *testing.T) {
	notifier := &recordingNotifier{}
	installNative(t, h32(0xA0), notifier)

	st := newMockState(common.HexToHash("0x99"))
	caller := common.HexToAddress("0x6666666666666666666666666666666666666666")
	input := encodeSubmit(h32(0x5E), h32(0x9D), 3, 2, feeWord(10), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	ret, _, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas, false)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	intentID := toArr(ret)

	// The intent was "notified" to A. But with NO committed receipt+proof, the intent
	// must remain PENDING — a ZAP nudge can never settle/consume it.
	store := newStateKVStore(st.db, st.blockNumber)
	if store.IntentStatus(intentID) != OutboxPending {
		t.Fatal("intent should remain pending after a ZAP nudge with no proof")
	}

	// Now prove the FULL settlement still requires a committed receipt+proof: try to
	// verify a Completed receipt WITHOUT committing its root => rejected, no credit.
	rcpt := AInferenceReceipt{
		Version: ReceiptVersion, IntentID: intentID, TaskID: h32(0x7A),
		CChainID: toArr(st.cChainID[:]), AChainID: h32(0xA0), Requester: caller,
		ModelSpecHash: h32(0x5E), PromptHash: h32(0x9D), CanonicalOutputHash: h32(0x0F),
		Status: StatusCompleted, N: 3, Threshold: 2, FeePaid: feeWord(10),
	}
	leaves := [][32]byte{ReceiptHash(rcpt), h32(0x02)}
	tree := buildMerkleTree(leaves)
	p := tree.proof(0)
	// Deliberately DO NOT CommitReceiptRoot — the root is not trusted.
	vin := encodeVerify(EncodeReceipt(rcpt), encodeProof(p))
	vg := BridgePrecompile.RequiredGas(vin)
	if _, _, verr := BridgePrecompile.Run(st, caller, ContractAddress, vin, vg, false); verr != ErrReceiptRootNotCommitted {
		t.Fatalf("verify without committed root err = %v, want ErrReceiptRootNotCommitted", verr)
	}
	// Still pending — no credit happened.
	if store.IntentStatus(intentID) != OutboxPending {
		t.Fatal("intent wrongly consumed without a committed proof")
	}
}

func TestZAP_NilNotifierIsFine(t *testing.T) {
	installNative(t, h32(0xA0), nil) // nil notifier == no nudge
	st := newMockState(common.HexToHash("0x01"))
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	if _, _, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, input, gas, false); err != nil {
		t.Fatalf("submit with nil notifier: %v", err)
	}
}
