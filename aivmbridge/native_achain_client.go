// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// native_achain_client.go is the C SIDE of the native C<->A inference seam — the
// concrete realization of the on-ramp the AChainClient interface describes. It is the
// STAGED (not direct) loopback: it mirrors dex/native_dchain_client.go, where a
// marketable swap STAGES a C->D atomic object (and never calls into the live dexvm).
//
// THE SHIP-SAFETY MODEL (the user's critical correction, decomplected):
//
//   - SubmitInferenceIntent RECORDS work in COMMITTED C STATE: it derives a
//     deterministic intent_id and WRITES the C-side outbox record (IntentStore). It
//     returns the intent_id ONLY — never a live inference result, never an in-block
//     output. It MUST NOT mutate aivm. The semantic object is: a committed C intent
//     that A's importer (Blue-B) reads LATER under A consensus. There is NO
//     vm.SubmitTask call here — that was the fork-unsafe direct loopback a prior build
//     shipped, and it is gone.
//
//   - VerifyInferenceReceipt verifies a COMMITTED receipt + proof against the
//     committed receipt root the C side already holds (verifyInferenceReceipt over
//     ReceiptVerifierState). It moves no value and queries no A process. The receipt
//     root's authenticity in production comes from the A->C atomic boundary / warp
//     (the seam) — the host's import handler writes it via CommitReceiptRoot at block
//     accept. This client NEVER live-reads aivm.
//
// CONSENSUS-SAFETY: the intent_id is a PURE function of the calldata + C tx identity
// (DeriveIntentID), identical on every validator. The optional ZAP notification is
// TRANSPORT-ONLY — exactly like dex's routing events, "the committed state alone is
// the source of truth; the notification just tells A to import." A node that drops
// every ZAP message loses nothing: A's importer can scan the committed C outbox
// directly. So the ZAP path is OFF the consensus-critical path by construction.

package aivmbridge

import (
	"context"
)

// ZAPNotifier is the OPTIONAL transport hook the native client uses to NOTIFY the
// A-Chain that a new committed intent exists. It is TRANSPORT-ONLY and OFF the
// consensus-critical path: the committed C outbox is the source of truth; this just
// nudges A's importer to look sooner. A nil notifier (the default) means "no nudge" —
// A's importer scans the committed outbox on its own schedule. An error from Notify
// is IGNORED by SubmitInferenceIntent (a transport failure must never fail or fork a
// consensus-path C tx, nor leave the committed intent unwritten).
type ZAPNotifier interface {
	// Notify is best-effort. It MUST NOT mutate any consensus state and MUST NOT
	// block the caller materially. Its return is advisory only.
	Notify(ctx context.Context, intentID [32]byte, in InferenceIntent) error
}

// NativeAChainClient records inference intents into COMMITTED C STATE and verifies
// committed A receipts. It holds NO *aivm handle and makes NO aivm call — that is the
// entire point of the staged design. brand is the white-label identity; achainID is
// the committed C<->A rail peer; notify is the optional transport nudge.
type NativeAChainClient struct {
	brand    string
	achainID [32]byte
	notify   ZAPNotifier // optional; nil == no transport nudge
}

var _ AChainClient = (*NativeAChainClient)(nil)

// NewNativeAChainClient constructs the staged C<->A loopback client. brand defaults to
// the OSS "Lux Inference" identity; a tenant surface (Hanzo / Zoo / white-label L1)
// passes its own. achainID is the committed A-Chain (aivm) peer id this on-ramp
// targets — it MUST be non-zero (InstallAChainClient enforces it) so the derived
// intent_id is rail-scoped. notify may be nil (no transport nudge); pass a ZAP
// transport to have A's importer nudged when an intent lands.
//
// CRITICAL (the user's correction): this constructor takes NO *aivm.VM and the client
// holds NO A handle. There is deliberately no path from here into aivm. The intent
// flows: committed C outbox -> A's importer (Blue-B) under A consensus.
func NewNativeAChainClient(brand string, achainID [32]byte, notify ZAPNotifier) *NativeAChainClient {
	if brand == "" {
		brand = "Lux Inference"
	}
	return &NativeAChainClient{brand: brand, achainID: achainID, notify: notify}
}

// Brand identifies the client in logs / error wrapping (white-label).
func (c *NativeAChainClient) Brand() string { return c.brand }

// AChainID returns the committed C<->A rail peer id (bound into intent_id).
func (c *NativeAChainClient) AChainID() [32]byte { return c.achainID }

// SubmitInferenceIntent derives the deterministic intent_id and WRITES the committed
// C-side outbox record. It returns the intent_id; it runs NO inference, returns NO
// output, and makes NO aivm call. The realized result settles on A asynchronously and
// is verified back on C via VerifyInferenceReceipt.
//
// REPLAY GUARD (CEI): the outbox is checked for an existing record at intent_id BEFORE
// the write — a re-derived id from a genuinely distinct tx cannot double-write, and an
// idempotent re-execution of the SAME tx derives the SAME id (the write is a no-op
// overwrite of an identical record, but we still reject a second submit to keep the
// outbox append-once and the semantics crisp). The optional ZAP nudge fires AFTER the
// committed write, best-effort, and its failure is swallowed (transport ≠ consensus).
func (c *NativeAChainClient) SubmitInferenceIntent(ctx context.Context, store IntentStore, in InferenceIntent) ([32]byte, error) {
	// Bind the rail peer the client is configured for. (The bridge also sets this from
	// the client; setting it here keeps DeriveIntentID self-consistent if a caller
	// constructs the intent directly.)
	in.AChainID = c.achainID

	intentID := DeriveIntentID(in)

	// Replay guard (CEI before the write): never overwrite/duplicate a recorded intent.
	if store.IntentStatus(intentID) != OutboxNone {
		return [32]byte{}, ErrIntentReplay
	}

	// THE COMMITTED C WRITE — and the ONLY side effect on the consensus path. No aivm
	// call. A's importer reads this committed outbox record under A consensus.
	store.PutPendingIntent(intentID, OutboxIntent{
		Status:        OutboxPending,
		Caller:        in.Caller,
		CChainID:      in.CChainID,
		AChainID:      in.AChainID,
		ModelSpecHash: in.ModelSpecHash,
		PromptHash:    in.ModelPromptHash,
		N:             in.N,
		Threshold:     in.Threshold,
		// BlockNumber is stamped by the store from its captured height (the authority
		// on "now"); we do not set it here.
	})

	// OPTIONAL transport-only nudge (off the consensus-critical path; failure ignored).
	if c.notify != nil {
		_ = c.notify.Notify(ctx, intentID, in)
	}
	return intentID, nil
}

// VerifyInferenceReceipt verifies a committed receipt + proof against the committed
// receipt root the C side holds. It delegates to the package verify core — a pure
// function of C-committed state + the proof. NO aivm query.
func (c *NativeAChainClient) VerifyInferenceReceipt(ctx context.Context, vs ReceiptVerifierState, r AInferenceReceipt, p AInferenceProof) (VerifiedAInferenceReceipt, error) {
	return verifyInferenceReceipt(vs, r, p)
}
