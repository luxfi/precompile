// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// verify.go — the Pattern-B verification core. It is a PURE function of C-committed
// state (via ReceiptVerifierState) + the caller-supplied (receipt, proof). It makes
// NO A-Chain query. This is the load-bearing consensus-safety routine: a C validator
// re-executing the block reaches the identical decision because every input is either
// committed C state or the deterministic calldata.
//
// CHECK ORDER (fail-secure — cheapest + most-fundamental first, and NEVER credit
// before every check passes):
//  1. status == Completed, output != 0           (only actionable receipts proceed)
//  2. recompute receipt_hash from the receipt    (the leaf is C-derived, not supplied)
//  3. receipt_root is committed in C state        (root authenticity = the A->C seam)
//  4. merkle: receipt_hash ∈ receipt_root @ Index (inclusion under the trusted root)
//  5. a pending C-outbox intent matches IntentID  (the receipt settles a real C intent)
//  6. that intent is not already consumed          (double-consume guard)
//  7. the receipt's bound fields == the intent's   (model/prompt/requester/chain/N/thr)
//  8. mark consumed; return the canonical output   (the single C effect)

package aivmbridge

// verifyInferenceReceipt runs the full Pattern-B check against C-committed state. On
// success it MARKS the matching intent consumed and returns the verified output. On
// any failure it returns the precise error and mutates NOTHING (no partial consume).
func verifyInferenceReceipt(vs ReceiptVerifierState, r AInferenceReceipt, p AInferenceProof) (VerifiedAInferenceReceipt, error) {
	// (1) Only a Completed receipt with a real output is actionable.
	if r.Status != StatusCompleted {
		return VerifiedAInferenceReceipt{}, ErrReceiptNotCompleted
	}
	if isZero32(r.CanonicalOutputHash) {
		return VerifiedAInferenceReceipt{}, ErrZeroOutput
	}

	// (2) Recompute the leaf from the receipt bytes — the proof never carries the
	// leaf, so a caller cannot substitute a leaf that differs from the receipt. The
	// receipt-tree leaf is leafHash(receipt_hash) = keccak(keccak(DOMAIN_RECEIPT||enc)),
	// matching the A side (chains/aivm) which COMMITS the receipt_root over leaf-hashed
	// receipt_hashes and exports proofs against that tree. (The outer leafHash is the
	// leaf-vs-node domain separation; A is the producer, C folds from the same leaf.)
	leaf := leafHash(ReceiptHash(r))

	// (3) The receipt root MUST be committed in C state (the A->C atomic-import seam
	// wrote it). An uncommitted / forged root is untrusted — inert.
	if !vs.ReceiptRootCommitted(p.ReceiptRoot) {
		return VerifiedAInferenceReceipt{}, ErrReceiptRootNotCommitted
	}

	// (4) The receipt_hash must be included under that committed root.
	if !VerifyMerkle(leaf, p) {
		return VerifiedAInferenceReceipt{}, ErrMerkleVerify
	}

	// (5) The receipt must settle a PENDING C-outbox intent (one C actually submitted).
	oi := vs.LoadIntent(r.IntentID)
	switch oi.Status {
	case OutboxNone:
		return VerifiedAInferenceReceipt{}, ErrNoMatchingIntent
	case OutboxConsumed:
		// (6) Already settled by a prior verified receipt — double-consume guard.
		return VerifiedAInferenceReceipt{}, ErrIntentConsumed
	case OutboxPending:
		// proceed
	default:
		return VerifiedAInferenceReceipt{}, ErrNoMatchingIntent
	}

	// (7) The receipt's bound fields must equal the intent's. A receipt for a
	// DIFFERENT model / prompt / requester / chain / fan-out can never settle THIS
	// intent, even if it rides a valid proof under a committed root.
	if r.ModelSpecHash != oi.ModelSpecHash ||
		r.PromptHash != oi.PromptHash ||
		r.Requester != oi.Caller ||
		r.CChainID != oi.CChainID ||
		r.AChainID != oi.AChainID ||
		r.N != oi.N ||
		r.Threshold != oi.Threshold {
		return VerifiedAInferenceReceipt{}, ErrReceiptBindMismatch
	}

	// (8) Single C effect: mark consumed (no value moves here — the calling contract
	// chooses what to do with the verified output). Idempotency is enforced by the
	// OutboxPending check above (CEI: the guard precedes the write).
	vs.MarkIntentConsumed(r.IntentID, oi.BlockNumber)

	return VerifiedAInferenceReceipt{
		IntentID:            r.IntentID,
		CanonicalOutputHash: r.CanonicalOutputHash,
		Status:              StatusCompleted,
	}, nil
}
