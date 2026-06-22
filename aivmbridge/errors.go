// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// errors.go — the bridge's error surface. Every error here makes the precompile
// REVERT cleanly (geth-canonical: charged gas consumed, remaining returned) and
// NEVER credits or mutates C state. Fail-secure is the rule: when in doubt, deny.

package aivmbridge

import "errors"

var (
	// ErrAChainUnavailable is returned by Pattern A when the node-LOCAL A-Chain
	// on-ramp is not wired in (the default client). A node that serves the bridge
	// selectors but is not running its local A on-ramp reverts cleanly — it never
	// fabricates a result and never masks the absent on-ramp. Mirror of
	// dex.ErrDChainUnavailable.
	ErrAChainUnavailable = errors.New("aivmbridge: local A-Chain on-ramp unavailable (node must wire the A-Chain on-ramp to submit inference intents)")

	// --- calldata / decode ---------------------------------------------------

	// ErrInputTooShort: the calldata is shorter than the fixed-width ABI frame the
	// selector requires.
	ErrInputTooShort = errors.New("aivmbridge: input too short")
	// ErrInputOversized: the calldata is longer than the fixed-width ABI frame the
	// selector accepts (reject trailing junk rather than silently ignore it).
	ErrInputOversized = errors.New("aivmbridge: input larger than expected frame")
	// ErrDirtyWord: a fixed-width numeric ABI word carries non-zero high bytes
	// above the field's declared width (a caller must not smuggle bits there).
	ErrDirtyWord = errors.New("aivmbridge: numeric ABI word has dirty high bytes")
	// ErrBadFanout: N outside [1, MaxFanout].
	ErrBadFanout = errors.New("aivmbridge: N out of range")
	// ErrBadThreshold: threshold outside [1, N].
	ErrBadThreshold = errors.New("aivmbridge: threshold out of range")
	// ErrZeroModelSpec / ErrZeroPrompt: an all-zero commitment is never a valid
	// request (it would collide an unbound intent across callers/models).
	ErrZeroModelSpec = errors.New("aivmbridge: modelSpecHash must be non-zero")
	ErrZeroPrompt    = errors.New("aivmbridge: promptHash must be non-zero")
	// ErrZeroTxHash: the C tx identity (StateDB.TxHash() and, on fallback, the atomic
	// TxID) resolved to all-zero — a broken host wiring under which distinct C txs would
	// alias the same deterministic intent id. Reject rather than mint an unbound id.
	ErrZeroTxHash = errors.New("aivmbridge: c_tx_hash must be non-zero (host wired no tx identity)")

	// --- intent state --------------------------------------------------------

	// ErrIntentReplay: an intent with this deterministic id was already submitted
	// (a re-derived id from a distinct tx must not double-write the outbox).
	ErrIntentReplay = errors.New("aivmbridge: intent already submitted (replay)")

	// --- receipt verification (Pattern B) ------------------------------------

	// ErrReceiptDecode: the receipt bytes are malformed (wrong length / version).
	ErrReceiptDecode = errors.New("aivmbridge: receipt decode failed")
	// ErrProofDecode: the proof bytes are malformed (length not a multiple of the
	// hash width, or impossible index).
	ErrProofDecode = errors.New("aivmbridge: proof decode failed")
	// ErrReceiptRootNotCommitted: the proof's ReceiptRoot is not committed in C
	// state. The root authenticity is the A->C atomic-import seam; a root C has not
	// recorded as committed is untrusted and the verify is inert (fail-secure).
	ErrReceiptRootNotCommitted = errors.New("aivmbridge: receipt root is not committed in C state")
	// ErrMerkleVerify: the receipt_hash is not included under ReceiptRoot at Index
	// along Path (a forged or wrong proof).
	ErrMerkleVerify = errors.New("aivmbridge: merkle inclusion proof failed")
	// ErrNoMatchingIntent: the receipt's IntentID does not match a pending C-outbox
	// intent (a receipt for an intent C never submitted is not actionable).
	ErrNoMatchingIntent = errors.New("aivmbridge: receipt does not match a pending C intent")
	// ErrIntentConsumed: the matching intent was already consumed by a prior
	// verified receipt (double-consume guard).
	ErrIntentConsumed = errors.New("aivmbridge: intent already consumed by a prior receipt")
	// ErrReceiptNotCompleted: the receipt status is not Completed (a pending /
	// failed / challenged receipt carries no actionable output — inert).
	ErrReceiptNotCompleted = errors.New("aivmbridge: receipt status is not Completed")
	// ErrZeroOutput: a Completed receipt with an all-zero CanonicalOutputHash is
	// self-contradictory and never actionable.
	ErrZeroOutput = errors.New("aivmbridge: completed receipt has zero canonical output hash")
	// ErrReceiptBindMismatch: the receipt's model/prompt/requester/chain binding
	// does not match the pending intent it claims to settle.
	ErrReceiptBindMismatch = errors.New("aivmbridge: receipt does not match the bound intent fields")

	// --- read-only -----------------------------------------------------------

	// ErrReadOnly: a state-mutating selector was invoked in a read-only (static)
	// call context. Both bridge ops mutate the C outbox, so a static call reverts.
	ErrReadOnly = errors.New("aivmbridge: cannot submit/verify in read-only mode")

	// --- atomic capability ---------------------------------------------------

	// ErrNoAtomicState: the host did not wire the cross-chain atomic capability
	// (single-chain dev / non-atomic harness). The deterministic intent id binds
	// the C/A chain ids + tx id sourced from this capability; without it the bridge
	// cannot mint a network-scoped id and reverts rather than guess a peer.
	ErrNoAtomicState = errors.New("aivmbridge: cross-chain atomic capability unavailable (host wired no shared-memory runtime)")
)
