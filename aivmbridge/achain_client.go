// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// achain_client.go — the precompile's handle to the node-LOCAL A-Chain (aivm)
// ON-RAMP. It is the EXACT shape of dex/dchain_client.go (the C->D on-ramp),
// adapted to AI inference and PROOF/RECEIPT-oriented (never a live-query surface).
//
// WHY A SEPARATE PACKAGE. The 0x0303 inference precompile runs a deterministic int8
// transformer entirely in pure Go on the consensus path — every validator computes
// byte-identical tokens with no GPU. That is the CANONICAL in-consensus brain for
// SMALL models (zen-nano), and it is left BYTE-IDENTICALLY UNCHANGED (it lives in
// its own package; this bridge never touches it). This bridge is its COMPLEMENT: an
// on-ramp so an EVM contract can request inference from a LARGE model / off-chain
// operator that CANNOT run inside C-Chain block execution (too big, non-deterministic
// across hardware, GPU-bound). That work lives on the A-Chain (aivm), validated by
// its own consensus + provider quorum; the C side only SUBMITS an inference job
// intent (Pattern A) or VERIFIES a committed A receipt (Pattern B).
//
// THE CONSENSUS-SAFETY RULE (the #1 law, copied in spirit from dex/dchain_client.go):
// an implementation MUST NOT make C-Chain consensus state depend on observing live
// A-Chain process state, and MUST NOT mutate live A-Chain state from C Run(). The
// C-Chain state root must be derivable WITHOUT observing any live A process. A
// SYNCHRONOUS in-block call to A's live engine FORKS: two validators executing the
// same C block at different instants observe different A output / latency / queue =>
// divergent StateRoot. Therefore the ONLY two safe shapes are:
//
//   - Pattern A — SubmitInferenceIntent: a C tx WRITES a COMMITTED C-side outbox
//     intent (a storage record keyed by a deterministic intent_id) and returns the
//     id. The id is a PURE function of the calldata + C tx identity — NOT of any A
//     response. The intent is later IMPORTED by A's own consensus (Blue-B's importer
//     reads the committed C outbox / the staged atomic object). This NEVER calls into
//     or mutates aivm.
//
//   - Pattern B — VerifyInferenceReceipt: a C tx carries an A receipt + a merkle
//     inclusion proof as CALLDATA. The C side deterministically verifies the receipt
//     hash is included under a receipt_root that C ALREADY HOLDS COMMITTED in its own
//     state (a checkpoint slot the A->C atomic boundary / warp populates), matches a
//     pending C outbox intent, and records the canonical output. The verification
//     depends ONLY on C-committed state + the proof — NEVER on a live A query.
//
// NOTE on method naming (deliberate): there is NO GetInferenceReceipt(id) method.
// Such a name invites a live mutable A query (exactly the fork-unsafe shape a prior
// build shipped). Verification takes the receipt + proof as calldata, so the C side
// never reaches into A to fetch anything.
//
// The precompile is a LEAF library: it must NOT reach up into the node chain manager.
// A node that does not wire its local A on-ramp leaves the default achainUnavailable
// client in place and every bridge selector reverts cleanly.

package aivmbridge

import (
	"context"
	"errors"
	"sync/atomic"
)

// AChainClient is the precompile's handle to the node-LOCAL A-Chain (aivm) on-ramp.
//
// THE MODEL (decomplected — one concern, one name): A is a normal Lux chain running
// aivm, validated by its own consensus + provider quorum (the staking/challenge layer
// lives in aivm, NOT here). This bridge is ONLY an ON-RAMP: it RECORDS inference
// intents into committed C state for A to import, and VERIFIES committed A receipts.
// It is NOT an inference engine and NOT a provider selector.
//
// Both methods are consensus-safe by construction: neither observes live A state.
// SubmitInferenceIntent writes only C state + a deterministic id; VerifyInferenceReceipt
// reads only C-committed state + the caller-supplied proof.
type AChainClient interface {
	// Brand returns the human-readable identity of the client (white-label). The
	// precompile uses it in boot logs / error wrapping. Implementations MUST return
	// a non-empty constant; an empty value trips a sanity check at InstallAChainClient.
	Brand() string

	// AChainID returns the A-Chain (aivm) peer id this on-ramp targets. It is bound
	// into the deterministic intent_id so an intent is scoped to exactly one C<->A
	// rail. It is COMMITTED on-ramp configuration (a constant for the life of the
	// process), NOT a live A observation.
	AChainID() [32]byte

	// SubmitInferenceIntent is Pattern A: deterministic intent submission. It WRITES a
	// COMMITTED C-side outbox intent (via the supplied IntentStore) and returns its id.
	// It MUST NOT call into or mutate aivm. The returned id is a pure function of `in`.
	SubmitInferenceIntent(ctx context.Context, store IntentStore, in InferenceIntent) (IntentID [32]byte, err error)

	// VerifyInferenceReceipt is Pattern B: verify a COMMITTED A receipt against a
	// committed receipt root the C side already holds (via the supplied ReceiptVerifierState).
	// It MUST NOT live-query aivm. The receipt + proof arrive as calldata; the root
	// authenticity comes from C-committed state.
	VerifyInferenceReceipt(ctx context.Context, vs ReceiptVerifierState, r AInferenceReceipt, p AInferenceProof) (VerifiedAInferenceReceipt, error)
}

// VerifiedAInferenceReceipt is the result of a successful Pattern-B verification: the
// settled intent id, the canonical output digest the C side now trusts, and the
// status (always StatusCompleted on success — the type exists so a caller reads named
// fields rather than re-decoding the receipt).
type VerifiedAInferenceReceipt struct {
	IntentID            [32]byte
	CanonicalOutputHash [32]byte
	Status              ReceiptStatus
}

// achainUnavailable is the precompile's client when the node-LOCAL A-Chain on-ramp is
// not wired. It runs NO inference and holds NO state: Pattern A returns
// ErrAChainUnavailable so a node without its local A on-ramp reverts cleanly. (Pattern
// B is a pure C-state verification and does NOT depend on the client — see bridge.go —
// so receipt verification keeps working even with the default client; that is correct,
// because verifying a committed receipt against committed C state never needs A.)
//
// This is NOT a "mode" and NOT a selectable engine — it is the honest default for a
// precompile whose A on-ramp is absent. Mirror of dex.dchainUnavailable. Contract:
// never panics, never fabricates a result.
type achainUnavailable struct{}

var _ AChainClient = (*achainUnavailable)(nil)

func (achainUnavailable) Brand() string      { return "aivmbridge (local A-Chain on-ramp unavailable)" }
func (achainUnavailable) AChainID() [32]byte { return [32]byte{} }

func (achainUnavailable) SubmitInferenceIntent(context.Context, IntentStore, InferenceIntent) ([32]byte, error) {
	return [32]byte{}, ErrAChainUnavailable
}

// VerifyInferenceReceipt on the unavailable client still performs the pure C-state
// verification — verifying a committed receipt against committed C state needs no A
// on-ramp. (bridge.go calls the package verify routine directly rather than routing
// Pattern B through the client; this method exists to satisfy the interface and is
// equivalent.)
func (achainUnavailable) VerifyInferenceReceipt(ctx context.Context, vs ReceiptVerifierState, r AInferenceReceipt, p AInferenceProof) (VerifiedAInferenceReceipt, error) {
	return verifyInferenceReceipt(vs, r, p)
}

// aChainClient is the singleton the bridge resolves through, held behind an
// atomic.Pointer so Run() reads it race-free across concurrent EVM threads and
// InstallAChainClient publishes a new client with a single atomic store. The DEFAULT
// is achainUnavailable (the on-ramp is closed until a node wires its local aivm).
var aChainClient atomic.Pointer[AChainClient]

// installed guards InstallAChainClient to install-once: a second install errors
// rather than silently swapping the live client (no late re-resolution race / TOCTOU
// against in-flight Run() calls). Mirror of dex's install-once discipline.
var installed atomic.Bool

func init() {
	def := AChainClient(achainUnavailable{})
	aChainClient.Store(&def)
}

// currentAChainClient returns the live client (never nil — defaults to
// achainUnavailable). The single read point used by the bridge.
func currentAChainClient() AChainClient {
	if p := aChainClient.Load(); p != nil {
		return *p
	}
	return achainUnavailable{}
}

// InstallAChainClient resolves the singleton against the node-LOCAL A-Chain (aivm)
// on-ramp client. MIRROR of dex.InstallDChainClient.
//
// THIS IS NOT A BACKEND SWAP. There is exactly ONE valid target: the co-located
// A-Chain this node runs (the staged-import counterpart Blue-B builds). The EVM
// plugin calls this exactly ONCE at boot, BEFORE the VM starts serving precompiles. A
// node without its local A on-ramp leaves the default achainUnavailable in place.
//
// SANITY + SAFETY at install time (fail-secure):
//   - c must be non-nil (a nil client would NPE the bridge).
//   - c.Brand() must be non-empty (white-label / log-line discipline).
//   - c.AChainID() must be non-zero (an unscoped peer would mint cross-rail-aliasable
//     intent ids — the rail binding is load-bearing for replay isolation).
//   - install is ONCE: a second call errors rather than swapping the live client, so a
//     misconfigured plugin cannot race a late re-resolution against in-flight Run().
//
// The atomic store makes the publication visible to the concurrent Run() readers that
// follow. The host binary is the single caller during process startup.
func InstallAChainClient(c AChainClient) error {
	if c == nil {
		return errors.New("aivmbridge: local A-Chain client must not be nil")
	}
	if c.Brand() == "" {
		return errors.New("aivmbridge: local A-Chain client must report a non-empty Brand()")
	}
	if isZero32(c.AChainID()) {
		return errors.New("aivmbridge: local A-Chain client must report a non-zero AChainID() (the C<->A rail peer)")
	}
	if !installed.CompareAndSwap(false, true) {
		return errors.New("aivmbridge: local A-Chain client already installed (install-once; cannot re-resolve a live client)")
	}
	cc := c
	aChainClient.Store(&cc)
	return nil
}

// resetAChainClientForTest restores the closed-on-ramp default so tests can drive the
// install path repeatedly. Test-only (not part of the production surface).
func resetAChainClientForTest() {
	def := AChainClient(achainUnavailable{})
	aChainClient.Store(&def)
	installed.Store(false)
}
