// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// state.go — the DURABLE C-side state of the inference bridge: the C->A OUTBOX
// (pending intents), the consumed-intent set (Pattern-B double-consume guard), and
// the committed RECEIPT-ROOT checkpoint set (the A->C atomic-import seam's landing
// slot). Everything lives under ONE namespace (aivmbridge.v1.*) so the bridge's
// state is one auditable region, and everything is content-addressed by the
// deterministic intent_id / receipt_root so a re-executed / reorged block replays
// identically on every validator (consensus-shared, durable, reverted atomically
// with the tx via the EVM snapshot).
//
// THE CONSENSUS-SAFETY MODEL (why this is the whole point):
//   - The OUTBOX is C state. A's importer (Blue-B) reads the COMMITTED outbox under A
//     consensus; C never calls A. (Pattern A writes here and nowhere into A.)
//   - The RECEIPT-ROOT checkpoint is C state, populated by the A->C atomic boundary /
//     warp at block accept (the seam). Pattern B trusts a receipt root ONLY if it is
//     recorded here. The verify reads C-committed state + the proof — never A.
//
// SEAM BOUNDARY (honest, for RED): in production the receipt-root checkpoint slot is
// written by the A->C atomic import / warp handler (the host's block-accept path,
// the same shape as dex's FlushAcceptedAtomicOps but in the A->C direction). This
// package ships the C-side store + verification; the test harness and the staged
// native client write the checkpoint directly to exercise the verify path. The
// authenticity of a committed root therefore rests on that import handler — clearly
// marked, never papered over: a root C has not recorded is untrusted and inert.

package aivmbridge

import (
	"github.com/luxfi/geth/common"
	"github.com/zeebo/blake3"
)

// BridgeAddress is the storage account under which ALL bridge state lives. It equals
// the precompile address (the bridge's own slot in the AI range) so the state and the
// contract share one identity. Defined in module.go (ContractAddress); aliased here
// for the state helpers.
var bridgeStateAddr = ContractAddress

// stateNamespace is the durable storage namespace prefix. Every key the bridge writes
// derives from this so the bridge's state is a single, auditable region.
const stateNamespace = "aivmbridge.v1."

// Storage-key prefixes (one per orthogonal pot — no aliasing across concerns).
var (
	outboxPrefix       = []byte(stateNamespace + "outbox")   // intent_id -> packed OutboxIntent
	intentConsumedPref = []byte(stateNamespace + "consumed") // intent_id -> blockNumber+1 sentinel
	receiptRootPrefix  = []byte(stateNamespace + "rcptroot") // receipt_root -> committed-height+1 sentinel
)

// makeStorageKey derives a storage slot key from a prefix and an id. blake3 (the same
// KDF dex uses for makeStorageKey) — collision-resistant key derivation so distinct
// (prefix,id) pairs never share a slot.
func makeStorageKey(prefix []byte, id []byte) common.Hash {
	h := blake3.New()
	_, _ = h.Write(prefix)
	_, _ = h.Write(id)
	var key common.Hash
	_, _ = h.Digest().Read(key[:])
	return key
}

// StateKV is the MINIMAL key-value state surface the bridge needs — just
// GetState/SetState. Decomplecting it from the full contract.StateDB (which braids in
// balances) lets the bridge's pure-metadata helpers be tested with a tiny fake and
// keeps the bridge honest: it touches NO balances. contract.StateDB satisfies this
// (its SetState returns the prior value; this narrower form ignores the return).
type StateKV interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	SetState(addr common.Address, key common.Hash, value common.Hash) common.Hash
}

// OutboxStatus is the C-side lifecycle of a recorded intent. It is ORTHOGONAL to the
// A-Chain ReceiptStatus: this tracks the C outbox slot, not the A job.
type OutboxStatus uint8

const (
	// OutboxNone — no intent recorded at this id (the zero value / absent slot).
	OutboxNone OutboxStatus = 0
	// OutboxPending — the intent was recorded and is awaiting A import + settlement.
	OutboxPending OutboxStatus = 1
	// OutboxConsumed — a verified A receipt settled this intent; it can never settle
	// again (double-consume guard).
	OutboxConsumed OutboxStatus = 2
)

// OutboxIntent is the COMMITTED C-side record of a submitted intent. It binds the
// fields a Pattern-B receipt must match (model/prompt/requester/chain/fan-out) so a
// receipt cannot settle an intent it does not correspond to. Stored across fixed-width
// slots keyed by intent_id.
type OutboxIntent struct {
	Status        OutboxStatus
	Caller        common.Address
	CChainID      [32]byte
	AChainID      [32]byte
	ModelSpecHash [32]byte
	PromptHash    [32]byte
	N             uint16
	Threshold     uint16
	BlockNumber   uint64
}

// IntentStore is the write surface Pattern A uses: record a pending intent (replay-
// guarded). It is an interface so the client depends on a capability, not a concrete
// StateDB — the same orthogonality dex applies. The concrete implementation is
// stateKVStore (over contract.StateDB); tests use a map-backed fake.
type IntentStore interface {
	// IntentStatus returns the recorded outbox status for intent_id (OutboxNone if
	// absent).
	IntentStatus(intentID [32]byte) OutboxStatus
	// PutPendingIntent records a new pending intent. It is only ever called after the
	// caller has checked IntentStatus == OutboxNone (replay guard, CEI before write).
	// The store stamps OutboxIntent.BlockNumber from its own captured height (it is the
	// authority on "now"); any BlockNumber on the passed-in value is ignored.
	PutPendingIntent(intentID [32]byte, oi OutboxIntent)
}

// ReceiptVerifierState is the read/update surface Pattern B uses: read a committed
// receipt root, read the bound pending intent, and mark it consumed. It is the read
// counterpart to IntentStore (same backing store; split by concern so verify cannot
// accidentally create an intent).
type ReceiptVerifierState interface {
	// ReceiptRootCommitted reports whether receiptRoot is recorded as committed in C
	// state (the A->C atomic-import seam wrote it). A root not recorded here is
	// untrusted and the verify is inert (fail-secure).
	ReceiptRootCommitted(receiptRoot [32]byte) bool
	// LoadIntent returns the committed OutboxIntent for intent_id (Status==OutboxNone
	// if absent).
	LoadIntent(intentID [32]byte) OutboxIntent
	// MarkIntentConsumed flips a pending intent to consumed (idempotent at the storage
	// level; the caller guards against re-consume by checking Status first).
	MarkIntentConsumed(intentID [32]byte, blockNumber uint64)
}

// --- the concrete store over a StateKV ----------------------------------------

// stateKVStore adapts a StateKV (i.e. contract.StateDB) to IntentStore +
// ReceiptVerifierState. The blockNumber is captured at construction (the current
// block) so writes stamp a consistent height.
type stateKVStore struct {
	kv          StateKV
	blockNumber uint64
}

var (
	_ IntentStore          = (*stateKVStore)(nil)
	_ ReceiptVerifierState = (*stateKVStore)(nil)
)

func newStateKVStore(kv StateKV, blockNumber uint64) *stateKVStore {
	return &stateKVStore{kv: kv, blockNumber: blockNumber}
}

// --- outbox slot layout (fixed-width, content-addressed by intent_id) ---------
//
// The OutboxIntent spans consecutive blake3-derived slots. Each field gets its own
// derived slot (sub-keyed by a field tag) so a layout change is explicit and a field
// read never depends on packing offsets. Slots:
//
//	slot("st")  word[31]      = status (1) ; word[0:8] high = blockNumber (redundant w/ "bn", kept in "bn")
//	slot("cl")  word[12:32]   = caller (20, right-aligned like an address word)
//	slot("cc")  word          = CChainID (32)
//	slot("ac")  word          = AChainID (32)
//	slot("ms")  word          = ModelSpecHash (32)
//	slot("pr")  word          = PromptHash (32)
//	slot("nt")  word[28:30]=N, word[30:32]=Threshold (u16be each)
//	slot("bn")  word[24:32]   = blockNumber (u64be)
//
// Reading status alone (the hot path: replay/consume checks) touches ONE slot.

func outboxFieldKey(intentID [32]byte, tag string) common.Hash {
	id := make([]byte, 0, 32+len(tag))
	id = append(id, intentID[:]...)
	id = append(id, tag...)
	return makeStorageKey(outboxPrefix, id)
}

func (s *stateKVStore) IntentStatus(intentID [32]byte) OutboxStatus {
	w := s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "st"))
	return OutboxStatus(w[31])
}

func (s *stateKVStore) PutPendingIntent(intentID [32]byte, oi OutboxIntent) {
	// status
	var st common.Hash
	st[31] = byte(OutboxPending)
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "st"), st)
	// caller (right-aligned 20 bytes, address-word convention)
	var cl common.Hash
	copy(cl[12:32], oi.Caller.Bytes())
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "cl"), cl)
	// chain ids + commitments (full words)
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "cc"), common.BytesToHash(oi.CChainID[:]))
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "ac"), common.BytesToHash(oi.AChainID[:]))
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "ms"), common.BytesToHash(oi.ModelSpecHash[:]))
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "pr"), common.BytesToHash(oi.PromptHash[:]))
	// N || Threshold (u16be each in the low 4 bytes)
	var nt common.Hash
	nt[28] = byte(oi.N >> 8)
	nt[29] = byte(oi.N)
	nt[30] = byte(oi.Threshold >> 8)
	nt[31] = byte(oi.Threshold)
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "nt"), nt)
	// blockNumber (u64be in the low 8 bytes) — stamped from the store's captured
	// height, the authority on "now" (the passed-in oi.BlockNumber is ignored).
	var bn common.Hash
	putU64(bn[24:32], s.blockNumber)
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "bn"), bn)
}

func (s *stateKVStore) LoadIntent(intentID [32]byte) OutboxIntent {
	st := s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "st"))
	status := OutboxStatus(st[31])
	if status == OutboxNone {
		return OutboxIntent{Status: OutboxNone}
	}
	var oi OutboxIntent
	oi.Status = status
	oi.Caller = common.BytesToAddress(s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "cl")).Bytes())
	copy(oi.CChainID[:], s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "cc")).Bytes())
	copy(oi.AChainID[:], s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "ac")).Bytes())
	copy(oi.ModelSpecHash[:], s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "ms")).Bytes())
	copy(oi.PromptHash[:], s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "pr")).Bytes())
	nt := s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "nt"))
	oi.N = uint16(nt[28])<<8 | uint16(nt[29])
	oi.Threshold = uint16(nt[30])<<8 | uint16(nt[31])
	bn := s.kv.GetState(bridgeStateAddr, outboxFieldKey(intentID, "bn"))
	oi.BlockNumber = bytesToU64(bn[24:32])
	return oi
}

func (s *stateKVStore) MarkIntentConsumed(intentID [32]byte, blockNumber uint64) {
	// Flip the outbox status to Consumed (the authoritative double-consume guard the
	// hot path reads via IntentStatus).
	var st common.Hash
	st[31] = byte(OutboxConsumed)
	s.kv.SetState(bridgeStateAddr, outboxFieldKey(intentID, "st"), st)
	// Also stamp a consumed-set sentinel keyed by intent_id (audit + redundant guard).
	var v common.Hash
	putU64(v[24:32], blockNumber+1)
	s.kv.SetState(bridgeStateAddr, makeStorageKey(intentConsumedPref, intentID[:]), v)
}

// --- committed receipt-root checkpoint ----------------------------------------

func receiptRootKey(receiptRoot [32]byte) common.Hash {
	return makeStorageKey(receiptRootPrefix, receiptRoot[:])
}

func (s *stateKVStore) ReceiptRootCommitted(receiptRoot [32]byte) bool {
	// An all-zero root is never a valid committed root (it would let a forged proof
	// claiming root==0 pass; the empty slot reads as zero).
	if isZero32(receiptRoot) {
		return false
	}
	return s.kv.GetState(bridgeStateAddr, receiptRootKey(receiptRoot)) != (common.Hash{})
}

// CommitReceiptRoot records receiptRoot as committed in C state at committedHeight.
// THIS IS THE A->C SEAM LANDING POINT: in production the host's A->C atomic-import /
// warp handler calls it at block accept; the test harness and the staged native
// client call it to exercise the verify path. It is exported so the host import
// handler (and tests) can populate the trusted set. A zero root is rejected.
func CommitReceiptRoot(kv StateKV, receiptRoot [32]byte, committedHeight uint64) {
	if isZero32(receiptRoot) {
		return
	}
	var v common.Hash
	putU64(v[24:32], committedHeight+1)
	kv.SetState(bridgeStateAddr, receiptRootKey(receiptRoot), v)
}

// --- small fixed-width helpers ------------------------------------------------

func putU64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

func bytesToU64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}
