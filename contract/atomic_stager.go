// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import "github.com/luxfi/ids"

// AtomicStager is the OPTIONAL host capability a STATELESS CONDUIT precompile (the
// LP-311 0x9999 settlement conduit) type-asserts to move cross-chain atomic objects
// WITHOUT writing any durable storage to its OWN account.
//
// ── WHY THIS EXISTS (the reaping dissolution, LP-311 §5) ────────────────────────────
// 0x9999 is an AlwaysOn precompile dispatched BY ADDRESS; an ERC-20 deposit leaves its
// account EMPTY in the EIP-158 sense (nonce==0 ∧ balance==0 ∧ codeHash==∅ — storage is
// NOT part of the test), so geth's Finalise(deleteEmptyObjects=true) reaps the account
// AND all of its storage. A precompile that stages cross-domain atomic ops in its OWN
// storage therefore loses them at end-of-tx (the live ERC-20 fund-strand), and the only
// way to defend that storage is a nonce marker on 0x9999 — which preserves the complect
// (a conduit owning a ledger) instead of dissolving it.
//
// AtomicStager dissolves it: the cross-domain staging buffer lives in the HOST's own
// NON-EMPTY staging account (the "host atomic backend"), never the conduit's account.
// The conduit then writes ZERO durable own-account storage, so reaping the conduit is a
// NO-OP (nothing to lose; the ERC-20 escrow is in the token's trie, the native escrow is
// the conduit's own native balance). No nonce marker on 0x9999 is needed or used.
//
// ── REVERT-SAFETY + DETERMINISM (the cross-domain atomicity the staging preserves) ──
// A direct atomic.SharedMemory.Apply inside a precompile Run is NOT covered by the EVM
// snapshot/revert, so a tx that reverts AFTER a Put would leave a C→D object with no
// backing C debit (a MINT), and a reverted Remove would drop a D→C object whose C credit
// rolled back (a LOSS). The host therefore stages every op into revert-safe, journaled
// EVM state (in its OWN non-empty account, NOT the conduit's), so a reverted tx discards
// the staged op atomically with its rolled-back escrow — and FLUSHES the staged ops to
// shared memory at BLOCK ACCEPT (the platformvm acceptor pattern: state commit and the
// shared-memory Apply land in one database batch). The flush window is derived from
// CONSENSUS STATE (a monotonic staged-op seq that is part of the state root), so every
// validator replaying the ordered block derives the identical request set — deterministic,
// never wall-clock / live-venue / GPU dependent.
//
// A precompile reaches this via:
//
//	stager, ok := accessibleState.(contract.AtomicStager)
//	if !ok { return revert } // host wired no atomic staging — fail-closed, never mint.
//
// Both methods return an error the conduit turns into a clean revert; neither mutates
// shared memory inside Run (that is the host's Accept-time job).
type AtomicStager interface {
	// StageExport records a revert-safe C→D atomic Put: the host writes `object` under
	// `key` for destination chain `dst`, in the host's NON-EMPTY staging account (never
	// the calling precompile's account). `object` is the canonical exported-output value
	// (rail|owner|asset|amount|spent) the peer chain's import side consumes. The op is
	// flushed to shared memory at the next block Accept; a tx that reverts after this call
	// discards the staged op (the staging write is journaled EVM state). `key` is the
	// cross-chain object id the conduit derives deterministically (e.g. from the
	// AtomicState TxID/CallIndex) so it is injective across calls and identical on every
	// validator. Returns an error only on a malformed object or absent host backend.
	StageExport(dst ids.ID, key ids.ID, object []byte) error

	// ConsumeImport reads a D→C atomic object from shared memory by (src, key) and, when
	// present, records a revert-safe Remove (exactly-once consume) staged for the next
	// block Accept. It returns the object bytes so the conduit can value-bind and release
	// escrow in the SAME tx. `found` is false when no such object is present (the fill has
	// not landed yet on the async path); the conduit then makes no release. A tx that
	// reverts after this call discards the staged Remove, so the object is NOT consumed and
	// no value is lost. The Remove is idempotent against a re-consume of the same key.
	ConsumeImport(src ids.ID, key ids.ID) (object []byte, found bool, err error)
}
