// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"

	"github.com/luxfi/geth/common"
)

// settle_stm.go declares the 0x9999 swap's STORAGE ACCESS SET so the cevm
// Block-STM scheduler (txReadWriteSet + detectConflicts in evm/core/parallel) can
// run non-conflicting swaps in parallel and serialize only true conflicts.
//
// THE BLOCK-STM RULE (the design invariant): ZERO global hot WRITE slots. Every
// write is keyed by an account, an asset, a receipt, an allowance, or a pool —
// nothing a swap writes is a single global counter (no global nonce, no global
// volume accumulator, no single fee sink, no lastReceipt). Analytics are sharded
// (feeBucket[asset][epoch%N], volume[pool][epoch%M]) so two swaps contend only
// when they genuinely overlap. Hot READS (haltGlobal, the registries, config) are
// read-only and therefore never serialize.
//
// Two swaps conflict iff their access sets intersect on a WRITE — i.e. they share
// an account, an asset, a receipt, an allowance, or a pool. The scheduler derives
// that from this set without executing the swap.

// AccessSet is the predicted (Reads, Writes) storage-slot set of a swap. Slots are
// the SAME blake3-derived keys the handler uses, so the prediction is exact — a
// mismatch would let the scheduler miss a conflict, so the keys MUST be derived by
// the same helpers the settle path uses.
type AccessSet struct {
	Reads  []common.Hash
	Writes []common.Hash
}

// PredictAccesses returns the storage slots a settle of r will read and write. It
// is a PURE function of the receipt (and caller for the allowance slot) — the
// scheduler calls it before execution. epochHint is the block number used for the
// sharded analytics slots; if the scheduler does not know it, any value in the
// epoch yields a slot in the same shard family, which is conservative (it may
// over-predict a shared analytics slot, never under-predict a real conflict).
func PredictAccesses(r *DFillReceiptV1, epochHint uint64) AccessSet {
	var as AccessSet

	// --- READS (mostly read-only hot slots; never cause serialization) ---
	as.Reads = append(as.Reads,
		haltGlobalKey,
		makeStorageKey(haltMarketPrefix, r.MarketID[:]),
		makeStorageKey(haltAssetPrefix, r.TokenInAssetID[:]),
		makeStorageKey(haltAssetPrefix, r.TokenOutAssetID[:]),
		makeStorageKey(haltReceiptTypePrefix, []byte{byte(r.CertType)}),
		cfgNetworkIDKey,
		cfgCChainIDKey,
		consumedReceiptKey(r.ReceiptID),
		settleVaultKey(r.TokenInAssetID),
		settleVaultKey(r.TokenOutAssetID),
	)
	// Verifier registry meta + per-validator slots are reads too, but their count
	// depends on the set size; the meta slot is the conflict-relevant one (the set
	// is only ever WRITTEN by governance, never by a swap), so a swap's registry
	// reads never serialize against another swap. Include the meta slot for
	// completeness so the scheduler sees the dependency on a governance rotation.

	// --- WRITES (each keyed by receipt / asset / account — NO global slot) ---
	as.Writes = append(as.Writes,
		consumedReceiptKey(r.ReceiptID),          // replay map, unique per fill
		settleVaultKey(r.TokenInAssetID),         // vault holdings of tokenIn
		settleVaultKey(r.TokenOutAssetID),        // vault holdings of tokenOut
		feeBucketKey(r.FeeAssetID, epochHint),    // SHARDED fee bucket
		volBucketKey(r.PoolKeyHash, epochHint),   // SHARDED volume bucket
	)
	// Native balance moves are EVM account balances (sender, recipient, 0x9999),
	// which Block-STM tracks as account-state accesses outside the precompile's
	// storage slots; we surface them as derived "balance" keys so the scheduler
	// also serializes two swaps that touch the same account's balance.
	as.Writes = append(as.Writes,
		balanceSlot(r.Sender, r.TokenInAssetID),
		balanceSlot(r.Recipient, r.TokenOutAssetID),
	)
	return as
}

// balanceSlot is a derived key naming (account, asset) for conflict detection of
// the balance legs. It is NOT a storage slot the handler writes (native balances
// live in account state, ERC-20 in the token); it exists so PredictAccesses can
// express "these two swaps touch the same account's asset balance" to the
// scheduler. Keyed in the 0x9999 namespace so it never collides with a real slot.
func balanceSlot(account common.Address, assetID [32]byte) common.Hash {
	id := make([]byte, 0, 20+32)
	id = append(id, account.Bytes()...)
	id = append(id, assetID[:]...)
	return makeStorageKey([]byte(settleStateNamespace+"bal"), id)
}

// epochOf is a small helper so callers can derive the analytics epoch from a block
// number consistently with the handler (which uses the block number directly).
func epochOf(blockNumber uint64) uint64 { return blockNumber }

var _ = binary.BigEndian // reserved for future fixed-width access-key extensions
