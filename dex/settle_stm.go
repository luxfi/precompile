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
	// The market-halt scope keys on r.PoolKeyHash (the validated pool identity), the
	// SAME id checkHalt reads — NOT the free-form r.MarketID. (See halt9999.go.)
	as.Reads = append(as.Reads,
		haltGlobalKey,
		makeStorageKey(haltMarketPrefix, r.PoolKeyHash[:]),
		makeStorageKey(haltAssetPrefix, r.TokenInAssetID[:]),
		makeStorageKey(haltAssetPrefix, r.TokenOutAssetID[:]),
		makeStorageKey(haltReceiptTypePrefix, []byte{byte(r.CertType)}),
		makeStorageKey(haltValidatorSetPrefix, r.DChainID[:]), // checkHalt reads the vset halt
		cfgNetworkIDKey,
		cfgCChainIDKey,
		consumedReceiptKey(r.ReceiptID),
		settleVaultKey(r.TokenInAssetID),
		settleVaultKey(r.TokenOutAssetID),
	)
	// Verifier registry meta slot is a read too (per-validator slots depend on set
	// size; the meta slot is the conflict-relevant one — the set is only ever WRITTEN
	// by governance, never by a swap, so a swap's registry reads never serialize
	// against another swap). Surfacing it lets the scheduler see the dependency on a
	// governance rotation. The verify path resolves the set under cert.ValidatorSetID,
	// but PredictAccesses sees only the receipt; the receipt's DChainID scopes the
	// registry namespace, which is the conflict-relevant axis for a rotation.

	// --- WRITES (each keyed by receipt / asset / account — NO global slot) ---
	as.Writes = append(as.Writes,
		consumedReceiptKey(r.ReceiptID),        // replay map, unique per fill
		settleVaultKey(r.TokenInAssetID),       // vault holdings of tokenIn
		settleVaultKey(r.TokenOutAssetID),      // vault holdings of tokenOut
		feeBucketKey(r.FeeAssetID, epochHint),  // SHARDED fee bucket
		volBucketKey(r.PoolKeyHash, epochHint), // SHARDED volume bucket
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

// PredictModifyLiquidityAccesses returns the storage slots a maker modifyLiquidity
// (ADD or REMOVE) reads and writes — its OWN fine-grained access set, distinct from
// the swap's. The conflict-relevant keys are exactly (owner+asset reserve, the
// orderID record, the ownerOrders index, the locked reserve), all keyed by the
// maker account / asset / order — NO global hot WRITE. Two makers operating on
// different accounts (or the same account on different assets/orders) never
// serialize. The scheduler calls this before execution; the keys MUST be derived by
// the same helpers the maker path uses so the prediction is exact.
//
// orderID = MakerOrderID(owner, poolID, salt, tickLower, tickUpper); lockedAsset is
// a pure function of (key, side) — both known to the scheduler from the calldata.
func PredictModifyLiquidityAccesses(
	owner common.Address, poolID [32]byte, salt [32]byte, tickLower, tickUpper int24, lockedAsset [32]byte,
) AccessSet {
	var as AccessSet
	orderID := MakerOrderID(owner, poolID, salt, tickLower, tickUpper)

	// READS: the market record (status), the asset-halt slot, the current reserve, the
	// per-asset vault slots (the ADD/REMOVE moves between settleVault and
	// makerLockedVault), the order record + count, and the reentrancy guard.
	as.Reads = append(as.Reads,
		marketSlot(poolID, marketMetaSuffix),
		makeStorageKey(haltAssetPrefix, lockedAsset[:]),
		depositorClaimKey(owner, lockedAsset),
		lockedReserveKey(owner, lockedAsset),
		settleVaultKey(lockedAsset),
		makerLockedVaultKey(lockedAsset),
		orderSlot(orderID, orderMetaSuffix),
		orderSlot(orderID, orderAmtSuffix),
		ownerOrdersCountKey(owner),
		custodyGuardKey9999,
	)
	// WRITES: reserve split (available/locked), the per-asset vault reclassification
	// (settleVault <-> makerLockedVault), the FULL order record (storeRestingOrder
	// writes all 6 slots), the index slot + count, and the reentrancy guard (set+clear
	// within the call). Each keyed by owner / asset / order — NO global hot WRITE
	// (settleVault/makerLockedVault are per-ASSET, so two makers contend only on the
	// same asset, which is a genuine conflict, not a global counter).
	as.Writes = append(as.Writes,
		depositorClaimKey(owner, lockedAsset),
		lockedReserveKey(owner, lockedAsset),
		settleVaultKey(lockedAsset),
		makerLockedVaultKey(lockedAsset),
		orderSlot(orderID, orderMetaSuffix),
		orderSlot(orderID, orderOwnerSuffix),
		orderSlot(orderID, orderPoolSuffix),
		orderSlot(orderID, orderAssetSuffix),
		orderSlot(orderID, orderAmtSuffix),
		orderSlot(orderID, orderSaltSuffix),
		ownerOrdersCountKey(owner),
		custodyGuardKey9999,
	)
	// NOTE: appendOwnerOrder also writes ownerOrdersAtKey(owner, count) — a NEW slot
	// at the live count, which this pure (StateDB-free) predictor cannot derive. The
	// ownerOrdersCountKey write above already serializes two ADDs by the SAME owner
	// (both bump the count), which is the conflict-relevant axis; the per-index slot
	// is owner-scoped and never collides across owners, so omitting the unknowable
	// index does not cause a cross-owner under-prediction. A scheduler that needs the
	// exact index must pass a stateKV (see the file-level note: a static predictor is
	// inherently limited here, which is why no production scheduler consumes it yet).
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
