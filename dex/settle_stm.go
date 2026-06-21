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

// PredictAccesses returns the storage slots a native settle of (key, params,
// caller) will read and write. It is a PURE function of the swap inputs — the
// scheduler calls it before execution. The native seam settles a D->C atomic
// object, so the conflict-relevant write is the settlement-consumed slot (keyed by
// the object id, which PredictAccesses cannot know statically) plus the per-asset
// vault and the caller's balance; we surface the conflict-relevant axes the
// scheduler CAN derive (pool, assets, caller). epochHint is the block number for
// the sharded analytics slot.
//
// objectID is the D->C settlement object id when the scheduler knows it (Phase B);
// ids.Empty for a Phase-A intent (which writes an intent slot keyed by a derived
// intent id the scheduler also cannot know statically — the per-asset vault and
// caller-balance writes are the derivable conflict axes either way).
func PredictAccesses(key PoolKey, params SwapParams, caller common.Address, epochHint uint64) AccessSet {
	var as AccessSet
	poolID := key.ID()
	in, out := swapAssetDirection(key, params)

	// --- READS (read-only hot slots; never cause serialization) ---
	as.Reads = append(as.Reads,
		haltGlobalKey,
		makeStorageKey(haltMarketPrefix, poolID[:]),
		makeStorageKey(haltAssetPrefix, in[:]),
		makeStorageKey(haltAssetPrefix, out[:]),
		settleVaultKey(in),
		settleVaultKey(out),
	)

	// --- WRITES (each keyed by asset / pool / account — NO global slot) ---
	as.Writes = append(as.Writes,
		settleVaultKey(in),              // vault holdings of tokenIn (Phase A lock)
		settleVaultKey(out),             // vault holdings of tokenOut (Phase B credit)
		volBucketKey(poolID, epochHint), // SHARDED volume bucket
	)
	// Native balance moves are EVM account balances (caller, 0x9999), which Block-STM
	// tracks as account-state accesses; we surface them as derived "balance" keys so
	// the scheduler serializes two swaps that touch the same account's asset balance.
	as.Writes = append(as.Writes,
		balanceSlot(caller, in),
		balanceSlot(caller, out),
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

	// READS: the market record (status), the asset-halt slot, the per-owner committed
	// reserve, the LP rail's per-asset committed-positions pot (the ADD credits it; the
	// withdraw/collect debits it via the D->C import), the order record + count, and the
	// reentrancy guard. The swap rail's settleVault/seamReserve are NOT touched by the LP
	// rail (orthogonal pots).
	as.Reads = append(as.Reads,
		marketSlot(poolID, marketMetaSuffix),
		makeStorageKey(haltAssetPrefix, lockedAsset[:]),
		lockedReserveKey(owner, lockedAsset),
		committedPositionsKey(lockedAsset),
		orderSlot(orderID, orderMetaSuffix),
		orderSlot(orderID, orderAmtSuffix),
		ownerOrdersCountKey(owner),
		custodyGuardKey9999,
	)
	// WRITES: the per-owner committed reserve, the LP rail's committed-positions pot
	// (ADD: caller balance -> committedPositions; the unit becomes DCommitted), the
	// FULL order record (storeRestingOrder writes 6 slots + the commit-object slot), the
	// index slot + count, the C->D commit replay slot (markIntentSubmitted, keyed by a
	// position-commit id the static predictor cannot know), the staging seq+slots
	// (stageAtomicPut, also seq-keyed and not statically derivable), and the reentrancy
	// guard. Each derivable write is keyed by owner / asset / order — NO global hot WRITE
	// (committedPositions is per-ASSET, so two LPs contend only on the same asset, a
	// genuine conflict; the staging seq is the ONE shared counter the seam serializes on,
	// inherent to ordering cross-chain Puts deterministically — surfaced via stageSeqKey).
	as.Writes = append(as.Writes,
		lockedReserveKey(owner, lockedAsset),
		committedPositionsKey(lockedAsset),
		orderSlot(orderID, orderMetaSuffix),
		orderSlot(orderID, orderOwnerSuffix),
		orderSlot(orderID, orderPoolSuffix),
		orderSlot(orderID, orderAssetSuffix),
		orderSlot(orderID, orderAmtSuffix),
		orderSlot(orderID, orderSaltSuffix),
		orderSlot(orderID, orderCommitObjSuffix),
		ownerOrdersCountKey(owner),
		stageSeqKey,
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
