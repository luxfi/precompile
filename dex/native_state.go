// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_state.go holds the DURABLE state of the native C<->D atomic seam: the
// configured D-Chain target id, the C->D intent replay set, and the D->C
// settlement consumed set. All live under the 0x9999 settlement namespace
// (dex.precompile.v1.9999.*) so the money path's state is one auditable region,
// and all are content-addressed by the cross-chain object id so a re-executed /
// reorged block replays identically on every validator (consensus-shared,
// durable, reverted atomically with the tx).

// --- D-Chain target id: the peer chain the C->D objects are PUT under and the D->C
// objects are read from. It is NOT configured and NOT persisted — 0x9999 is always-on
// with zero per-net config. The host resolves the D-Chain (dexvm) id at RUNTIME from
// the chain topology (the consensus context's blockchain-alias lookup of "D"), surfaced
// to the precompile via contract.AtomicState.DChainID(). ids.Empty (no dexvm on this
// network) closes the on-ramp; the client refuses to move value rather than guess a peer.

// --- C->D intent replay set: an intent id is submitted at most once. Keyed by the
// intent id (== the object's shared-memory key), value = blockNumber+1 sentinel.
var intentSubmittedPrefix = []byte(settleStateNamespace + "intent")

func intentSubmittedKey(intentID ids.ID) common.Hash {
	return makeStorageKey(intentSubmittedPrefix, intentID[:])
}

func isIntentSubmitted(stateDB stateKV, intentID ids.ID) bool {
	return stateDB.GetState(poolManagerAddr9999, intentSubmittedKey(intentID)) != (common.Hash{})
}

func markIntentSubmitted(stateDB stateKV, intentID ids.ID, blockNumber uint64) {
	var v common.Hash
	uint256.NewInt(blockNumber + 1).WriteToSlice(v[:])
	stateDB.SetState(poolManagerAddr9999, intentSubmittedKey(intentID), v)
}

// --- D->C settlement consumed set: a settlement object is consumed at most once
// (the RED H1 exactly-once property the BLS path also required, now over the
// atomic object id). Keyed by the object id, value = blockNumber+1 sentinel.
var settlementConsumedPrefix = []byte(settleStateNamespace + "settled")

func settlementConsumedKey(outputID ids.ID) common.Hash {
	return makeStorageKey(settlementConsumedPrefix, outputID[:])
}

func isSettlementConsumed(stateDB stateKV, outputID ids.ID) bool {
	return stateDB.GetState(poolManagerAddr9999, settlementConsumedKey(outputID)) != (common.Hash{})
}

func markSettlementConsumed(stateDB stateKV, outputID ids.ID, blockNumber uint64) {
	var v common.Hash
	uint256.NewInt(blockNumber + 1).WriteToSlice(v[:])
	stateDB.SetState(poolManagerAddr9999, settlementConsumedKey(outputID), v)
}

// --- Per-intent SWAP escrow record (the swap-rail analog of the LP RestingOrder).
// ONE record, created at SubmitSwapIntent, drives BOTH the per-taker settlement cap
// (MEDIUM — bound a settlement credit by this taker's OWN remaining locked principal,
// so an over-export for taker X can never draw on other takers' pooled tokenIn) AND
// the deadline reclaim (HIGH — refund the remaining principal to the locker once the
// deadline passes and D has not settled). It is content-addressed by the intent id
// (the C->D object key), consensus-shared, durable, and reverted atomically with the
// tx — exactly like every other 0x9999 native-seam record.
//
// FIELDS (each its own fine-grained slot under the intent id; no global hot write):
//   - owner      : the taker who locked the principal (the C tx caller). The sole
//     account whose settlement may draw against this intent and the sole
//     reclaim payee. Equality-checked against the recorded D->C object's
//     owner so a settlement cannot bind a victim's intent.
//   - assetIn    : the LOCKED (input) asset — the numeraire the remaining principal is
//     measured in and the asset the reclaim refunds.
//   - remaining  : the still-unsettled locked principal (in assetIn units). Starts at
//     the value actually locked; each settlement credit and the reclaim
//     decrement it. A settlement is capped by it; reclaim drains it to 0.
//   - deadline   : the swap deadline (block timestamp). 0 = none. Phase-B settlement is
//     refused after it; reclaim is allowed only after it.
//   - status     : Open (settlable / reclaimable) or Reclaimed (terminal — no further
//     settlement or reclaim).
var (
	swapIntentPrefix          = []byte(settleStateNamespace + "swint") // swapIntent[intentID][suffix]
	swapIntentReclaimedPrefix = []byte(settleStateNamespace + "swrcl") // reclaimed-set: intentID -> blockNumber+1
)

// swapIntentStatus is the per-intent lifecycle: an intent is Open from submission
// until either fully settled/reclaimed. Reclaimed is terminal (one-time, replay-safe).
type swapIntentStatus uint8

const (
	swapIntentNone      swapIntentStatus = 0 // never submitted (no record)
	swapIntentOpen      swapIntentStatus = 1 // submitted; remaining principal settlable/reclaimable
	swapIntentReclaimed swapIntentStatus = 2 // principal reclaimed to the locker (terminal)
)

// swapIntentRecord is the in-memory image of the per-intent escrow record.
type swapIntentRecord struct {
	Owner     common.Address
	AssetIn   [32]byte
	Remaining uint64
	Deadline  uint64
	Status    swapIntentStatus
}

// swap-intent record slot suffixes (one concern per slot, mirroring the LP order).
var (
	swapIntentOwnerSuffix  = []byte("o") // owner (address)
	swapIntentAssetSuffix  = []byte("a") // assetIn (bytes32)
	swapIntentMetaSuffix   = []byte("m") // status(1) | deadline(uint64, big-endian in low 8 bytes)
	swapIntentRemainSuffix = []byte("r") // remaining principal (uint64)
)

func swapIntentSlot(intentID ids.ID, suffix []byte) common.Hash {
	id := make([]byte, 0, 32+len(suffix))
	id = append(id, intentID[:]...)
	id = append(id, suffix...)
	return makeStorageKey(swapIntentPrefix, id)
}

// putSwapIntentRecord persists a swap-intent escrow record across its slots.
func putSwapIntentRecord(stateDB stateKV, intentID ids.ID, r swapIntentRecord) {
	stateDB.SetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentOwnerSuffix),
		common.BytesToHash(r.Owner.Bytes()))
	stateDB.SetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentAssetSuffix),
		common.BytesToHash(r.AssetIn[:]))
	var meta common.Hash
	meta[0] = byte(r.Status)
	putU64(meta[24:32], r.Deadline)
	stateDB.SetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentMetaSuffix), meta)
	var rem common.Hash
	putU64(rem[24:32], r.Remaining)
	stateDB.SetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentRemainSuffix), rem)
}

// loadSwapIntentRecord reads a swap-intent record. Status swapIntentNone means no
// such intent was ever submitted (every slot zero).
func loadSwapIntentRecord(stateDB stateKV, intentID ids.ID) swapIntentRecord {
	meta := stateDB.GetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentMetaSuffix))
	var r swapIntentRecord
	r.Status = swapIntentStatus(meta[0])
	r.Deadline = bytesToU64(meta[24:32])
	if r.Status == swapIntentNone {
		return r
	}
	r.Owner = common.BytesToAddress(stateDB.GetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentOwnerSuffix)).Bytes())
	copy(r.AssetIn[:], stateDB.GetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentAssetSuffix)).Bytes())
	r.Remaining = bytesToU64(stateDB.GetState(poolManagerAddr9999, swapIntentSlot(intentID, swapIntentRemainSuffix)).Bytes())
	return r
}

// --- Reclaim-set: an intent's principal is reclaimed at most once. Keyed by the
// intent id, value = blockNumber+1 sentinel. The record's Status (Reclaimed) is the
// authoritative terminal marker; this set is the explicit one-time replay guard the
// reclaim path checks (mirroring the settlement-consumed set), so a re-submitted /
// reorged reclaim tx is a guaranteed no-op rather than a second refund.
func swapIntentReclaimedKey(intentID ids.ID) common.Hash {
	return makeStorageKey(swapIntentReclaimedPrefix, intentID[:])
}

func isSwapIntentReclaimed(stateDB stateKV, intentID ids.ID) bool {
	return stateDB.GetState(poolManagerAddr9999, swapIntentReclaimedKey(intentID)) != (common.Hash{})
}

func markSwapIntentReclaimed(stateDB stateKV, intentID ids.ID, blockNumber uint64) {
	var v common.Hash
	uint256.NewInt(blockNumber + 1).WriteToSlice(v[:])
	stateDB.SetState(poolManagerAddr9999, swapIntentReclaimedKey(intentID), v)
}

// --- Seam reserve: the seam's OWN per-asset pot inside the 0x9999 vault, tracked
// SEPARATELY from the depositor pot (settleVault) and the maker-locked pot
// (makerLockedVault). This is the FIX-3 conservation decomplection: the seam (Phase-A
// lock + Phase-B credit) and custody (deposit/withdraw) both move value through the
// SAME 0x9999 vault ACCOUNT, but their CLAIMS on it are distinct values and must not
// raid each other. So:
//
//	seamReserve[a]      = operator seed of a  +  Σ Phase-A tokenIn locks of a
//	                                            −  Σ Phase-B tokenOut credits of a
//	settleVault[a]      = Σ depositorClaim[*][a]              (the depositor pot)
//	makerLockedVault[a] = Σ makers' locked reserve of a       (the maker pot)
//
// THE VAULT-ACCOUNT INVARIANT (per asset a):
//
//	GetBalance(0x9999)/ERC20 holding of a == settleVault[a] + makerLockedVault[a] + seamReserve[a]
//
// A Phase-B settlement credit draws ONLY on seamReserve[a] (creditSettlementOutput),
// so it can NEVER pay a taker out of a depositor's claim or a maker's locked reserve.
// A withdraw draws ONLY on settleVault[a], so it can NEVER strand a backed settlement.
// The pots are orthogonal; the blast radius of one subsystem can't reach another.
var seamReservePrefix = []byte(settleStateNamespace + "seam") // seamReserve[asset] -> seam-owned holdings

func seamReserveKey(assetID [32]byte) common.Hash {
	return makeStorageKey(seamReservePrefix, assetID[:])
}

func loadSeamReserve(stateDB stateKV, assetID [32]byte) *big.Int {
	return new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, seamReserveKey(assetID)).Bytes())
}

func storeSeamReserve(stateDB stateKV, assetID [32]byte, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr9999, seamReserveKey(assetID), w)
}

// --- Committed-positions reserve: the LP RAIL's OWN per-asset pot inside the 0x9999
// vault, tracked SEPARATELY from the depositor pot (settleVault), the legacy maker
// C-side pot (makerLockedVault), and the swap-rail pot (seamReserve). This is the
// fourth orthogonal claim on the SAME 0x9999 vault account — the FIX-3 decomplection
// extended to the LP rail. It tracks the C-side BACKING of value COMMITTED to live D
// positions (the DCommitted state):
//
//	committedPositions[a] = operator seed of a (fee backing)
//	                       + Σ LP principal commits of a (C->D DL01 commits)
//	                       − Σ collect/decrease/burn credits of a (D->C imports)
//
// THE VAULT-ACCOUNT INVARIANT becomes (per asset a):
//
//	realHolding(0x9999, a) == settleVault[a] + makerLockedVault[a]
//	                          + seamReserve[a] + committedPositions[a]
//
// An LP commit moves value from the caller's CSpendable EVM balance INTO
// committedPositions (DCommitted): the unit is no longer spendable on C and a C->D
// commit object backs a funded D position. A collect/decrease/burn draws ONLY on
// committedPositions (creditPositionCollect), so it can NEVER pay an LP out of a
// depositor's claim, a maker's legacy lock, or the swap rail's seam reserve — and a
// swap settlement (which draws ONLY seamReserve) can never raid an LP's committed
// principal. The pots are orthogonal; the blast radius of one rail can't reach
// another. The NEVER-BOTH invariant (a unit is CSpendable XOR DCommitted) is the
// commit debit + the committedPositions credit being a single balanced move.
var committedPositionsPrefix = []byte(settleStateNamespace + "cpos") // committedPositions[asset]

func committedPositionsKey(assetID [32]byte) common.Hash {
	return makeStorageKey(committedPositionsPrefix, assetID[:])
}

func loadCommittedPositions(stateDB stateKV, assetID [32]byte) *big.Int {
	return new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, committedPositionsKey(assetID)).Bytes())
}

func storeCommittedPositions(stateDB stateKV, assetID [32]byte, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr9999, committedPositionsKey(assetID), w)
}
