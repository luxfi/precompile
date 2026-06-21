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

// --- D-Chain target id: the peer chain the C->D objects are PUT under and the
// D->C objects are read from. Written at Configure (durable, consensus-shared),
// the same discipline as the (networkID, cChainID) chain identity.
var cfgDChainIDKey = makeStorageKey([]byte(settleStateNamespace+"cfg.did"), []byte{})

// SetSettleDChainTarget records the D-Chain (dexvm) id the native seam routes
// atomic objects to/from. A zero id means atomic settlement is not wired (the
// on-ramp is closed); the client refuses to move value rather than guess a peer.
func SetSettleDChainTarget(stateDB stateKV, dChainID [32]byte) {
	var c common.Hash
	copy(c[:], dChainID[:])
	stateDB.SetState(poolManagerAddr9999, cfgDChainIDKey, c)
}

// loadDChainTarget reads the configured D-Chain id (ids.Empty when unset).
func loadDChainTarget(stateDB stateKV) ids.ID {
	c := stateDB.GetState(poolManagerAddr9999, cfgDChainIDKey)
	return ids.ID(c)
}

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
