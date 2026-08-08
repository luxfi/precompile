// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_state.go holds the DURABLE state of the C<->D funding rail: the C->D
// written-claim set, the D->C consumed-claim set, and custody. All live under the
// 0x9999 settlement namespace
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

// --- C->D written set: a claim id is written at most once. Keyed by the claim id
// (== the object's shared-memory key), value = blockNumber+1 sentinel.
var claimWrittenPrefix = []byte(settleStateNamespace + "written")

func claimWrittenKey(claimID ids.ID) common.Hash {
	return makeStorageKey(claimWrittenPrefix, claimID[:])
}

func isClaimWritten(stateDB stateKV, claimID ids.ID) bool {
	return stateDB.GetState(poolManagerAddr9999, claimWrittenKey(claimID)) != (common.Hash{})
}

func markClaimWritten(stateDB stateKV, claimID ids.ID, blockNumber uint64) {
	var v common.Hash
	uint256.NewInt(blockNumber + 1).WriteToSlice(v[:])
	stateDB.SetState(poolManagerAddr9999, claimWrittenKey(claimID), v)
}

// --- D->C consumed set: a claim is consumed at most once. Keyed by the claim id,
// value = blockNumber+1 sentinel. This is the exactly-once property the whole rail
// rests on: the mark and the credit land together or neither does.
var claimConsumedPrefix = []byte(settleStateNamespace + "consumed")

func claimConsumedKey(claimID ids.ID) common.Hash {
	return makeStorageKey(claimConsumedPrefix, claimID[:])
}

func isClaimConsumed(stateDB stateKV, claimID ids.ID) bool {
	return stateDB.GetState(poolManagerAddr9999, claimConsumedKey(claimID)) != (common.Hash{})
}

func markClaimConsumed(stateDB stateKV, claimID ids.ID, blockNumber uint64) {
	var v common.Hash
	uint256.NewInt(blockNumber + 1).WriteToSlice(v[:])
	stateDB.SetState(poolManagerAddr9999, claimConsumedKey(claimID), v)
}

// --- Custody: the funding rail's per-asset pot inside the 0x9999 vault, tracked
// SEPARATELY from the depositor pot (settleVault) and the maker-locked pot
// (makerLockedVault). The three are distinct CLAIMS on the same vault account and
// must not raid each other:
//
//	custody[a]          = operator seed of a
//	                      + Σ value exported to D (C->D claims written)
//	                      − Σ value imported from D (D->C claims consumed)
//	settleVault[a]      = Σ depositorClaim[*][a]          (the depositor pot)
//	makerLockedVault[a] = Σ makers' locked reserve of a   (the maker pot)
//
// THE VAULT-ACCOUNT INVARIANT (per asset a):
//
//	GetBalance(0x9999)/ERC20 holding of a == settleVault[a] + makerLockedVault[a] + custody[a]
//
// An import draws ONLY on custody[a], so it can never pay out of a depositor's claim
// or a maker's reserve; a withdraw draws ONLY on settleVault[a], so it can never
// strand a backed import.
//
// THERE IS ONE CUSTODY POT, NOT ONE PER PRODUCT. It used to be two — a swap pot and
// an LP pot — and the object carried a lane byte saying which one a claim could
// draw. That byte was the only thing keeping the two apart, and it made the funding
// rail know what the value was FOR. A rail that moves ownership does not: "value C
// holds because D owns it" is one quantity per asset, so it is one number. Splitting
// it created the cross-lane drain the byte then had to defend against.
var custodyPrefix = []byte(settleStateNamespace + "cust") // custody[asset]

func custodyKey(assetID [32]byte) common.Hash {
	return makeStorageKey(custodyPrefix, assetID[:])
}

func loadCustody(stateDB stateKV, assetID [32]byte) *big.Int {
	return new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, custodyKey(assetID)).Bytes())
}

func storeCustody(stateDB stateKV, assetID [32]byte, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr9999, custodyKey(assetID), w)
}
