// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
)

// native_events.go emits the funding rail's C-side signal. The claim in shared
// memory is what moves value; this log only tells an indexer — and whoever delivers
// the claim — that a crossing happened and under which id.
//
// It carries no routing instruction, because there is nothing to route: the claim
// names its own beneficiary, so delivering it can only credit that account. Anyone
// who drops this event loses visibility, never value.

// ClaimExported(bytes32 claimID, bytes32 dChainID, address owner, address beneficiary,
// bytes32 asset, uint256 amount). The name is the deployed ABI and hashes to topic0.
var claimExportedSig = common.BytesToHash(crypto.Keccak256([]byte(
	"ClaimExported(bytes32,bytes32,address,address,bytes32,uint256)")))

// emitExportEvent logs a C->D crossing under its claim id (the indexed topic), from
// the 0x9999 money path so an indexer sees custody in and custody out in one place.
func emitExportEvent(stateDB StateDB, claimID, dChainID ids.ID, owner, beneficiary common.Address, asset [32]byte, amount uint64) {
	data := make([]byte, 0, 4*32)
	data = append(data, abiEncodeAddress(owner)...)
	data = append(data, abiEncodeAddress(beneficiary)...)
	data = append(data, abiEncodeBytes32(asset)...)
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(amount))...)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			claimExportedSig,
			common.BytesToHash(claimID[:]),
			common.BytesToHash(dChainID[:]),
		},
		Data: data,
	})
}

// --- position lifecycle notifications ---------------------------------------------
//
// A position lives on D; these two logs announce a C-side record transition so an
// indexer (and whoever drives the D-side position) sees it. They carry no value and
// authorize nothing — the value for a withdraw arrives as an ordinary claim on the
// funding rail, like every other crossing.

// PositionClosing(bytes32 positionID, bytes32 marketID, address owner)
var positionClosingSig = common.BytesToHash(crypto.Keccak256([]byte(
	"CancelSubmitted(bytes32,bytes32,address)")))

// PositionCollecting(bytes32 positionID, bytes32 marketID, address owner)
var positionCollectingSig = common.BytesToHash(crypto.Keccak256([]byte(
	"CollectSubmitted(bytes32,bytes32,address)")))

func emitPositionClosing(stateDB StateDB, positionID ids.ID, marketID [32]byte, owner common.Address) {
	emitPositionEvent(stateDB, positionClosingSig, positionID, marketID, owner)
}

func emitPositionCollecting(stateDB StateDB, positionID ids.ID, marketID [32]byte, owner common.Address) {
	emitPositionEvent(stateDB, positionCollectingSig, positionID, marketID, owner)
}

func emitPositionEvent(stateDB StateDB, sig common.Hash, positionID ids.ID, marketID [32]byte, owner common.Address) {
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			sig,
			common.BytesToHash(positionID[:]),
			common.BytesToHash(marketID[:]),
		},
		Data: abiEncodeAddress(owner),
	})
}
