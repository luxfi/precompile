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

// native_events.go emits the ROUTING events for the native C<->D atomic seam. The
// atomic shared-memory object alone moves value; these events only tell the keeper
// (a relayer with NO custody authority) how to route an intent into a D order, or
// that a cancel/collect was requested. A keeper that drops every event cannot lose
// or steal value — the value is already locked in shared memory; the worst case is
// a settlement that no one builds, which the user reclaims via the cancel path.
//
// Events are emitted from the 0x9999 settlement address so an indexer keyed to the
// money path sees the full intent->settlement lifecycle in one place.

var (
	// IntentSubmitted(bytes32 intentID, bytes32 dChainID, address account, bytes32 assetIn, uint256 amountIn, bytes32 marketID, uint256 minAmountOut, address recipient, uint64 deadline, uint8 kind)
	nativeIntentEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"IntentSubmitted(bytes32,bytes32,address,bytes32,uint256,bytes32,uint256,address,uint64,uint8)")))
	// CancelSubmitted(bytes32 orderID, bytes32 marketID, address owner)
	nativeCancelEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"CancelSubmitted(bytes32,bytes32,address)")))
	// CollectSubmitted(bytes32 positionID, bytes32 marketID, address owner)
	nativeCollectEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"CollectSubmitted(bytes32,bytes32,address)")))
)

// nativeIntentKind distinguishes a taker swap intent from an LP position-open
// intent so the keeper builds the right D order. Carried in the event (non-value).
type nativeIntentKind uint8

const (
	intentKindSwap     nativeIntentKind = 0
	intentKindPosition nativeIntentKind = 1
)

// emitNativeIntentEvent logs a C->D intent's routing metadata for the keeper. The
// intentID is the indexed topic so a keeper subscribes per-intent; the rest is the
// order the keeper submits to D against the locked collateral.
func emitNativeIntentEvent(stateDB StateDB, intentID, dChainID ids.ID, req IntentRequest, locked uint64) {
	data := make([]byte, 0, 7*32)
	data = append(data, abiEncodeAddress(req.Account)...)
	data = append(data, abiEncodeBytes32(req.AssetIn)...)
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(locked))...)
	data = append(data, abiEncodeBytes32(req.MarketID)...)
	min := req.MinAmountOut
	if min == nil {
		min = big.NewInt(0)
	}
	data = append(data, abiEncodeBigInt(min)...)
	data = append(data, abiEncodeAddress(req.Recipient)...)
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(req.Deadline))...)
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(uint64(intentKindSwap)))...)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			nativeIntentEventSig,
			common.BytesToHash(intentID[:]),
			common.BytesToHash(dChainID[:]),
		},
		Data: data,
	})
}

// emitNativeCancelEvent logs a cancel request for the keeper to forward to D.
func emitNativeCancelEvent(stateDB StateDB, orderID ids.ID, marketID [32]byte, owner common.Address) {
	data := abiEncodeAddress(owner)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			nativeCancelEventSig,
			common.BytesToHash(orderID[:]),
			common.BytesToHash(marketID[:]),
		},
		Data: data,
	})
}

// emitNativeCollectEvent logs a collect request for the keeper to forward to D.
func emitNativeCollectEvent(stateDB StateDB, positionID ids.ID, marketID [32]byte, owner common.Address) {
	data := abiEncodeAddress(owner)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			nativeCollectEventSig,
			common.BytesToHash(positionID[:]),
			common.BytesToHash(marketID[:]),
		},
		Data: data,
	})
}
