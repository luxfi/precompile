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
// that a cancel/collect/reclaim was requested. A keeper that drops every event cannot
// lose or steal value — the value is already locked in shared memory; the worst case
// is a swap settlement that no one builds, which the LOCKER RECLAIMS DIRECTLY via the
// reclaimIntent selector once the intent's deadline passes (no keeper required — the
// reclaim refunds the locked principal from the seam reserve on the locker's own tx).
//
// Events are emitted from the 0x9999 settlement address so an indexer keyed to the
// money path sees the full intent->settlement/reclaim lifecycle in one place.

var (
	// IntentSubmitted(bytes32 intentID, bytes32 dChainID, address account, bytes32 assetIn, uint256 amountIn, bytes32 marketID, uint256 minAmountOut, address recipient, uint64 deadline, uint8 kind, uint64 priceLimit, uint8 limitIsUpper)
	// priceLimit (CLOB quote-per-base float64 bits) + limitIsUpper let the keeper carry
	// the taker's slippage floor onto the settling relay (the bounded-MEV guard) without
	// re-deriving it from the V4 sqrt limit.
	nativeIntentEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"IntentSubmitted(bytes32,bytes32,address,bytes32,uint256,bytes32,uint256,address,uint64,uint8,uint64,uint8)")))
	// CancelSubmitted(bytes32 orderID, bytes32 marketID, address owner)
	nativeCancelEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"CancelSubmitted(bytes32,bytes32,address)")))
	// CollectSubmitted(bytes32 positionID, bytes32 marketID, address owner)
	nativeCollectEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"CollectSubmitted(bytes32,bytes32,address)")))
	// IntentReclaimed(bytes32 intentID, address owner, bytes32 assetIn, uint256 amount)
	nativeReclaimEventSig = common.BytesToHash(crypto.Keccak256([]byte(
		"IntentReclaimed(bytes32,address,bytes32,uint256)")))
)

// nativeIntentKind distinguishes a taker swap intent from an LP position-open
// intent so the keeper builds the right D order. Carried in the event (non-value).
type nativeIntentKind uint8

const (
	intentKindSwap     nativeIntentKind = 0
	intentKindPosition nativeIntentKind = 1
)

// emitNativeIntentEvent logs a C->D SWAP intent's routing metadata for the keeper.
// The intentID is the indexed topic so a keeper subscribes per-intent; the rest is
// the taker order the keeper submits to D against the locked collateral. Kind is
// fixed intentKindSwap — this is the taker rail; the LP rail uses
// emitNativePositionCommitEvent (kind intentKindPosition).
func emitNativeIntentEvent(stateDB StateDB, intentID, dChainID ids.ID, req IntentRequest, locked uint64) {
	emitNativeRoutingEvent(stateDB, intentID, dChainID, req, locked, intentKindSwap)
}

// emitNativePositionCommitEvent logs a C->D LP POSITION-COMMIT (DL01) routing event
// for the keeper. Identical wire to the swap intent event but kind=intentKindPosition,
// so the keeper OPENS a funded D position (range = the tick window carried in the
// position record) against the committed collateral instead of placing a taker order.
// The atomic commit object alone moves the value; this event only routes it into the
// D position-open. positionID is the C->D object key (the indexed topic).
func emitNativePositionCommitEvent(stateDB StateDB, positionID, dChainID ids.ID, req IntentRequest, locked uint64) {
	emitNativeRoutingEvent(stateDB, positionID, dChainID, req, locked, intentKindPosition)
}

// emitNativeRoutingEvent is the SINGLE DRY emitter for both C->D rails: it logs the
// (account, assetIn, locked, marketID, minAmountOut, recipient, deadline, kind)
// routing metadata under the object id. kind selects the rail (swap vs position) so
// the keeper builds the right D op; the value-bearing identity is in the staged
// atomic object, never here.
func emitNativeRoutingEvent(stateDB StateDB, objectID, dChainID ids.ID, req IntentRequest, locked uint64, kind nativeIntentKind) {
	data := make([]byte, 0, 9*32)
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
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(uint64(kind)))...)
	// Slippage floor for the keeper to carry onto the settling relay (bounded-MEV guard):
	// priceLimit is the CLOB quote-per-base limit as float64 bits, limitIsUpper its side.
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(req.PriceLimit))...)
	var limitFlag uint64
	if limitIsUpper(req.Side) {
		limitFlag = 1
	}
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(limitFlag))...)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			nativeIntentEventSig,
			common.BytesToHash(objectID[:]),
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

// emitNativeReclaimEvent logs a completed intent reclaim: the locker recovered
// `amount` of `assetIn` for the stranded `intentID` (deadline-gated). This is a
// settled value-movement signal (the refund already happened on this tx), not a
// keeper request — an indexer surfaces it as the intent's terminal exit.
func emitNativeReclaimEvent(stateDB StateDB, intentID ids.ID, owner common.Address, assetIn [32]byte, amount uint64) {
	data := make([]byte, 0, 3*32)
	data = append(data, abiEncodeAddress(owner)...)
	data = append(data, abiEncodeBytes32(assetIn)...)
	data = append(data, abiEncodeBigInt(new(big.Int).SetUint64(amount))...)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			nativeReclaimEventSig,
			common.BytesToHash(intentID[:]),
		},
		Data: data,
	})
}
