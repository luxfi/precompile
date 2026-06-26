// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
)

// Event topic0 hashes, derived from the canonical signature strings (the single
// source of truth, mirroring dex/events.go).
var (
	lockedEventSig   = common.BytesToHash(crypto.Keccak256([]byte("Locked(bytes32,bytes32,address,address,address,uint256,uint64)")))
	claimedEventSig  = common.BytesToHash(crypto.Keccak256([]byte("Claimed(bytes32,bytes32,bytes32,address,uint256)")))
	refundedEventSig = common.BytesToHash(crypto.Keccak256([]byte("Refunded(bytes32,address,uint256)")))
)

type logSink interface{ AddLog(*ethtypes.Log) }

// emitLocked: Locked(bytes32 indexed swapId, bytes32 indexed hashlock, address
// recipient, address refund, address asset, uint256 amount, uint64 timeout).
func emitLocked(db logSink, swapId, hashlock common.Hash, recipient, refund, asset common.Address, amount *big.Int, timeout uint64) {
	data := make([]byte, 0, 5*32)
	data = append(data, addressWord(recipient)...)
	data = append(data, addressWord(refund)...)
	data = append(data, addressWord(asset)...)
	data = append(data, common.BigToHash(amount).Bytes()...)
	data = append(data, uint64Word(timeout)...)
	db.AddLog(&ethtypes.Log{
		Address: swapAddr,
		Topics:  []common.Hash{lockedEventSig, swapId, hashlock},
		Data:    data,
	})
}

// emitClaimed: Claimed(bytes32 indexed swapId, bytes32 indexed hashlock, bytes32
// preimage, address recipient, uint256 amount). This is the on-chain secret relay:
// the counterparty's watchtower subscribes by hashlock and reads preimage.
func emitClaimed(db logSink, swapId, hashlock common.Hash, preimage [preimageLen]byte, recipient common.Address, amount *big.Int) {
	data := make([]byte, 0, 3*32)
	data = append(data, preimage[:]...)
	data = append(data, addressWord(recipient)...)
	data = append(data, common.BigToHash(amount).Bytes()...)
	db.AddLog(&ethtypes.Log{
		Address: swapAddr,
		Topics:  []common.Hash{claimedEventSig, swapId, hashlock},
		Data:    data,
	})
}

// emitRefunded: Refunded(bytes32 indexed swapId, address refund, uint256 amount).
func emitRefunded(db logSink, swapId common.Hash, refund common.Address, amount *big.Int) {
	data := make([]byte, 0, 2*32)
	data = append(data, addressWord(refund)...)
	data = append(data, common.BigToHash(amount).Bytes()...)
	db.AddLog(&ethtypes.Log{
		Address: swapAddr,
		Topics:  []common.Hash{refundedEventSig, swapId},
		Data:    data,
	})
}
