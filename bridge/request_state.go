// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"encoding/binary"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/precompile/contract"
)

// request_state.go holds every bridge request in StateDB under the gateway
// address, replacing the in-memory map that reorg/restart used to strand. The
// record IS the state: a reorg rolls it back with the block, a restart re-reads
// it deterministically, and a StateDB snapshot/revert un-does a status flip
// atomically with the rest of the settling transaction.
//
// Storage layout (keccak base + integer offset, 5 words per request):
//
//	baseR = keccak("lux.bridge.req" || requestID[32])
//	  baseR + 0  W0: status (byte0) | flags (byte1) |
//	                 srcChain (u32 @4) | destChain (u32 @8) |
//	                 srcNetwork (u32 @12) | destNetwork (u32 @16) | nonce (u64 @20)
//	  baseR + 1  W1: deadline (u64 @0) | createdAt (u64 @8) | completedAt (u64 @16)
//	  baseR + 2  W2: recipient (20 @12)
//	  baseR + 3  W3: token (20 @12; zero => native)
//	  baseR + 4  W4: amount (uint256 BE)
//
// The lifecycle FSM (driven from gateway.go):
//
//	Absent --RecordInbound(quorum)--> Pending
//	Pending --CompleteBridge(quorum, bt<=deadline)--> Completed   (terminal)
//	Pending --RefundExpired(bt>deadline)--> Refunded              (terminal)
//
// Terminal states are terminal: a consumed request can never be re-settled or
// refunded (the status guard in VerifyCompletion/RefundExpired enforces it).
var reqNS = []byte("lux.bridge.req")

// reqBase is the base slot for the request with the given id.
func reqBase(requestID [32]byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(reqNS, requestID[:]))
}

// ReadRequest decodes the request record at requestID. A request whose status
// byte is zero (StatusAbsent) was never recorded and is reported as
// ErrRequestNotFound — a swap with no bridge backing is impossible.
func ReadRequest(state contract.StateDB, gwAddr common.Address, requestID [32]byte) (*BridgeRequest, error) {
	base := reqBase(requestID)
	w0 := state.GetState(gwAddr, base)
	status := BridgeStatus(w0[0])
	if status == StatusAbsent {
		return nil, ErrRequestNotFound
	}
	w1 := state.GetState(gwAddr, addOffset(base, 1))
	w2 := state.GetState(gwAddr, addOffset(base, 2))
	w3 := state.GetState(gwAddr, addOffset(base, 3))
	w4 := state.GetState(gwAddr, addOffset(base, 4))

	return &BridgeRequest{
		ID:            requestID,
		Status:        status,
		SourceChain:   binary.BigEndian.Uint32(w0[4:8]),
		DestChain:     binary.BigEndian.Uint32(w0[8:12]),
		SourceNetwork: binary.BigEndian.Uint32(w0[12:16]),
		DestNetwork:   binary.BigEndian.Uint32(w0[16:20]),
		Nonce:         binary.BigEndian.Uint64(w0[20:28]),
		Deadline:      binary.BigEndian.Uint64(w1[0:8]),
		CreatedAt:     binary.BigEndian.Uint64(w1[8:16]),
		CompletedAt:   binary.BigEndian.Uint64(w1[16:24]),
		Recipient:     common.BytesToAddress(w2[12:32]),
		Token:         common.BytesToAddress(w3[12:32]),
		Amount:        new(big.Int).SetBytes(w4[:]),
	}, nil
}

// writeRequest persists r as a fresh Pending record. Callers (RecordInbound)
// MUST validate r.Amount fits 256 bits before calling — FillBytes would panic on
// an oversized value, which RecordInbound rules out up front.
func writeRequest(state contract.StateDB, gwAddr common.Address, r *BridgeRequest) {
	base := reqBase(r.ID)

	var w0, w1, w2, w3, w4 common.Hash
	w0[0] = byte(StatusPending)
	binary.BigEndian.PutUint32(w0[4:8], r.SourceChain)
	binary.BigEndian.PutUint32(w0[8:12], r.DestChain)
	binary.BigEndian.PutUint32(w0[12:16], r.SourceNetwork)
	binary.BigEndian.PutUint32(w0[16:20], r.DestNetwork)
	binary.BigEndian.PutUint64(w0[20:28], r.Nonce)

	binary.BigEndian.PutUint64(w1[0:8], r.Deadline)
	binary.BigEndian.PutUint64(w1[8:16], r.CreatedAt)
	binary.BigEndian.PutUint64(w1[16:24], r.CompletedAt)

	copy(w2[12:32], r.Recipient.Bytes())
	copy(w3[12:32], r.Token.Bytes())
	r.Amount.FillBytes(w4[:])

	state.SetState(gwAddr, base, w0)
	state.SetState(gwAddr, addOffset(base, 1), w1)
	state.SetState(gwAddr, addOffset(base, 2), w2)
	state.SetState(gwAddr, addOffset(base, 3), w3)
	state.SetState(gwAddr, addOffset(base, 4), w4)
}

// setRequestStatus flips the on-state status byte of an existing record and, when
// completedAt is non-zero, stamps the resolution time. It read-modify-writes only
// the words it changes so the rest of the record is preserved.
func setRequestStatus(state contract.StateDB, gwAddr common.Address, requestID [32]byte, status BridgeStatus, completedAt uint64) {
	base := reqBase(requestID)
	w0 := state.GetState(gwAddr, base)
	w0[0] = byte(status)
	state.SetState(gwAddr, base, w0)

	if completedAt > 0 {
		w1 := state.GetState(gwAddr, addOffset(base, 1))
		binary.BigEndian.PutUint64(w1[16:24], completedAt)
		state.SetState(gwAddr, addOffset(base, 1), w1)
	}
}
