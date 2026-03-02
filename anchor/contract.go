// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package anchor implements on-chain checkpoint anchoring for CRDT state.
// Address: 0x0700 (Privacy/Encryption page, C-Chain slot, item 0x00)
//
// Applications compute a Merkle root of their CRDT state and submit it
// as an anchor: (appID, height, root). The chain stores the root and
// enforces height monotonicity per appID. Users verify by querying the
// chain and comparing against their local Merkle root.
//
// Operations:
//   - Submit: Store a new anchor (write, 25400 gas)
//   - Get: Retrieve anchor root at a specific height (read, 2600 gas)
//   - GetLatest: Retrieve the latest anchored height (read, 2600 gas)
//   - List: Retrieve anchors in a height range (read, 2600 + 200/entry gas)
package anchor

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress: Privacy/Encryption range (0x0700-0x07FF), offset 0x10
	// to leave the low 4 slots for FHE (0x0700..00-03). Data-anchoring
	// has its own canonical slot here.
	ContractAddress = common.HexToAddress("0x0700000000000000000000000000000000000010")

	// Singleton
	AnchorPrecompile = &anchorPrecompile{}

	_ contract.StatefulPrecompiledContract = &anchorPrecompile{}

	ErrInvalidInput       = errors.New("anchor: invalid input")
	ErrInvalidSelector    = errors.New("anchor: unknown function selector")
	ErrHeightNotMonotonic = errors.New("anchor: height must exceed latest")
	ErrAnchorNotFound     = errors.New("anchor: not found")
	ErrReadOnlySubmit     = errors.New("anchor: submit not allowed in read-only mode")
	ErrInputTooShort      = errors.New("anchor: input too short")
	ErrRangeTooLarge      = errors.New("anchor: range exceeds 256 entries")
)

// Function selectors (first 4 bytes of keccak256 of signature).
// submit(bytes32,uint64,bytes32)
// get(bytes32,uint64)
// getLatest(bytes32)
// list(bytes32,uint64,uint64)
var (
	selectorSubmit    = crypto.Keccak256([]byte("submit(bytes32,uint64,bytes32)"))[:4]
	selectorGet       = crypto.Keccak256([]byte("get(bytes32,uint64)"))[:4]
	selectorGetLatest = crypto.Keccak256([]byte("getLatest(bytes32)"))[:4]
	selectorList      = crypto.Keccak256([]byte("list(bytes32,uint64,uint64)"))[:4]
)

// Gas costs
const (
	GasSubmit      = 25_400 // 2 x SSTORE_NEW + keccak + base
	GasGet         = 2_600  // 1 x SLOAD (warm)
	GasGetLatest   = 2_600  // 1 x SLOAD (warm)
	GasListBase    = 2_600  // base for list
	GasListPerItem = 200    // per SLOAD in range
	MaxListRange   = 256    // cap range queries
)

// latestSentinel is appended to appID to derive the latest-height slot.
// 32 bytes of 0xFF avoids collision with any valid uint64 height.
var latestSentinel = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

type anchorPrecompile struct{}

func (p *anchorPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < 4 {
		return nil, suppliedGas, ErrInvalidInput
	}

	sel := input[:4]
	data := input[4:]

	switch {
	case matchSelector(sel, selectorSubmit):
		return p.submit(accessibleState, caller, data, suppliedGas, readOnly)
	case matchSelector(sel, selectorGet):
		return p.get(accessibleState, data, suppliedGas)
	case matchSelector(sel, selectorGetLatest):
		return p.getLatest(accessibleState, data, suppliedGas)
	case matchSelector(sel, selectorList):
		return p.list(accessibleState, data, suppliedGas)
	default:
		return nil, suppliedGas, ErrInvalidSelector
	}
}

// submit stores anchor(appID, height, root).
// Input: 32 bytes appID + 32 bytes height (uint64 right-aligned) + 32 bytes root = 96 bytes ABI-encoded.
func (p *anchorPrecompile) submit(
	state contract.AccessibleState,
	caller common.Address,
	data []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrReadOnlySubmit
	}
	if suppliedGas < GasSubmit {
		return nil, 0, contract.ErrOutOfGas
	}
	// ABI-encoded: 3 x 32-byte words
	if len(data) < 96 {
		return nil, suppliedGas - GasSubmit, ErrInputTooShort
	}

	var appID common.Hash
	copy(appID[:], data[0:32])

	height := binary.BigEndian.Uint64(data[56:64]) // uint64 in last 8 bytes of 32-byte word

	var root common.Hash
	copy(root[:], data[64:96])

	db := state.GetStateDB()

	// Enforce monotonicity: height must exceed current latest.
	latestSlot := latestKey(appID)
	latestVal := db.GetState(ContractAddress, latestSlot)
	latestHeight := decodeHeight(latestVal)
	if height <= latestHeight && latestVal != (common.Hash{}) {
		return nil, suppliedGas - GasSubmit, ErrHeightNotMonotonic
	}

	// Store root at keccak256(appID || height).
	rootSlot := rootKey(appID, height)
	db.SetState(ContractAddress, rootSlot, root)

	// Update latest height.
	db.SetState(ContractAddress, latestSlot, encodeHeight(height))

	remaining := suppliedGas - GasSubmit
	return encodeHeight(height).Bytes(), remaining, nil
}

// get returns the root at (appID, height).
// Input: 32 bytes appID + 32 bytes height = 64 bytes ABI-encoded.
func (p *anchorPrecompile) get(
	state contract.AccessibleState,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasGet {
		return nil, 0, contract.ErrOutOfGas
	}
	if len(data) < 64 {
		return nil, suppliedGas - GasGet, ErrInputTooShort
	}

	var appID common.Hash
	copy(appID[:], data[0:32])
	height := binary.BigEndian.Uint64(data[56:64])

	db := state.GetStateDB()
	rootSlot := rootKey(appID, height)
	root := db.GetState(ContractAddress, rootSlot)

	if root == (common.Hash{}) {
		return nil, suppliedGas - GasGet, ErrAnchorNotFound
	}

	return root.Bytes(), suppliedGas - GasGet, nil
}

// getLatest returns the latest anchored height for appID.
// Input: 32 bytes appID.
func (p *anchorPrecompile) getLatest(
	state contract.AccessibleState,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasGetLatest {
		return nil, 0, contract.ErrOutOfGas
	}
	if len(data) < 32 {
		return nil, suppliedGas - GasGetLatest, ErrInputTooShort
	}

	var appID common.Hash
	copy(appID[:], data[0:32])

	db := state.GetStateDB()
	latestSlot := latestKey(appID)
	val := db.GetState(ContractAddress, latestSlot)

	// Return 32-byte ABI-encoded uint64
	return val.Bytes(), suppliedGas - GasGetLatest, nil
}

// list returns roots for heights [from, to).
// Input: 32 bytes appID + 32 bytes from + 32 bytes to = 96 bytes ABI-encoded.
func (p *anchorPrecompile) list(
	state contract.AccessibleState,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasListBase {
		return nil, 0, contract.ErrOutOfGas
	}
	if len(data) < 96 {
		return nil, suppliedGas - GasListBase, ErrInputTooShort
	}

	var appID common.Hash
	copy(appID[:], data[0:32])
	from := binary.BigEndian.Uint64(data[56:64])
	to := binary.BigEndian.Uint64(data[88:96])

	if to <= from {
		return nil, suppliedGas - GasListBase, ErrInputTooShort
	}
	count := to - from
	if count > MaxListRange {
		return nil, suppliedGas - GasListBase, ErrRangeTooLarge
	}

	totalGas := GasListBase + uint64(count)*GasListPerItem
	if suppliedGas < totalGas {
		return nil, 0, contract.ErrOutOfGas
	}

	db := state.GetStateDB()

	// ABI-encode: offset(32) + length(32) + count*32 bytes
	result := make([]byte, 64+count*32)
	// offset to array data
	binary.BigEndian.PutUint64(result[24:32], 64)
	// array length
	binary.BigEndian.PutUint64(result[56:64], count)

	for i := uint64(0); i < count; i++ {
		h := from + i
		rootSlot := rootKey(appID, h)
		root := db.GetState(ContractAddress, rootSlot)
		copy(result[64+i*32:64+(i+1)*32], root.Bytes())
	}

	return result, suppliedGas - totalGas, nil
}

// rootKey returns keccak256(appID || height) as the storage slot for a root.
func rootKey(appID common.Hash, height uint64) common.Hash {
	buf := make([]byte, 40) // 32 + 8
	copy(buf[:32], appID[:])
	binary.BigEndian.PutUint64(buf[32:40], height)
	h := crypto.Keccak256(buf)
	return common.BytesToHash(h)
}

// latestKey returns keccak256(appID || sentinel) as the storage slot for latest height.
func latestKey(appID common.Hash) common.Hash {
	buf := make([]byte, 64) // 32 + 32
	copy(buf[:32], appID[:])
	copy(buf[32:64], latestSentinel[:])
	h := crypto.Keccak256(buf)
	return common.BytesToHash(h)
}

// encodeHeight packs a uint64 into a 32-byte hash (right-aligned).
func encodeHeight(h uint64) common.Hash {
	var out common.Hash
	binary.BigEndian.PutUint64(out[24:32], h)
	return out
}

// decodeHeight unpacks a uint64 from a 32-byte hash (right-aligned).
func decodeHeight(h common.Hash) uint64 {
	return binary.BigEndian.Uint64(h[24:32])
}

func matchSelector(a, b []byte) bool {
	return len(a) >= 4 && len(b) >= 4 &&
		a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}
