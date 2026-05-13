// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"encoding/binary"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/precompile/contract"
)

// Storage layout for the on-chain chain registry, namespaced under a fixed
// slot prefix so it never collides with the bridge gateway's other state.
//
// Slot derivation (all keccak256-free, deterministic, gas-cheap):
//
//	slotCount   = registryBase || u64(0)              -> uint256 count of chains
//	slotRow(i)  = registryBase || u64(1 + i*3 + k)    -> word k of row i (k in 0..2)
//
// Row layout (3 32-byte words per chain):
//
//	word 0: packed header
//	  bytes  0.. 3: ChainID    (big-endian uint32)
//	  byte         4: EVM flag (0x01 = native EVM, 0x00 = virtual)
//	  bytes  5..24: GatewayAt  (20-byte address)
//	  bytes 25..31: reserved (zero)
//	word 1: name (right-padded utf-8, up to 32 bytes — names longer than 32
//	         bytes are rejected at seed time, see SeedRegistry)
//	word 2: reserved for future expansion (e.g. message-protocol id)
//
// The slot scheme is exposed so a future BridgeRegistrar precompile can add
// rows by writing the next free index.
var registryBase = [24]byte{
	// fixed ASCII prefix "lux.bridge.registry" left-padded with zero bytes
	0x00, 0x00, 0x00, 0x00, 0x00,
	'l', 'u', 'x', '.', 'b', 'r', 'i', 'd', 'g', 'e', '.',
	'r', 'e', 'g', 'i', 's', 't', 'r', 'y',
}

// registrySlot composes the 24-byte registryBase with an 8-byte offset.
func registrySlot(offset uint64) common.Hash {
	var h common.Hash
	copy(h[:24], registryBase[:])
	binary.BigEndian.PutUint64(h[24:], offset)
	return h
}

// slotCount is the storage key holding the registered-chain count.
func slotCount() common.Hash {
	return registrySlot(0)
}

// slotRow returns the three storage keys backing row i.
func slotRow(i uint64) (header, name, reserved common.Hash) {
	header = registrySlot(1 + i*3 + 0)
	name = registrySlot(1 + i*3 + 1)
	reserved = registrySlot(1 + i*3 + 2)
	return
}

// packRow encodes a Chain into the on-disk header + name words.
func packRow(c Chain) (header, name common.Hash) {
	binary.BigEndian.PutUint32(header[0:4], uint32(c.ID))
	if c.EVM {
		header[4] = 0x01
	}
	copy(header[5:25], c.GatewayAt.Bytes())
	// name is right-padded with zero bytes; truncated names are validated at
	// seed time so we never silently lose data.
	copy(name[:], []byte(c.Name))
	return
}

// unpackRow decodes the on-disk header + name words back into a Chain.
func unpackRow(header, name common.Hash) Chain {
	return Chain{
		ID:        ChainID(binary.BigEndian.Uint32(header[0:4])),
		EVM:       header[4] == 0x01,
		GatewayAt: common.BytesToAddress(header[5:25]),
		Name:      trimRightZero(name[:]),
	}
}

func trimRightZero(b []byte) string {
	n := len(b)
	for n > 0 && b[n-1] == 0 {
		n--
	}
	return string(b[:n])
}

// stateRegistry reads (and via SeedRegistry, writes) registry rows from the
// EVM storage of the bridge gateway contract.
type stateRegistry struct {
	state contract.StateDB
	addr  common.Address
}

// NewStateRegistry returns a Registry backed by EVM storage at the given
// contract address. Reads are cheap (one SLOAD per word). Reads on an empty
// registry return an empty set — callers should ensure SeedRegistry has been
// invoked at deployment time.
func NewStateRegistry(state contract.StateDB, contractAddr common.Address) Registry {
	return &stateRegistry{state: state, addr: contractAddr}
}

func (r *stateRegistry) count() uint64 {
	h := r.state.GetState(r.addr, slotCount())
	return binary.BigEndian.Uint64(h[24:])
}

func (r *stateRegistry) row(i uint64) Chain {
	hdrKey, nameKey, _ := slotRow(i)
	return unpackRow(
		r.state.GetState(r.addr, hdrKey),
		r.state.GetState(r.addr, nameKey),
	)
}

func (r *stateRegistry) Get(id ChainID) (Chain, bool) {
	n := r.count()
	for i := uint64(0); i < n; i++ {
		c := r.row(i)
		if c.ID == id {
			return c, true
		}
	}
	return Chain{}, false
}

func (r *stateRegistry) All() []Chain {
	n := r.count()
	out := make([]Chain, 0, n)
	for i := uint64(0); i < n; i++ {
		out = append(out, r.row(i))
	}
	return out
}

// SeedRegistry writes chains to EVM storage at addr. Idempotent: if the
// registry already has any rows, this is a no-op. Returns the count written.
//
// The maximum supported name length is 32 bytes; longer names are rejected to
// keep the on-disk layout stable. Callers should normalize names before seed.
func SeedRegistry(state contract.StateDB, addr common.Address, chains []Chain) (int, error) {
	r := &stateRegistry{state: state, addr: addr}
	if r.count() > 0 {
		return 0, nil
	}
	for _, c := range chains {
		if len(c.Name) > 32 {
			return 0, ErrChainNameTooLong
		}
	}
	for i, c := range chains {
		hdr, name := packRow(c)
		hdrKey, nameKey, _ := slotRow(uint64(i))
		state.SetState(addr, hdrKey, hdr)
		state.SetState(addr, nameKey, name)
	}
	var cnt common.Hash
	binary.BigEndian.PutUint64(cnt[24:], uint64(len(chains)))
	state.SetState(addr, slotCount(), cnt)
	return len(chains), nil
}
