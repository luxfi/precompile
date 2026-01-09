// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package modules

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/luxfi/geth/common"
)

// AddressRange represents a continuous range of addresses
type AddressRange struct {
	Start common.Address
	End   common.Address
}

// Contains returns true iff [addr] is contained within the (inclusive)
// range of addresses defined by [a].
func (a *AddressRange) Contains(addr common.Address) bool {
	addrBytes := addr.Bytes()
	return bytes.Compare(addrBytes, a.Start[:]) >= 0 && bytes.Compare(addrBytes, a.End[:]) <= 0
}

// BlackholeAddr is the address where assets are burned
var BlackholeAddr = common.Address{
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var (
	// registeredModules is a list of Module to preserve order
	// for deterministic iteration
	registeredModules = make([]Module, 0)

	// Reserved address ranges for stateful precompiles
	//
	// HIGH-BYTE RANGES (legacy format: 0xXX00...0000):
	// 0x0100-0x01FF: Warp/Teleport messaging
	// 0x0200-0x02FF: Chain config (AllowLists, FeeManager, etc.)
	// 0x0300-0x03FF: Reserved (legacy)
	// 0x0400-0x04FF: DEX (Uniswap v4-style)
	// 0x0500-0x05FF: Graph/Query layer
	// 0x0600-0x06FF: Post-quantum crypto
	// 0x0700-0x07FF: Privacy/Encryption
	// 0x0800-0x08FF: Threshold signatures
	// 0x0900-0x09FF: ZK proofs
	// 0x0A00-0x0AFF: Curves (secp256r1, etc.)
	//
	// LOW-BYTE RANGES (EIP-collision-free: 0x0000...XXXX):
	// 0x8000-0x8FFF: Lux Core System (AI Mining at 0x8100)
	// 0x9000-0x9FFF: Lux Crypto Privacy (HPKE, ECIES, FHE)
	// 0xA000-0xAFFF: Lux Hashing & ZK (Poseidon2, Blake3, STARK)
	// 0xB000-0xBFFF: Lux KZG Extensions
	reservedRanges = []AddressRange{
		// Warp/Teleport (0x0100-0x01FF)
		{
			Start: common.HexToAddress("0x0100000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x01000000000000000000000000000000000000ff"),
		},
		// Chain Config (0x0200-0x02FF)
		{
			Start: common.HexToAddress("0x0200000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x02000000000000000000000000000000000000ff"),
		},
		// AI Mining (0x0300-0x03FF)
		{
			Start: common.HexToAddress("0x0300000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x03000000000000000000000000000000000000ff"),
		},
		// DEX - Uniswap v4-style (0x0400-0x04FF)
		{
			Start: common.HexToAddress("0x0400000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x04000000000000000000000000000000000000ff"),
		},
		// Graph/Query Layer (0x0500-0x05FF)
		{
			Start: common.HexToAddress("0x0500000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x05000000000000000000000000000000000000ff"),
		},
		// Post-Quantum Crypto (0x0600-0x06FF)
		{
			Start: common.HexToAddress("0x0600000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x06000000000000000000000000000000000000ff"),
		},
		// Privacy/Encryption (0x0700-0x07FF)
		{
			Start: common.HexToAddress("0x0700000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x07000000000000000000000000000000000000ff"),
		},
		// Threshold Signatures (0x0800-0x08FF)
		{
			Start: common.HexToAddress("0x0800000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x08000000000000000000000000000000000000ff"),
		},
		// ZK Proofs (0x0900-0x09FF)
		{
			Start: common.HexToAddress("0x0900000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x09000000000000000000000000000000000000ff"),
		},
		// Curves - secp256r1, etc. (0x0A00-0x0AFF)
		{
			Start: common.HexToAddress("0x0A00000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x0A000000000000000000000000000000000000ff"),
		},
		// =====================================================================
		// LP-ALIGNED RANGES (Low-byte format: 0x0000...LPNUM)
		// Address = LP number directly, e.g., LP-9010 = 0x...9010
		// See precompile/registry/registry.go for full scheme documentation
		// =====================================================================
		// LP-2xxx: PQ Identity (0x0..2000 - 0x0..2FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000002000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000002fff"),
		},
		// LP-3xxx: EVM/Crypto (0x0..3000 - 0x0..3FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000003000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000003fff"),
		},
		// LP-4xxx: Privacy/ZK (0x0..4000 - 0x0..4FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000004000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000004fff"),
		},
		// LP-5xxx: Threshold/MPC (0x0..5000 - 0x0..5FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000005000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000005fff"),
		},
		// LP-6xxx: Bridges (0x0..6000 - 0x0..6FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000006000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000006fff"),
		},
		// LP-7xxx: AI (0x0..7000 - 0x0..7FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000007000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000007fff"),
		},
		// LP-9xxx: DEX/Markets (0x0..9000 - 0x0..9FFF)
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000009000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000009fff"),
		},
		// =====================================================================
		// LOW-BYTE RANGES (EIP-collision-free addresses)
		// =====================================================================
		// Lux Core System (0x8000-0x8FFF) - AI Mining, etc.
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000008000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000008fff"),
		},
		// Lux Crypto Privacy (0x9000-0x9FFF) - HPKE, ECIES, FHE
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000009000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000009fff"),
		},
		// Lux Hashing & ZK (0xA000-0xAFFF) - Poseidon2, Blake3, STARK, etc.
		{
			Start: common.HexToAddress("0x000000000000000000000000000000000000a000"),
			End:   common.HexToAddress("0x000000000000000000000000000000000000afff"),
		},
		// Lux KZG Extensions (0xB000-0xBFFF)
		{
			Start: common.HexToAddress("0x000000000000000000000000000000000000b000"),
			End:   common.HexToAddress("0x000000000000000000000000000000000000bfff"),
		},
		// Dead/Burn Addresses (LP-0150)
		// 0x0000...0000 - Zero address
		{
			Start: common.HexToAddress("0x0000000000000000000000000000000000000000"),
			End:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		},
		// 0x0000...dEaD - Common dead address
		{
			Start: common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
			End:   common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		},
		// 0xdEaD...0000 - Full dead address prefix
		{
			Start: common.HexToAddress("0xdEaD000000000000000000000000000000000000"),
			End:   common.HexToAddress("0xdEaD000000000000000000000000000000000000"),
		},
	}
)

// ReservedAddress returns true if [addr] is in a reserved range for custom precompiles
func ReservedAddress(addr common.Address) bool {
	for _, reservedRange := range reservedRanges {
		if reservedRange.Contains(addr) {
			return true
		}
	}

	return false
}

// RegisterModule registers a stateful precompile module
func RegisterModule(stm Module) error {
	address := stm.Address
	key := stm.ConfigKey

	if address == BlackholeAddr {
		return fmt.Errorf("address %s overlaps with blackhole address", address)
	}
	if !ReservedAddress(address) {
		return fmt.Errorf("address %s not in a reserved range", address)
	}

	for _, registeredModule := range registeredModules {
		if registeredModule.ConfigKey == key {
			return fmt.Errorf("name %s already used by a stateful precompile", key)
		}
		if registeredModule.Address == address {
			return fmt.Errorf("address %s already used by a stateful precompile", address)
		}
	}
	// sort by address to ensure deterministic iteration
	registeredModules = insertSortedByAddress(registeredModules, stm)
	return nil
}

func GetPrecompileModuleByAddress(address common.Address) (Module, bool) {
	for _, stm := range registeredModules {
		if stm.Address == address {
			return stm, true
		}
	}
	return Module{}, false
}

func GetPrecompileModule(key string) (Module, bool) {
	for _, stm := range registeredModules {
		if stm.ConfigKey == key {
			return stm, true
		}
	}
	return Module{}, false
}

func RegisteredModules() []Module {
	return registeredModules
}

func insertSortedByAddress(data []Module, stm Module) []Module {
	data = append(data, stm)
	sort.Sort(moduleArray(data))
	return data
}
