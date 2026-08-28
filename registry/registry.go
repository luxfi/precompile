// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package registry links every precompile into the binary and answers questions
// about the resulting set.
//
// Importing this package — even blank — runs each precompile's init(), which is
// where it claims its address through modules.RegisterModule. A host that wants
// the whole Lux precompile surface imports registry and nothing else:
//
//	import _ "github.com/luxfi/precompile/registry"
//
// There is exactly one record of where a precompile lives: the address it
// registers at init time. This package derives its answers from
// modules.RegisteredModules() rather than keeping a parallel table, so a
// question asked here and an address dispatched by the EVM cannot disagree.
//
// # Address scheme (LP-0099)
//
// LP-numbered precompiles use trailing-significant 20-byte addresses:
//
//	0x0000000000000000000000000000000000PCII
//	                                    │ │ └┴─ Item (8 bits, 256 per family×chain)
//	                                    │ └──── Chain slot (4 bits)
//	                                    └────── Family page (4 bits, the LP-Pxxx digit)
//
// Family page (P), aligned with the LP range's first digit:
//
//	P=2 → LP-2xxx PQ identity      P=3 → LP-3xxx EVM/crypto
//	P=4 → LP-4xxx privacy/ZK       P=5 → LP-5xxx threshold/MPC
//	P=6 → LP-6xxx bridges          P=7 → LP-7xxx AI
//	P=9 → LP-9xxx DEX/markets
//
// Chain slot (C) is a 4-bit routing index over the chains that host C-nibble-
// routed precompiles, plus the sovereign-L1 EVM targets that reuse the C-Chain
// precompile surface. It is the mapping ChainSlot implements:
//
//	C=0 P-Chain (platform)   C=1 X-Chain (avm)        C=2 C-Chain (evm)
//	C=3 Q-Chain (quantumvm)  C=4 A-Chain (aivm)       C=5 B-Chain (bridgevm)
//	C=6 Z-Chain (zkvm)       C=7 M-Chain (mpcvm)      C=8 Zoo (sovereign L1)
//	C=9 Hanzo (sovereign L1) C=A SPC (sovereign L1)
//
// Chains outside this set address precompiles by full chain ID, not by nibble.
//
// Example: FROST on C-Chain is P=5, C=2, II=0x00 → LP-5200 →
// 0x0000000000000000000000000000000000005200.
package registry

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"

	// Every package below claims an address in its init(). The blank imports
	// are the entire reason this package exists as a link target.
	_ "github.com/luxfi/precompile/ai"
	_ "github.com/luxfi/precompile/aivmbridge"
	_ "github.com/luxfi/precompile/anchor"
	_ "github.com/luxfi/precompile/attestation"
	_ "github.com/luxfi/precompile/babyjubjub"
	_ "github.com/luxfi/precompile/blake3"
	_ "github.com/luxfi/precompile/bls12381"
	_ "github.com/luxfi/precompile/bridge"
	_ "github.com/luxfi/precompile/cggmp21"
	_ "github.com/luxfi/precompile/compute"
	_ "github.com/luxfi/precompile/corona"
	_ "github.com/luxfi/precompile/curve25519"
	_ "github.com/luxfi/precompile/dead"
	_ "github.com/luxfi/precompile/dex"
	_ "github.com/luxfi/precompile/ed25519"
	_ "github.com/luxfi/precompile/fhe"
	_ "github.com/luxfi/precompile/frost"
	_ "github.com/luxfi/precompile/graph"
	_ "github.com/luxfi/precompile/hpke"
	_ "github.com/luxfi/precompile/hqc"
	_ "github.com/luxfi/precompile/inference"
	_ "github.com/luxfi/precompile/kzg4844"
	_ "github.com/luxfi/precompile/magnetar"
	_ "github.com/luxfi/precompile/math"
	_ "github.com/luxfi/precompile/mldsa"
	_ "github.com/luxfi/precompile/mlkem"
	_ "github.com/luxfi/precompile/modelregistry"
	_ "github.com/luxfi/precompile/p3q"
	_ "github.com/luxfi/precompile/pasta"
	_ "github.com/luxfi/precompile/pedersen"
	_ "github.com/luxfi/precompile/poseidon"
	_ "github.com/luxfi/precompile/pulsar"
	_ "github.com/luxfi/precompile/ring"
	_ "github.com/luxfi/precompile/secp256r1"
	_ "github.com/luxfi/precompile/slhdsa"
	_ "github.com/luxfi/precompile/sr25519"
	_ "github.com/luxfi/precompile/stableswap"
	_ "github.com/luxfi/precompile/starkfri"
	_ "github.com/luxfi/precompile/swap"
	_ "github.com/luxfi/precompile/v3"
	_ "github.com/luxfi/precompile/vrf"
	_ "github.com/luxfi/precompile/x25519"
	_ "github.com/luxfi/precompile/xwing"
	_ "github.com/luxfi/precompile/zk"
)

// nibbleMax is the largest value a 4-bit address nibble can hold.
const nibbleMax = 15

// PrecompileAddress builds the PCII address for a family page, chain slot and
// item. ok is false when p or c does not fit in a nibble; the address is zero
// in that case, which is why the boolean exists — the zero address is also the
// legitimate answer for (0, 0, 0).
func PrecompileAddress(p, c, ii uint8) (addr common.Address, ok bool) {
	if p > nibbleMax || c > nibbleMax {
		return common.Address{}, false
	}
	addr[common.AddressLength-2] = p<<4 | c
	addr[common.AddressLength-1] = ii
	return addr, true
}

// ChainSlot returns the C-nibble for a chain name. ok is false for a chain that
// does not route precompiles by nibble.
func ChainSlot(chain string) (slot uint8, ok bool) {
	switch chain {
	case "P", "p":
		return 0, true
	case "X", "x":
		return 1, true
	case "C", "c":
		return 2, true
	case "Q", "q":
		return 3, true
	case "A", "a":
		return 4, true
	case "B", "b":
		return 5, true
	case "Z", "z":
		return 6, true
	case "M", "m":
		return 7, true
	case "Zoo", "zoo":
		return 8, true
	case "Hanzo", "hanzo":
		return 9, true
	case "SPC", "spc":
		return 0xA, true
	default:
		return 0, false
	}
}

// FamilyPage returns the P-nibble for a family name, aligned with LP-Pxxx.
// ok is false for a name that names no family.
func FamilyPage(family string) (page uint8, ok bool) {
	switch family {
	case "PQ", "pq":
		return 2, true
	case "EVM", "evm", "Crypto", "crypto":
		return 3, true
	case "Privacy", "privacy", "ZK", "zk":
		return 4, true
	case "Threshold", "threshold", "MPC", "mpc":
		return 5, true
	case "Bridge", "bridge":
		return 6, true
	case "AI", "ai":
		return 7, true
	case "DEX", "dex", "Markets", "markets":
		return 9, true
	default:
		return 0, false
	}
}

// InFamily returns the registered precompiles whose address carries the given
// family's P-nibble, in the same deterministic address order the host
// dispatches them in. ok is false for an unknown family, which is distinct from
// a known family with no precompiles registered in this binary.
//
// Only PCII-scheme addresses can answer: an address is in the family when its
// leading 18 bytes are zero and byte 18's high nibble is the family page.
// Legacy leading-significant addresses (0x0400..0050 math, 0x0400..0060
// stableswap) carry no P-nibble and are in no family.
func InFamily(family string) (found []modules.Module, ok bool) {
	page, ok := FamilyPage(family)
	if !ok {
		return nil, false
	}
	for _, m := range modules.RegisteredModules() {
		if p, inScheme := familyPageOf(m.Address); inScheme && p == page {
			found = append(found, m)
		}
	}
	return found, true
}

// familyPageOf returns the P-nibble of a PCII address. inScheme is false for an
// address outside the PCII scheme, which therefore belongs to no family.
func familyPageOf(addr common.Address) (page uint8, inScheme bool) {
	for _, b := range addr[:common.AddressLength-2] {
		if b != 0 {
			return 0, false
		}
	}
	return addr[common.AddressLength-2] >> 4, true
}
