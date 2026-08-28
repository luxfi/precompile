// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// PrecompileAddress
// ============================================================================

func TestPrecompileAddress(t *testing.T) {
	tests := []struct {
		name     string
		p, c, ii uint8
		want     string
	}{
		{"FROST C-Chain (LP-5200)", 5, 2, 0x00, "0x0000000000000000000000000000000000005200"},
		{"FROST Q-Chain (LP-5300)", 5, 3, 0x00, "0x0000000000000000000000000000000000005300"},
		{"ML-DSA C-Chain (LP-2200)", 2, 2, 0x00, "0x0000000000000000000000000000000000002200"},
		{"LXPool (LP-9010)", 9, 0, 0x10, "0x0000000000000000000000000000000000009010"},
		{"LXOracle (LP-9011)", 9, 0, 0x11, "0x0000000000000000000000000000000000009011"},
		{"max nibbles", 15, 15, 0xFF, "0x000000000000000000000000000000000000ffff"},
		{"all zero", 0, 0, 0x00, "0x0000000000000000000000000000000000000000"},
		{"item carries the low byte alone", 0, 0, 0xFF, "0x00000000000000000000000000000000000000ff"},
		{"chain nibble is the low half of byte 18", 0, 1, 0x00, "0x0000000000000000000000000000000000000100"},
		{"family nibble is the high half of byte 18", 1, 0, 0x00, "0x0000000000000000000000000000000000001000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := PrecompileAddress(tt.p, tt.c, tt.ii)
			require.True(t, ok)
			require.Equal(t, common.HexToAddress(tt.want), got)
		})
	}
}

func TestPrecompileAddressRejectsOverflowingNibbles(t *testing.T) {
	// A nibble is 4 bits. Packing 16 into it would silently corrupt the
	// neighbouring nibble — 16<<4 overflows byte 18's high half into nothing and
	// the address would collide with (0, c, ii).
	for _, tt := range []struct{ p, c uint8 }{{16, 2}, {5, 16}, {20, 20}, {255, 0}, {0, 255}} {
		got, ok := PrecompileAddress(tt.p, tt.c, 0)
		require.False(t, ok, "p=%d c=%d must be refused", tt.p, tt.c)
		require.Equal(t, common.Address{}, got)
	}

	// The boundary itself is accepted: 15 is the largest nibble.
	_, ok := PrecompileAddress(15, 15, 0)
	require.True(t, ok)
}

func TestPrecompileAddressZeroIsDistinguishableFromRefusal(t *testing.T) {
	// (0,0,0) is a legitimate address that happens to be zero. A refusal is also
	// zero. Only the boolean separates them — a caller ignoring it would treat a
	// bad family page as "the zero address", which is a live burn address.
	zero, ok := PrecompileAddress(0, 0, 0)
	require.True(t, ok)
	require.Equal(t, common.Address{}, zero)

	refused, ok := PrecompileAddress(16, 0, 0)
	require.False(t, ok)
	require.Equal(t, zero, refused)
}

func TestPrecompileAddressIsInjective(t *testing.T) {
	// Every (p, c, ii) triple must map to its own address. A shift or mask slip
	// would fold two coordinates onto one address — two precompiles, one slot.
	seen := make(map[common.Address][3]uint8, 16*16*256)
	for p := uint8(0); p <= nibbleMax; p++ {
		for c := uint8(0); c <= nibbleMax; c++ {
			for ii := 0; ii < 256; ii++ {
				a, ok := PrecompileAddress(p, c, uint8(ii))
				require.True(t, ok)
				if prev, dup := seen[a]; dup {
					t.Fatalf("address %s produced by both %v and %v", a.Hex(), prev, [3]uint8{p, c, uint8(ii)})
				}
				seen[a] = [3]uint8{p, c, uint8(ii)}
			}
		}
	}
	require.Len(t, seen, 16*16*256)
}

func TestPrecompileAddressRoundTripsThroughFamilyPage(t *testing.T) {
	// The address encodes its own family. Building one and reading the family
	// back must agree, or InFamily and PrecompileAddress disagree about layout.
	for p := uint8(0); p <= nibbleMax; p++ {
		for c := uint8(0); c <= nibbleMax; c++ {
			a, ok := PrecompileAddress(p, c, 0x42)
			require.True(t, ok)
			got, inScheme := familyPageOf(a)
			require.True(t, inScheme)
			require.Equal(t, p, got)
		}
	}
}

// ============================================================================
// ChainSlot / FamilyPage
// ============================================================================

func TestChainSlot(t *testing.T) {
	want := map[string]uint8{
		"P": 0, "X": 1, "C": 2, "Q": 3, "A": 4, "B": 5,
		"Z": 6, "M": 7, "Zoo": 8, "Hanzo": 9, "SPC": 0xA,
	}
	for name, slot := range want {
		got, ok := ChainSlot(name)
		require.True(t, ok, "%s must resolve", name)
		require.Equal(t, slot, got, "%s", name)
	}

	// Every slot is claimed by exactly one chain: a duplicate would route two
	// chains' precompiles to one address.
	claimed := make(map[uint8]string, len(want))
	for name, slot := range want {
		require.NotContains(t, claimed, slot, "slot %d claimed twice", slot)
		claimed[slot] = name
	}

	// Slots fit in a nibble, so composing ChainSlot with PrecompileAddress
	// always succeeds.
	for name := range want {
		slot, ok := ChainSlot(name)
		require.True(t, ok)
		_, ok = PrecompileAddress(2, slot, 0)
		require.True(t, ok, "%s slot %d does not fit a nibble", name, slot)
	}
}

func TestChainSlotCaseVariants(t *testing.T) {
	// Only the documented spellings resolve. A lowercase alias is accepted; an
	// arbitrary casing is not, so a typo fails loudly instead of routing to a
	// neighbouring chain.
	for _, pair := range [][2]string{{"C", "c"}, {"Zoo", "zoo"}, {"Hanzo", "hanzo"}, {"SPC", "spc"}} {
		up, ok := ChainSlot(pair[0])
		require.True(t, ok)
		lo, ok := ChainSlot(pair[1])
		require.True(t, ok)
		require.Equal(t, up, lo)
	}
	for _, bad := range []string{"ZOO", "hANZO", "spC"} {
		_, ok := ChainSlot(bad)
		require.False(t, ok, "%q must not resolve", bad)
	}
}

func TestChainSlotUnknown(t *testing.T) {
	for _, bad := range []string{"", "D", "T", "G", "K", "I", "O", "R", "unknown", "0", "  C  "} {
		slot, ok := ChainSlot(bad)
		require.False(t, ok, "%q must not resolve to a slot", bad)
		require.Zero(t, slot, "a refused lookup must not hand back a usable slot")
	}
}

func TestFamilyPage(t *testing.T) {
	want := map[string]uint8{
		"PQ": 2, "EVM": 3, "Crypto": 3, "Privacy": 4, "ZK": 4,
		"Threshold": 5, "MPC": 5, "Bridge": 6, "AI": 7, "DEX": 9, "Markets": 9,
	}
	for name, page := range want {
		got, ok := FamilyPage(name)
		require.True(t, ok, "%s must resolve", name)
		require.Equal(t, page, got, "%s", name)

		lower, ok := FamilyPage(lowerASCII(name))
		require.True(t, ok, "lowercase %s must resolve", name)
		require.Equal(t, page, lower)
	}

	// The page is the LP range's first digit, so it must fit a nibble and be a
	// decimal digit — LP-Pxxx has no hex page.
	for name := range want {
		page, ok := FamilyPage(name)
		require.True(t, ok)
		require.LessOrEqual(t, page, uint8(9), "%s page %d is not an LP digit", name, page)
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func TestFamilyPageUnknown(t *testing.T) {
	for _, bad := range []string{"", "INVALID", "Pq", "dEx", "8", "LP-9xxx"} {
		page, ok := FamilyPage(bad)
		require.False(t, ok, "%q must not resolve to a page", bad)
		require.Zero(t, page)
	}
}

// ============================================================================
// InFamily — derived from what actually registered
// ============================================================================

func TestInFamilyUnknownFamily(t *testing.T) {
	got, ok := InFamily("INVALID")
	require.False(t, ok)
	require.Nil(t, got)
}

func TestInFamilyReturnsOnlyMatchingPage(t *testing.T) {
	for _, family := range []string{"PQ", "EVM", "Privacy", "Threshold", "Bridge", "AI", "DEX"} {
		page, ok := FamilyPage(family)
		require.True(t, ok)

		got, ok := InFamily(family)
		require.True(t, ok, "%s is a known family", family)
		for _, m := range got {
			p, inScheme := familyPageOf(m.Address)
			require.True(t, inScheme, "%s: %s is not a PCII address", family, m.Address.Hex())
			require.Equal(t, page, p, "%s: %s has page %d", family, m.Address.Hex(), p)
		}
	}
}

func TestInFamilyIsAPartitionOfThePCIIAddresses(t *testing.T) {
	// Every registered PCII-scheme precompile belongs to exactly one family
	// page, and InFamily over all known families must find each of them at most
	// once. A precompile appearing in two families would mean two answers to
	// "what is this".
	seen := make(map[common.Address]string)
	for _, family := range []string{"PQ", "EVM", "Privacy", "Threshold", "Bridge", "AI", "DEX"} {
		got, ok := InFamily(family)
		require.True(t, ok)
		for _, m := range got {
			if prev, dup := seen[m.Address]; dup {
				t.Fatalf("%s is in both %q and %q", m.Address.Hex(), prev, family)
			}
			seen[m.Address] = family
		}
	}
	require.NotEmpty(t, seen, "no PCII precompiles found — the blank imports are the fixture")
}

func TestInFamilyPreservesRegistryOrder(t *testing.T) {
	// The host dispatches in address order. A family view that reorders would
	// give a caller a different picture of the same set.
	order := make(map[common.Address]int)
	for i, m := range modules.RegisteredModules() {
		order[m.Address] = i
	}
	for _, family := range []string{"PQ", "EVM", "Privacy", "Threshold", "Bridge", "AI", "DEX"} {
		got, ok := InFamily(family)
		require.True(t, ok)
		for i := 1; i < len(got); i++ {
			require.Less(t, order[got[i-1].Address], order[got[i].Address],
				"%s is out of registry order", family)
		}
	}
}

func TestInFamilyDEXFindsTheDexPrecompiles(t *testing.T) {
	// The DEX settlement precompile is the money path; it must be discoverable
	// through the family view. Before this package derived from the module
	// registry, the DEX family resolved to nil because the hand-written table
	// tagged DEX rows "LP-9010" while the lookup compared against "LP-9xxx".
	got, ok := InFamily("DEX")
	require.True(t, ok)
	require.NotEmpty(t, got, "DEX family must not be empty")

	keys := make(map[string]bool, len(got))
	for _, m := range got {
		keys[m.ConfigKey] = true
	}
	require.True(t, keys["dexSettleConfig"], "DEX family must include the settlement precompile")
}

func TestInFamilyExcludesLegacyLeadingSignificantAddresses(t *testing.T) {
	// math (0x0400..0050) and stableswap (0x0400..0060) are leading-significant
	// legacy addresses: byte 0 is nonzero, so they carry no P-nibble and belong
	// to no family. Reading byte 18 of those would report a bogus family.
	for _, key := range []string{"fixedPointMathConfig", "stableSwapConfig"} {
		m, found := modules.GetPrecompileModule(key)
		require.True(t, found, "%s must be registered", key)
		_, inScheme := familyPageOf(m.Address)
		require.False(t, inScheme, "%s (%s) must not be read as a PCII address", key, m.Address.Hex())
	}
}

// ============================================================================
// EIP-mandated addresses
// ============================================================================

// TestEIPAddressesAreClaimedByTheRightPrecompiles is the one place the external
// standards' addresses are written down in this package, and it checks them
// against what actually registered rather than against another table. Lux ships
// EIP-2537 and EIP-7212 as stateful precompiles, so a module MUST occupy each
// address — an empty slot means the chain silently lacks the EIP.
func TestEIPAddressesAreClaimedByTheRightPrecompiles(t *testing.T) {
	eip := map[string]string{
		// EIP-2537 BLS12-381.
		"0x000000000000000000000000000000000000000b": "bls12381G1AddConfig",
		"0x000000000000000000000000000000000000000c": "bls12381G1MulConfig",
		"0x000000000000000000000000000000000000000d": "bls12381G1MSMConfig",
		"0x000000000000000000000000000000000000000e": "bls12381G2AddConfig",
		"0x000000000000000000000000000000000000000f": "bls12381G2MulConfig",
		"0x0000000000000000000000000000000000000010": "bls12381G2MSMConfig",
		"0x0000000000000000000000000000000000000011": "bls12381PairingConfig",
		// EIP-7212 secp256r1 / P-256 verify (passkeys, WebAuthn).
		"0x0000000000000000000000000000000000000100": "secp256r1Config",
	}

	for addr, key := range eip {
		a := common.HexToAddress(addr)
		m, ok := modules.GetPrecompileModuleByAddress(a)
		require.True(t, ok, "no precompile registered at EIP address %s", addr)
		require.Equal(t, key, m.ConfigKey,
			"%s is occupied by %q, not the expected precompile", addr, m.ConfigKey)
		require.NotNil(t, m.Contract)
	}
}
