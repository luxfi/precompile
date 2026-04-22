// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package modules

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// withCleanRegistry snapshots the package-level registeredModules slice and
// restores it after the test runs. This keeps tests hermetic even when other
// tests in the same binary execution register modules.
func withCleanRegistry(t *testing.T) {
	t.Helper()
	saved := make([]Module, len(registeredModules))
	copy(saved, registeredModules)
	registeredModules = make([]Module, 0)
	t.Cleanup(func() {
		registeredModules = saved
	})
}

// ============================================================================
// AddressRange.Contains
// ============================================================================

func TestAddressRange_Contains(t *testing.T) {
	r := &AddressRange{
		Start: common.HexToAddress("0x0000000000000000000000000000000000005000"),
		End:   common.HexToAddress("0x0000000000000000000000000000000000005fff"),
	}

	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"exact start", "0x0000000000000000000000000000000000005000", true},
		{"exact end", "0x0000000000000000000000000000000000005fff", true},
		{"middle", "0x0000000000000000000000000000000000005abc", true},
		{"one before start", "0x0000000000000000000000000000000000004fff", false},
		{"one after end", "0x0000000000000000000000000000000000006000", false},
		{"far below", "0x0000000000000000000000000000000000000001", false},
		{"far above", "0xffffffffffffffffffffffffffffffffffffffff", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Contains(common.HexToAddress(tt.addr))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAddressRange_Contains_SingletonRange(t *testing.T) {
	// Dead/burn addresses are encoded as single-address ranges (Start == End).
	singleton := &AddressRange{
		Start: common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		End:   common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
	}
	require.True(t, singleton.Contains(common.HexToAddress("0x000000000000000000000000000000000000dEaD")))
	require.False(t, singleton.Contains(common.HexToAddress("0x000000000000000000000000000000000000dEaC")))
	require.False(t, singleton.Contains(common.HexToAddress("0x000000000000000000000000000000000000dEaE")))
}

func TestAddressRange_Contains_InvertedRangeIsEmpty(t *testing.T) {
	// If a caller ever accidentally constructs an inverted range (Start > End),
	// Contains should return false for every address rather than panic.
	inverted := &AddressRange{
		Start: common.HexToAddress("0x00000000000000000000000000000000000000ff"),
		End:   common.HexToAddress("0x0000000000000000000000000000000000000001"),
	}
	require.False(t, inverted.Contains(common.HexToAddress("0x0000000000000000000000000000000000000001")))
	require.False(t, inverted.Contains(common.HexToAddress("0x0000000000000000000000000000000000000050")))
	require.False(t, inverted.Contains(common.HexToAddress("0x00000000000000000000000000000000000000ff")))
}

// ============================================================================
// ReservedAddress
// ============================================================================

func TestReservedAddress_KnownRangesAllowed(t *testing.T) {
	// Representative address from each documented reserved range. If any of
	// these returns false, either the range table is wrong or the documentation
	// in registerer.go is lying about the layout.
	reserved := []string{
		// High-byte (legacy) ranges.
		"0x0100000000000000000000000000000000000000", // Warp/Teleport
		"0x0200000000000000000000000000000000000050", // Chain Config
		"0x0300000000000000000000000000000000000001", // AI Mining (0x03xx)
		"0x04000000000000000000000000000000000000ff", // DEX
		"0x0500000000000000000000000000000000000010", // Graph
		"0x0600000000000000000000000000000000000020", // PQ Crypto
		"0x0700000000000000000000000000000000000030", // Privacy
		"0x0800000000000000000000000000000000000040", // Threshold
		"0x0900000000000000000000000000000000000050", // ZK
		"0x0A00000000000000000000000000000000000060", // Curves
		// LP-aligned low-byte ranges.
		"0x0000000000000000000000000000000000002000", // LP-2xxx PQ Identity
		"0x0000000000000000000000000000000000002fff",
		"0x0000000000000000000000000000000000003200", // LP-3xxx EVM/Crypto
		"0x0000000000000000000000000000000000004abc", // LP-4xxx Privacy/ZK
		"0x0000000000000000000000000000000000005200", // FROST C-Chain (LP-5200)
		"0x0000000000000000000000000000000000006100", // LP-6xxx Bridges
		"0x0000000000000000000000000000000000007000", // LP-7xxx AI
		"0x0000000000000000000000000000000000009010", // DEX LXPool (LP-9010)
		"0x0000000000000000000000000000000000008100", // Core (AI Mining at 0x8100)
		"0x000000000000000000000000000000000000a000", // Hashing & ZK
		"0x000000000000000000000000000000000000b000", // KZG Extensions
		// Standard EVM precompiles.
		"0x0000000000000000000000000000000000000001",
		"0x00000000000000000000000000000000000000ff",
		// Dead / burn addresses.
		"0x0000000000000000000000000000000000000000",
		"0x000000000000000000000000000000000000dEaD",
		"0xdEaD000000000000000000000000000000000000",
	}

	for _, a := range reserved {
		addr := common.HexToAddress(a)
		require.True(t, ReservedAddress(addr), "expected %s to be in a reserved range", addr.Hex())
	}
}

func TestReservedAddress_UnreservedRejected(t *testing.T) {
	// Addresses deliberately outside every documented range.
	unreserved := []string{
		// Gaps between high-byte ranges (0x0B-0xFF first byte).
		"0x0B00000000000000000000000000000000000000",
		"0x1000000000000000000000000000000000000000",
		"0x1234567890abcdef1234567890abcdef12345678",
		// Below the LP-2xxx range and above the standard EVM range.
		"0x0000000000000000000000000000000000000100",
		"0x0000000000000000000000000000000000001fff",
		// Unreserved high-byte address (0x0C prefix has no documented range).
		"0x0C00000000000000000000000000000000000050",
		// A plausibly-looking but unreserved address.
		"0xc0ffee0000000000000000000000000000000000",
	}

	for _, a := range unreserved {
		addr := common.HexToAddress(a)
		require.False(t, ReservedAddress(addr), "expected %s to NOT be in any reserved range", addr.Hex())
	}
}

// ============================================================================
// RegisterModule — happy paths
// ============================================================================

func TestRegisterModule_Success(t *testing.T) {
	withCleanRegistry(t)

	m := Module{
		ConfigKey: "testPrecompileA",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	}
	require.NoError(t, RegisterModule(m))

	got, ok := GetPrecompileModule("testPrecompileA")
	require.True(t, ok)
	require.Equal(t, m.Address, got.Address)

	gotByAddr, ok := GetPrecompileModuleByAddress(m.Address)
	require.True(t, ok)
	require.Equal(t, "testPrecompileA", gotByAddr.ConfigKey)

	require.Len(t, RegisteredModules(), 1)
}

func TestRegisterModule_DeterministicAddressOrder(t *testing.T) {
	withCleanRegistry(t)

	// Insert in reverse-address order; RegisteredModules must return them
	// sorted ascending by address (the documented invariant consensus relies on).
	addrs := []string{
		"0x0000000000000000000000000000000000009010",
		"0x0000000000000000000000000000000000005200",
		"0x0000000000000000000000000000000000002200",
		"0x0000000000000000000000000000000000007000",
	}
	for i, a := range addrs {
		require.NoError(t, RegisterModule(Module{
			ConfigKey: string(rune('a'+i)) + "_module",
			Address:   common.HexToAddress(a),
		}))
	}

	got := RegisteredModules()
	require.Len(t, got, len(addrs))
	for i := 1; i < len(got); i++ {
		prev := got[i-1].Address.Bytes()
		curr := got[i].Address.Bytes()
		require.Less(t, string(prev), string(curr),
			"registered modules are not sorted by address: %s then %s",
			got[i-1].Address.Hex(), got[i].Address.Hex())
	}

	// Concretely assert the sorted order.
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000002200"), got[0].Address)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000005200"), got[1].Address)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000007000"), got[2].Address)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000009010"), got[3].Address)
}

// ============================================================================
// RegisterModule — validation failures
// ============================================================================

func TestRegisterModule_BlackholeAddressRejected(t *testing.T) {
	withCleanRegistry(t)

	err := RegisterModule(Module{
		ConfigKey: "blackholeSquatter",
		Address:   BlackholeAddr,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "blackhole")
	require.Empty(t, RegisteredModules())
}

func TestRegisterModule_UnreservedAddressRejected(t *testing.T) {
	withCleanRegistry(t)

	// An address that is NOT in any reserved range must be rejected.
	err := RegisterModule(Module{
		ConfigKey: "randomSquatter",
		Address:   common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in a reserved range")
	require.Empty(t, RegisteredModules())
}

func TestRegisterModule_ConfigKeyCollisionRejected(t *testing.T) {
	withCleanRegistry(t)

	require.NoError(t, RegisterModule(Module{
		ConfigKey: "duplicateKey",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	}))

	// Different address, same ConfigKey — must be rejected with a collision
	// error referencing the already-registered address.
	err := RegisterModule(Module{
		ConfigKey: "duplicateKey",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005300"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "config key collision")
	require.Contains(t, err.Error(), "duplicateKey")
	require.Len(t, RegisteredModules(), 1)
}

func TestRegisterModule_AddressCollisionRejected(t *testing.T) {
	withCleanRegistry(t)

	require.NoError(t, RegisterModule(Module{
		ConfigKey: "firstModule",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	}))

	// Different ConfigKey, same address — must be rejected with an address
	// collision error referencing the already-registered ConfigKey.
	err := RegisterModule(Module{
		ConfigKey: "secondModule",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "address collision")
	require.Contains(t, err.Error(), "firstModule")
	require.Len(t, RegisteredModules(), 1)
}

func TestRegisterModule_RejectionDoesNotMutateRegistry(t *testing.T) {
	// A failed registration must leave the registry untouched — regardless of
	// which validation step failed. This prevents a rejected Module from
	// "poisoning" the deterministic iteration order.
	withCleanRegistry(t)

	valid := Module{
		ConfigKey: "validModule",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	}
	require.NoError(t, RegisterModule(valid))
	before := append([]Module(nil), RegisteredModules()...)

	cases := []Module{
		{ConfigKey: "blackhole", Address: BlackholeAddr},
		{ConfigKey: "offrange", Address: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")},
		{ConfigKey: "validModule", Address: common.HexToAddress("0x0000000000000000000000000000000000005300")},
		{ConfigKey: "aliasCollider", Address: valid.Address},
	}
	for _, bad := range cases {
		require.Error(t, RegisterModule(bad), "expected rejection for %+v", bad)
	}

	after := RegisteredModules()
	require.Equal(t, before, after, "registry must be unchanged after rejected registrations")
}

// ============================================================================
// GetPrecompileModule lookups
// ============================================================================

func TestGetPrecompileModule_NotFound(t *testing.T) {
	withCleanRegistry(t)

	_, ok := GetPrecompileModule("never-registered")
	require.False(t, ok)

	_, ok = GetPrecompileModuleByAddress(common.HexToAddress("0x0000000000000000000000000000000000005200"))
	require.False(t, ok)
}

func TestGetPrecompileModule_LookupByKeyAndAddressAgree(t *testing.T) {
	withCleanRegistry(t)

	m := Module{
		ConfigKey: "symmetricLookup",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	}
	require.NoError(t, RegisterModule(m))

	byKey, ok := GetPrecompileModule(m.ConfigKey)
	require.True(t, ok)
	byAddr, ok := GetPrecompileModuleByAddress(m.Address)
	require.True(t, ok)
	require.Equal(t, byKey.ConfigKey, byAddr.ConfigKey)
	require.Equal(t, byKey.Address, byAddr.Address)
}

// ============================================================================
// RegisteredModules invariants
// ============================================================================

func TestRegisteredModules_ReflectsLiveState(t *testing.T) {
	// Document the existing behavior: RegisteredModules returns the live
	// backing slice, so callers that append to it could corrupt registry state.
	// This test pins that behavior so any future refactor that changes it
	// must do so intentionally.
	withCleanRegistry(t)

	require.NoError(t, RegisterModule(Module{
		ConfigKey: "liveSliceModule",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005200"),
	}))

	require.Len(t, RegisteredModules(), 1)
	require.NoError(t, RegisterModule(Module{
		ConfigKey: "liveSliceModule2",
		Address:   common.HexToAddress("0x0000000000000000000000000000000000005300"),
	}))
	require.Len(t, RegisteredModules(), 2)
}
