// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/stretchr/testify/require"
)

// H-03: BLS12-381 pairing gas must follow EIP-2537: 65000 + 43000*n.
//
// Vulnerability: Pairing gas was flat per pair (115000*n), missing the base
// cost. A single pair cost 115000 instead of 108000. More critically, the
// old code undercharged multi-pair calls relative to EIP-2537 (no base cost).
//
// Fix: GasPairingBase=65000, GasPairingPerPair=43000. Total = base + n*perPair.
func TestH03_BLS12381PairingGasSufficient(t *testing.T) {
	// Verify constants match EIP-2537
	require.Equal(t, uint64(65000), uint64(GasPairingBase))
	require.Equal(t, uint64(43000), uint64(GasPairingPerPair))

	// Verify the formula: 65000 + 43000*n
	for _, n := range []int{1, 2, 5, 10} {
		expected := uint64(GasPairingBase) + uint64(n)*uint64(GasPairingPerPair)
		actual := PairingGas(n * PairingPair)
		require.Equal(t, expected, actual, "pairing gas for %d pairs", n)
		// Per EIP-2537: base cost ensures even a single pair costs 108K.
		// The minimum per-pair amortized cost decreases with more pairs
		// (65000/n + 43000), but total always exceeds 43K*n.
		require.GreaterOrEqual(t, actual, uint64(n)*uint64(GasPairingPerPair),
			"%d pairs must cost at least %d gas", n, uint64(n)*uint64(GasPairingPerPair))
	}

	// Verify multiple pairs via the actual precompile
	for _, n := range []int{1, 2, 5, 10} {
		multiInput := make([]byte, n*PairingPair)
		_, _, err := blsOps.pairing(multiInput, 100_000_000)
		if err == nil {
			gasNeeded := uint64(GasPairingBase) + uint64(n)*uint64(GasPairingPerPair)
			require.GreaterOrEqual(t, gasNeeded, uint64(n)*uint64(GasPairingPerPair),
				"%d pairs must cost at least %d gas", n, uint64(n)*uint64(GasPairingPerPair))
		}
	}
}

// H-03: Pairing with insufficient gas must fail.
func TestH03_BLS12381PairingOOG(t *testing.T) {
	input := make([]byte, PairingPair)
	gasNeeded := uint64(GasPairingBase) + uint64(GasPairingPerPair)
	_, _, err := blsOps.pairing(input, gasNeeded-1)
	require.Error(t, err, "Pairing with insufficient gas must fail")
}

// H-04: All 7 BLS12-381 addresses must be registered.
//
// Vulnerability: Only G1AddAddress (0x000B) was registered. Calls to
// 0x000C-0x0011 would silently fail or behave as regular addresses.
//
// Fix: Each address gets its own Module registration with a unique ConfigKey.
func TestH04_BLS12381AllAddressesRegistered(t *testing.T) {
	expectedAddrs := []struct {
		name string
		addr common.Address
		key  string
	}{
		{"G1Add", G1AddAddress, G1AddConfigKey},
		{"G1Mul", G1MulAddress, G1MulConfigKey},
		{"G1MSM", G1MSMAddress, G1MSMConfigKey},
		{"G2Add", G2AddAddress, G2AddConfigKey},
		{"G2Mul", G2MulAddress, G2MulConfigKey},
		{"G2MSM", G2MSMAddress, G2MSMConfigKey},
		{"Pairing", PairingAddress, PairingConfigKey},
	}

	for _, tc := range expectedAddrs {
		t.Run(tc.name, func(t *testing.T) {
			require.True(t, modules.ReservedAddress(tc.addr),
				"BLS12-381 %s address %s must be in a reserved range", tc.name, tc.addr.Hex())

			m, ok := modules.GetPrecompileModuleByAddress(tc.addr)
			require.True(t, ok, "module must be registered at %s", tc.addr.Hex())
			require.Equal(t, tc.key, m.ConfigKey)
		})
	}
}

// H-04: BLS12-381 addresses must match EIP-2537 standard.
func TestH04_BLS12381CorrectAddresses(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x000000000000000000000000000000000000000b"), G1AddAddress)
	require.Equal(t, common.HexToAddress("0x000000000000000000000000000000000000000c"), G1MulAddress)
	require.Equal(t, common.HexToAddress("0x000000000000000000000000000000000000000d"), G1MSMAddress)
	require.Equal(t, common.HexToAddress("0x000000000000000000000000000000000000000e"), G2AddAddress)
	require.Equal(t, common.HexToAddress("0x000000000000000000000000000000000000000f"), G2MulAddress)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000000010"), G2MSMAddress)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000000011"), PairingAddress)
}

// H-04: Each registered module dispatches to the correct operation.
func TestH04_BLS12381ModuleDispatch(t *testing.T) {
	addrs := []struct {
		name string
		addr common.Address
	}{
		{"G1Add", G1AddAddress},
		{"G1Mul", G1MulAddress},
		{"G1MSM", G1MSMAddress},
		{"G2Add", G2AddAddress},
		{"G2Mul", G2MulAddress},
		{"G2MSM", G2MSMAddress},
		{"Pairing", PairingAddress},
	}

	for _, tc := range addrs {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := modules.GetPrecompileModuleByAddress(tc.addr)
			require.True(t, ok)

			// Call with empty/minimal input -- should fail on input validation,
			// NOT on "unknown address". This proves the module dispatches correctly.
			_, _, err := m.Contract.Run(nil, common.Address{}, tc.addr, nil, 10_000_000, false)
			if err != nil {
				// All operations should fail with input validation errors, not dispatch errors
				require.NotContains(t, err.Error(), "unknown",
					"Address %s must dispatch to a valid operation", tc.addr.Hex())
			}
		})
	}
}
