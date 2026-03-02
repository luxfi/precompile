// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// H-02: CGGMP21 gas cost must not overflow with extreme totalSigners.
//
// Vulnerability: The gas calculation was CGGMP21VerifyBaseGas + totalSigners * CGGMP21VerifyPerSignerGas
// where totalSigners is a uint32 read from calldata. With totalSigners = 0xFFFFFFFF:
//   0xFFFFFFFF * 10_000 = 42_949_672_950_000 which overflows uint64? No, but it
//   produces an absurdly high gas cost (42.9 trillion) that a malicious caller
//   could use to cause unexpected behavior in gas estimation or accounting.
//
// Fix: Cap totalSigners at a reasonable maximum (e.g., 256) and/or cap total
// gas to a reasonable maximum. Gas must never exceed block gas limit equivalent.
func TestH02_CGGMP21GasOverflowMaxSigners(t *testing.T) {
	input := make([]byte, MinInputSize)
	// threshold = 1
	binary.BigEndian.PutUint32(input[0:4], 1)
	// totalSigners = 0xFFFFFFFF (max uint32)
	binary.BigEndian.PutUint32(input[4:8], math.MaxUint32)

	gas := CGGMP21VerifyGasCost(input)

	// Gas must not be astronomically high. A reasonable cap for a single
	// precompile call should be well under 1 billion gas.
	maxReasonableGas := uint64(1_000_000_000) // 1B gas
	require.Less(t, gas, maxReasonableGas,
		"Gas for totalSigners=0xFFFFFFFF must be capped (got %d)", gas)
}

// H-02: CGGMP21 gas must not wrap around to a small value.
//
// If the multiplication overflows uint64, the gas wraps to a small number,
// and the precompile becomes extremely cheap for adversarial inputs.
func TestH02_CGGMP21GasNoWrapAround(t *testing.T) {
	input := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(input[0:4], 1)
	binary.BigEndian.PutUint32(input[4:8], math.MaxUint32)

	gas := CGGMP21VerifyGasCost(input)

	// Gas must be at least the base cost -- a wrapped value would be lower.
	require.GreaterOrEqual(t, gas, CGGMP21VerifyBaseGas,
		"Gas must not wrap below base cost")
}

// H-02: Reasonable totalSigners should produce reasonable gas.
func TestH02_CGGMP21GasReasonableValues(t *testing.T) {
	tests := []struct {
		name         string
		totalSigners uint32
		maxGas       uint64
	}{
		{"2-of-3", 3, 150_000},
		{"5-of-10", 10, 250_000},
		{"20-of-50", 50, 700_000},
		{"100-of-256", 256, 3_000_000},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, MinInputSize)
			binary.BigEndian.PutUint32(input[0:4], 1)
			binary.BigEndian.PutUint32(input[4:8], tc.totalSigners)

			gas := CGGMP21VerifyGasCost(input)
			require.Less(t, gas, tc.maxGas,
				"Gas for %d signers should be under %d", tc.totalSigners, tc.maxGas)
			require.Greater(t, gas, CGGMP21VerifyBaseGas,
				"Gas must be greater than base for %d signers", tc.totalSigners)
		})
	}
}

// H-02: totalSigners = 0 should not cause issues.
func TestH02_CGGMP21GasZeroSigners(t *testing.T) {
	input := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(input[0:4], 0)
	binary.BigEndian.PutUint32(input[4:8], 0)

	gas := CGGMP21VerifyGasCost(input)
	require.Equal(t, CGGMP21VerifyBaseGas, gas,
		"Zero signers should return base gas cost")
}
