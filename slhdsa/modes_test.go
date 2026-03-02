// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"fmt"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestSLHDSAVerify_AllModes exercises every one of the 12 FIPS 205 parameter
// sets end-to-end: generate key, sign, pass through the precompile, assert
// result == 1. Previously only SHA2_128s and SHAKE_128f were covered, leaving
// the 192-bit and 256-bit security levels entirely untested.
func TestSLHDSAVerify_AllModes(t *testing.T) {
	cases := []struct {
		name        string
		precompMode uint8
		cryptoMode  slhdsa.Mode
	}{
		// SHA2 family (0x00..0x05)
		{"SHA2_128s", ModeSHA2_128s, slhdsa.SHA2_128s},
		{"SHA2_128f", ModeSHA2_128f, slhdsa.SHA2_128f},
		{"SHA2_192s", ModeSHA2_192s, slhdsa.SHA2_192s},
		{"SHA2_192f", ModeSHA2_192f, slhdsa.SHA2_192f},
		{"SHA2_256s", ModeSHA2_256s, slhdsa.SHA2_256s},
		{"SHA2_256f", ModeSHA2_256f, slhdsa.SHA2_256f},
		// SHAKE family (0x10..0x15)
		{"SHAKE_128s", ModeSHAKE_128s, slhdsa.SHAKE_128s},
		{"SHAKE_128f", ModeSHAKE_128f, slhdsa.SHAKE_128f},
		{"SHAKE_192s", ModeSHAKE_192s, slhdsa.SHAKE_192s},
		{"SHAKE_192f", ModeSHAKE_192f, slhdsa.SHAKE_192f},
		{"SHAKE_256s", ModeSHAKE_256s, slhdsa.SHAKE_256s},
		{"SHAKE_256f", ModeSHAKE_256f, slhdsa.SHAKE_256f},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pk, signature, message, _ := createTestSignature(t, tc.cryptoMode)
			input := prepareInputWithMode(tc.precompMode, pk, message, signature)

			gas := SLHDSAVerifyPrecompile.RequiredGas(input)
			result, _, err := SLHDSAVerifyPrecompile.Run(
				nil, common.Address{}, ContractSLHDSAVerifyAddress,
				input, gas, true,
			)

			require.NoError(t, err, "%s: Run returned error", tc.name)
			require.Len(t, result, 32, "%s: result must be 32 bytes", tc.name)
			require.Equal(t, byte(1), result[31],
				"%s: signature should verify as valid", tc.name)
		})
	}
}

// TestSLHDSAVerify_AllModes_Corrupted ensures every mode also rejects a
// tampered signature. Catches regressions where a mode's verify path returns
// success unconditionally.
func TestSLHDSAVerify_AllModes_Corrupted(t *testing.T) {
	modes := []struct {
		name        string
		precompMode uint8
		cryptoMode  slhdsa.Mode
	}{
		{"SHA2_128s", ModeSHA2_128s, slhdsa.SHA2_128s},
		{"SHA2_128f", ModeSHA2_128f, slhdsa.SHA2_128f},
		{"SHA2_192s", ModeSHA2_192s, slhdsa.SHA2_192s},
		{"SHA2_192f", ModeSHA2_192f, slhdsa.SHA2_192f},
		{"SHA2_256s", ModeSHA2_256s, slhdsa.SHA2_256s},
		{"SHA2_256f", ModeSHA2_256f, slhdsa.SHA2_256f},
		{"SHAKE_128s", ModeSHAKE_128s, slhdsa.SHAKE_128s},
		{"SHAKE_128f", ModeSHAKE_128f, slhdsa.SHAKE_128f},
		{"SHAKE_192s", ModeSHAKE_192s, slhdsa.SHAKE_192s},
		{"SHAKE_192f", ModeSHAKE_192f, slhdsa.SHAKE_192f},
		{"SHAKE_256s", ModeSHAKE_256s, slhdsa.SHAKE_256s},
		{"SHAKE_256f", ModeSHAKE_256f, slhdsa.SHAKE_256f},
	}

	for _, tc := range modes {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pk, signature, message, _ := createTestSignature(t, tc.cryptoMode)
			signature[0] ^= 0xFF
			input := prepareInputWithMode(tc.precompMode, pk, message, signature)

			gas := SLHDSAVerifyPrecompile.RequiredGas(input)
			result, _, err := SLHDSAVerifyPrecompile.Run(
				nil, common.Address{}, ContractSLHDSAVerifyAddress,
				input, gas, true,
			)

			require.NoError(t, err,
				"%s: Run should not return error on invalid sig", tc.name)
			require.Len(t, result, 32)
			require.Equal(t, byte(0), result[31],
				"%s: corrupted signature must NOT verify", tc.name)
		})
	}
}

// TestSLHDSAVerify_ModeGasIncreasesWithSecurity sanity check: gas costs must
// grow with security level because signature sizes and SHA tree heights both
// increase. Catches regressions that would price 256-bit verify as cheap.
func TestSLHDSAVerify_ModeGasIncreasesWithSecurity(t *testing.T) {
	levels := []struct {
		mode uint8
		bits int
	}{
		{ModeSHA2_128s, 128},
		{ModeSHA2_192s, 192},
		{ModeSHA2_256s, 256},
	}

	var prev uint64
	for _, lv := range levels {
		_, _, baseGas, _, err := getModeParams(lv.mode)
		require.NoError(t, err, "getModeParams failed for %d-bit", lv.bits)
		require.Greater(t, baseGas, prev,
			fmt.Sprintf("%d-bit gas must be > previous level", lv.bits))
		prev = baseGas
	}
}
