// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xwing

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// C-02: X-Wing KeyGen must not be exposed on-chain.
//
// Vulnerability: KeyGen (0x01) returned secret key material in EVM return data,
// visible to all validators and archived in transaction receipts forever.
//
// Fix: Remove OpKeyGen entirely. Only OpEncapsulate (0x02) is permitted.
// This test fails if KeyGen op is accepted.
func TestC02_XWingKeyGenRejected(t *testing.T) {
	// OpKeyGen was 0x01 in the vulnerable version
	const opKeyGen = 0x01
	input := []byte{opKeyGen}

	gas := XWingPrecompile.RequiredGas(input)
	// RequiredGas should return 0 for unknown ops
	require.Equal(t, uint64(0), gas, "KeyGen op must not have a gas cost")

	ret, _, err := XWingPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1_000_000,
		false,
	)
	require.Error(t, err, "KeyGen op (0x01) must be rejected")
	require.Nil(t, ret, "KeyGen must not return any data")
}

// C-02: X-Wing Decapsulate must not be exposed on-chain.
//
// Vulnerability: Decapsulate required the secret key in calldata, which is
// public on-chain. Any node can read the secret key from the transaction.
//
// Fix: Remove OpDecapsulate. Only OpEncapsulate is permitted.
func TestC02_XWingDecapsulateRejected(t *testing.T) {
	// OpDecapsulate was 0x03 in the vulnerable version
	const opDecapsulate = 0x03
	input := []byte{opDecapsulate}

	gas := XWingPrecompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas, "Decapsulate op must not have a gas cost")

	ret, _, err := XWingPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1_000_000,
		false,
	)
	require.Error(t, err, "Decapsulate op (0x03) must be rejected")
	require.Nil(t, ret, "Decapsulate must not return any data")
}

// C-02: Only OpEncapsulate (0x02) is a valid operation.
//
// Verify that every single-byte op code other than 0x02 is rejected.
func TestC02_XWingOnlyEncapsulateAllowed(t *testing.T) {
	for op := byte(0x00); op <= 0x10; op++ {
		if op == OpEncapsulate {
			continue
		}
		input := []byte{op}
		gas := XWingPrecompile.RequiredGas(input)
		require.Equal(t, uint64(0), gas, "Op 0x%02x must not have gas cost", op)

		ret, _, err := XWingPrecompile.Run(
			nil,
			common.Address{},
			ContractAddress,
			input,
			1_000_000,
			false,
		)
		require.Error(t, err, "Op 0x%02x must be rejected", op)
		require.Nil(t, ret, "Op 0x%02x must not return data", op)
	}
}
