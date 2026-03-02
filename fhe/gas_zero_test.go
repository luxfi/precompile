// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

func TestGasZero_Rejected(t *testing.T) {
	// Use the add(bytes32,bytes32) selector to reach a real handler path.
	// Format: [4-byte selector][2 x 32-byte ciphertext handles]
	input := make([]byte, 4+64)
	copy(input[:4], []byte{0x23, 0xb8, 0x72, 0xdd}) // add(bytes32,bytes32)
	_, remainingGas, err := FHEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas)
}
