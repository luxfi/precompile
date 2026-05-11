// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestGasZero_Rejected asserts the retired precompile refuses to execute
// with zero gas and returns contract.ErrOutOfGas.
func TestGasZero_Rejected(t *testing.T) {
	input := make([]byte, 192)
	_, remainingGas, err := KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas)
}
