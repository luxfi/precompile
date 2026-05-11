// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package babyjubjub

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestGasZero_Rejected asserts the precompile refuses to execute with zero
// gas and returns contract.ErrOutOfGas. Red team flagged this as a
// cross-cutting gap across the entire precompile library.
func TestGasZero_Rejected(t *testing.T) {
	p := &babyJubJubPrecompile{}
	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul

	_, remainingGas, err := p.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err, "gas=0 must error")
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas, "no gas consumed on failure")
}
