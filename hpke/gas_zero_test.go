// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hpke

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

func TestGasZero_Rejected(t *testing.T) {
	// Valid OpSingleShotSeal with zero calldata — enough to reach gas check.
	input := make([]byte, 64)
	input[0] = 0x20 // OpSingleShotSeal
	_, remainingGas, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err, "gas=0 must error")
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas)
}
