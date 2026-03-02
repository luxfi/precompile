// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

func TestGasZero_Rejected(t *testing.T) {
	input := make([]byte, 1+64)
	input[0] = OpCommit // 0x01
	_, remainingGas, err := PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas)
}
