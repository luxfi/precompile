// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestRetiredAddress confirms the reserved address is stable across releases.
func TestRetiredAddress(t *testing.T) {
	require.Equal(t,
		common.HexToAddress("0x0500000000000000000000000000000000000006"),
		ContractAddress,
	)
}

// TestForbiddenInPQ confirms every call refuses execution.
func TestForbiddenInPQ(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{},
		{0x01},
		make([]byte, 1+64),
		make([]byte, 1+1+32*32+32),
	} {
		_, remainingGas, err := PedersenPrecompile.Run(
			nil, common.Address{}, ContractAddress, input, MinCallGas, true,
		)
		require.ErrorIs(t, err, contract.ErrClassicalForbiddenInPQ)
		require.Equal(t, uint64(0), remainingGas)
	}
}
