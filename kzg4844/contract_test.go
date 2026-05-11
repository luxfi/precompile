// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestRetiredAddress confirms the reserved address is stable across releases.
func TestRetiredAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0xB002"), KZG4844Precompile.Address())
}

// TestForbiddenInPQ confirms every call refuses execution and deducts
// the minimum gas to prevent zero-cost probing.
func TestForbiddenInPQ(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{},
		{0x01},
		make([]byte, 4096),
	} {
		_, remainingGas, err := KZG4844Precompile.Run(
			nil, common.Address{}, ContractAddress, input, MinCallGas, true,
		)
		require.ErrorIs(t, err, contract.ErrClassicalForbiddenInPQ)
		require.Equal(t, uint64(0), remainingGas)
	}
}
