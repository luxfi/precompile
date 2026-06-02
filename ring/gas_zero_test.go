// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

func TestGasZero_Rejected(t *testing.T) {
	// Valid OpVerify + valid SchemeLSAGSecp256k1 ensures we reach the
	// gas check path rather than failing scheme validation first.
	input := make([]byte, 128)
	input[0] = OpVerify            // 0x02 — only supported op
	input[1] = SchemeLSAGSecp256k1 // 0x01
	_, remainingGas, err := RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas)
}
