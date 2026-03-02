// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pasta

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

func TestGasZero_Rejected(t *testing.T) {
	// Valid-shape input: curve selector (Pallas=0x01) + OpPointAdd + two points.
	// This ensures we reach the gas check path rather than failing input
	// validation first.
	input := make([]byte, 1+1+128) // curve + op + 2 points
	input[0] = 0x01                // Pallas curve
	input[1] = OpPointAdd
	_, remainingGas, err := PastaPrecompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.Error(t, err, "gas=0 must error")
	require.ErrorIs(t, err, contract.ErrOutOfGas,
		"must reject with ErrOutOfGas before consuming gas")
	require.Zero(t, remainingGas, "no gas consumed on gas=0 rejection")
}
