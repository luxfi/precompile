// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ringtailthreshold

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

func TestGasZero_Rejected(t *testing.T) {
	input := make([]byte, 128)
	_, remainingGas, err := RingtailThresholdPrecompile.Run(nil, common.Address{}, RingtailThresholdPrecompile.Address(), input, 0, true)
	require.Error(t, err)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remainingGas)
}
