// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_SingleByte(t *testing.T) {
	_, _, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, []byte{0x01}, 100000, true)
	require.Error(t, err)
}

func TestDeep_AllZeros(t *testing.T) {
	// Full-sized but all-zero input
	input := make([]byte, 256)
	gas := FROSTVerifyPrecompile.RequiredGas(input)
	ret, _, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, gas+100000, true)
	if err == nil {
		require.Equal(t, byte(0), ret[31], "all zeros must not verify")
	}
}

func TestDeep_GasInsufficient(t *testing.T) {
	input := make([]byte, 128)
	gas := FROSTVerifyPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 128)
	_, _, err := FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, 0, true)
	require.Error(t, err)
}

func TestDeep_GasNonZeroForNil(t *testing.T) {
	// FROST charges base gas even for nil input
	gas := FROSTVerifyPrecompile.RequiredGas(nil)
	require.Greater(t, gas, uint64(0))
}

func TestDeep_Concurrent(t *testing.T) {
	input := make([]byte, 128)
	gas := FROSTVerifyPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic: %v", r)
				}
			}()
			FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, gas+100000, true)
		})
	}
	wg.Wait()
}

func FuzzFROST(f *testing.F) {
	f.Add(make([]byte, 128))
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := FROSTVerifyPrecompile.RequiredGas(input)
		FROSTVerifyPrecompile.Run(nil, addr0, ContractFROSTVerifyAddress, input, gas+100000, true)
	})
}
