// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_SingleByte(t *testing.T) {
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, []byte{0x01}, 100000, true)
	require.Error(t, err)
}

func TestDeep_AllZeros(t *testing.T) {
	input := make([]byte, 4096)
	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, input, gas+100000, true)
	if err == nil {
		require.Equal(t, byte(0), ret[31], "all zeros must not verify")
	}
}

func TestDeep_GasInsufficient(t *testing.T) {
	input := make([]byte, 100)
	input[0] = 0x01
	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 100)
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, input, 0, true)
	require.Error(t, err)
}

func TestDeep_Address(t *testing.T) {
	require.Equal(t, ContractSLHDSAVerifyAddress, SLHDSAVerifyPrecompile.Address())
}

func TestDeep_Concurrent(t *testing.T) {
	input := make([]byte, 100)
	input[0] = 0x01
	gas := SLHDSAVerifyPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic: %v", r)
				}
			}()
			SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, input, gas+100000, true)
		})
	}
	wg.Wait()
}

func FuzzSLHDSA(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x20})
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := SLHDSAVerifyPrecompile.RequiredGas(input)
		SLHDSAVerifyPrecompile.Run(nil, addr0, ContractSLHDSAVerifyAddress, input, gas+100000, true)
	})
}
