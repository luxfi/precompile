// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_SingleByte(t *testing.T) {
	_, _, err := CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, []byte{0x01}, 100000, true)
	require.Error(t, err)
}

func TestDeep_AllZeros(t *testing.T) {
	input := make([]byte, 256)
	gas := CGGMP21VerifyPrecompile.RequiredGas(input)
	ret, _, err := CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, input, gas+100000, true)
	if err == nil {
		require.Equal(t, byte(0), ret[31], "all zeros must not verify")
	}
}

func TestDeep_GasInsufficient(t *testing.T) {
	input := make([]byte, 128)
	gas := CGGMP21VerifyPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 128)
	_, _, err := CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, input, 0, true)
	require.Error(t, err)
}

func TestDeep_GasNonZeroForNil(t *testing.T) {
	gas := CGGMP21VerifyPrecompile.RequiredGas(nil)
	require.Greater(t, gas, uint64(0))
}

func TestDeep_Concurrent(t *testing.T) {
	input := make([]byte, 128)
	gas := CGGMP21VerifyPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic: %v", r)
				}
			}()
			CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, input, gas+100000, true)
		})
	}
	wg.Wait()
}

func FuzzCGGMP21(f *testing.F) {
	f.Add(make([]byte, 128))
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := CGGMP21VerifyPrecompile.RequiredGas(input)
		CGGMP21VerifyPrecompile.Run(nil, addr0, ContractCGGMP21VerifyAddress, input, gas+100000, true)
	})
}
