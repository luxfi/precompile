// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sr25519

import (
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_SingleByte(t *testing.T) {
	_, _, err := SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, []byte{0x01}, 100000, true)
	require.Error(t, err)
}

func TestDeep_AllZeros(t *testing.T) {
	input := make([]byte, 128)
	gas := SR25519VerifyPrecompile.RequiredGas(input)
	ret, _, err := SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	if err == nil {
		require.Equal(t, byte(0), ret[31], "all zeros must not verify")
	}
}

func TestDeep_GasInsufficient(t *testing.T) {
	input := make([]byte, 128)
	gas := SR25519VerifyPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 128)
	_, _, err := SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, input, 0, true)
	require.Error(t, err)
}

func TestDeep_GasEmpty(t *testing.T) {
	// sr25519 charges base gas even for short/nil input
	require.Equal(t, SR25519VerifyBaseGas, SR25519VerifyPrecompile.RequiredGas(nil))
}

func TestDeep_Concurrent(t *testing.T) {
	input := make([]byte, 128)
	gas := SR25519VerifyPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic: %v", r)
				}
			}()
			SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
		})
	}
	wg.Wait()
}

func FuzzSR25519(f *testing.F) {
	f.Add(make([]byte, 128))
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := SR25519VerifyPrecompile.RequiredGas(input)
		SR25519VerifyPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}
