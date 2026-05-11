// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_SingleByte(t *testing.T) {
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, []byte{0x01}, 100000, true)
	require.Error(t, err)
}

func TestDeep_InvalidOp(t *testing.T) {
	input := make([]byte, 100)
	input[0] = 0xFF
	gas := ZKVerifyPrecompile.RequiredGas(input)
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, input, gas+10000, true)
	require.Error(t, err)
}

func TestDeep_AllOps_ShortInput(t *testing.T) {
	ops := []byte{OpVerifyNullifier, OpVerifyCommitment}
	for _, op := range ops {
		input := []byte{op, 0x00}
		gas := ZKVerifyPrecompile.RequiredGas(input)
		_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, input, gas+100000, true)
		require.Error(t, err, "op=0x%02x with short input must error", op)
	}
}

func TestDeep_GasAccounting(t *testing.T) {
	ops := []byte{OpVerifyNullifier, OpVerifyCommitment}
	for _, op := range ops {
		input := make([]byte, 100)
		input[0] = op
		gas := ZKVerifyPrecompile.RequiredGas(input)
		if gas > 0 {
			_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, input, gas-1, true)
			require.Error(t, err, "op=0x%02x must fail with insufficient gas", op)
		}
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 100)
	input[0] = OpVerifyNullifier
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, input, 0, true)
	require.Error(t, err)
}

func TestDeep_GasForNil(t *testing.T) {
	// ZK precompile may charge base gas even for nil
	_ = ZKVerifyPrecompile.RequiredGas(nil)
	_ = ZKVerifyPrecompile.RequiredGas([]byte{})
}

func TestDeep_Concurrent(t *testing.T) {
	input := make([]byte, 100)
	input[0] = OpVerifyNullifier
	gas := ZKVerifyPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic in concurrent run: %v", r)
				}
			}()
			ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, input, gas+100000, true)
		})
	}
	wg.Wait()
}

func FuzzZK(f *testing.F) {
	f.Add([]byte{OpVerifyNullifier, 0x00})
	f.Add([]byte{OpVerifyCommitment, 0x00})
	f.Add([]byte{0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := ZKVerifyPrecompile.RequiredGas(input)
		ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, input, gas+100000, true)
	})
}
