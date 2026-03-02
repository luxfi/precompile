// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"sync"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_InvalidOp(t *testing.T) {
	input := make([]byte, 100)
	input[0] = 0xFF
	gas := MLKEMPrecompile.RequiredGas(input)
	_, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
}

func TestDeep_OpEncapsulate_ShortInput(t *testing.T) {
	input := []byte{OpEncapsulate, ModeMLKEM768}
	gas := MLKEMPrecompile.RequiredGas(input)
	_, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
}

func TestDeep_Encapsulate_768(t *testing.T) {
	pub, _, err := mlkem768.GenerateKeyPair(nil)
	require.NoError(t, err)

	pubBytes, err := pub.MarshalBinary()
	require.NoError(t, err)

	input := make([]byte, 0, 2+SeedSize+len(pubBytes))
	input = append(input, OpEncapsulate)
	input = append(input, ModeMLKEM768)
	input = append(input, make([]byte, SeedSize)...) // deterministic seed
	input = append(input, pubBytes...)

	gas := MLKEMPrecompile.RequiredGas(input)
	ret, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	require.NoError(t, err)
	require.NotEmpty(t, ret, "encapsulate must return ciphertext+shared_secret")
}

func TestDeep_Encapsulate_InvalidPubKey(t *testing.T) {
	input := make([]byte, 2+SeedSize+1184)
	input[0] = OpEncapsulate
	input[1] = ModeMLKEM768
	gas := MLKEMPrecompile.RequiredGas(input)
	// Invalid pubkey -- may error or return empty
	_, _, _ = MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
}

func TestDeep_GasInsufficient(t *testing.T) {
	pub, _, _ := mlkem768.GenerateKeyPair(nil)
	pubBytes, _ := pub.MarshalBinary()
	input := append(append([]byte{OpEncapsulate, ModeMLKEM768}, make([]byte, SeedSize)...), pubBytes...)
	gas := MLKEMPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 100)
	input[0] = OpEncapsulate
	_, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, 0, true)
	require.Error(t, err)
}

func TestDeep_Concurrent(t *testing.T) {
	pub, _, _ := mlkem768.GenerateKeyPair(nil)
	pubBytes, _ := pub.MarshalBinary()
	input := append(append([]byte{OpEncapsulate, ModeMLKEM768}, make([]byte, SeedSize)...), pubBytes...)
	gas := MLKEMPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			ret, _, err := MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
			require.NoError(t, err)
			require.NotEmpty(t, ret)
		})
	}
	wg.Wait()
}

func FuzzMLKEM(f *testing.F) {
	f.Add([]byte{OpEncapsulate, ModeMLKEM768})
	f.Add([]byte{0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := MLKEMPrecompile.RequiredGas(input)
		MLKEMPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}
