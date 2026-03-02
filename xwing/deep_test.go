// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xwing

import (
	"sync"
	"testing"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

func TestDeep_NilInput(t *testing.T) {
	_, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_InvalidOp(t *testing.T) {
	input := make([]byte, 100)
	input[0] = 0xFF
	_, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, input, 100000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestDeep_Encapsulate_Valid(t *testing.T) {
	scheme := xwing.Scheme()
	pub, priv, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	pubBytes, err := pub.MarshalBinary()
	require.NoError(t, err)

	input := append([]byte{OpEncapsulate}, pubBytes...)
	gas := XWingPrecompile.RequiredGas(input)
	ret, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	require.NoError(t, err)
	require.NotEmpty(t, ret)

	// Parse ct and ss from result
	ctSize := scheme.CiphertextSize()
	ssSize := scheme.SharedKeySize()
	require.GreaterOrEqual(t, len(ret), 2+ctSize+ssSize)

	retCtLen := int(ret[0])<<8 | int(ret[1])
	ct := ret[2 : 2+retCtLen]
	ss := ret[2+retCtLen : 2+retCtLen+ssSize]

	// Decapsulate to verify
	privBytes, _ := priv.MarshalBinary()
	privKey, _ := scheme.UnmarshalBinaryPrivateKey(privBytes)
	ssExpected, err := scheme.Decapsulate(privKey, ct)
	require.NoError(t, err)
	require.Equal(t, ssExpected, ss, "shared secrets must match")
}

func TestDeep_Encapsulate_ShortInput(t *testing.T) {
	input := []byte{OpEncapsulate, 0x00} // no pubkey
	gas := XWingPrecompile.RequiredGas(input)
	_, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	require.Error(t, err)
}

func TestDeep_GasInsufficient(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _, _ := scheme.GenerateKeyPair()
	pubBytes, _ := pub.MarshalBinary()
	input := append([]byte{OpEncapsulate}, pubBytes...)
	gas := XWingPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_Concurrent(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _, _ := scheme.GenerateKeyPair()
	pubBytes, _ := pub.MarshalBinary()
	input := append([]byte{OpEncapsulate}, pubBytes...)
	gas := XWingPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			ret, _, err := XWingPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
			require.NoError(t, err)
			require.NotEmpty(t, ret)
		})
	}
	wg.Wait()
}

func FuzzXWing(f *testing.F) {
	f.Add([]byte{OpEncapsulate})
	f.Add([]byte{0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := XWingPrecompile.RequiredGas(input)
		XWingPrecompile.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}
