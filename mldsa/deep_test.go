// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

// --- Edge Cases ---

func TestDeep_NilInput(t *testing.T) {
	_, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_EmptyInput(t *testing.T) {
	_, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestDeep_SingleByte(t *testing.T) {
	_, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, []byte{0x00}, 100000, true)
	require.Error(t, err)
}

func TestDeep_AllZeros(t *testing.T) {
	input := make([]byte, 2+1952+2+32+3293)
	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas+1_000_000, true)
	if err == nil {
		require.Equal(t, byte(0), ret[31], "all zeros must not verify")
	}
}

// --- Cryptographic Correctness ---

// buildMLDSAInput builds the correct input format:
// mode(1) + pubkey(pubKeySize) + msg_len(32 as uint256) + sig(sigSize) + msg
func buildMLDSAInput(t *testing.T, mode byte, pubBytes, msg, sigBytes []byte) []byte {
	t.Helper()
	msgLenBytes := make([]byte, 32)
	msgLenBytes[31] = byte(len(msg))
	if len(msg) > 255 {
		msgLenBytes[30] = byte(len(msg) >> 8)
	}

	input := make([]byte, 0, 1+len(pubBytes)+32+len(sigBytes)+len(msg))
	input = append(input, mode)
	input = append(input, pubBytes...)
	input = append(input, msgLenBytes...)
	input = append(input, sigBytes...)
	input = append(input, msg...)
	return input
}

func TestDeep_ValidSignature(t *testing.T) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	require.NoError(t, err)

	msg := []byte("test message for ML-DSA-65")
	sigBytes := make([]byte, mldsa65.SignatureSize)
	err = mldsa65.SignTo(priv, msg, precompileCtx, false, sigBytes)
	require.NoError(t, err)

	pubBytes, _ := pub.MarshalBinary()
	input := buildMLDSAInput(t, ModeMLDSA65, pubBytes, msg, sigBytes)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas+1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31], "valid ML-DSA-65 signature must verify")
}

func TestDeep_WrongMessage(t *testing.T) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	require.NoError(t, err)

	msg := []byte("original")
	sigBytes := make([]byte, mldsa65.SignatureSize)
	err = mldsa65.SignTo(priv, msg, precompileCtx, false, sigBytes)
	require.NoError(t, err)

	pubBytes, _ := pub.MarshalBinary()
	input := buildMLDSAInput(t, ModeMLDSA65, pubBytes, []byte("tampered"), sigBytes)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas+1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), ret[31])
}

func TestDeep_BitFlipSig(t *testing.T) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	require.NoError(t, err)

	msg := []byte("bit flip ML-DSA")
	sigBytes := make([]byte, mldsa65.SignatureSize)
	err = mldsa65.SignTo(priv, msg, precompileCtx, false, sigBytes)
	require.NoError(t, err)
	sigBytes[0] ^= 0x01

	pubBytes, _ := pub.MarshalBinary()
	input := buildMLDSAInput(t, ModeMLDSA65, pubBytes, msg, sigBytes)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas+1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), ret[31])
}

// --- Gas Accounting ---

func TestDeep_GasInsufficient(t *testing.T) {
	input := make([]byte, 100)
	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	if gas > 0 {
		_, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas-1, true)
		require.Error(t, err)
	}
}

func TestDeep_GasZero(t *testing.T) {
	input := make([]byte, 100)
	_, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, 0, true)
	require.Error(t, err)
}

// --- Concurrency ---

func TestDeep_Concurrent(t *testing.T) {
	pub, priv, _ := mldsa65.GenerateKey(nil)
	msg := []byte("concurrent ML-DSA")
	sigBytes := make([]byte, mldsa65.SignatureSize)
	_ = mldsa65.SignTo(priv, msg, precompileCtx, false, sigBytes)
	pubBytes, _ := pub.MarshalBinary()
	input := buildMLDSAInput(t, ModeMLDSA65, pubBytes, msg, sigBytes)
	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			ret, _, err := MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas+1_000_000, true)
			require.NoError(t, err)
			require.Equal(t, byte(1), ret[31])
		})
	}
	wg.Wait()
}

// --- Fuzz ---

func FuzzMLDSA(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x20})
	f.Add([]byte{0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := MLDSAVerifyPrecompile.RequiredGas(input)
		MLDSAVerifyPrecompile.Run(nil, addr0, ContractMLDSAVerifyAddress, input, gas+1_000_000, true)
	})
}
