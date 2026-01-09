// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// createTestSignature creates test keys and signatures using the specified mode
func createTestSignature(t testing.TB, mode mldsa.Mode, message []byte) ([]byte, []byte, []byte) {
	priv, err := mldsa.GenerateKey(rand.Reader, mode)
	require.NoError(t, err)

	signature, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)

	return priv.PublicKey.Bytes(), signature, message
}

// createInputWithMode creates precompile input with mode byte
func createInputWithMode(mode uint8, pk, signature, message []byte) []byte {
	input := make([]byte, 0)
	input = append(input, mode)
	input = append(input, pk...)

	// Message length as big-endian uint256
	msgLen := make([]byte, 32)
	for i := 0; i < 8; i++ {
		msgLen[31-i] = byte(len(message) >> (i * 8))
	}
	input = append(input, msgLen...)
	input = append(input, signature...)
	input = append(input, message...)

	return input
}

func TestMLDSAVerify_ValidSignature_MLDSA65(t *testing.T) {
	message := []byte("test message for ML-DSA-65 verification")
	pk, signature, msg := createTestSignature(t, mldsa.MLDSA65, message)

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, remainingGas, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
	require.Len(t, ret, 32)
	require.Equal(t, byte(1), ret[31])
}

func TestMLDSAVerify_ValidSignature_MLDSA44(t *testing.T) {
	message := []byte("test message for ML-DSA-44 verification")
	pk, signature, msg := createTestSignature(t, mldsa.MLDSA44, message)

	input := createInputWithMode(ModeMLDSA44, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, remainingGas, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
	require.Len(t, ret, 32)
	require.Equal(t, byte(1), ret[31])
}

func TestMLDSAVerify_ValidSignature_MLDSA87(t *testing.T) {
	message := []byte("test message for ML-DSA-87 verification")
	pk, signature, msg := createTestSignature(t, mldsa.MLDSA87, message)

	input := createInputWithMode(ModeMLDSA87, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, remainingGas, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, uint64(0), remainingGas)
	require.Len(t, ret, 32)
	require.Equal(t, byte(1), ret[31])
}

func TestMLDSAVerify_InvalidSignature(t *testing.T) {
	message := []byte("test message")
	pk, signature, msg := createTestSignature(t, mldsa.MLDSA65, message)

	// Modify signature to make it invalid
	signature[0] ^= 0xFF

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Len(t, ret, 32)
	require.Equal(t, byte(0), ret[31])
}

func TestMLDSAVerify_WrongMessage(t *testing.T) {
	message1 := []byte("original message")
	pk, signature, _ := createTestSignature(t, mldsa.MLDSA65, message1)

	message2 := []byte("different message")

	input := createInputWithMode(ModeMLDSA65, pk, signature, message2)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Len(t, ret, 32)
	require.Equal(t, byte(0), ret[31])
}

func TestMLDSAVerify_InputTooShort(t *testing.T) {
	// Use a valid mode byte so we test input length, not mode validation
	input := make([]byte, 100)
	input[0] = ModeMLDSA65 // Valid mode, but input is too short

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.Error(t, err)
	require.Nil(t, ret)
	require.Contains(t, err.Error(), "invalid input length")
}

func TestMLDSAVerify_InvalidMode(t *testing.T) {
	// Use an invalid mode byte
	input := make([]byte, 5000)
	input[0] = 0xFF // Invalid mode

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.Error(t, err)
	require.Nil(t, ret)
	require.Contains(t, err.Error(), "unsupported")
}

func TestMLDSAVerify_EmptyMessage(t *testing.T) {
	message := []byte("")
	pk, signature, msg := createTestSignature(t, mldsa.MLDSA65, message)

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, byte(1), ret[31])
}

func TestMLDSAVerify_LargeMessage(t *testing.T) {
	message := make([]byte, 10240)
	for i := range message {
		message[i] = byte(i % 256)
	}

	pk, signature, msg := createTestSignature(t, mldsa.MLDSA65, message)

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	ret, _, err := MLDSAVerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractMLDSAVerifyAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, byte(1), ret[31])
}

func TestMLDSAVerify_GasCost(t *testing.T) {
	message := []byte("test")
	pk, signature, msg := createTestSignature(t, mldsa.MLDSA65, message)

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	// Calculate expected gas
	expectedGas := MLDSAVerifyPrecompile.RequiredGas(input)

	// Should be base cost + per-byte cost
	require.GreaterOrEqual(t, expectedGas, uint64(100000)) // ML-DSA-65 base cost

	// Verify per-mode gas costs
	tests := []struct {
		mode   uint8
		minGas uint64
		maxGas uint64
	}{
		{ModeMLDSA44, 75000, 80000},   // Smaller keys, faster
		{ModeMLDSA65, 100000, 110000}, // Medium
		{ModeMLDSA87, 150000, 160000}, // Larger keys, slower
	}

	for _, tt := range tests {
		input := make([]byte, 5000)
		input[0] = tt.mode
		gas := MLDSAVerifyPrecompile.RequiredGas(input)
		require.GreaterOrEqual(t, gas, tt.minGas, "Mode 0x%x gas too low", tt.mode)
	}
}

func TestMLDSAPrecompile_Address(t *testing.T) {
	expectedAddr := common.HexToAddress("0x0200000000000000000000000000000000000006")
	require.Equal(t, expectedAddr, ContractMLDSAVerifyAddress)
	require.Equal(t, expectedAddr, MLDSAVerifyPrecompile.Address())
}

// Benchmark tests
func BenchmarkMLDSAVerify_SmallMessage(b *testing.B) {
	message := []byte("small test message")
	pk, signature, msg := createTestSignature(b, mldsa.MLDSA65, message)

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = MLDSAVerifyPrecompile.Run(
			nil,
			common.Address{},
			ContractMLDSAVerifyAddress,
			input,
			gas,
			false,
		)
	}
}

func BenchmarkMLDSAVerify_LargeMessage(b *testing.B) {
	message := make([]byte, 10240)
	pk, signature, msg := createTestSignature(b, mldsa.MLDSA65, message)

	input := createInputWithMode(ModeMLDSA65, pk, signature, msg)

	gas := MLDSAVerifyPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = MLDSAVerifyPrecompile.Run(
			nil,
			common.Address{},
			ContractMLDSAVerifyAddress,
			input,
			gas,
			false,
		)
	}
}

func BenchmarkMLDSAVerify_AllModes(b *testing.B) {
	modes := []struct {
		name string
		mode mldsa.Mode
		byte uint8
	}{
		{"ML-DSA-44", mldsa.MLDSA44, ModeMLDSA44},
		{"ML-DSA-65", mldsa.MLDSA65, ModeMLDSA65},
		{"ML-DSA-87", mldsa.MLDSA87, ModeMLDSA87},
	}

	message := []byte("benchmark message for all modes")

	for _, m := range modes {
		b.Run(m.name, func(b *testing.B) {
			pk, signature, msg := createTestSignature(b, m.mode, message)
			input := createInputWithMode(m.byte, pk, signature, msg)
			gas := MLDSAVerifyPrecompile.RequiredGas(input)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _ = MLDSAVerifyPrecompile.Run(
					nil,
					common.Address{},
					ContractMLDSAVerifyAddress,
					input,
					gas,
					false,
				)
			}
		})
	}
}
