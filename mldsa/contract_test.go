// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
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
	for i := range 8 {
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
	require.ErrorIs(t, err, contract.ErrInvalidInput)
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

// --- Batch Verify Tests ---

// createBatchInput builds calldata for OpBatchVerify
func createBatchInput(mode uint8, entries []struct{ pk, sig, msg []byte }) []byte {
	count := len(entries)
	out := []byte{OpBatchVerify, mode, byte(count >> 8), byte(count)}
	for _, e := range entries {
		out = append(out, e.pk...)
		msgLen := make([]byte, 32)
		for i := range 8 {
			msgLen[31-i] = byte(len(e.msg) >> (i * 8))
		}
		out = append(out, msgLen...)
		out = append(out, e.sig...)
		out = append(out, e.msg...)
	}
	return out
}

func TestBatchVerify_SingleSig(t *testing.T) {
	message := []byte("batch single sig test")
	pk, sig, msg := createTestSignature(t, mldsa.MLDSA65, message)

	// Single verify
	singleInput := createInputWithMode(ModeMLDSA65, pk, sig, msg)
	singleGas := MLDSAVerifyPrecompile.RequiredGas(singleInput)
	singleRet, _, singleErr := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, singleInput, singleGas, false)
	require.NoError(t, singleErr)

	// Batch verify with 1 entry
	entries := []struct{ pk, sig, msg []byte }{{pk, sig, msg}}
	batchInput := createBatchInput(ModeMLDSA65, entries)
	batchGas := MLDSAVerifyPrecompile.RequiredGas(batchInput)
	batchRet, _, batchErr := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, batchInput, batchGas, false)
	require.NoError(t, batchErr)

	// Single returns 1 in last byte of 32-byte word
	require.Equal(t, byte(1), singleRet[31])
	// Batch returns 1 in last byte of 32-byte word (1 result, right-aligned)
	require.Equal(t, byte(1), batchRet[31])
}

func TestBatchVerify_MultipleSigs(t *testing.T) {
	// 3 valid signatures + 1 invalid
	type entry struct{ pk, sig, msg []byte }
	var entries []entry

	for i := range 3 {
		msg := fmt.Appendf(nil, "valid message %d", i)
		pk, sig, m := createTestSignature(t, mldsa.MLDSA65, msg)
		entries = append(entries, entry{pk, sig, m})
	}

	// 4th: valid keygen but corrupted signature
	msg4 := []byte("invalid signature message")
	pk4, sig4, m4 := createTestSignature(t, mldsa.MLDSA65, msg4)
	sig4[0] ^= 0xFF
	entries = append(entries, entry{pk4, sig4, m4})

	batchEntries := make([]struct{ pk, sig, msg []byte }, len(entries))
	for i, e := range entries {
		batchEntries[i] = struct{ pk, sig, msg []byte }{e.pk, e.sig, e.msg}
	}

	input := createBatchInput(ModeMLDSA65, batchEntries)
	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, gas, false)

	require.NoError(t, err)
	require.Len(t, ret, 32)
	// 4 results right-aligned in 32 bytes: positions [28]=valid, [29]=valid, [30]=valid, [31]=invalid
	require.Equal(t, byte(1), ret[28], "entry 0 should be valid")
	require.Equal(t, byte(1), ret[29], "entry 1 should be valid")
	require.Equal(t, byte(1), ret[30], "entry 2 should be valid")
	require.Equal(t, byte(0), ret[31], "entry 3 should be invalid")
}

func TestBatchVerify_Empty(t *testing.T) {
	input := []byte{OpBatchVerify, ModeMLDSA65, 0x00, 0x00}
	gas := MLDSAVerifyPrecompile.RequiredGas(input)
	ret, remaining, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, gas, false)

	require.NoError(t, err)
	require.Len(t, ret, 32)
	// All zeros
	for i := range ret {
		require.Equal(t, byte(0), ret[i])
	}
	require.Equal(t, gas-gas, remaining) // all gas consumed
}

func TestBatchVerify_GasCost(t *testing.T) {
	// Batch of N should cost less than N * single verify
	msg := []byte("gas test message")
	pk, sig, m := createTestSignature(t, mldsa.MLDSA65, msg)

	// Single verify gas
	singleInput := createInputWithMode(ModeMLDSA65, pk, sig, m)
	singleGas := MLDSAVerifyPrecompile.RequiredGas(singleInput)

	for _, n := range []int{1, 3, 5, 10} {
		entries := make([]struct{ pk, sig, msg []byte }, n)
		for i := range entries {
			entries[i] = struct{ pk, sig, msg []byte }{pk, sig, m}
		}
		batchInput := createBatchInput(ModeMLDSA65, entries)
		batchGas := MLDSAVerifyPrecompile.RequiredGas(batchInput)

		totalSingleGas := uint64(n) * singleGas
		require.Less(t, batchGas, totalSingleGas,
			"batch of %d: %d should be < %d (N * single)", n, batchGas, totalSingleGas)
	}
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
