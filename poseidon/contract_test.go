// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0500000000000000000000000000000000000005"), ContractAddress)
}

func TestHash_SingleElement(t *testing.T) {
	p := &poseidonPrecompile{}

	// Hash of a single zero field element
	input := make([]byte, 1+32)
	input[0] = OpHash
	// data[1:33] = 0 (zero element)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
	require.False(t, isZero(ret), "hash of zero should not be zero")
}

func TestHash_TwoElements(t *testing.T) {
	p := &poseidonPrecompile{}

	// Hash [1, 2] as field elements
	input := make([]byte, 1+64)
	input[0] = OpHash
	input[32] = 1 // first element = 1 (big-endian, last byte of first 32-byte word)
	input[64] = 2 // second element = 2

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}

func TestHash_Determinism(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+32)
	input[0] = OpHash
	input[32] = 42

	gas := p.RequiredGas(input)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(ret1, ret2), "Poseidon must be deterministic")
}

func TestHash_DifferentInputs(t *testing.T) {
	p := &poseidonPrecompile{}

	input1 := make([]byte, 1+32)
	input1[0] = OpHash
	input1[32] = 1

	input2 := make([]byte, 1+32)
	input2[0] = OpHash
	input2[32] = 2

	gas := p.RequiredGas(input1)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input1, gas, true)
	require.NoError(t, err)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input2, gas, true)
	require.NoError(t, err)

	require.False(t, bytes.Equal(ret1, ret2), "different inputs must produce different hashes")
}

func TestHashPair(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+64)
	input[0] = OpHashPair
	input[32] = 1 // left = 1
	input[64] = 2 // right = 2

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}

func TestHashPair_ConsistentWithHash(t *testing.T) {
	p := &poseidonPrecompile{}

	// HashPair(left, right) should equal Hash([left, right])
	left := make([]byte, 32)
	left[31] = 5
	right := make([]byte, 32)
	right[31] = 7

	// HashPair
	pairInput := make([]byte, 1+64)
	pairInput[0] = OpHashPair
	copy(pairInput[1:33], left)
	copy(pairInput[33:65], right)

	gas := p.RequiredGas(pairInput)
	pairResult, _, err := p.Run(nil, common.Address{}, ContractAddress, pairInput, gas, true)
	require.NoError(t, err)

	// Hash with 2 elements
	hashInput := make([]byte, 1+64)
	hashInput[0] = OpHash
	copy(hashInput[1:33], left)
	copy(hashInput[33:65], right)

	gas = p.RequiredGas(hashInput)
	hashResult, _, err := p.Run(nil, common.Address{}, ContractAddress, hashInput, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(pairResult, hashResult), "HashPair and Hash with 2 elements should match")
}

func TestHashPair_InputTooShort(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+32) // only 1 element, need 2
	input[0] = OpHashPair

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestHash_TooManyElements(t *testing.T) {
	p := &poseidonPrecompile{}

	// 17 elements exceeds the max of 16
	input := make([]byte, 1+17*32)
	input[0] = OpHash

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTooManyInputs)
}

func TestHash_BadAlignment(t *testing.T) {
	p := &poseidonPrecompile{}

	// 33 bytes after opcode = not divisible by 32
	input := make([]byte, 1+33)
	input[0] = OpHash

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestSponge(t *testing.T) {
	p := &poseidonPrecompile{}

	// Sponge: 4 bytes outLen + n*32 bytes data
	input := make([]byte, 1+4+32)
	input[0] = OpSponge
	binary.BigEndian.PutUint32(input[1:5], 32) // request 32 bytes output
	input[36] = 1                              // one field element = 1

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}

func TestSponge_CustomOutputLen(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+4+32)
	input[0] = OpSponge
	binary.BigEndian.PutUint32(input[1:5], 16) // request 16 bytes output
	input[36] = 42

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 16)
}

func TestSponge_ZeroOutputLen(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+4+32)
	input[0] = OpSponge
	binary.BigEndian.PutUint32(input[1:5], 0) // zero output

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestSponge_OutputTooLarge(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+4+32)
	input[0] = OpSponge
	binary.BigEndian.PutUint32(input[1:5], 2048) // exceeds 1024 max

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestInvalidOperation(t *testing.T) {
	p := &poseidonPrecompile{}

	input := []byte{0xFF, 0x00}
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+1000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEmptyInput(t *testing.T) {
	p := &poseidonPrecompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 10000, true)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &poseidonPrecompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"hash_1elem", func() []byte {
			b := make([]byte, 1+32)
			b[0] = OpHash
			return b
		}(), GasHashBase + 1*GasPerElement},
		{"hash_4elem", func() []byte {
			b := make([]byte, 1+4*32)
			b[0] = OpHash
			return b
		}(), GasHashBase + 4*GasPerElement},
		{"hashpair", []byte{OpHashPair}, GasHashPair},
		{"sponge_1elem", func() []byte {
			b := make([]byte, 1+4+32)
			b[0] = OpSponge
			return b
		}(), GasSpongeBase + 1*GasSpongePerIn},
		{"invalid_op", []byte{0xFF}, 0},
		{"empty", []byte{}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gas := p.RequiredGas(tc.input)
			require.Equal(t, tc.expected, gas)
		})
	}
}

func TestOutOfGas(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+32)
	input[0] = OpHash
	input[32] = 1

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 10, true)
	require.Error(t, err)
}

// Regression: H-01 — Sponge must squeeze (not zero-pad) for output > 32 bytes.
// The old code copied only the first 32 bytes from the Merkle-Damgard hasher
// and left the remaining output as zeros.
func TestSponge_LargeOutput_NotZeroPadded(t *testing.T) {
	p := &poseidonPrecompile{}

	// Request 128 bytes of output (4 sponge blocks)
	input := make([]byte, 1+4+32)
	input[0] = OpSponge
	binary.BigEndian.PutUint32(input[1:5], 128)
	input[36] = 0x42 // one non-zero input element

	gas := p.RequiredGas(input) + 100000 // generous gas for sponge
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 128)

	// The first 32 bytes are from the initial squeeze
	firstBlock := ret[:32]
	require.False(t, isZero(firstBlock), "first sponge block must not be zero")

	// CRITICAL: bytes 32..127 must NOT be zero.
	// The old broken code would have all zeros here.
	tail := ret[32:]
	require.False(t, isZero(tail),
		"sponge output beyond first 32 bytes must not be zero (was zero-padded before fix)")

	// Each 32-byte block should be different (sponge re-permutes between squeezes)
	for i := range 3 {
		block := ret[(i+1)*32 : (i+2)*32]
		require.False(t, bytes.Equal(firstBlock, block),
			"each squeezed block should differ from the first")
	}
}

// Regression: H-01 — Sponge determinism with multi-block output.
func TestSponge_LargeOutput_Deterministic(t *testing.T) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+4+64)
	input[0] = OpSponge
	binary.BigEndian.PutUint32(input[1:5], 96)
	input[36] = 0x01
	input[68] = 0x02

	gas := p.RequiredGas(input) + 100000
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(ret1, ret2), "sponge must be deterministic")
}

func BenchmarkHash1(b *testing.B) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+32)
	input[0] = OpHash
	input[32] = 42
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkHash8(b *testing.B) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+8*32)
	input[0] = OpHash
	for i := range 8 {
		input[1+i*32+31] = byte(i)
	}
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkHashPair(b *testing.B) {
	p := &poseidonPrecompile{}

	input := make([]byte, 1+64)
	input[0] = OpHashPair
	input[32] = 1
	input[64] = 2
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
