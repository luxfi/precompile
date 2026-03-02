// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var (
	addr0 = common.Address{}
)

// --- Edge Case Tests ---

func TestEdge_EmptyInput(t *testing.T) {
	p := Blake3Precompile
	_, _, err := p.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestEdge_SingleByte(t *testing.T) {
	p := Blake3Precompile
	_, _, err := p.Run(nil, addr0, ContractAddress, []byte{0xFF}, 100000, true)
	require.Error(t, err, "unknown op must error")
}

func TestEdge_OpOnlyNoData(t *testing.T) {
	p := Blake3Precompile
	for _, op := range []byte{OpHash256, OpHash512} {
		input := []byte{op}
		gas := p.RequiredGas(input)
		ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
		require.NoError(t, err, "op=0x%02x with no data should hash empty", op)
		require.NotNil(t, ret)
	}
}

func TestEdge_Hash256_EmptyData(t *testing.T) {
	p := Blake3Precompile
	input := []byte{OpHash256}
	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}

func TestEdge_Hash512_EmptyData(t *testing.T) {
	p := Blake3Precompile
	input := []byte{OpHash512}
	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Len(t, ret, 64)
}

func TestEdge_XOF_OutputLength(t *testing.T) {
	p := Blake3Precompile
	for _, outLen := range []uint32{1, 32, 64, 128, 256, MaxOutputLength} {
		input := make([]byte, 5+32)
		input[0] = OpHashXOF
		binary.BigEndian.PutUint32(input[1:5], outLen)
		// 32 bytes of data
		for i := 5; i < len(input); i++ {
			input[i] = byte(i)
		}
		gas := p.RequiredGas(input)
		ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+10000, true)
		require.NoError(t, err, "outLen=%d", outLen)
		require.Len(t, ret, int(outLen), "outLen=%d", outLen)
	}
}

func TestEdge_XOF_OutputTooLarge(t *testing.T) {
	p := Blake3Precompile
	input := make([]byte, 5+32)
	input[0] = OpHashXOF
	binary.BigEndian.PutUint32(input[1:5], MaxOutputLength+1)
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	require.Error(t, err)
}

func TestEdge_XOF_ZeroOutput(t *testing.T) {
	p := Blake3Precompile
	input := make([]byte, 5+32)
	input[0] = OpHashXOF
	binary.BigEndian.PutUint32(input[1:5], 0)
	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	// Zero output may return empty or error depending on implementation
	if err == nil {
		require.Len(t, ret, 0, "zero output should return empty")
	}
}

func TestEdge_DomainSeparated(t *testing.T) {
	p := Blake3Precompile
	domain := []byte("test-domain")
	data := []byte("hello world")

	input := make([]byte, 1+2+len(domain)+len(data))
	input[0] = OpHashWithDomain
	binary.BigEndian.PutUint16(input[1:3], uint16(len(domain)))
	copy(input[3:3+len(domain)], domain)
	copy(input[3+len(domain):], data)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)

	// Different domain must produce different hash
	domain2 := []byte("other-domain")
	input2 := make([]byte, 1+2+len(domain2)+len(data))
	input2[0] = OpHashWithDomain
	binary.BigEndian.PutUint16(input2[1:3], uint16(len(domain2)))
	copy(input2[3:3+len(domain2)], domain2)
	copy(input2[3+len(domain2):], data)

	gas2 := p.RequiredGas(input2)
	ret2, _, err := p.Run(nil, addr0, ContractAddress, input2, gas2+10000, true)
	require.NoError(t, err)
	require.NotEqual(t, ret, ret2, "different domains must produce different hashes")
}

// --- Gas Accounting ---

func TestGas_ExactRequired(t *testing.T) {
	p := Blake3Precompile
	input := append([]byte{OpHash256}, make([]byte, 32)...)
	gas := p.RequiredGas(input)

	ret, remaining, err := p.Run(nil, addr0, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.NotNil(t, ret)
	require.Equal(t, uint64(0), remaining)
}

func TestGas_InsufficientGas(t *testing.T) {
	p := Blake3Precompile
	input := append([]byte{OpHash256}, make([]byte, 32)...)
	gas := p.RequiredGas(input)

	_, _, err := p.Run(nil, addr0, ContractAddress, input, gas-1, true)
	require.Error(t, err, "insufficient gas must error")
}

func TestGas_ZeroGas(t *testing.T) {
	p := Blake3Precompile
	input := append([]byte{OpHash256}, make([]byte, 32)...)
	_, _, err := p.Run(nil, addr0, ContractAddress, input, 0, true)
	require.Error(t, err)
}

func TestGas_EmptyInputGasZero(t *testing.T) {
	p := Blake3Precompile
	require.Equal(t, uint64(0), p.RequiredGas(nil))
	require.Equal(t, uint64(0), p.RequiredGas([]byte{}))
}

func TestGas_UnknownOpGasZero(t *testing.T) {
	p := Blake3Precompile
	require.Equal(t, uint64(0), p.RequiredGas([]byte{0xFF}))
}

// --- Determinism ---

func TestDeterminism_Hash256(t *testing.T) {
	p := Blake3Precompile
	input := append([]byte{OpHash256}, []byte("deterministic input")...)
	gas := p.RequiredGas(input)

	ret1, _, _ := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	ret2, _, _ := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.Equal(t, ret1, ret2)
}

func TestDeterminism_DifferentInput(t *testing.T) {
	p := Blake3Precompile
	input1 := append([]byte{OpHash256}, []byte("input A")...)
	input2 := append([]byte{OpHash256}, []byte("input B")...)
	gas := uint64(100000)

	ret1, _, _ := p.Run(nil, addr0, ContractAddress, input1, gas, true)
	ret2, _, _ := p.Run(nil, addr0, ContractAddress, input2, gas, true)
	require.NotEqual(t, ret1, ret2)
}

// --- Concurrency ---

func TestConcurrent_Hash256(t *testing.T) {
	p := Blake3Precompile
	input := append([]byte{OpHash256}, []byte("concurrent test data")...)
	gas := p.RequiredGas(input)

	var wg sync.WaitGroup
	results := make([][]byte, 100)
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
			require.NoError(t, err)
			results[idx] = ret
		}(i)
	}
	wg.Wait()
	for i := 1; i < 100; i++ {
		require.Equal(t, results[0], results[i], "concurrent results must match")
	}
}

// --- Fuzz ---

func FuzzBlake3(f *testing.F) {
	f.Add([]byte{OpHash256, 0x01, 0x02, 0x03})
	f.Add([]byte{OpHash512, 0x01})
	f.Add([]byte{0xFF})
	f.Add([]byte{})

	p := Blake3Precompile
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input len=%d: %v", len(input), r)
			}
		}()
		gas := p.RequiredGas(input)
		p.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}

// --- Address ---

func TestAddress_Correct(t *testing.T) {
	p := Blake3Precompile
	require.Equal(t, ContractAddress, p.Address())
}

// --- Derive Key ---

func TestDeep_DeriveKey(t *testing.T) {
	p := Blake3Precompile
	context := []byte("Lux 2025 KDF context")
	material := []byte("key material here")

	input := make([]byte, 1+2+len(context)+len(material))
	input[0] = OpDeriveKey
	binary.BigEndian.PutUint16(input[1:3], uint16(len(context)))
	copy(input[3:3+len(context)], context)
	copy(input[3+len(context):], material)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}

// --- Merkle Root ---

func TestDeep_MerkleRoot_TwoLeaves(t *testing.T) {
	p := Blake3Precompile
	numLeaves := uint32(2)
	leaf1 := make([]byte, 32)
	leaf2 := make([]byte, 32)
	leaf1[0] = 1
	leaf2[0] = 2

	input := make([]byte, 1+4+int(numLeaves)*32)
	input[0] = OpMerkleRoot
	binary.BigEndian.PutUint32(input[1:5], numLeaves)
	copy(input[5:37], leaf1)
	copy(input[37:69], leaf2)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}
