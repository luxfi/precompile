// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// mockAccessibleState implements the minimal interface for testing
type mockAccessibleState struct{}

func (m *mockAccessibleState) GetStateDB() interface{}      { return nil }
func (m *mockAccessibleState) GetBlockContext() interface{} { return nil }

func TestBlake3Address(t *testing.T) {
	// Address in Lux reserved hashing range: 0x0500...0004 (Blake3)
	expected := "0x0500000000000000000000000000000000000004"
	actual := ContractAddress.Hex()
	require.Equal(t, expected, actual, "Blake3 precompile address mismatch")
}

func TestHash256(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"32bytes", make([]byte, 32)},
		{"1kb", make([]byte, 1024)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := p.hash256(tc.input)
			require.Len(t, result, DigestLength32, "hash256 should return 32 bytes")
		})
	}
}

func TestHash512(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello world")},
		{"64bytes", make([]byte, 64)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := p.hash512(tc.input)
			require.Len(t, result, DigestLength64, "hash512 should return 64 bytes")
		})
	}
}

func TestHashXOF(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name      string
		outputLen uint32
		input     []byte
		wantErr   bool
	}{
		{"16bytes", 16, []byte("test"), false},
		{"64bytes", 64, []byte("test"), false},
		{"128bytes", 128, []byte("test data here"), false},
		{"max1024", 1024, []byte("test"), false},
		{"tooLarge", 2048, []byte("test"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 4+len(tc.input))
			binary.BigEndian.PutUint32(data[:4], tc.outputLen)
			copy(data[4:], tc.input)

			result, _, err := p.hashXOF(data)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, result, int(tc.outputLen))
		})
	}
}

func TestHashWithDomain(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name   string
		domain string
		data   []byte
	}{
		{"simple", "test", []byte("data")},
		{"commitment", "LUX.commitment.v1", []byte{1, 2, 3, 4}},
		{"empty_data", "domain", []byte{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domainBytes := []byte(tc.domain)
			data := make([]byte, 1+len(domainBytes)+len(tc.data))
			data[0] = byte(len(domainBytes))
			copy(data[1:], domainBytes)
			copy(data[1+len(domainBytes):], tc.data)

			result, _, err := p.hashWithDomain(data)
			require.NoError(t, err)
			require.Len(t, result, DigestLength32)
		})
	}
}

func TestHashDeterminism(t *testing.T) {
	p := &blake3Precompile{}

	input := []byte("deterministic test input")
	result1 := p.hash256(input)
	result2 := p.hash256(input)

	require.True(t, bytes.Equal(result1, result2), "Blake3 should be deterministic")
}

func TestHashDifferentInputs(t *testing.T) {
	p := &blake3Precompile{}

	input1 := []byte("input one")
	input2 := []byte("input two")

	result1 := p.hash256(input1)
	result2 := p.hash256(input2)

	require.False(t, bytes.Equal(result1, result2), "Different inputs should produce different hashes")
}

func TestMerkleRoot(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name      string
		numLeaves uint32
		wantErr   bool
	}{
		{"empty", 0, false},
		{"single", 1, false},
		{"two", 2, false},
		{"four", 4, false},
		{"eight", 8, false},
		{"odd", 7, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 4+int(tc.numLeaves)*32)
			binary.BigEndian.PutUint32(data[:4], tc.numLeaves)

			// Fill with dummy leaf hashes
			for i := uint32(0); i < tc.numLeaves; i++ {
				offset := 4 + i*32
				copy(data[offset:offset+32], p.hash256([]byte{byte(i)}))
			}

			result, _, err := p.merkleRoot(data)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, result, DigestLength32)
		})
	}
}

func TestMerkleRootDeterminism(t *testing.T) {
	p := &blake3Precompile{}

	leaves := [][]byte{
		p.hash256([]byte("leaf1")),
		p.hash256([]byte("leaf2")),
		p.hash256([]byte("leaf3")),
		p.hash256([]byte("leaf4")),
	}

	data := make([]byte, 4+len(leaves)*32)
	binary.BigEndian.PutUint32(data[:4], uint32(len(leaves)))
	for i, leaf := range leaves {
		copy(data[4+i*32:], leaf)
	}

	result1, _, err := p.merkleRoot(data)
	require.NoError(t, err)

	result2, _, err := p.merkleRoot(data)
	require.NoError(t, err)

	require.True(t, bytes.Equal(result1, result2), "Merkle root should be deterministic")
}

func TestDeriveKey(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name    string
		context string
		key     []byte
	}{
		{"simple", "test", make([]byte, 32)},
		{"encryption", "LUX.encryption.v1", make([]byte, 32)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contextBytes := []byte(tc.context)
			data := make([]byte, 1+len(contextBytes)+32)
			data[0] = byte(len(contextBytes))
			copy(data[1:], contextBytes)
			copy(data[1+len(contextBytes):], tc.key)

			result, _, err := p.deriveKey(data)
			require.NoError(t, err)
			require.Len(t, result, DigestLength32)
		})
	}
}

func TestDeriveKeyDifferentContexts(t *testing.T) {
	p := &blake3Precompile{}

	keyMaterial := make([]byte, 32)
	copy(keyMaterial, []byte("key material"))

	buildInput := func(context string) []byte {
		contextBytes := []byte(context)
		data := make([]byte, 1+len(contextBytes)+32)
		data[0] = byte(len(contextBytes))
		copy(data[1:], contextBytes)
		copy(data[1+len(contextBytes):], keyMaterial)
		return data
	}

	result1, _, err := p.deriveKey(buildInput("context1"))
	require.NoError(t, err)

	result2, _, err := p.deriveKey(buildInput("context2"))
	require.NoError(t, err)

	require.False(t, bytes.Equal(result1, result2), "Different contexts should produce different keys")
}

func TestRequiredGas(t *testing.T) {
	p := &blake3Precompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"hash256_empty", []byte{OpHash256}, GasBase256},
		{"hash256_32b", append([]byte{OpHash256}, make([]byte, 32)...), GasBase256 + GasPerInputWord},
		{"hash256_64b", append([]byte{OpHash256}, make([]byte, 64)...), GasBase256 + 2*GasPerInputWord},
		{"hash512_empty", []byte{OpHash512}, GasBase512},
		{"merkle_4leaves", func() []byte {
			data := make([]byte, 5)
			data[0] = OpMerkleRoot
			binary.BigEndian.PutUint32(data[1:], 4)
			return data
		}(), GasMerkleBase + 4*GasMerklePerLeaf},
		{"derive_key", []byte{OpDeriveKey}, GasDeriveKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gas := p.RequiredGas(tc.input)
			require.Equal(t, tc.expected, gas)
		})
	}
}

func TestRunInvalidOperation(t *testing.T) {
	p := &blake3Precompile{}

	input := []byte{0xFF, 0x00, 0x00} // Invalid operation

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 1000000, true)
	require.Error(t, err)
	require.Equal(t, ErrInvalidOperation, err)
}

func TestRunOutOfGas(t *testing.T) {
	p := &blake3Precompile{}

	input := append([]byte{OpHash256}, make([]byte, 1024)...) // Large input

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 10, true) // Very low gas
	require.Error(t, err)
}

func BenchmarkHash256(b *testing.B) {
	p := &blake3Precompile{}
	input := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.hash256(input)
	}
}

func BenchmarkHash512(b *testing.B) {
	p := &blake3Precompile{}
	input := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.hash512(input)
	}
}

func BenchmarkMerkleRoot8Leaves(b *testing.B) {
	p := &blake3Precompile{}
	data := make([]byte, 4+8*32)
	binary.BigEndian.PutUint32(data[:4], 8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.merkleRoot(data)
	}
}

func BenchmarkMerkleRoot256Leaves(b *testing.B) {
	p := &blake3Precompile{}
	data := make([]byte, 4+256*32)
	binary.BigEndian.PutUint32(data[:4], 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.merkleRoot(data)
	}
}
