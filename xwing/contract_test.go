// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xwing

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/kem/xwing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000002221"), ContractAddress)
}

func TestEncapsulate_ValidKey(t *testing.T) {
	p := &xwingPrecompile{}
	scheme := xwing.Scheme()

	// Generate a key pair off-chain
	pk, sk, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	// Build precompile input: [OpEncapsulate][pk]
	input := make([]byte, 1+len(pkBytes))
	input[0] = OpEncapsulate
	copy(input[1:], pkBytes)

	gas := p.RequiredGas(input)
	require.Equal(t, uint64(GasEncapsulate), gas)

	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)
	require.NotNil(t, ret)

	// Parse result: [2 bytes ct_len][ct][ss]
	ctLen := int(binary.BigEndian.Uint16(ret[:2]))
	require.Equal(t, scheme.CiphertextSize(), ctLen)

	ct := ret[2 : 2+ctLen]
	ssEncap := ret[2+ctLen:]
	require.Len(t, ssEncap, scheme.SharedKeySize())

	// Decapsulate off-chain and verify shared secrets match
	ssDecap, err := scheme.Decapsulate(sk, ct)
	require.NoError(t, err)
	require.Equal(t, ssEncap, ssDecap, "encapsulated and decapsulated shared secrets must match")
}

func TestEncapsulate_DifferentInvocations(t *testing.T) {
	p := &xwingPrecompile{}
	scheme := xwing.Scheme()

	pk, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	input := make([]byte, 1+len(pkBytes))
	input[0] = OpEncapsulate
	copy(input[1:], pkBytes)

	gas := p.RequiredGas(input)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.NoError(t, err)

	// Encapsulation uses randomness, so outputs should differ
	require.NotEqual(t, ret1, ret2, "two encapsulations of the same key should produce different ciphertexts")
}

func TestEncapsulate_MultipleKeyPairs(t *testing.T) {
	p := &xwingPrecompile{}
	scheme := xwing.Scheme()

	for i := 0; i < 3; i++ {
		pk, sk, err := scheme.GenerateKeyPair()
		require.NoError(t, err)

		pkBytes, err := pk.MarshalBinary()
		require.NoError(t, err)

		input := make([]byte, 1+len(pkBytes))
		input[0] = OpEncapsulate
		copy(input[1:], pkBytes)

		gas := p.RequiredGas(input)
		ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
		require.NoError(t, err)

		ctLen := int(binary.BigEndian.Uint16(ret[:2]))
		ct := ret[2 : 2+ctLen]
		ssEncap := ret[2+ctLen:]

		ssDecap, err := scheme.Decapsulate(sk, ct)
		require.NoError(t, err)
		require.Equal(t, ssEncap, ssDecap, "key pair %d: shared secrets must match", i)
	}
}

func TestEncapsulate_InputTooShort(t *testing.T) {
	p := &xwingPrecompile{}

	// Public key is too short (only 32 bytes, X-Wing needs 1216)
	input := make([]byte, 1+32)
	input[0] = OpEncapsulate

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	require.Error(t, err)
}

func TestEncapsulate_MalformedKey(t *testing.T) {
	p := &xwingPrecompile{}
	scheme := xwing.Scheme()

	// Create garbage public key of correct length
	garbage := make([]byte, scheme.PublicKeySize())
	_, err := rand.Read(garbage)
	require.NoError(t, err)

	input := make([]byte, 1+len(garbage))
	input[0] = OpEncapsulate
	copy(input[1:], garbage)

	gas := p.RequiredGas(input)
	// This may or may not error depending on the KEM impl's validation
	// but it should not panic
	_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
}

func TestInvalidOperation(t *testing.T) {
	p := &xwingPrecompile{}

	input := []byte{0xFF, 0x00}
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, false)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEmptyInput(t *testing.T) {
	p := &xwingPrecompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 100000, false)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &xwingPrecompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"encapsulate", []byte{OpEncapsulate}, GasEncapsulate},
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
	p := &xwingPrecompile{}
	scheme := xwing.Scheme()

	pk, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	input := make([]byte, 1+len(pkBytes))
	input[0] = OpEncapsulate
	copy(input[1:], pkBytes)

	_, _, err = p.Run(nil, common.Address{}, ContractAddress, input, 100, false)
	require.Error(t, err)
}

func BenchmarkEncapsulate(b *testing.B) {
	p := &xwingPrecompile{}
	scheme := xwing.Scheme()

	pk, _, err := scheme.GenerateKeyPair()
	require.NoError(b, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(b, err)

	input := make([]byte, 1+len(pkBytes))
	input[0] = OpEncapsulate
	copy(input[1:], pkBytes)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, false)
	}
}
