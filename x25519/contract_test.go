// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package x25519

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000009203"), ContractAddress)
}

// RFC 7748 Section 5.2 — X25519 test vectors
func TestScalarMult_RFC7748_Vector1(t *testing.T) {
	p := &x25519Precompile{}

	// Alice's scalar (private key)
	scalar := hexBytes(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	// Bob's public key
	pubkey := hexBytes(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	// Expected shared secret
	expected := hexBytes(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	input := make([]byte, 1+64)
	input[0] = OpScalarMult
	copy(input[1:], scalar)
	copy(input[33:], pubkey)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, ret), "RFC 7748 vector 1 mismatch")
}

func TestScalarMult_RFC7748_Vector2(t *testing.T) {
	p := &x25519Precompile{}

	// Bob's scalar
	scalar := hexBytes(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	// Alice's public key
	pubkey := hexBytes(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	// Expected shared secret (same as vector 1 — DH is commutative)
	expected := hexBytes(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	input := make([]byte, 1+64)
	input[0] = OpScalarMult
	copy(input[1:], scalar)
	copy(input[33:], pubkey)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, ret), "RFC 7748 vector 2 mismatch")
}

func TestBasepoint(t *testing.T) {
	p := &x25519Precompile{}

	// Alice's scalar from RFC 7748
	scalar := hexBytes(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	// Expected public key (Alice's public key from RFC 7748)
	expected := hexBytes(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, ret), "basepoint multiplication mismatch")
}

func TestBasepoint_Bob(t *testing.T) {
	p := &x25519Precompile{}

	scalar := hexBytes(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	expected := hexBytes(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, ret), "Bob's basepoint multiplication mismatch")
}

func TestDHRoundTrip(t *testing.T) {
	p := &x25519Precompile{}

	aliceScalar := hexBytes(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bobScalar := hexBytes(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

	// Generate public keys via basepoint
	alicePub, err := curve25519.X25519(aliceScalar, curve25519.Basepoint)
	require.NoError(t, err)
	bobPub, err := curve25519.X25519(bobScalar, curve25519.Basepoint)
	require.NoError(t, err)

	// Alice computes shared secret using Bob's public key
	input1 := make([]byte, 1+64)
	input1[0] = OpScalarMult
	copy(input1[1:], aliceScalar)
	copy(input1[33:], bobPub)
	gas := p.RequiredGas(input1)
	shared1, _, err := p.Run(nil, common.Address{}, ContractAddress, input1, gas, true)
	require.NoError(t, err)

	// Bob computes shared secret using Alice's public key
	input2 := make([]byte, 1+64)
	input2[0] = OpScalarMult
	copy(input2[1:], bobScalar)
	copy(input2[33:], alicePub)
	gas = p.RequiredGas(input2)
	shared2, _, err := p.Run(nil, common.Address{}, ContractAddress, input2, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(shared1, shared2), "DH shared secrets must match")
}

func TestScalarMult_InputTooShort(t *testing.T) {
	p := &x25519Precompile{}

	input := make([]byte, 1+16) // only 16 bytes of data, need 64
	input[0] = OpScalarMult

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestBasepoint_InputTooShort(t *testing.T) {
	p := &x25519Precompile{}

	input := make([]byte, 1+8) // only 8 bytes, need 32
	input[0] = OpBasepoint

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestInvalidOperation(t *testing.T) {
	p := &x25519Precompile{}

	input := []byte{0xFF, 0x00}

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+1000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEmptyInput(t *testing.T) {
	p := &x25519Precompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 10000, true)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &x25519Precompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"scalarMult", []byte{OpScalarMult}, GasScalarMult},
		{"basepoint", []byte{OpBasepoint}, GasBasepoint},
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
	p := &x25519Precompile{}

	scalar := hexBytes(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], scalar)

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 100, true)
	require.Error(t, err)
}

func BenchmarkScalarMult(b *testing.B) {
	p := &x25519Precompile{}

	scalar := hexBytes(b, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	pubkey := hexBytes(b, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

	input := make([]byte, 1+64)
	input[0] = OpScalarMult
	copy(input[1:], scalar)
	copy(input[33:], pubkey)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkBasepoint(b *testing.B) {
	p := &x25519Precompile{}

	scalar := hexBytes(b, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], scalar)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

// TestScalarVisibility_SecurityConstraint documents that both ScalarMult and
// Basepoint accept a private scalar in calldata. On-chain, calldata is public
// and immutable — any scalar passed to this precompile is permanently visible
// to all chain observers. This test exists to ensure developers understand the
// constraint: ONLY use ephemeral/disposable scalars, NEVER long-term identity
// keys.
func TestScalarVisibility_SecurityConstraint(t *testing.T) {
	p := &x25519Precompile{}

	// Simulate a "long-term" identity key — this WOULD be leaked on-chain.
	// The test proves the precompile happily accepts it (no enforcement).
	// Enforcement is the caller's responsibility.
	identityScalar := hexBytes(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")

	// ScalarMult: scalar is in calldata bytes [1:33] — visible to all.
	peerPub := hexBytes(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	input := make([]byte, 1+64)
	input[0] = OpScalarMult
	copy(input[1:], identityScalar)
	copy(input[33:], peerPub)

	gas := p.RequiredGas(input)
	shared, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, shared, 32)

	// The scalar bytes are identical to what was passed in calldata.
	// On a real chain, input[1:33] is permanently stored in the transaction.
	// An observer can extract the scalar and compute the same shared secret.
	recoveredScalar := input[1:33]
	recoveredShared, err := curve25519.X25519(recoveredScalar, peerPub)
	require.NoError(t, err)
	require.True(t, bytes.Equal(shared, recoveredShared),
		"observer can recover shared secret from public calldata — this is the security constraint")

	// Basepoint: scalar is in calldata bytes [1:33] — visible to all.
	input2 := make([]byte, 1+32)
	input2[0] = OpBasepoint
	copy(input2[1:], identityScalar)

	gas = p.RequiredGas(input2)
	pubKey, _, err := p.Run(nil, common.Address{}, ContractAddress, input2, gas, true)
	require.NoError(t, err)
	require.Len(t, pubKey, 32)

	// Observer extracts scalar from calldata and derives the same public key.
	recoveredPub, err := curve25519.X25519(input2[1:33], curve25519.Basepoint)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pubKey, recoveredPub),
		"observer can derive public key from leaked scalar — ephemeral keys only")
}

func hexBytes(tb testing.TB, s string) []byte {
	tb.Helper()
	b := common.Hex2Bytes(s)
	require.Len(tb, b, len(s)/2)
	return b
}
