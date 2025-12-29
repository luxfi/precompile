// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// createTestSignature creates test keys and signatures using the specified mode
func createTestSignature(t testing.TB, mode slhdsa.Mode) ([]byte, []byte, []byte, []byte) {
	priv, err := slhdsa.GenerateKey(rand.Reader, mode)
	require.NoError(t, err)

	message := []byte("test message for SLH-DSA signature verification")
	signature, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)

	return priv.PublicKey.Bytes(), signature, message, nil
}

// prepareInputWithMode creates precompile input with mode byte
// Format: [mode(1)][pubKeyLen(2)][pubKey][msgLen(2)][message][signature]
func prepareInputWithMode(mode uint8, publicKey, message, signature []byte) []byte {
	input := make([]byte, 0)

	// Mode byte
	input = append(input, mode)

	// Public key length (2 bytes, big-endian)
	pubKeyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(pubKeyLen, uint16(len(publicKey)))
	input = append(input, pubKeyLen...)

	// Public key
	input = append(input, publicKey...)

	// Message length (2 bytes, big-endian)
	msgLen := make([]byte, 2)
	binary.BigEndian.PutUint16(msgLen, uint16(len(message)))
	input = append(input, msgLen...)

	// Message
	input = append(input, message...)

	// Signature
	input = append(input, signature...)

	return input
}

// TestSLHDSAVerify_ValidSignature tests successful signature verification
func TestSLHDSAVerify_ValidSignature_SHA2_128s(t *testing.T) {
	pk, signature, message, _ := createTestSignature(t, slhdsa.SHA2_128s)

	input := prepareInputWithMode(ModeSHA2_128s, pk, message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	result, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "signature should be valid")
}

func TestSLHDSAVerify_ValidSignature_SHAKE_128f(t *testing.T) {
	pk, signature, message, _ := createTestSignature(t, slhdsa.SHAKE_128f)

	input := prepareInputWithMode(ModeSHAKE_128f, pk, message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	result, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "signature should be valid")
}

// TestSLHDSAVerify_InvalidSignature tests rejection of invalid signatures
func TestSLHDSAVerify_InvalidSignature(t *testing.T) {
	pk, signature, message, _ := createTestSignature(t, slhdsa.SHA2_128s)

	// Corrupt signature
	signature[0] ^= 0xFF

	input := prepareInputWithMode(ModeSHA2_128s, pk, message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	result, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "corrupted signature should be invalid")
}

// TestSLHDSAVerify_WrongMessage tests rejection when message doesn't match
func TestSLHDSAVerify_WrongMessage(t *testing.T) {
	pk, signature, _, _ := createTestSignature(t, slhdsa.SHA2_128s)
	wrongMessage := []byte("wrong message!!!")

	input := prepareInputWithMode(ModeSHA2_128s, pk, wrongMessage, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	result, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "signature for different message should be invalid")
}

// TestSLHDSAVerify_InputTooShort tests error handling for insufficient input
func TestSLHDSAVerify_InputTooShort(t *testing.T) {
	input := make([]byte, 2) // Too short - just mode and partial pubKeyLen
	input[0] = ModeSHA2_128s

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	_, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid input length")
}

// TestSLHDSAVerify_InvalidMode tests rejection of invalid mode byte
func TestSLHDSAVerify_InvalidMode(t *testing.T) {
	// Create a valid-looking input with invalid mode
	input := make([]byte, 10000)
	input[0] = 0xFF // Invalid mode

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	_, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

// TestSLHDSAVerify_EmptyMessage tests verification with empty message
func TestSLHDSAVerify_EmptyMessage(t *testing.T) {
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	require.NoError(t, err)

	message := []byte{}
	signature, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)

	input := prepareInputWithMode(ModeSHA2_128s, priv.PublicKey.Bytes(), message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	result, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "signature for empty message should be valid")
}

// TestSLHDSAVerify_LargeMessage tests verification with large message
func TestSLHDSAVerify_LargeMessage(t *testing.T) {
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	require.NoError(t, err)

	// Create 10KB message
	message := make([]byte, 10*1024)
	for i := range message {
		message[i] = byte(i % 256)
	}

	signature, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)

	input := prepareInputWithMode(ModeSHA2_128s, priv.PublicKey.Bytes(), message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)
	result, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "signature for large message should be valid")
}

// TestSLHDSAVerify_GasCost tests per-mode gas cost calculation
func TestSLHDSAVerify_GasCost(t *testing.T) {
	tests := []struct {
		name   string
		mode   uint8
		minGas uint64
	}{
		{"SHA2_128s", ModeSHA2_128s, SLH128sVerifyBaseGas},
		{"SHA2_128f", ModeSHA2_128f, SLH128fVerifyBaseGas},
		{"SHAKE_128s", ModeSHAKE_128s, SLH128sVerifyBaseGas},
		{"SHAKE_128f", ModeSHAKE_128f, SLH128fVerifyBaseGas},
		{"SHA2_192s", ModeSHA2_192s, SLH192sVerifyBaseGas},
		{"SHA2_192f", ModeSHA2_192f, SLH192fVerifyBaseGas},
		{"SHA2_256s", ModeSHA2_256s, SLH256sVerifyBaseGas},
		{"SHA2_256f", ModeSHA2_256f, SLH256fVerifyBaseGas},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create minimal valid input for the mode
			// Just mode + pubKeyLen (set to expected size for the mode)
			input := make([]byte, 3)
			input[0] = tt.mode

			// Set correct pubkey size for mode
			var pubKeySize uint16
			switch tt.mode {
			case ModeSHA2_128s, ModeSHA2_128f, ModeSHAKE_128s, ModeSHAKE_128f:
				pubKeySize = SLH128PublicKeySize
			case ModeSHA2_192s, ModeSHA2_192f, ModeSHAKE_192s, ModeSHAKE_192f:
				pubKeySize = SLH192PublicKeySize
			case ModeSHA2_256s, ModeSHA2_256f, ModeSHAKE_256s, ModeSHAKE_256f:
				pubKeySize = SLH256PublicKeySize
			}
			binary.BigEndian.PutUint16(input[1:3], pubKeySize)

			gas := SLHDSAVerifyPrecompile.RequiredGas(input)
			require.GreaterOrEqual(t, gas, tt.minGas, "gas cost should be at least base gas for mode")
		})
	}
}

// TestSLHDSAPrecompile_Address tests precompile address
func TestSLHDSAPrecompile_Address(t *testing.T) {
	expectedAddress := ContractSLHDSAVerifyAddress
	require.Equal(t, expectedAddress, SLHDSAVerifyPrecompile.Address())
}

// TestSLHDSAVerify_OutOfGas tests out of gas error
func TestSLHDSAVerify_OutOfGas(t *testing.T) {
	pk, signature, message, _ := createTestSignature(t, slhdsa.SHA2_128s)

	input := prepareInputWithMode(ModeSHA2_128s, pk, message, signature)

	_, _, err := SLHDSAVerifyPrecompile.Run(
		nil, common.Address{}, ContractSLHDSAVerifyAddress,
		input, 1000, true, // Insufficient gas
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

// BenchmarkSLHDSAVerify benchmarks verification for different modes
func BenchmarkSLHDSAVerify_SHA2_128s(b *testing.B) {
	priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	message := []byte("benchmark message")
	signature, _ := priv.Sign(rand.Reader, message, nil)
	input := prepareInputWithMode(ModeSHA2_128s, priv.PublicKey.Bytes(), message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SLHDSAVerifyPrecompile.Run(
			nil, common.Address{}, ContractSLHDSAVerifyAddress,
			input, gas, true,
		)
	}
}

func BenchmarkSLHDSAVerify_SHA2_128f(b *testing.B) {
	priv, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	message := []byte("benchmark message")
	signature, _ := priv.Sign(rand.Reader, message, nil)
	input := prepareInputWithMode(ModeSHA2_128f, priv.PublicKey.Bytes(), message, signature)

	gas := SLHDSAVerifyPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SLHDSAVerifyPrecompile.Run(
			nil, common.Address{}, ContractSLHDSAVerifyAddress,
			input, gas, true,
		)
	}
}
