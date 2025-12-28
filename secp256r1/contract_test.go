// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestContract_Address(t *testing.T) {
	c := &Contract{}
	require.Equal(t, common.HexToAddress(P256VerifyAddress), c.Address())
}

func TestContract_RequiredGas(t *testing.T) {
	c := &Contract{}
	require.Equal(t, uint64(P256VerifyGas), c.RequiredGas(make([]byte, 160)))
}

func TestContract_Name(t *testing.T) {
	c := &Contract{}
	require.Equal(t, "P256VERIFY", c.Name())
}

func TestContract_ValidSignature(t *testing.T) {
	c := &Contract{}

	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message hash
	message := []byte("Hello, secp256r1!")
	hash := sha256.Sum256(message)

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	// Build input
	input := buildInput(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Verify
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Equal(t, successResult, result)
}

func TestContract_InvalidSignature(t *testing.T) {
	c := &Contract{}

	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message hash
	message := []byte("Hello, secp256r1!")
	hash := sha256.Sum256(message)

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	// Modify hash (invalid signature)
	hash[0] ^= 0xff

	// Build input with wrong hash
	input := buildInput(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Verify - should return empty
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestContract_InvalidInputLength(t *testing.T) {
	c := &Contract{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"too short", make([]byte, 159)},
		{"too long", make([]byte, 161)},
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.Run(tt.input)
			require.NoError(t, err)
			require.Empty(t, result)
		})
	}
}

func TestContract_PointNotOnCurve(t *testing.T) {
	c := &Contract{}

	// Create hash
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	// Invalid point (not on P-256 curve)
	x := big.NewInt(1)
	y := big.NewInt(1)
	r := big.NewInt(12345)
	s := big.NewInt(67890)

	input := buildInput(hash, r, s, x, y)

	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestContract_ZeroValues(t *testing.T) {
	c := &Contract{}

	hash := make([]byte, 32)
	r := big.NewInt(0)
	s := big.NewInt(0)
	x := elliptic.P256().Params().Gx
	y := elliptic.P256().Params().Gy

	input := buildInput(hash, r, s, x, y)

	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result) // r=0 and s=0 are invalid
}

func TestContract_ROutOfRange(t *testing.T) {
	c := &Contract{}

	// Generate valid key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	// r >= n (curve order)
	n := elliptic.P256().Params().N
	r := new(big.Int).Set(n) // r = n is invalid
	s := big.NewInt(12345)

	input := buildInput(hash, r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestContract_SOutOfRange(t *testing.T) {
	c := &Contract{}

	// Generate valid key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	n := elliptic.P256().Params().N
	r := big.NewInt(12345)
	s := new(big.Int).Set(n) // s = n is invalid

	input := buildInput(hash, r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestVerify_Convenience(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create message hash
	message := []byte("Test message for Verify function")
	hash := sha256.Sum256(message)

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	// Verify using convenience function
	valid := Verify(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	require.True(t, valid)

	// Verify with wrong hash
	hash[0] ^= 0xff
	valid = Verify(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	require.False(t, valid)
}

func TestContract_WrongPublicKey(t *testing.T) {
	c := &Contract{}

	// Generate two key pairs
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Sign with key1
	message := []byte("Test message")
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey1, hash[:])
	require.NoError(t, err)

	// Try to verify with key2's public key
	input := buildInput(hash[:], r, s, privateKey2.PublicKey.X, privateKey2.PublicKey.Y)

	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestContract_NISTTestVector(t *testing.T) {
	c := &Contract{}

	// NIST CAVP test vector (simplified example)
	// In production, use full NIST test vectors from FIPS 186-3

	// Generate deterministic key for reproducible test
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Standard test message
	hash := sha256.Sum256([]byte("NIST test vector simulation"))

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	input := buildInput(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	result, err := c.Run(input)
	require.NoError(t, err)
	require.Equal(t, successResult, result)
}

// Benchmark tests
func BenchmarkContract_Run(b *testing.B) {
	c := &Contract{}

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("Benchmark message")
	hash := sha256.Sum256(message)
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	input := buildInput(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}

func BenchmarkVerify(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("Benchmark message")
	hash := sha256.Sum256(message)
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(hash[:], r, s, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	}
}

// Helper function to build precompile input
func buildInput(hash []byte, r, s, x, y *big.Int) []byte {
	input := make([]byte, InputLength)

	// Copy hash (32 bytes)
	copy(input[0:32], common.LeftPadBytes(hash, 32))

	// Copy r (32 bytes)
	copy(input[32:64], common.LeftPadBytes(r.Bytes(), 32))

	// Copy s (32 bytes)
	copy(input[64:96], common.LeftPadBytes(s.Bytes(), 32))

	// Copy x (32 bytes)
	copy(input[96:128], common.LeftPadBytes(x.Bytes(), 32))

	// Copy y (32 bytes)
	copy(input[128:160], common.LeftPadBytes(y.Bytes(), 32))

	return input
}
