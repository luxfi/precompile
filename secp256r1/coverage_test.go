// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- Module tests ---

func TestModule_NewModule(t *testing.T) {
	m := NewModule()
	require.NotNil(t, m)
}

func TestModule_Address(t *testing.T) {
	m := NewModule()
	require.Equal(t, Address, m.Address())
}

func TestModule_Contract(t *testing.T) {
	m := NewModule()
	c := m.Contract()
	require.NotNil(t, c)
}

func TestModule_ConfigKey(t *testing.T) {
	m := NewModule()
	require.Equal(t, "secp256r1Config", m.ConfigKey())
}

func TestModule_Name(t *testing.T) {
	m := NewModule()
	require.Equal(t, "secp256r1", m.Name())
}

func TestModule_Description(t *testing.T) {
	m := NewModule()
	require.Contains(t, m.Description(), "secp256r1")
}

func TestModule_Version(t *testing.T) {
	m := NewModule()
	require.Equal(t, "1.0.0", m.Version())
}

func TestModule_EIPs(t *testing.T) {
	m := NewModule()
	require.Equal(t, []int{7212}, m.EIPs())
}

func TestModule_LPs(t *testing.T) {
	m := NewModule()
	require.Equal(t, []int{3651}, m.LPs())
}

// --- Verify() convenience function error paths ---

func TestVerify_PointNotOnCurve(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	r := big.NewInt(12345)
	s := big.NewInt(67890)
	x := big.NewInt(1)
	y := big.NewInt(1)
	require.False(t, Verify(hash[:], r, s, x, y))
}

func TestVerify_RZero(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	r := big.NewInt(0)
	s := big.NewInt(1)
	require.False(t, Verify(hash[:], r, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_RNegative(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	r := big.NewInt(-1)
	s := big.NewInt(1)
	require.False(t, Verify(hash[:], r, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_REqualsN(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	n := elliptic.P256().Params().N
	s := big.NewInt(1)
	require.False(t, Verify(hash[:], n, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_SZero(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	r := big.NewInt(1)
	s := big.NewInt(0)
	require.False(t, Verify(hash[:], r, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_SNegative(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	r := big.NewInt(1)
	s := big.NewInt(-1)
	require.False(t, Verify(hash[:], r, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_SEqualsN(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	n := elliptic.P256().Params().N
	r := big.NewInt(1)
	require.False(t, Verify(hash[:], r, n, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_ValidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	require.NoError(t, err)

	require.True(t, Verify(hash[:], r, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

func TestVerify_InvalidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	require.NoError(t, err)

	// Use wrong hash
	wrongHash := sha256.Sum256([]byte("wrong"))
	require.False(t, Verify(wrongHash[:], r, s, privKey.PublicKey.X, privKey.PublicKey.Y))
}

// --- Run() edge branches ---

func TestRun_NegativeR(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	input := buildInput(hash[:], big.NewInt(-1), big.NewInt(1), privKey.PublicKey.X, privKey.PublicKey.Y)
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestRun_NegativeS(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	// Valid r but negative s
	r, _, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	require.NoError(t, err)

	input := buildInput(hash[:], r, big.NewInt(-1), privKey.PublicKey.X, privKey.PublicKey.Y)
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestRun_RAboveN(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	n := elliptic.P256().Params().N
	rAboveN := new(big.Int).Add(n, big.NewInt(1))
	input := buildInput(hash[:], rAboveN, big.NewInt(1), privKey.PublicKey.X, privKey.PublicKey.Y)
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestRun_SAboveN(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	n := elliptic.P256().Params().N
	sAboveN := new(big.Int).Add(n, big.NewInt(1))
	input := buildInput(hash[:], big.NewInt(1), sAboveN, privKey.PublicKey.X, privKey.PublicKey.Y)
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

// Test Run with valid point on curve but invalid signature (r,s in range)
func TestRun_ValidRangeInvalidSig(t *testing.T) {
	c := &Contract{}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test"))
	// r=1, s=1 are in valid range but won't verify
	input := buildInput(hash[:], big.NewInt(1), big.NewInt(1), privKey.PublicKey.X, privKey.PublicKey.Y)
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result)
}

// Verify the generator point is on curve
func TestRun_GeneratorPoint(t *testing.T) {
	c := &Contract{}
	hash := sha256.Sum256([]byte("test"))
	gx := elliptic.P256().Params().Gx
	gy := elliptic.P256().Params().Gy
	// r=1, s=1 with generator point
	input := buildInput(hash[:], big.NewInt(1), big.NewInt(1), gx, gy)
	result, err := c.Run(input)
	require.NoError(t, err)
	require.Empty(t, result) // valid point, valid range, but won't verify
}
