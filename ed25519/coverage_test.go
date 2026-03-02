// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
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
	require.Equal(t, ContractAddress, m.Address())
}

func TestModule_Contract(t *testing.T) {
	m := NewModule()
	require.Equal(t, Ed25519VerifyPrecompile, m.Contract())
}

func TestModule_ConfigKey(t *testing.T) {
	m := NewModule()
	require.Equal(t, "ed25519Config", m.ConfigKey())
}

func TestModule_Name(t *testing.T) {
	m := NewModule()
	require.Equal(t, "ed25519", m.Name())
}

// --- Verify() convenience function ---

func TestVerify_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message for Verify")
	sig := ed25519.Sign(priv, msg)

	require.True(t, Verify(msg, sig, pub))
}

func TestVerify_InvalidSig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("test")
	sig := make([]byte, SignatureSize)

	require.False(t, Verify(msg, sig, pub))
}

func TestVerify_WrongPubKeyLength(t *testing.T) {
	require.False(t, Verify([]byte("msg"), make([]byte, SignatureSize), make([]byte, 31)))
	require.False(t, Verify([]byte("msg"), make([]byte, SignatureSize), make([]byte, 33)))
}

func TestVerify_WrongSigLength(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.False(t, Verify([]byte("msg"), make([]byte, 63), pub))
	require.False(t, Verify([]byte("msg"), make([]byte, 65), pub))
}

// --- VerifyRaw() error paths ---

func TestVerifyRaw_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("raw message for Solana-style verify")
	sig := ed25519.Sign(priv, msg)

	require.True(t, VerifyRaw(msg, sig, pub))
}

func TestVerifyRaw_WrongPubKeyLength(t *testing.T) {
	require.False(t, VerifyRaw([]byte("msg"), make([]byte, SignatureSize), make([]byte, 31)))
	require.False(t, VerifyRaw([]byte("msg"), make([]byte, SignatureSize), make([]byte, 33)))
}

func TestVerifyRaw_WrongSigLength(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.False(t, VerifyRaw([]byte("msg"), make([]byte, 63), pub))
	require.False(t, VerifyRaw([]byte("msg"), make([]byte, 65), pub))
}

func TestVerifyRaw_InvalidSig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.False(t, VerifyRaw([]byte("msg"), make([]byte, SignatureSize), pub))
}
