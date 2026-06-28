// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sr25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestSR25519_RejectsEd25519Forgery is the regression proof for the
// wrong-curve accel divergence: the precompile used to route through
// luxfi/accel's Ed25519 GPU kernel ("closest GPU kernel"), so a *valid
// Ed25519* signature (same 32-byte key / 64-byte sig shape) was accepted as a
// valid sr25519/Schnorrkel signature, and accel-equipped validators returned
// a different verdict than CPU-only ones.
//
// sr25519 is Schnorrkel over Ristretto255 with a Merlin "substrate"
// transcript; an Ed25519 signature can never satisfy that verification
// equation. After the fix the precompile MUST reject this input.
func TestSR25519_RejectsEd25519Forgery(t *testing.T) {
	pub, priv, err := stded25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("cross-scheme forgery: an ed25519 signature presented as sr25519")
	sig := stded25519.Sign(priv, msg)

	// The input is, by construction, a genuinely valid Ed25519 signature with
	// the exact byte-shape sr25519 expects -- precisely what the deleted accel
	// (Ed25519 kernel) path verified and accepted.
	require.True(t, stded25519.Verify(pub, msg, sig),
		"vector must be a valid Ed25519 signature (the input the accel path accepted)")
	require.Len(t, []byte(pub), PublicKeySize)
	require.Len(t, sig, SignatureSize)

	input := buildInput(pub, sig, msg)
	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress, input, gas, true,
	)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31],
		"FORGERY: ed25519 signature must NOT verify as sr25519 (wrong-curve acceptance closed)")
}

// TestSR25519_RealSignatureStillVerifies pins the positive direction: the CPU
// Schnorrkel path (now the single source of truth) still accepts Alice's
// genuine sr25519 signature. Together with the forgery test this proves the
// verdict is the CPU verdict, byte-stable across the validator set.
func TestSR25519_RealSignatureStillVerifies(t *testing.T) {
	input := buildInput(alicePubKey, aliceSignature, aliceMessage)
	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress, input, gas, true,
	)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "genuine sr25519 signature must verify")
}
