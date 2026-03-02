// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// H-07: Ed25519 must implement StatefulPrecompiledContract.
//
// Vulnerability: Ed25519 Contract had a standalone Run(input) signature that
// did not match the StatefulPrecompiledContract interface (which requires
// accessibleState, caller, addr, input, suppliedGas, readOnly). This meant
// it could not be registered in the module system and could not properly
// deduct gas, allowing free verification.
//
// Fix: Ed25519 Contract must implement StatefulPrecompiledContract with proper
// gas deduction.
func TestH07_Ed25519ImplementsStatefulInterface(t *testing.T) {
	// Compile-time check that ed25519VerifyPrecompile satisfies the interface.
	var _ contract.StatefulPrecompiledContract = Ed25519VerifyPrecompile

	// Generate a valid Ed25519 key pair and signature
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := make([]byte, MessageHashSize)
	rand.Read(message)

	signature := ed25519.Sign(priv, message)

	// Build input: message(32) + signature(64) + pubkey(32) = 128 bytes
	input := make([]byte, InputLength)
	copy(input[0:MessageHashSize], message)
	copy(input[MessageHashSize:MessageHashSize+SignatureSize], signature)
	copy(input[MessageHashSize+SignatureSize:], pub)

	// Call via StatefulPrecompiledContract interface
	suppliedGas := uint64(100_000)
	ret, remainingGas, err := Ed25519VerifyPrecompile.Run(
		nil,
		ContractAddress,
		ContractAddress,
		input,
		suppliedGas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, ret, "Valid signature must return a result")
	require.Equal(t, byte(1), ret[31], "Valid signature must return 1")

	// Gas must be deducted
	require.Less(t, remainingGas, suppliedGas,
		"Gas must be deducted for verification (remaining=%d, supplied=%d)",
		remainingGas, suppliedGas)

	expectedRemaining := suppliedGas - Ed25519VerifyGas
	require.Equal(t, expectedRemaining, remainingGas,
		"Remaining gas must equal supplied - Ed25519VerifyGas")
}

// H-07: Ed25519 must reject invalid signatures via StatefulPrecompiledContract.
func TestH07_Ed25519InvalidSigViaStateful(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := make([]byte, MessageHashSize)
	rand.Read(message)

	// Invalid signature (all zeros)
	input := make([]byte, InputLength)
	copy(input[0:MessageHashSize], message)
	// signature is all zeros (invalid)
	copy(input[MessageHashSize+SignatureSize:], pub)

	c := Ed25519VerifyPrecompile
	ret, remainingGas, err := c.Run(nil, ContractAddress, ContractAddress, input, 100_000, false)

	require.NoError(t, err, "Invalid sig should return nil/empty, not error")
	// Invalid signature returns nil or zero result
	if ret != nil {
		require.Equal(t, byte(0), ret[31], "Invalid signature must return 0")
	}

	// Gas must still be deducted
	require.Less(t, remainingGas, uint64(100_000),
		"Gas must be deducted even for invalid signatures")
}

// H-07: Ed25519 with insufficient gas must fail.
func TestH07_Ed25519OutOfGas(t *testing.T) {
	input := make([]byte, InputLength)

	c := Ed25519VerifyPrecompile
	_, _, err := c.Run(nil, ContractAddress, ContractAddress, input, Ed25519VerifyGas-1, false)
	require.Error(t, err, "Must fail with insufficient gas")
}

// H-07: Ed25519 with wrong input length must return nil.
func TestH07_Ed25519WrongInputLength(t *testing.T) {
	c := Ed25519VerifyPrecompile

	for _, size := range []int{0, 1, 64, 127, 129, 256} {
		input := make([]byte, size)
		ret, _, err := c.Run(nil, ContractAddress, ContractAddress, input, 100_000, false)
		require.NoError(t, err, "Wrong length %d should not error (should return nil)", size)
		require.Nil(t, ret, "Wrong length %d must return nil", size)
	}
}
