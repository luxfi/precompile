// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sr25519

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Known test vector from sr25519-donna examples:
// Alice's well-known Substrate dev account.
var (
	// Alice's sr25519 public key (SS58: 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY)
	alicePubKey = mustHex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")

	// Message signed by Alice
	aliceMessage = []byte("I hereby verify that I control 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")

	// sr25519 signature from Alice over the message (with "substrate" context)
	aliceSignature = mustHex("1037eb7e51613d0dcf5930ae518819c87d655056605764840d9280984e1b7063c4566b55bf292fcab07b369d01095879b50517beca4d26e6a65866e25fec0d83")
)

// buildInput constructs precompile input: pubkey(32) || signature(64) || message(N)
func buildInput(pubkey, sig, msg []byte) []byte {
	input := make([]byte, 0, len(pubkey)+len(sig)+len(msg))
	input = append(input, pubkey...)
	input = append(input, sig...)
	input = append(input, msg...)
	return input
}

func TestSR25519Verify_AliceKnownVector(t *testing.T) {
	input := buildInput(alicePubKey, aliceSignature, aliceMessage)

	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, remainingGas, err := SR25519VerifyPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "Alice's known signature should verify")
	require.Equal(t, uint64(0), remainingGas, "all gas should be consumed")
}

func TestSR25519Verify_InvalidSignature(t *testing.T) {
	// Corrupt signature by flipping a byte
	badSig := make([]byte, len(aliceSignature))
	copy(badSig, aliceSignature)
	badSig[0] ^= 0xFF

	input := buildInput(alicePubKey, badSig, aliceMessage)

	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "corrupted signature should be invalid")
}

func TestSR25519Verify_WrongMessage(t *testing.T) {
	input := buildInput(alicePubKey, aliceSignature, []byte("wrong message"))

	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "wrong message should not verify")
}

func TestSR25519Verify_WrongPubkey(t *testing.T) {
	// Use Bob's public key with Alice's signature
	bobPubKey := mustHex("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")
	input := buildInput(bobPubKey, aliceSignature, aliceMessage)

	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		input, gas, true,
	)

	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "wrong public key should not verify")
}

func TestSR25519Verify_InputTooShort(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"just pubkey", make([]byte, 32)},
		{"pubkey+sig no msg", make([]byte, 96)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gas := SR25519VerifyPrecompile.RequiredGas(tt.input)
			result, _, err := SR25519VerifyPrecompile.Run(
				nil, common.Address{}, ContractAddress,
				tt.input, gas+10_000, true,
			)
			require.Error(t, err)
			require.Equal(t, byte(0), result[31])
		})
	}
}

func TestSR25519Verify_OutOfGas(t *testing.T) {
	input := buildInput(alicePubKey, aliceSignature, aliceMessage)

	_, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress,
		input, 100, // way too little gas
		true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

func TestSR25519Verify_GasCost(t *testing.T) {
	// Empty message (minimum)
	shortInput := make([]byte, MinInputSize)
	gasShort := SR25519VerifyPrecompile.RequiredGas(shortInput)
	require.Equal(t, SR25519VerifyBaseGas+1*SR25519VerifyPerByteGas, gasShort)

	// 1KB message
	longInput := make([]byte, PublicKeySize+SignatureSize+1024)
	gasLong := SR25519VerifyPrecompile.RequiredGas(longInput)
	require.Equal(t, SR25519VerifyBaseGas+1024*SR25519VerifyPerByteGas, gasLong)
}

func TestSR25519Verify_Address(t *testing.T) {
	require.Equal(t, ContractAddress, SR25519VerifyPrecompile.Address())
}

func BenchmarkSR25519Verify(b *testing.B) {
	input := buildInput(alicePubKey, aliceSignature, aliceMessage)
	gas := SR25519VerifyPrecompile.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SR25519VerifyPrecompile.Run(
			nil, common.Address{}, ContractAddress,
			input, gas, true,
		)
	}
}
