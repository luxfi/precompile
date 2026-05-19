// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestMagnetarPrecompile_Address pins the canonical LP-4200 slot 0x012207.
func TestMagnetarPrecompile_Address(t *testing.T) {
	want := common.HexToAddress("0x0000000000000000000000000000000000012207")
	require.Equal(t, want, ContractMagnetarVerifyAddress)
}

// TestMagnetarPrecompile_RequiredGas_Defaults verifies the gas-default
// path for too-short and unknown-mode inputs.
func TestMagnetarPrecompile_RequiredGas_Defaults(t *testing.T) {
	// Empty input → default gas (mode byte unreadable).
	require.Equal(t, MagnetarDefaultGas, MagnetarVerifyPrecompile.RequiredGas(nil))

	// Unknown mode → default gas.
	require.Equal(t, MagnetarDefaultGas, MagnetarVerifyPrecompile.RequiredGas([]byte{0xFF}))
}

// TestMagnetarPrecompile_RequiredGas_PerMode exercises the per-mode
// base-gas table.
func TestMagnetarPrecompile_RequiredGas_PerMode(t *testing.T) {
	for _, tc := range []struct {
		mode    uint8
		baseGas uint64
	}{
		{ModeSHA2_128s, SLH128sVerifyBaseGas},
		{ModeSHA2_128f, SLH128fVerifyBaseGas},
		{ModeSHA2_192s, SLH192sVerifyBaseGas},
		{ModeSHA2_192f, SLH192fVerifyBaseGas},
		{ModeSHA2_256s, SLH256sVerifyBaseGas},
		{ModeSHA2_256f, SLH256fVerifyBaseGas},
		{ModeSHAKE_128s, SLH128sVerifyBaseGas},
		{ModeSHAKE_128f, SLH128fVerifyBaseGas},
		{ModeSHAKE_192s, SLH192sVerifyBaseGas},
		{ModeSHAKE_192f, SLH192fVerifyBaseGas},
		{ModeSHAKE_256s, SLH256sVerifyBaseGas},
		{ModeSHAKE_256f, SLH256fVerifyBaseGas},
	} {
		// Mode byte only → base gas (no pubkey or message yet).
		got := MagnetarVerifyPrecompile.RequiredGas([]byte{tc.mode})
		require.Equal(t, tc.baseGas, got, "mode=0x%02x", tc.mode)
	}
}

// TestMagnetarPrecompile_RejectsShortInput confirms inputs shorter
// than the minimum header fail with ErrInvalidInput.
func TestMagnetarPrecompile_RejectsShortInput(t *testing.T) {
	for _, sz := range []int{0, 1, 2} {
		input := make([]byte, sz)
		gas := MagnetarDefaultGas * 2
		_, _, err := MagnetarVerifyPrecompile.Run(
			nil, common.Address{}, ContractMagnetarVerifyAddress,
			input, gas, true,
		)
		require.Error(t, err, "len=%d", sz)
		require.ErrorIs(t, err, contract.ErrInvalidInput, "len=%d", sz)
	}
}

// TestMagnetarPrecompile_RejectsUnsupportedMode confirms mode bytes
// outside the FIPS 205 set are rejected with ErrUnsupportedMode.
func TestMagnetarPrecompile_RejectsUnsupportedMode(t *testing.T) {
	input := []byte{0xFF, 0x00, 0x00}
	_, _, err := MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress,
		input, MagnetarDefaultGas*2, true,
	)
	require.ErrorIs(t, err, ErrUnsupportedMode)
}

// TestMagnetarPrecompile_RoundTrip_VerifyAcceptsValid is the manifesto
// test: a single-party FIPS 205 signature on the Magnetar precompile
// context verifies through the Magnetar precompile, because the
// verification operation IS FIPS 205 SLH-DSA.Verify. The Magnetar MPC
// ceremony off-chain produces byte-equal output.
func TestMagnetarPrecompile_RoundTrip_VerifyAcceptsValid(t *testing.T) {
	// Use SHA2_128s for the round-trip — fastest parameter set.
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	require.NoError(t, err)

	message := []byte("magnetar threshold sign roundtrip via precompile")
	signature, err := priv.SignCtx(rand.Reader, message, precompileCtx)
	require.NoError(t, err)

	input := buildInput(ModeSHA2_128s, priv.PublicKey.Bytes(), message, signature)

	gas := MagnetarVerifyPrecompile.RequiredGas(input)
	result, _, err := MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress,
		input, gas, true,
	)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "valid signature should verify")
}

// TestMagnetarPrecompile_RejectsTamperedSignature confirms that
// flipping a byte in the signature causes verification to return 0.
func TestMagnetarPrecompile_RejectsTamperedSignature(t *testing.T) {
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	require.NoError(t, err)

	message := []byte("tamper detection")
	signature, err := priv.SignCtx(rand.Reader, message, precompileCtx)
	require.NoError(t, err)
	signature[0] ^= 0xFF

	input := buildInput(ModeSHA2_128s, priv.PublicKey.Bytes(), message, signature)

	gas := MagnetarVerifyPrecompile.RequiredGas(input)
	result, _, err := MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress,
		input, gas, true,
	)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "tampered signature should not verify")
}

// TestModeName checks the human-readable mode-name mapping.
func TestModeName(t *testing.T) {
	require.Equal(t, "Magnetar-SHA2-128s", ModeName(ModeSHA2_128s))
	require.Equal(t, "Magnetar-SHAKE-256f", ModeName(ModeSHAKE_256f))
	require.Equal(t, "unknown", ModeName(0xFF))
}

// buildInput serialises [mode][pubKeyLen][pubKey][msgLen][msg][sig]
// in the wire format the precompile expects.
func buildInput(mode uint8, pubKey, message, signature []byte) []byte {
	out := make([]byte, 0, 1+2+len(pubKey)+2+len(message)+len(signature))
	out = append(out, mode)

	var plen [2]byte
	binary.BigEndian.PutUint16(plen[:], uint16(len(pubKey)))
	out = append(out, plen[:]...)
	out = append(out, pubKey...)

	var mlen [2]byte
	binary.BigEndian.PutUint16(mlen[:], uint16(len(message)))
	out = append(out, mlen[:]...)
	out = append(out, message...)

	out = append(out, signature...)
	return out
}
