// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestP3Q_Address pins the canonical LP-4200 slot 0x012205.
func TestP3Q_Address(t *testing.T) {
	want := common.HexToAddress("0x0000000000000000000000000000000000012205")
	require.Equal(t, want, ContractP3QVerifyAddress)
}

// TestP3Q_RequiredGas verifies the gas formula: 200_000 + 10 * len(input).
func TestP3Q_RequiredGas(t *testing.T) {
	for _, n := range []int{0, 1, 64, 256, 4096, 131072} {
		input := make([]byte, n)
		got := P3QVerifyPrecompile.RequiredGas(input)
		want := BaseVerifyGas + uint64(n)*PerByteGas
		require.Equal(t, want, got, "len=%d", n)
	}
}

// TestP3Q_RejectsBadMagic ensures proofs without the "P3Q1" header are
// rejected with ErrInvalidProof (even when a verifier is registered).
func TestP3Q_RejectsBadMagic(t *testing.T) {
	// Register a verifier that would say yes if asked; the structural
	// check must reject before the verifier is invoked.
	called := false
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		called = true
		return true, nil
	})
	defer RegisterVerifier(nil)

	proof := []byte("BOGUS-not-a-p3q-proof-but-long-enough")
	pub := []byte{0xde, 0xad, 0xbe, 0xef}
	input := buildInput(VersionV1, proof, pub)

	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidProof)
	require.False(t, called, "verifier callback must not run on bad magic")
}

// TestP3Q_RejectsShortInput ensures inputs below MinInputLength fail with
// ErrInvalidInputLength.
func TestP3Q_RejectsShortInput(t *testing.T) {
	for _, sz := range []int{0, 1, 5, MinInputLength - 1} {
		input := make([]byte, sz)
		gas := P3QVerifyPrecompile.RequiredGas(input) * 2
		_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
		require.ErrorIs(t, err, ErrInvalidInputLength, "len=%d", sz)
	}
}

// TestP3Q_RoundTrip_WithRegisteredVerifier registers a fake verifier
// that accepts and asserts Run() succeeds end-to-end.
func TestP3Q_RoundTrip_WithRegisteredVerifier(t *testing.T) {
	saw := struct {
		version byte
		proof   []byte
		pub     []byte
	}{}
	RegisterVerifier(func(v byte, p, pi []byte) (bool, error) {
		saw.version = v
		saw.proof = append([]byte(nil), p...)
		saw.pub = append([]byte(nil), pi...)
		return true, nil
	})
	defer RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("STARK-FRI-cSHAKE256-Goldilocks-payload")...)
	pub := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	input := buildInput(VersionV1, proof, pub)

	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, gasLeft, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Empty(t, out)
	require.Less(t, gasLeft, gas)
	require.Equal(t, VersionV1, saw.version)
	require.Equal(t, proof, saw.proof)
	require.Equal(t, pub, saw.pub)
}

// TestP3Q_NoVerifierRegistered confirms that without a registered
// verifier callback, structurally-valid input yields
// ErrVerifierNotRegistered.
func TestP3Q_NoVerifierRegistered(t *testing.T) {
	RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("payload")...)
	pub := []byte{0xaa}
	input := buildInput(VersionV1, proof, pub)

	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrVerifierNotRegistered)
}

// TestP3Q_RejectsBadVersion confirms versions other than 0x01 are
// rejected with ErrInvalidVersion.
func TestP3Q_RejectsBadVersion(t *testing.T) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	defer RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("payload")...)
	pub := []byte{0xaa}
	input := buildInput(0x00, proof, pub)

	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidVersion)
}

// TestP3Q_VerifierReturnsFalse confirms that when the registered
// verifier reports the proof as invalid we surface ErrInvalidProof.
func TestP3Q_VerifierReturnsFalse(t *testing.T) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return false, nil })
	defer RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("payload")...)
	pub := []byte{0xaa}
	input := buildInput(VersionV1, proof, pub)

	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidProof)
}

// buildInput serialises [version][proof_len][proof][pub_len][pub] in
// the wire format the precompile expects.
func buildInput(version byte, proof, pub []byte) []byte {
	out := make([]byte, 0, 1+4+len(proof)+4+len(pub))
	out = append(out, version)
	var pl [4]byte
	binary.BigEndian.PutUint32(pl[:], uint32(len(proof)))
	out = append(out, pl[:]...)
	out = append(out, proof...)
	var ul [4]byte
	binary.BigEndian.PutUint32(ul[:], uint32(len(pub)))
	out = append(out, ul[:]...)
	out = append(out, pub...)
	return out
}
