// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package starkfri

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestStarkFRI_Address pins the slot allocated to the strict-PQ
// STARK-FRI verifier dispatch (placeholder 0x012220 pending dedicated
// LP allocation; see contract.go package doc).
func TestStarkFRI_Address(t *testing.T) {
	want := common.HexToAddress("0x0000000000000000000000000000000000012220")
	require.Equal(t, want, ContractStarkFRIVerifyAddress)
}

// TestStarkFRI_RequiredGas verifies the gas formula: 200_000 + 10 * len(input).
func TestStarkFRI_RequiredGas(t *testing.T) {
	for _, n := range []int{0, 1, 64, 256, 4096, 131072} {
		input := make([]byte, n)
		got := StarkFRIVerifyPrecompile.RequiredGas(input)
		want := BaseVerifyGas + uint64(n)*PerByteGas
		require.Equal(t, want, got, "len=%d", n)
	}
}

// TestStarkFRI_RejectsBadMagic ensures proofs without the "P3Q1" header
// are rejected with ErrInvalidProof (even when a verifier is
// registered).
func TestStarkFRI_RejectsBadMagic(t *testing.T) {
	// Register a verifier that would say yes if asked; the structural
	// check must reject before the verifier is invoked.
	called := false
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		called = true
		return true, nil
	})
	defer RegisterVerifier(nil)

	proof := []byte("BOGUS-not-a-starkfri-proof-but-long-enough")
	pub := []byte{0xde, 0xad, 0xbe, 0xef}
	input := buildInput(VersionV1, proof, pub)

	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidProof)
	require.False(t, called, "verifier callback must not run on bad magic")
}

// TestStarkFRI_RejectsShortInput ensures inputs below MinInputLength
// fail with ErrInvalidInputLength.
func TestStarkFRI_RejectsShortInput(t *testing.T) {
	for _, sz := range []int{0, 1, 5, MinInputLength - 1} {
		input := make([]byte, sz)
		gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
		_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
		require.ErrorIs(t, err, ErrInvalidInputLength, "len=%d", sz)
	}
}

// TestStarkFRI_RoundTrip_WithRegisteredVerifier registers a fake
// verifier that accepts and asserts Run() succeeds end-to-end.
func TestStarkFRI_RoundTrip_WithRegisteredVerifier(t *testing.T) {
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

	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
	out, gasLeft, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Empty(t, out)
	require.Less(t, gasLeft, gas)
	require.Equal(t, VersionV1, saw.version)
	require.Equal(t, proof, saw.proof)
	require.Equal(t, pub, saw.pub)
}

// TestStarkFRI_NoVerifierRegistered confirms that without a registered
// verifier callback, structurally-valid input yields
// ErrVerifierNotRegistered.
func TestStarkFRI_NoVerifierRegistered(t *testing.T) {
	RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("payload")...)
	pub := []byte{0xaa}
	input := buildInput(VersionV1, proof, pub)

	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrVerifierNotRegistered)
}

// TestStarkFRI_RejectsBadVersion confirms versions other than 0x01 are
// rejected with ErrInvalidVersion.
func TestStarkFRI_RejectsBadVersion(t *testing.T) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return true, nil })
	defer RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("payload")...)
	pub := []byte{0xaa}
	input := buildInput(0x00, proof, pub)

	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidVersion)
}

// TestStarkFRI_VerifierReturnsFalse confirms that when the registered
// verifier reports the proof as invalid we surface ErrInvalidProof.
func TestStarkFRI_VerifierReturnsFalse(t *testing.T) {
	RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return false, nil })
	defer RegisterVerifier(nil)

	proof := append([]byte(MagicHeader), []byte("payload")...)
	pub := []byte{0xaa}
	input := buildInput(VersionV1, proof, pub)

	gas := StarkFRIVerifyPrecompile.RequiredGas(input) * 2
	_, _, err := StarkFRIVerifyPrecompile.Run(nil, common.Address{}, ContractStarkFRIVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidProof)
}

// TestStarkFRI_RegisterDefaultVerifier_DoesNotClobber pins the init-
// order invariant: a real verifier registered FIRST (via the imported
// precompile package's init) is NOT overwritten by a later
// RegisterDefaultVerifier (the geth-side refuse stub, whose init runs
// after the imported package's). This is what makes the build-tagged
// cgo binding win regardless of init order.
func TestStarkFRI_RegisterDefaultVerifier_DoesNotClobber(t *testing.T) {
	defer RegisterVerifier(nil)
	RegisterVerifier(nil) // start from an empty slot
	realFn := func(byte, []byte, []byte) (bool, error) { return true, nil }
	RegisterVerifier(realFn) // real binding claims the slot first
	installed := RegisterDefaultVerifier(func(byte, []byte, []byte) (bool, error) {
		return false, ErrVerifierNotRegistered // refuse stub, "runs later"
	})
	require.False(t, installed, "default must not install over an existing verifier")
	ok, err := loadVerifier()(VersionV1, nil, nil)
	require.True(t, ok)
	require.NoError(t, err, "the real verifier must survive the default registration")
}

// TestStarkFRI_RegisterDefaultVerifier_EngagesWhenAbsent confirms the
// safe-refuse default engages when (and only when) no verifier is
// present — the no-tag / cgo-disabled build path.
func TestStarkFRI_RegisterDefaultVerifier_EngagesWhenAbsent(t *testing.T) {
	defer RegisterVerifier(nil)
	RegisterVerifier(nil) // empty slot
	installed := RegisterDefaultVerifier(func(byte, []byte, []byte) (bool, error) {
		return false, ErrVerifierNotRegistered
	})
	require.True(t, installed, "default must install into an empty slot")
	_, err := loadVerifier()(VersionV1, nil, nil)
	require.ErrorIs(t, err, ErrVerifierNotRegistered)
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
