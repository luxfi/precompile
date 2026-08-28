// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
//go:build cgo

// See the file LICENSE for licensing terms.

// Confidentiality regression tests for the FHE gateway precompile (LP-134).
//
// These tests pin the launch-safety invariant that the original code violated:
// the precompile held a deterministic in-source secret key and returned real
// plaintext from a local decrypt, so anyone could read anyone's ciphertexts.
// After the fix the precompile holds NO secret key; decrypt/seal are ACL-gated
// and fail closed (threshold ceremony required) and NEVER return plaintext from
// a local key. Each test fails on the vulnerable code and passes on the fix.

package fhe

import (
	"context"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// aclTestState is a minimal AccessibleState wrapping a StateDB. The FHE
// handlers only touch GetStateDB(); the other accessors are never called on
// the decrypt/seal paths.
type aclTestState struct{ db contract.StateDB }

func (s *aclTestState) GetStateDB() contract.StateDB                     { return s.db }
func (s *aclTestState) GetBlockContext() contract.BlockContext           { return nil }
func (s *aclTestState) GetConsensusContext() context.Context             { return nil }
func (s *aclTestState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (s *aclTestState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

var _ contract.AccessibleState = (*aclTestState)(nil)

var (
	ownerAddr    = common.HexToAddress("0x00000000000000000000000000000000000000aa")
	attackerAddr = common.HexToAddress("0x00000000000000000000000000000000000000bb")

	selDecrypt    = []byte{0x12, 0x3d, 0x4c, 0x87} // decrypt(bytes32)
	selSealOutput = []byte{0x56, 0x7a, 0x11, 0x98} // sealOutput(bytes32,bytes)
)

// TestDecrypt_RejectsUnauthorizedCaller proves the ACL gate: a caller that does
// not own a handle is rejected — never handed plaintext-shaped output. On the
// vulnerable code this returned the real plaintext (42).
func TestDecrypt_RejectsUnauthorizedCaller(t *testing.T) {
	require.NoError(t, initTFHE())
	db := newTestStateDB()

	handle := encryptValue(db, 42, TypeEuint8, ownerAddr)
	require.NotEqual(t, common.Hash{}, handle)

	input := append(append([]byte{}, selDecrypt...), handle.Bytes()...)
	st := &aclTestState{db: db}

	ret, _, err := FHEPrecompile.Run(st, attackerAddr, ContractAddress, input, GasDecryptRequest, false)
	require.ErrorIs(t, err, ErrACLUnauthorized, "unauthorized decrypt must be rejected by the ACL")
	require.Empty(t, ret, "rejected decrypt must return no bytes")
	require.NotEqual(t, big.NewInt(42).Bytes(), ret, "must never leak the plaintext")
}

// TestDecrypt_OwnerFailsClosed_NeverLocalPlaintext proves that even the
// authorized owner cannot extract plaintext locally: decryption requires the
// F-Chain threshold ceremony, so the request fails closed. The precompile has
// no secret key, so there is no local plaintext to return.
func TestDecrypt_OwnerFailsClosed_NeverLocalPlaintext(t *testing.T) {
	require.NoError(t, initTFHE())
	db := newTestStateDB()

	handle := encryptValue(db, 42, TypeEuint8, ownerAddr)
	require.NotEqual(t, common.Hash{}, handle)

	input := append(append([]byte{}, selDecrypt...), handle.Bytes()...)
	st := &aclTestState{db: db}

	ret, _, err := FHEPrecompile.Run(st, ownerAddr, ContractAddress, input, GasDecryptRequest, false)
	require.ErrorIs(t, err, ErrThresholdDecryptionRequired,
		"owner decrypt must fail closed pending the F-Chain threshold ceremony")
	require.Empty(t, ret, "fail-closed decrypt must return no bytes")
	require.NotEqual(t, big.NewInt(42).Bytes(), ret, "must never return local plaintext")
}

// TestSealOutput_FailsClosed proves sealOutput is ACL-gated and fails closed,
// and that it NEVER hands the raw network-key ciphertext back to the caller
// (which on the vulnerable code it did, via a plain concat with the pubkey).
func TestSealOutput_FailsClosed(t *testing.T) {
	require.NoError(t, initTFHE())
	db := newTestStateDB()

	handle := encryptValue(db, 7, TypeEuint8, ownerAddr)
	require.NotEqual(t, common.Hash{}, handle)
	rawCt, _, ok := getCiphertext(db, handle)
	require.True(t, ok)

	sealPubKey := make([]byte, 32) // caller-provided seal target key
	input := append(append(append([]byte{}, selSealOutput...), handle.Bytes()...), sealPubKey...)
	st := &aclTestState{db: db}

	// Unauthorized caller: rejected by the ACL.
	ret, _, err := FHEPrecompile.Run(st, attackerAddr, ContractAddress, input, GasEncrypt, false)
	require.ErrorIs(t, err, ErrACLUnauthorized)
	require.Empty(t, ret)

	// Authorized owner: still fails closed (threshold re-encryption required),
	// and crucially never returns the raw ciphertext.
	ret, _, err = FHEPrecompile.Run(st, ownerAddr, ContractAddress, input, GasEncrypt, false)
	require.ErrorIs(t, err, ErrThresholdDecryptionRequired)
	require.Empty(t, ret)
	require.NotEqual(t, rawCt, ret, "must never leak the raw network-key ciphertext")
}

// TestSafePath_EncryptComputeStillWorks proves the 46 callers' safe path
// (encrypt-with-public-key + homomorphic compute) is intact. The result is
// verified OUT OF BAND with the test-held secret key (the threshold stand-in);
// the precompile itself never decrypts.
func TestSafePath_EncryptComputeStillWorks(t *testing.T) {
	require.NoError(t, initTFHE())
	db := newTestStateDB()

	h10 := encryptValue(db, 10, TypeEuint8, ownerAddr)
	h3 := encryptValue(db, 3, TypeEuint8, ownerAddr)
	require.NotEqual(t, common.Hash{}, h10)
	require.NotEqual(t, common.Hash{}, h3)

	sum := performFHEOperation(db, "add", h10, h3, ownerAddr)
	require.NotEqual(t, common.Hash{}, sum, "homomorphic add must succeed under public keys")

	ct, _, ok := getCiphertext(db, sum)
	require.True(t, ok)
	require.Equal(t, uint64(13), tfheDecrypt(ct, TypeEuint8).Uint64(),
		"encrypt+compute must produce the correct plaintext when decrypted out-of-band")
}

// TestNoNetworkKeys_FailsClosed proves there is no insecure default key: with no
// key material installed, encrypt and compute fail closed (empty handle) rather
// than fabricating a key. Snapshots and restores the suite keyset so other
// tests are unaffected.
func TestNoNetworkKeys_FailsClosed(t *testing.T) {
	require.NoError(t, initTFHE())
	keysMu.RLock()
	savedPk, savedBsk := publicKey, bootstrapKey
	keysMu.RUnlock()
	defer func() { require.NoError(t, SetNetworkKeys(savedPk, savedBsk)) }()

	require.NoError(t, SetNetworkKeys(nil, nil))
	require.False(t, HasNetworkKeys(), "precompile must report no keys after clearing")

	db := newTestStateDB()
	require.Equal(t, common.Hash{}, encryptValue(db, 5, TypeEuint8, ownerAddr),
		"encrypt must fail closed with no public key")

	// Even with two pre-stored ciphertexts, compute fails closed with no
	// bootstrap key.
	require.NoError(t, SetNetworkKeys(savedPk, savedBsk)) // briefly to stage inputs
	a := encryptValue(db, 1, TypeEuint8, ownerAddr)
	b := encryptValue(db, 2, TypeEuint8, ownerAddr)
	require.NoError(t, SetNetworkKeys(nil, nil))
	require.Equal(t, common.Hash{}, performFHEOperation(db, "add", a, b, ownerAddr),
		"compute must fail closed with no bootstrap key")
}
