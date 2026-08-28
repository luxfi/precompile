// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
//go:build cgo

// See the file LICENSE for licensing terms.

package fhe

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// The two ways every FHE operation can fail without doing any cryptography: the network
// keys are not installed, or an operand handle resolves to bytes that are not a ciphertext.
// Both must fail CLOSED — an error, never a result — and neither costs real FHE work, so
// they are cheap to exercise across the whole operation set.

// withoutKeys clears the installed network key material for the duration of f and restores
// it afterwards. Clearing is the documented fail-closed path of SetNetworkKeys.
func withoutKeys(t *testing.T, f func()) {
	t.Helper()
	require.NoError(t, initTFHE())

	keysMu.RLock()
	pk, bsk := publicKey, bootstrapKey
	keysMu.RUnlock()
	require.NotNil(t, pk, "the test harness must have installed keys before they can be cleared")

	require.NoError(t, SetNetworkKeys(nil, nil))
	require.False(t, HasNetworkKeys(), "clearing must actually disarm the precompile")
	defer func() {
		require.NoError(t, SetNetworkKeys(pk, bsk))
		require.True(t, HasNetworkKeys(), "keys must be restored for the rest of the suite")
	}()

	f()
}

// TestOps_FailClosedWithoutKeys proves that with no key material installed, every operation
// refuses rather than fabricating a key or returning an empty-but-successful result. This is
// the state a validator is in before the F-Chain DKG output is loaded, and the state it
// returns to if keys are withdrawn — an op that "succeeded" there would write a handle
// referring to nothing.
//
// Operands are stored while keys are present, so the refusal comes from the missing
// evaluator and not from an unresolvable handle.
func TestOps_FailClosedWithoutKeys(t *testing.T) {
	require.NoError(t, initTFHE())
	db := newTestStateDB()
	a := encryptValue(db, 5, TypeEuint8, ownerAddr)
	b := encryptValue(db, 3, TypeEuint8, ownerAddr)
	cond := encryptValue(db, 1, TypeEbool, ownerAddr)
	require.NotEqual(t, common.Hash{}, a)

	c := &FHEContract{}
	state := &aclTestState{db: db}

	withoutKeys(t, func() {
		for _, op := range allSelectors {
			body := make([]byte, len(op.body))
			copy(body, op.body)
			// Point the operand words at handles that DO resolve, so the only thing
			// missing is the key material.
			if len(body) >= 32 {
				copy(body[0:32], a.Bytes())
			}
			if len(body) >= 64 {
				copy(body[32:64], b.Bytes())
			}
			if len(body) >= 96 {
				copy(body[0:32], cond.Bytes())
				copy(body[32:64], a.Bytes())
				copy(body[64:96], b.Bytes())
			}

			_, _, err := c.Run(state, ownerAddr, ContractAddress,
				append([]byte(op.sel), body...), 1<<62, false)
			require.Errorf(t, err, "%s must fail closed with no keys installed", op.name)
		}

		// The primitives report the same thing directly.
		require.Nil(t, tfheAdd(nil, nil, TypeEuint8))
		require.Nil(t, tfheTrivialEncrypt(nil, TypeEuint8))
		require.Nil(t, tfheRandom(TypeEuint8, 42))
		require.Nil(t, tfheGetNetworkPublicKey())
		require.False(t, HasNetworkKeys())
	})

	// And once keys are back, the same call succeeds — proving the refusal was the keys.
	_, _, err := c.Run(state, ownerAddr, ContractAddress,
		append([]byte("\x23\xb8\x72\xdd"), append(a.Bytes(), b.Bytes()...)...), 1<<62, false)
	require.NoError(t, err)
}

// plantCorrupt stores a handle whose metadata claims a ciphertext of the given length while
// the data slots hold bytes that are not a valid encoding.
func plantCorrupt(db *testStateDB, ctType uint8, n int) common.Hash {
	var handle common.Hash
	handle[0], handle[31] = ctType, byte(n)

	var meta common.Hash
	meta[0] = ctType
	meta[1] = byte(n >> 24)
	meta[2] = byte(n >> 16)
	meta[3] = byte(n >> 8)
	meta[4] = byte(n)
	db.SetState(ContractAddress, handle, meta)

	for i := 0; i < n; i += 32 {
		slot := keccak256Hash(handle.Bytes(), common.BigToHash(big.NewInt(int64(i/32))).Bytes())
		var chunk common.Hash
		for j := range chunk {
			chunk[j] = 0xEE // not a ciphertext under any encoding
		}
		db.SetState(ContractAddress, slot, chunk)
	}
	return handle
}

// takesPlaintext names the operations whose first argument is a public value from calldata
// rather than a handle to a stored ciphertext. They cannot meet a corrupt operand.
var takesPlaintext = map[string]bool{
	"asEbool": true, "asEuint4": true, "asEuint8": true, "asEuint16": true,
	"asEuint32": true, "asEuint64": true, "asEuint128": true, "asEuint256": true,
	"asEaddress": true, "rand": true, "verify": true,
}

// TestOps_FailClosedOnCorruptCiphertext proves an operand that resolves to bytes which are
// not a ciphertext is refused, rather than being fed to the evaluator or silently treated
// as an empty value.
func TestOps_FailClosedOnCorruptCiphertext(t *testing.T) {
	require.NoError(t, initTFHE())
	db := newTestStateDB()
	good := encryptValue(db, 5, TypeEuint8, ownerAddr)
	bad := plantCorrupt(db, TypeEuint8, 64)
	badBool := plantCorrupt(db, TypeEbool, 64)

	c := &FHEContract{}
	state := &aclTestState{db: db}

	for _, op := range allSelectors {
		if takesPlaintext[op.name] {
			// These read a public value out of calldata rather than resolving a handle,
			// so a corrupt stored ciphertext is not something they can encounter.
			continue
		}
		body := make([]byte, len(op.body))
		copy(body, op.body)
		if len(body) >= 32 {
			copy(body[0:32], bad.Bytes())
		}
		if len(body) >= 64 {
			copy(body[32:64], bad.Bytes())
		}
		if len(body) >= 96 {
			copy(body[0:32], badBool.Bytes())
			copy(body[32:64], bad.Bytes())
			copy(body[64:96], good.Bytes())
		}

		_, _, err := c.Run(state, ownerAddr, ContractAddress,
			append([]byte(op.sel), body...), 1<<62, false)
		require.Errorf(t, err, "%s must refuse an operand that is not a ciphertext", op.name)
	}

	// One good operand and one corrupt one is still a refusal, at either position.
	for name, body := range map[string][]byte{
		"left corrupt":  append(bad.Bytes(), good.Bytes()...),
		"right corrupt": append(good.Bytes(), bad.Bytes()...),
	} {
		_, _, err := c.Run(state, ownerAddr, ContractAddress,
			append([]byte("\x23\xb8\x72\xdd"), body...), 1<<62, false)
		require.Errorf(t, err, "add with %s must be refused", name)
	}

	// The control: two good operands succeed, so the refusals above are the corruption.
	_, _, err := c.Run(state, ownerAddr, ContractAddress,
		append([]byte("\x23\xb8\x72\xdd"), append(good.Bytes(), good.Bytes()...)...), 1<<62, false)
	require.NoError(t, err)
}

// TestGetCiphertext_UnknownAndEmptyHandles covers the two ways a handle fails to resolve:
// nothing was ever stored, and metadata declaring a zero-length ciphertext.
func TestGetCiphertext_UnknownAndEmptyHandles(t *testing.T) {
	db := newTestStateDB()

	var missing common.Hash
	missing[0] = 0x01
	_, _, ok := getCiphertext(db, missing)
	require.False(t, ok, "a handle nothing was stored at must not resolve")

	// Metadata present but declaring zero length is not a ciphertext either.
	var zeroLen common.Hash
	zeroLen[0] = 0x02
	var meta common.Hash
	meta[0] = TypeEuint8 // type set, length left at zero
	db.SetState(ContractAddress, zeroLen, meta)
	_, _, ok = getCiphertext(db, zeroLen)
	require.False(t, ok, "a zero-length ciphertext must not resolve")
}
