// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xwing

import (
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// frame builds a well-formed encapsulate call: op || seed(32) || pk(1216).
func frame(t *testing.T, seed byte) ([]byte, xwing.PrivateKey) {
	t.Helper()
	scheme := xwing.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	in := make([]byte, 1+SeedSize+len(pkBytes))
	in[0] = OpEncapsulate
	for i := range SeedSize {
		in[1+i] = seed
	}
	copy(in[1+SeedSize:], pkBytes)
	return in, *sk.(*xwing.PrivateKey)
}

// The frame is exact. One byte short and one byte long are both refused --
// a trailing byte would give the same encapsulation two calldata spellings.
func TestRefuse_FrameLengthIsExact(t *testing.T) {
	in, _ := frame(t, 0x01)
	gas := XWingPrecompile.RequiredGas(in)

	_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, in, gas, true)
	require.NoError(t, err, "the exact frame is the accepted one")

	short := in[:len(in)-1]
	_, _, err = XWingPrecompile.Run(nil, common.Address{}, ContractAddress, short, gas, true)
	require.ErrorIs(t, err, ErrInvalidInput, "one byte short must be refused")

	long := append(append([]byte{}, in...), 0x00)
	_, _, err = XWingPrecompile.Run(nil, common.Address{}, ContractAddress, long, gas, true)
	require.ErrorIs(t, err, ErrInvalidInput, "one trailing byte must be refused")
}

// Empty calldata carries no op byte at all.
func TestRefuse_Empty(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, in, 100_000, true)
		require.ErrorIs(t, err, ErrInvalidInput)
	}
}

// A public key of the right length whose bytes are not a valid ML-KEM-768
// encapsulation key is refused, not encapsulated against.
func TestRefuse_PublicKeyFailingModulusCheck(t *testing.T) {
	in, _ := frame(t, 0x01)
	for i := 1 + SeedSize; i < len(in); i++ {
		in[i] = 0xFF // 0xFFF > q-1 = 3328 in every 12-bit lane
	}
	ret, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, in, 100_000, true)
	require.Error(t, err)
	require.Nil(t, ret)
}

// The caller address is bound into the encapsulation seed. Two callers
// submitting byte-identical calldata must not land on the same ciphertext:
// without that binding, one contract could replay another's encapsulation
// and hold the shared secret it thought was its own.
func TestBinding_CallerSeparatesSeed(t *testing.T) {
	in, sk := frame(t, 0x07)
	gas := XWingPrecompile.RequiredGas(in)

	a := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	b := common.HexToAddress("0x00000000000000000000000000000000000000bb")

	retA, _, err := XWingPrecompile.Run(nil, a, ContractAddress, in, gas, true)
	require.NoError(t, err)
	retB, _, err := XWingPrecompile.Run(nil, b, ContractAddress, in, gas, true)
	require.NoError(t, err)

	require.NotEqual(t, retA, retB,
		"identical calldata from two callers produced one encapsulation: the caller is not bound into the seed")

	// Both remain honest encapsulations under the same key.
	scheme := xwing.Scheme()
	ctSize, ssSize := scheme.CiphertextSize(), scheme.SharedKeySize()
	for name, ret := range map[string][]byte{"a": retA, "b": retB} {
		ss, err := scheme.Decapsulate(&sk, ret[2:2+ctSize])
		require.NoError(t, err, name)
		require.Equal(t, ss, ret[2+ctSize:2+ctSize+ssSize],
			"caller %s: returned shared secret must be the one the ciphertext carries", name)
	}
}

// Same caller, same calldata, same answer -- every validator replays this
// call and must reach the same state.
func TestBinding_SameCallerIsDeterministic(t *testing.T) {
	in, _ := frame(t, 0x07)
	gas := XWingPrecompile.RequiredGas(in)
	caller := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	first, _, err := XWingPrecompile.Run(nil, caller, ContractAddress, in, gas, true)
	require.NoError(t, err)
	for range 4 {
		again, _, err := XWingPrecompile.Run(nil, caller, ContractAddress, in, gas, true)
		require.NoError(t, err)
		require.Equal(t, first, again, "encapsulation must not depend on anything but its inputs")
	}
}

// expandSeed is pinned to its construction, not just to "is deterministic".
// The two halves are separated by a trailing tag byte; if that tag were
// dropped the halves would be equal and the 64-byte seed would carry only
// 32 bytes of entropy -- a silent halving that every round-trip test
// still passes.
func TestBinding_ExpandSeedConstruction(t *testing.T) {
	caller := common.HexToAddress("0x0000000000000000000000000000000000001234")
	raw := make([]byte, SeedSize)
	for i := range raw {
		raw[i] = byte(i)
	}

	got := expandSeed(caller, raw)
	require.Len(t, got, 64)

	want := make([]byte, 0, 64)
	for _, tag := range []byte{0x00, 0x01} {
		h := sha256.New()
		h.Write([]byte("XWING_ENCAP_v1"))
		h.Write(caller.Bytes())
		h.Write(raw)
		h.Write([]byte{tag})
		want = h.Sum(want)
	}
	require.Equal(t, want, got)
	require.NotEqual(t, got[:32], got[32:], "the halves must be domain-separated")
}
