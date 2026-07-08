// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// legacyEncodeNoKind reproduces the pre-decomplection (kind-less) wire
// layout: [mode][sigLen][sig][pkLen][pk][hash]. This is what a Solidity
// P3QLib.encode() that forgot the leading kind byte would produce. The
// precompile MUST reject it (the mode byte 0x44/0x65/0x87 is not a valid
// kind, so kind dispatch hits the default branch → abiFalse).
func legacyEncodeNoKind(mode uint8, sig, pk, hash []byte) []byte {
	out := make([]byte, 0, 1+4+len(sig)+4+len(pk)+len(hash))
	out = append(out, mode)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(sig)))
	out = append(out, b4[:]...)
	out = append(out, sig...)
	binary.BigEndian.PutUint32(b4[:], uint32(len(pk)))
	out = append(out, b4[:]...)
	out = append(out, pk...)
	out = append(out, hash...)
	return out
}

// TestP3Q_WireFormat_KindByteMandatory is the regression guard for the
// canonical-encoder invariant: the Go EncodeInput and the Solidity
// P3QLib.encode() MUST both put the kind byte at offset 0. A kind-less
// (mode-first) encoding of an otherwise-valid signature MUST be rejected,
// while the correct kind-first encoding of the same signature verifies.
//
// This test exists because the Solidity mirror encoder previously omitted
// the kind byte, which would have made every on-chain verify return false
// even for valid signatures.
func TestP3Q_WireFormat_KindByteMandatory(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	hash := make([]byte, MessageHashSize)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	sig, err := sk.SignCtx(rand.Reader, hash, PrecompileCtx)
	require.NoError(t, err)
	pk := sk.PublicKey.Bytes()

	// Canonical (kind-first) encoding — must verify.
	good := EncodeInput(ModeMLDSA65, sig, pk, hash)
	require.Equal(t, KindPulsar, good[0], "canonical encoder must place KindPulsar at offset 0")
	gas := P3QVerifyPrecompile.RequiredGas(good) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, good, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiTrueClone(), out, "canonical kind-first encoding must verify")

	// Kind-less (legacy / buggy Solidity) encoding of the SAME valid
	// signature — must be rejected on the kind-dispatch default branch.
	bad := legacyEncodeNoKind(ModeMLDSA65, sig, pk, hash)
	require.Equal(t, ModeMLDSA65, bad[0], "kind-less encoding starts with the mode byte")
	gas = P3QVerifyPrecompile.RequiredGas(bad) * 2
	out, _, err = P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, bad, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out,
		"kind-less encoding (mode byte read as kind) must be rejected — this is the Solidity-encoder bug guard")
}
