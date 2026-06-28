// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestCGGMP21_RecoveryByteIsBound proves the CPU verifier's recover-and-compare
// binding is authoritative. The deleted accel SigECDSA path verified only the
// 64-byte r||s (ignoring the recovery byte) and truncated the 65-byte
// uncompressed key to 33 bytes -- so it could return "valid" for an input the
// CPU verifier rejects, a CPU/GPU consensus split. A signature with valid r||s
// but a flipped recovery byte must be rejected, because verifyECDSASignature
// ecrecovers under that byte and compares against the supplied key.
func TestCGGMP21_RecoveryByteIsBound(t *testing.T) {
	priv, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	pub := crypto.FromECDSAPub(&priv.PublicKey)
	msgHash := crypto.Keccak256([]byte("cggmp21 recovery-byte binding"))
	sig, err := crypto.Sign(msgHash, priv) // 65 bytes: r || s || v, correct v in {0,1}
	require.NoError(t, err)

	run := func(s []byte) byte {
		input := make([]byte, MinInputSize)
		binary.BigEndian.PutUint32(input[0:4], 3)
		binary.BigEndian.PutUint32(input[4:8], 5)
		copy(input[8:73], pub)
		copy(input[73:105], msgHash)
		copy(input[105:170], s)
		res, _, err := CGGMP21VerifyPrecompile.Run(
			nil, common.Address{}, ContractCGGMP21VerifyAddress, input, 1_000_000, true,
		)
		require.NoError(t, err)
		return res[31]
	}

	// Correct signature verifies on the CPU path.
	require.Equal(t, byte(1), run(sig), "correct ECDSA signature must verify")

	// Same r||s, flipped recovery byte: r||s still satisfies VerifySignature,
	// but ecrecover now yields a different key, so the recover-compare binding
	// rejects it. The deleted accel path (r||s only) would have accepted it.
	bad := make([]byte, 65)
	copy(bad, sig)
	bad[64] ^= 0x01
	require.Equal(t, byte(0), run(bad),
		"flipped recovery byte must be rejected (recover-compare binding is authoritative)")
}
