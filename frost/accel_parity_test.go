// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestFROST_RejectsECDSAShapedSignature proves the precompile verifies SCHNORR,
// not ECDSA. The deleted accel path routed FROST through the SigECDSA kernel --
// a different verification equation, with the 32-byte x-only key mis-framed
// against the kernel's 33-byte ECDSA key layout. That could accept an ECDSA
// signature the Schnorr verifier rejects, a wrong-primitive forgery surface and
// a CPU/GPU split. A genuine secp256k1 ECDSA signature, presented with the
// signer's x-only public key, must NOT verify as a FROST Schnorr signature.
func TestFROST_RejectsECDSAShapedSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)

	msgHash := crypto.Keccak256([]byte("ecdsa signature presented as frost-schnorr"))
	sig65, err := crypto.Sign(msgHash, priv) // r || s || v
	require.NoError(t, err)
	rs := sig65[:64] // r || s -- a valid ECDSA signature for (priv, msgHash)

	// x-only public key in FROST/BIP-340 layout (left-padded to 32 bytes).
	xb := priv.PublicKey.X.Bytes()
	pk := make([]byte, 32)
	copy(pk[32-len(xb):], xb)

	input := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(input[0:4], 3)
	binary.BigEndian.PutUint32(input[4:8], 5)
	copy(input[8:40], pk)
	copy(input[40:72], msgHash)
	copy(input[72:136], rs)

	res, _, err := FROSTVerifyPrecompile.Run(
		nil, common.Address{}, ContractFROSTVerifyAddress, input, 1_000_000, true,
	)
	require.NoError(t, err)
	require.Equal(t, byte(0), res[31],
		"a valid ECDSA signature must NOT verify as FROST-Schnorr (wrong-primitive accel path removed)")
}
