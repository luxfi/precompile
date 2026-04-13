// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hpke

import (
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// C-03: HPKE SingleShotOpen must not accept private keys in calldata.
//
// Vulnerability: OpSingleShotOpen (0x21) required the recipient's secret key
// in calldata, which is public on-chain. Any validator or block explorer can
// read the private key from the transaction.
//
// Fix: Remove OpSingleShotOpen. Only OpSingleShotSeal (0x20) is permitted.
// Decryption must be performed off-chain.
func TestC03_HPKEOpenRejected(t *testing.T) {
	input := make([]byte, 100)
	input[0] = 0x21 // Old OpSingleShotOpen
	input[1] = 0x00
	input[2] = 0x20 // KEMX25519
	input[3] = 0x00
	input[4] = 0x01 // KDF_HKDF_SHA256
	input[5] = 0x00
	input[6] = 0x01 // AEAD_AES128GCM

	ret, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1_000_000,
		false,
	)
	require.Error(t, err, "HPKE SingleShotOpen (0x21) must be rejected -- accepts private key in calldata")
	require.Nil(t, ret, "Open must not return any data")
}

// C-03: All HPKE Receiver/Open operations must be rejected.
//
// Any op that requires a secret key in calldata is a vulnerability.
// These op codes existed in the old contract and are now fully removed.
func TestC03_HPKEAllReceiverOpsRejected(t *testing.T) {
	receiverOps := []struct {
		name string
		op   byte
	}{
		{"SetupBaseR", 0x02},
		{"SetupPSKR", 0x04},
		{"SetupAuthR", 0x06},
		{"SetupAuthPSKR", 0x08},
		{"Open", 0x11},
		{"SingleShotOpen", 0x21},
	}

	for _, tc := range receiverOps {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, 100)
			input[0] = tc.op

			ret, _, err := HPKEPrecompile.Run(
				nil,
				common.Address{},
				ContractAddress,
				input,
				1_000_000,
				false,
			)
			require.Error(t, err, "HPKE %s (0x%02x) must be rejected", tc.name, tc.op)
			require.Nil(t, ret, "HPKE %s must not return data", tc.name)
		})
	}
}

// C-03: HPKE SingleShotSeal must still work (sender-side, public-key only).
func TestC03_HPKESealStillWorks(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kem, _, _ := suite.Params()

	pk, _, err := kem.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	// Build SingleShotSeal input
	input := []byte{OpSingleShotSeal}
	// cipher suite: KEM=0x0020, KDF=0x0001, AEAD=0x0001
	input = append(input, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01)
	// recipient pk length (2 bytes big-endian)
	input = append(input, byte(len(pkBytes)>>8), byte(len(pkBytes)))
	// recipient pk
	input = append(input, pkBytes...)
	// info length = 0
	input = append(input, 0x00, 0x00)
	// aad length = 0
	input = append(input, 0x00, 0x00)
	// plaintext
	input = append(input, []byte("test plaintext for HPKE seal")...)

	ret, _, err := HPKEPrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1_000_000,
		false,
	)
	require.NoError(t, err, "SingleShotSeal must succeed")
	require.NotEmpty(t, ret, "SingleShotSeal must return enc||ciphertext")
}
