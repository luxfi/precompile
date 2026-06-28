// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
//go:build cgo

// See the file LICENSE for licensing terms.

package fhe

import (
	"math/big"
	"sync"

	"github.com/luxfi/fhe"
)

// Test-only threshold-FHE simulation.
//
// In production the precompile holds ONLY public key material (installed via
// SetNetworkKeys) and CANNOT decrypt — decryption is an F-Chain threshold
// ceremony where no single party holds the secret key. To unit-test the
// encrypt/compute path end to end, the test harness stands in for the DKG: it
// generates a throwaway keypair, installs the PUBLIC half into the precompile,
// and keeps the SECRET half HERE (in the test process only, never in the
// precompile) to verify results out of band — exactly what a threshold
// decryptor does, minus the share distribution.
//
// initTFHE and tfheDecrypt are the shims the op-level tests call. They exist
// ONLY in the test build. The precompile itself has no secret key, no
// decryptor, and no keygen seed.

var (
	testKeyOnce   sync.Once
	testDecryptor *fhe.BitwiseDecryptor // secret key lives ONLY here, in the test
	testKeyErr    error
)

// initTFHE installs a throwaway network keypair's PUBLIC half into the
// precompile and stashes the SECRET half in a test-only decryptor. Idempotent.
func initTFHE() error {
	testKeyOnce.Do(func() {
		params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
		if err != nil {
			testKeyErr = err
			return
		}
		kg := fhe.NewKeyGenerator(params)
		sk, pk := kg.GenKeyPair()
		bsk := kg.GenBootstrapKey(sk)
		if err := SetNetworkKeys(pk, bsk); err != nil {
			testKeyErr = err
			return
		}
		// The secret key NEVER enters the precompile — it lives only in this
		// test-side decryptor, mirroring the F-Chain threshold decryptor.
		testDecryptor = fhe.NewBitwiseDecryptor(params, sk)
	})
	return testKeyErr
}

// tfheDecrypt is the test-side (threshold-stand-in) decryptor. The precompile
// has no decrypt capability; this uses the test-held secret key to confirm that
// encrypt/compute produced the right plaintext.
func tfheDecrypt(ct []byte, fheType uint8) *big.Int {
	bc := deserializeBitCiphertext(ct)
	if bc == nil || testDecryptor == nil {
		return big.NewInt(0)
	}
	return new(big.Int).SetUint64(testDecryptor.DecryptUint64(bc))
}
