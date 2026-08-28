// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package sr25519

import (
	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

// backend names the verifier this build linked. The two builds must return the
// same verdict for every input; see the parity corpus in the tests.
const backend = "go-schnorrkel (pure Go)"

// verifySR25519 is the pure-Go fallback when CGO is disabled.
// Uses ChainSafe/go-schnorrkel for Substrate-compatible sr25519 verification.
func verifySR25519(publicKey, signature, message []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize || len(message) == 0 {
		return false
	}

	var pubBytes [32]byte
	copy(pubBytes[:], publicKey)
	pub, err := schnorrkel.NewPublicKey(pubBytes)
	if err != nil {
		return false
	}

	var sigBytes [64]byte
	copy(sigBytes[:], signature)
	sig := new(schnorrkel.Signature)
	if err := sig.Decode(sigBytes); err != nil {
		return false
	}

	// "substrate" is the default signing context used by all Substrate runtimes
	// and polkadot-js. This matches the sr25519-donna C library.
	transcript := schnorrkel.NewSigningContext([]byte("substrate"), message)

	ok, err := pub.Verify(sig, transcript)
	return err == nil && ok
}
