// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package sr25519

/*
#cgo CFLAGS: -I${SRCDIR}/donna -I${SRCDIR}/donna/ed25519-donna -DED25519_CUSTOMRANDOM -DED25519_CUSTOMHASH -DED25519_NO_INLINE_ASM -O3 -w
#include "sr25519.h"
*/
import "C"
import "unsafe"

// backend names the verifier this build linked. The two builds must return the
// same verdict for every input; see the parity corpus in the tests.
const backend = "sr25519-donna (cgo)"

// verifySR25519 verifies an sr25519 Schnorrkel signature using the
// sr25519-donna C library. Signing context is hardcoded to "substrate".
func verifySR25519(publicKey, signature, message []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize || len(message) == 0 {
		return false
	}

	// sr25519_verify(signature, message, message_length, public_key) → bool
	result := C.sr25519_verify(
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		C.ulong(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
	)
	return bool(result)
}
