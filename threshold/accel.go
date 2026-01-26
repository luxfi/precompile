// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"crypto/ed25519"
	"sync"

	"github.com/luxfi/accel"
	accelcrypto "github.com/luxfi/accel/ops/crypto"
	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/mldsa"
)

// BatchVerifyThreshold is the minimum batch size to use GPU acceleration.
// Below this threshold, CPU verification is more efficient.
const BatchVerifyThreshold = 4

// verifyBatchSignatures verifies multiple signatures using GPU acceleration when available.
// Falls back to sequential CPU verification when GPU is unavailable or batch is small.
func (tm *ThresholdManager) VerifyBatchSignatures(
	keyType KeyType,
	sigs, pks, msgs [][]byte,
) ([]bool, error) {
	if len(sigs) == 0 {
		return nil, nil
	}
	if len(sigs) != len(pks) || len(sigs) != len(msgs) {
		return nil, ErrInvalidSignature
	}

	// Use GPU acceleration for larger batches
	if accel.Available() && len(sigs) >= BatchVerifyThreshold {
		results, err := verifyBatchGPU(keyType, sigs, pks, msgs)
		if err == nil {
			return results, nil
		}
		// Fall through to CPU on GPU error
	}

	// Sequential CPU fallback
	return verifyBatchCPU(keyType, sigs, pks, msgs)
}

// verifyBatchGPU performs batch signature verification using GPU acceleration.
func verifyBatchGPU(keyType KeyType, sigs, pks, msgs [][]byte) ([]bool, error) {
	var sigType accelcrypto.SigType
	switch keyType {
	case KeyTypeSecp256k1:
		sigType = accelcrypto.SigECDSA
	case KeyTypeEd25519:
		sigType = accelcrypto.SigEd25519
	case KeyTypeBLS12381:
		sigType = accelcrypto.SigBLS
	case KeyTypeMLDSA:
		sigType = accelcrypto.SigMLDSA65
	default:
		return nil, ErrInvalidKeyType
	}

	return accelcrypto.BatchVerify(sigType, sigs, msgs, pks)
}

// verifyBatchCPU performs sequential signature verification on CPU.
func verifyBatchCPU(keyType KeyType, sigs, pks, msgs [][]byte) ([]bool, error) {
	results := make([]bool, len(sigs))

	// Use worker pool for parallel CPU verification
	var wg sync.WaitGroup
	for i := range sigs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = verifySingleSignature(keyType, sigs[idx], pks[idx], msgs[idx])
		}(i)
	}
	wg.Wait()

	return results, nil
}

// verifySingleSignature verifies a single signature on CPU.
func verifySingleSignature(keyType KeyType, sig, pk, msg []byte) bool {
	switch keyType {
	case KeyTypeSecp256k1:
		return verifyECDSA(sig, pk, msg)
	case KeyTypeEd25519:
		return verifyEd25519(sig, pk, msg)
	case KeyTypeBLS12381:
		return verifyBLS(sig, pk, msg)
	case KeyTypeMLDSA:
		return verifyMLDSA(sig, pk, msg)
	default:
		return false
	}
}

// verifyECDSA verifies an ECDSA secp256k1 signature.
func verifyECDSA(sig, pk, msg []byte) bool {
	if len(sig) < 64 || len(msg) != 32 {
		return false
	}
	// Use luxfi/crypto for ECDSA verification
	// In production, this calls into the actual crypto library
	return verifyECDSAInternal(sig, pk, msg)
}

// verifyEd25519 verifies an Ed25519 signature.
func verifyEd25519(sig, pk, msg []byte) bool {
	if len(sig) != 64 || len(pk) != 32 {
		return false
	}
	return verifyEd25519Internal(sig, pk, msg)
}

// verifyBLS verifies a BLS12-381 signature.
func verifyBLS(sig, pk, msg []byte) bool {
	if len(sig) != 96 || len(pk) != 48 {
		return false
	}
	return verifyBLSInternal(sig, pk, msg)
}

// verifyMLDSA verifies an ML-DSA-65 post-quantum signature.
func verifyMLDSA(sig, pk, msg []byte) bool {
	return verifyMLDSAInternal(sig, pk, msg)
}

// Internal verification functions using luxfi/crypto libraries.

func verifyECDSAInternal(sig, pk, msg []byte) bool {
	// Use luxfi/crypto.VerifySignature for secp256k1 ECDSA
	// Signature must be 64 bytes [R || S], pubkey 33 (compressed) or 65 (uncompressed)
	return crypto.VerifySignature(pk, msg, sig)
}

func verifyEd25519Internal(sig, pk, msg []byte) bool {
	// Use standard library ed25519.Verify
	if len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), msg, sig)
}

func verifyBLSInternal(sig, pk, msg []byte) bool {
	// Use luxfi/crypto/bls.Verify
	publicKey, err := bls.PublicKeyFromCompressedBytes(pk)
	if err != nil {
		return false
	}
	signature, err := bls.SignatureFromBytes(sig)
	if err != nil {
		return false
	}
	return bls.Verify(publicKey, signature, msg)
}

func verifyMLDSAInternal(sig, pk, msg []byte) bool {
	// Use luxfi/crypto/mldsa for post-quantum ML-DSA verification
	// Default to MLDSA65 (NIST Level 3, 192-bit security)
	publicKey, err := mldsa.PublicKeyFromBytes(pk, mldsa.MLDSA65)
	if err != nil {
		return false
	}
	return publicKey.VerifySignature(msg, sig)
}
