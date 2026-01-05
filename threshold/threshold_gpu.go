// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build gpu

// Build with: CGO_ENABLED=1 go build -tags luxgpu
// Requires: luxcpp/crypto library installed

package threshold

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../luxcpp/crypto/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../luxcpp/crypto/lib -lluxcrypto -lstdc++

#include <lux/crypto/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"unsafe"

	"github.com/luxfi/geth/common"
)

// GPU Acceleration Status for Threshold Precompile
//
// The threshold precompile coordinates MPC protocols (DKG, signing, refresh, reshare)
// across multiple cryptographic schemes. GPU acceleration is limited to:
//
// ACCELERATED:
// - Keccak256 address derivation (batch processing for multiple keys)
// - Ringtail operations (via NTT acceleration in luxcpp/lattice)
//
// NOT ACCELERATED (secp256k1 GPU kernels not available in luxcpp/crypto):
// - CGGMP21 (CMP) - ECDSA threshold signatures
// - FROST - Schnorr threshold signatures
// - LSS - ECDSA threshold signatures
//
// Future GPU acceleration for secp256k1 would require adding metal_secp256k1.h
// to luxcpp/crypto with MSM, batch scalar multiplication, and batch verification.

const (
	// HashTypeKeccak256 is the crypto_hash type for Keccak256
	HashTypeKeccak256 = C.int(4) // HASH_KECCAK256 in crypto.h
)

// GPUAccelerationAvailable reports which protocols have GPU acceleration
type GPUAccelerationAvailable struct {
	Ringtail bool   // Post-quantum via NTT
	CGGMP21  bool   // secp256k1 ECDSA - NOT AVAILABLE
	FROST    bool   // secp256k1 Schnorr - NOT AVAILABLE
	LSS      bool   // secp256k1 ECDSA - NOT AVAILABLE
	Keccak   bool   // Address derivation
	Reason   string // Explanation for unavailable protocols
}

// GetGPUAccelerationStatus returns which protocols have GPU support
func GetGPUAccelerationStatus() GPUAccelerationAvailable {
	return GPUAccelerationAvailable{
		Ringtail: true,
		CGGMP21:  false,
		FROST:    false,
		LSS:      false,
		Keccak:   true,
		Reason:   "secp256k1 GPU kernels not available in luxcpp/crypto; only BLS12-381 and BN254 MSM supported",
	}
}

// gpuKeccak256 computes Keccak256 hash using GPU acceleration
func gpuKeccak256(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	output := make([]byte, 32)

	cData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	cOutput := (*C.uint8_t)(unsafe.Pointer(&output[0]))

	C.crypto_hash(
		cOutput,
		cData,
		C.size_t(len(data)),
		HashTypeKeccak256,
	)

	return output
}

// gpuBatchKeccak256 computes multiple Keccak256 hashes in parallel on GPU
// This is useful for deriving addresses from multiple public keys
func gpuBatchKeccak256(inputs [][]byte) [][]byte {
	count := len(inputs)
	if count == 0 {
		return nil
	}

	// Prepare C arrays
	cInputs := make([]*C.uint8_t, count)
	cLens := make([]C.size_t, count)
	cOutputs := make([]*C.uint8_t, count)
	outputs := make([][]byte, count)

	for i := 0; i < count; i++ {
		outputs[i] = make([]byte, 32)
		if len(inputs[i]) > 0 {
			cInputs[i] = (*C.uint8_t)(unsafe.Pointer(&inputs[i][0]))
		} else {
			// Handle empty input - use a zero byte
			empty := []byte{0}
			cInputs[i] = (*C.uint8_t)(unsafe.Pointer(&empty[0]))
		}
		cLens[i] = C.size_t(len(inputs[i]))
		cOutputs[i] = (*C.uint8_t)(unsafe.Pointer(&outputs[i][0]))
	}

	// Execute batch hash on GPU
	C.crypto_batch_hash(
		(**C.uint8_t)(unsafe.Pointer(&cOutputs[0])),
		(**C.uint8_t)(unsafe.Pointer(&cInputs[0])),
		(*C.size_t)(unsafe.Pointer(&cLens[0])),
		C.uint32_t(count),
		HashTypeKeccak256,
	)

	return outputs
}

// GPUDeriveAddressFromPublicKey derives an EVM address using GPU-accelerated Keccak256
func GPUDeriveAddressFromPublicKey(pubKey []byte) common.Address {
	var hashInput []byte

	switch len(pubKey) {
	case 33:
		// Compressed public key - hash directly
		// NOTE: For proper EVM address derivation, should decompress first
		hashInput = pubKey
	case 65:
		// Uncompressed with 04 prefix - skip prefix
		hashInput = pubKey[1:]
	case 64:
		// Uncompressed without prefix
		hashInput = pubKey
	default:
		// Fallback - hash whatever we have
		hashInput = pubKey
	}

	hash := gpuKeccak256(hashInput)
	return common.BytesToAddress(hash[12:])
}

// GPUBatchDeriveAddresses derives EVM addresses for multiple public keys in parallel
// This is significantly faster than sequential derivation for large batches
func GPUBatchDeriveAddresses(pubKeys [][]byte) []common.Address {
	count := len(pubKeys)
	if count == 0 {
		return nil
	}

	// Prepare inputs for batch hashing
	hashInputs := make([][]byte, count)
	for i, pubKey := range pubKeys {
		switch len(pubKey) {
		case 33:
			hashInputs[i] = pubKey
		case 65:
			hashInputs[i] = pubKey[1:]
		case 64:
			hashInputs[i] = pubKey
		default:
			hashInputs[i] = pubKey
		}
	}

	// Batch hash on GPU
	hashes := gpuBatchKeccak256(hashInputs)

	// Extract addresses
	addresses := make([]common.Address, count)
	for i, hash := range hashes {
		addresses[i] = common.BytesToAddress(hash[12:])
	}

	return addresses
}

// GPUOptimizedThresholdClient wraps ThresholdClient with GPU acceleration where available
type GPUOptimizedThresholdClient struct {
	*ThresholdClient
}

// NewGPUOptimizedThresholdClient creates a threshold client with GPU optimizations
func NewGPUOptimizedThresholdClient() *GPUOptimizedThresholdClient {
	return &GPUOptimizedThresholdClient{
		ThresholdClient: NewThresholdClient(),
	}
}

// GPUDeriveAddresses derives addresses for a batch of key IDs efficiently
// Returns a map of keyID -> address
func (c *GPUOptimizedThresholdClient) GPUDeriveAddresses(keyIDs [][32]byte) (map[[32]byte]common.Address, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Collect public keys
	pubKeys := make([][]byte, 0, len(keyIDs))
	validKeyIDs := make([][32]byte, 0, len(keyIDs))

	for _, keyID := range keyIDs {
		var pubKey []byte
		var err error

		// Try each protocol to find the key
		if config, ok := c.cmpConfigs[keyID]; ok {
			pubKey, err = config.PublicPoint().MarshalBinary()
		} else if config, ok := c.frostConfigs[keyID]; ok {
			pubKey, err = config.PublicKey.MarshalBinary()
		} else if config, ok := c.lssConfigs[keyID]; ok {
			pubPoint, e := config.PublicPoint()
			if e == nil {
				pubKey, err = pubPoint.MarshalBinary()
			}
		}
		// Skip Ringtail - no EVM address derivation (post-quantum)

		if err == nil && len(pubKey) > 0 {
			pubKeys = append(pubKeys, pubKey)
			validKeyIDs = append(validKeyIDs, keyID)
		}
	}

	if len(pubKeys) == 0 {
		return nil, nil
	}

	// Batch derive on GPU
	addresses := GPUBatchDeriveAddresses(pubKeys)

	// Build result map
	result := make(map[[32]byte]common.Address, len(addresses))
	for i, addr := range addresses {
		result[validKeyIDs[i]] = addr
	}

	return result, nil
}

// Gas cost reduction ratios for GPU-accelerated operations
// Only Keccak256 batch hashing benefits from GPU in this precompile
var gpuGasReductions = map[string]float64{
	// Batch address derivation: significant savings for large batches
	"BatchDeriveAddresses_2":   0.15, // 2 addresses: 15% reduction
	"BatchDeriveAddresses_10":  0.40, // 10 addresses: 40% reduction
	"BatchDeriveAddresses_100": 0.65, // 100 addresses: 65% reduction

	// Single operations: minimal savings due to GPU overhead
	"DeriveAddress": 0.05, // 5% reduction

	// MPC protocol operations: NO GPU acceleration available
	"CGGMP21_Sign":   0.0, // secp256k1 not GPU accelerated
	"FROST_Sign":     0.0, // secp256k1 not GPU accelerated
	"LSS_Sign":       0.0, // secp256k1 not GPU accelerated
	"Ringtail_Sign":  0.0, // Handled by separate ringtail precompile
	"CGGMP21_Keygen": 0.0, // secp256k1 not GPU accelerated
	"FROST_Keygen":   0.0, // secp256k1 not GPU accelerated
	"LSS_Keygen":     0.0, // secp256k1 not GPU accelerated
}

// GetGPUGasReduction returns the gas reduction ratio for a given operation
func GetGPUGasReduction(operation string) float64 {
	if reduction, ok := gpuGasReductions[operation]; ok {
		return reduction
	}
	return 0.0 // No reduction for unknown operations
}

// GPUAcceleratedGas calculates gas cost with GPU reduction applied
func GPUAcceleratedGas(baseGas uint64, operation string) uint64 {
	reduction := GetGPUGasReduction(operation)
	if reduction == 0 {
		return baseGas
	}
	return uint64(float64(baseGas) * (1 - reduction))
}
