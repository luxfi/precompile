// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package blake3

/*
#cgo CFLAGS: -I/Users/z/work/luxcpp/crypto/include
#cgo LDFLAGS: -L/Users/z/work/luxcpp/crypto/build-local -lluxcrypto -lstdc++ -lm
#cgo darwin LDFLAGS: -framework Foundation -framework Metal -framework MetalPerformanceShaders

#include <lux/crypto/crypto.h>
#include <stdlib.h>
#include <string.h>

// Short aliases for Go code readability (hides lux_crypto_ prefix)
#define crypto_gpu_available    lux_crypto_gpu_available
#define crypto_get_backend      lux_crypto_get_backend
#define crypto_blake3           lux_crypto_blake3
#define crypto_batch_hash       lux_crypto_batch_hash
#define CRYPTO_SUCCESS          LUX_CRYPTO_SUCCESS
*/
import "C"

import (
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// GPU context management
var (
	gpuAvailable bool
	gpuCheckOnce sync.Once
)

// initGPU checks if GPU acceleration is available
func initGPU() {
	gpuCheckOnce.Do(func() {
		gpuAvailable = bool(C.crypto_gpu_available())
	})
}

// isGPUAvailable returns true if GPU acceleration is available
func isGPUAvailable() bool {
	initGPU()
	return gpuAvailable
}

// =============================================================================
// GPU-Accelerated Blake3 Precompile
// =============================================================================

// blake3PrecompileGPU is the GPU-accelerated implementation
type blake3PrecompileGPU struct {
	*blake3Precompile
}

// NewGPUPrecompile creates a GPU-accelerated Blake3 precompile
func NewGPUPrecompile() contract.StatefulPrecompiledContract {
	initGPU()

	base := &blake3Precompile{}

	if gpuAvailable {
		return &blake3PrecompileGPU{base}
	}

	return base
}

// Address returns the precompile address
func (p *blake3PrecompileGPU) Address() common.Address {
	return ContractAddress
}

// RequiredGas returns gas with GPU discount if available
func (p *blake3PrecompileGPU) RequiredGas(input []byte) uint64 {
	baseCost := p.blake3Precompile.RequiredGas(input)

	if !gpuAvailable || len(input) < 1 {
		return baseCost
	}

	op := input[0]
	switch op {
	case OpMerkleRoot:
		// Merkle tree computation is highly parallelizable - massive GPU speedup
		return baseCost * 25 / 100 // 75% reduction for GPU
	case OpHashXOF:
		// XOF with large output benefits from GPU
		if len(input) >= 5 {
			outputLen := binary.BigEndian.Uint32(input[1:5])
			if outputLen > 64 {
				return baseCost * 40 / 100 // 60% reduction for GPU
			}
		}
		return baseCost * 60 / 100 // 40% reduction for moderate XOF
	case OpHash256, OpHash512:
		// Single hashes have moderate GPU benefit for large inputs
		dataLen := len(input) - 1
		if dataLen > 1024 {
			return baseCost * 50 / 100 // 50% reduction for large inputs
		}
		return baseCost * 80 / 100 // 20% reduction for small inputs
	default:
		return baseCost * 70 / 100 // 30% default reduction
	}
}

// Run executes the Blake3 precompile with GPU acceleration
func (p *blake3PrecompileGPU) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	requiredGas := p.RequiredGas(input)
	if suppliedGas < requiredGas {
		return nil, 0, contract.ErrOutOfGas
	}
	remainingGas = suppliedGas - requiredGas

	if len(input) < 1 {
		return nil, remainingGas, ErrInvalidInput
	}

	op := input[0]
	data := input[1:]

	// Use GPU-accelerated paths where available
	switch op {
	case OpHash256:
		if gpuAvailable && len(data) > 256 { // Threshold for GPU benefit
			return gpuHash256(data), remainingGas, nil
		}
		return p.hash256(data), remainingGas, nil

	case OpHash512:
		if gpuAvailable && len(data) > 256 {
			return gpuHash512(data), remainingGas, nil
		}
		return p.hash512(data), remainingGas, nil

	case OpHashXOF:
		if gpuAvailable {
			return gpuHashXOF(data)
		}
		return p.hashXOF(data)

	case OpHashWithDomain:
		return p.hashWithDomain(data)

	case OpMerkleRoot:
		if gpuAvailable {
			return gpuMerkleRoot(data)
		}
		return p.merkleRoot(data)

	case OpDeriveKey:
		return p.deriveKey(data)

	default:
		return nil, remainingGas, ErrInvalidOperation
	}
}

// =============================================================================
// GPU-Accelerated Hash Operations
// =============================================================================

// gpuHash256 computes a 32-byte Blake3 hash using GPU
func gpuHash256(data []byte) []byte {
	if len(data) > MaxInputLength {
		data = data[:MaxInputLength]
	}

	result := make([]byte, DigestLength32)

	// Use GPU-accelerated Blake3
	cData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	cResult := (*C.uint8_t)(unsafe.Pointer(&result[0]))

	C.crypto_blake3(cResult, cData, C.size_t(len(data)))

	return result
}

// gpuHash512 computes a 64-byte Blake3 hash using GPU
func gpuHash512(data []byte) []byte {
	if len(data) > MaxInputLength {
		data = data[:MaxInputLength]
	}

	// Blake3 XOF for 64-byte output
	result := make([]byte, DigestLength64)

	// GPU Blake3 produces 32 bytes by default
	// For 64 bytes, we use XOF mode or hash twice with different suffixes
	cData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	cResult := (*C.uint8_t)(unsafe.Pointer(&result[0]))

	// First 32 bytes
	C.crypto_blake3(cResult, cData, C.size_t(len(data)))

	// Second 32 bytes with suffix
	suffixData := append(data, 0x01) // Domain separation
	cSuffix := (*C.uint8_t)(unsafe.Pointer(&suffixData[0]))
	cResult2 := (*C.uint8_t)(unsafe.Pointer(&result[32]))
	C.crypto_blake3(cResult2, cSuffix, C.size_t(len(suffixData)))

	return result
}

// gpuHashXOF computes arbitrary-length Blake3 hash using GPU
func gpuHashXOF(data []byte) ([]byte, uint64, error) {
	if len(data) < 4 {
		return nil, 0, ErrInvalidDataLength
	}

	outputLen := binary.BigEndian.Uint32(data[:4])
	if outputLen > MaxOutputLength {
		return nil, 0, ErrOutputTooLarge
	}

	inputData := data[4:]
	if len(inputData) > MaxInputLength {
		inputData = inputData[:MaxInputLength]
	}

	result := make([]byte, outputLen)

	// Generate output in 32-byte chunks using GPU
	numChunks := (int(outputLen) + 31) / 32

	for i := 0; i < numChunks; i++ {
		// Create chunk-specific input
		chunkData := append(inputData, byte(i>>8), byte(i))

		chunkResult := make([]byte, 32)
		cData := (*C.uint8_t)(unsafe.Pointer(&chunkData[0]))
		cResult := (*C.uint8_t)(unsafe.Pointer(&chunkResult[0]))

		C.crypto_blake3(cResult, cData, C.size_t(len(chunkData)))

		// Copy to result
		start := i * 32
		end := start + 32
		if end > int(outputLen) {
			end = int(outputLen)
		}
		copy(result[start:end], chunkResult[:end-start])
	}

	return result, 0, nil
}

// gpuMerkleRoot computes Merkle tree root using GPU batch hashing
func gpuMerkleRoot(data []byte) ([]byte, uint64, error) {
	if len(data) < 4 {
		return nil, 0, ErrInvalidDataLength
	}

	numLeaves := binary.BigEndian.Uint32(data[:4])
	if numLeaves > MaxMerkleLeaves {
		numLeaves = MaxMerkleLeaves
	}
	if numLeaves == 0 {
		return make([]byte, DigestLength32), 0, nil
	}

	expectedLen := 4 + int(numLeaves)*DigestLength32
	if len(data) < expectedLen {
		return nil, 0, ErrInvalidDataLength
	}

	// Extract leaves
	leaves := make([][]byte, numLeaves)
	for i := uint32(0); i < numLeaves; i++ {
		start := 4 + i*DigestLength32
		leaves[i] = make([]byte, DigestLength32)
		copy(leaves[i], data[start:start+DigestLength32])
	}

	// Pad to power of 2
	for len(leaves)&(len(leaves)-1) != 0 {
		lastLeaf := make([]byte, DigestLength32)
		copy(lastLeaf, leaves[len(leaves)-1])
		leaves = append(leaves, lastLeaf)
	}

	// GPU batch Merkle tree computation
	return gpuComputeMerkleTree(leaves), 0, nil
}

// gpuComputeMerkleTree computes Merkle root using GPU batch hashing
func gpuComputeMerkleTree(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, DigestLength32)
	}
	if len(leaves) == 1 {
		result := make([]byte, DigestLength32)
		copy(result, leaves[0])
		return result
	}

	// Build tree level by level with GPU batch hashing
	currentLevel := leaves

	for len(currentLevel) > 1 {
		numPairs := len(currentLevel) / 2

		// Prepare batch inputs for GPU
		// Each input is 64 bytes (left || right)
		inputs := make([][]byte, numPairs)
		inputLens := make([]C.size_t, numPairs)
		outputs := make([][]byte, numPairs)

		for i := 0; i < numPairs; i++ {
			inputs[i] = make([]byte, 64)
			copy(inputs[i][:32], currentLevel[i*2])
			copy(inputs[i][32:], currentLevel[i*2+1])
			inputLens[i] = 64
			outputs[i] = make([]byte, 32)
		}

		// Use GPU batch hash if batch is large enough
		if numPairs >= 8 { // Threshold for GPU batch benefit
			gpuBatchBlake3(inputs, outputs)
		} else {
			// Fall back to sequential GPU hashes
			for i := 0; i < numPairs; i++ {
				cData := (*C.uint8_t)(unsafe.Pointer(&inputs[i][0]))
				cResult := (*C.uint8_t)(unsafe.Pointer(&outputs[i][0]))
				C.crypto_blake3(cResult, cData, 64)
			}
		}

		currentLevel = outputs
	}

	return currentLevel[0]
}

// gpuBatchBlake3 performs batch Blake3 hashing using GPU
func gpuBatchBlake3(inputs [][]byte, outputs [][]byte) {
	count := len(inputs)
	if count == 0 {
		return
	}

	// Prepare C arrays
	cInputs := make([]*C.uint8_t, count)
	cOutputs := make([]*C.uint8_t, count)
	cLens := make([]C.size_t, count)

	for i := 0; i < count; i++ {
		cInputs[i] = (*C.uint8_t)(unsafe.Pointer(&inputs[i][0]))
		cOutputs[i] = (*C.uint8_t)(unsafe.Pointer(&outputs[i][0]))
		cLens[i] = C.size_t(len(inputs[i]))
	}

	// Call batch hash function
	// hash_type = 2 for BLAKE3
	ret := C.crypto_batch_hash(
		(**C.uint8_t)(unsafe.Pointer(&cOutputs[0])),
		(**C.uint8_t)(unsafe.Pointer(&cInputs[0])),
		(*C.size_t)(unsafe.Pointer(&cLens[0])),
		C.uint32_t(count),
		C.int(2), // BLAKE3
	)

	if ret != C.CRYPTO_SUCCESS {
		// Fall back to sequential hashing on failure
		for i := 0; i < count; i++ {
			C.crypto_blake3(cOutputs[i], cInputs[i], cLens[i])
		}
	}
}

func init() {
	initGPU()
}
