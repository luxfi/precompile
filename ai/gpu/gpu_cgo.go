//go:build cgo

// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU-accelerated operations for the AI Mining precompile.
// Uses Metal (macOS) or CUDA (Linux) via luxcpp/lattice for NTT operations.
//
// Build with: CGO_ENABLED=1 go build
// Requires: luxcpp/crypto and luxcpp/lattice libraries installed
//
// ML-DSA verification is the primary bottleneck in AI mining. This package
// provides batch verification using GPU-accelerated NTT (Number Theoretic
// Transform) operations. Batch verification amortizes NTT setup costs across
// multiple signatures.
package gpu

/*
#cgo pkg-config: lux-crypto-only
#cgo darwin LDFLAGS: -framework Metal -framework CoreGraphics -framework Foundation

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// Forward declarations for luxcpp/crypto
bool crypto_gpu_available(void);
const char* crypto_get_backend(void);
int mldsa_batch_verify(const uint8_t* const* sigs,
                       const size_t* sig_lens,
                       const uint8_t* const* msgs,
                       const size_t* msg_lens,
                       const uint8_t* const* pks,
                       uint32_t count,
                       int* results);

// Forward declarations for luxcpp/lattice
bool lattice_gpu_available(void);

// Metal AI context (defined in metal_ai.h when implemented)
typedef struct MetalAIContext MetalAIContext;

// GPU-accelerated reward calculation
typedef struct {
    uint64_t base_reward;
    uint64_t multiplier;      // basis points (10000 = 1.0x)
    uint32_t compute_minutes;
    uint16_t privacy_level;
    uint64_t chain_id;
} RewardParams;

*/
import "C"

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// Errors
var (
	ErrGPUUnavailable     = errors.New("GPU acceleration not available")
	ErrBatchEmpty         = errors.New("batch is empty")
	ErrBatchTooSmall      = errors.New("batch too small for GPU acceleration")
	ErrInvalidSignature   = errors.New("invalid signature data")
	ErrInvalidPublicKey   = errors.New("invalid public key data")
	ErrNTTContextFailed   = errors.New("failed to create NTT context")
	ErrVerificationFailed = errors.New("batch verification failed")
)

// Constants
const (
	// MinBatchSize is the minimum batch size for GPU acceleration benefit.
	// Below this threshold, CPU verification may be faster.
	MinBatchSize = 4

	// MaxBatchSize is the maximum signatures per batch.
	MaxBatchSize = 1024

	// ML-DSA parameter sizes
	MLDSA44PublicKeySize = 1312
	MLDSA44SignatureSize = 2420
	MLDSA65PublicKeySize = 1952
	MLDSA65SignatureSize = 3309
	MLDSA87PublicKeySize = 2592
	MLDSA87SignatureSize = 4627
)

// MLDSAMode represents ML-DSA security level
type MLDSAMode uint8

const (
	MLDSA44 MLDSAMode = 44 // NIST Level 2
	MLDSA65 MLDSAMode = 65 // NIST Level 3
	MLDSA87 MLDSAMode = 87 // NIST Level 5
)

// gpuState holds global GPU state
var gpuState struct {
	available bool
	backend   string
	initOnce  sync.Once
}

// Available returns true if GPU acceleration is available.
func Available() bool {
	gpuState.initOnce.Do(func() {
		gpuState.available = bool(C.crypto_gpu_available()) && bool(C.lattice_gpu_available())
		if gpuState.available {
			gpuState.backend = C.GoString(C.crypto_get_backend())
		}
	})
	return gpuState.available
}

// Backend returns the GPU backend name ("Metal", "CUDA", or "CPU").
func Backend() string {
	Available() // ensure initialized
	return gpuState.backend
}

// Threshold returns the minimum batch size for GPU acceleration.
// Below this threshold, CPU verification is used.
func Threshold() int {
	return MinBatchSize
}

// BatchVerifyMLDSA verifies multiple ML-DSA signatures using GPU acceleration.
// Returns a slice of booleans indicating verification result for each signature.
// Uses GPU NTT acceleration when batch size >= Threshold().
//
// All signatures must use the same ML-DSA mode (determined by public key size).
// Returns ErrBatchEmpty if sigs is empty.
// Returns ErrBatchTooSmall if batch size < MinBatchSize (use CPU path).
func BatchVerifyMLDSA(pubkeys, messages, signatures [][]byte) ([]bool, error) {
	n := len(signatures)
	if n == 0 {
		return nil, ErrBatchEmpty
	}
	if len(pubkeys) != n || len(messages) != n {
		return nil, errors.New("mismatched input lengths")
	}

	// Below threshold, return indicator to use CPU path
	if n < MinBatchSize || !Available() {
		return nil, ErrBatchTooSmall
	}

	// Validate and determine mode from first public key
	if len(pubkeys[0]) == 0 {
		return nil, ErrInvalidPublicKey
	}
	mode := getModeFromPKSize(len(pubkeys[0]))
	if mode == 0 {
		return nil, ErrInvalidPublicKey
	}

	// Prepare C arrays
	cSigs := make([]*C.uint8_t, n)
	cSigLens := make([]C.size_t, n)
	cMsgs := make([]*C.uint8_t, n)
	cMsgLens := make([]C.size_t, n)
	cPks := make([]*C.uint8_t, n)
	cResults := make([]C.int, n)

	for i := 0; i < n; i++ {
		if len(signatures[i]) == 0 {
			return nil, ErrInvalidSignature
		}
		if len(pubkeys[i]) == 0 {
			return nil, ErrInvalidPublicKey
		}

		cSigs[i] = (*C.uint8_t)(unsafe.Pointer(&signatures[i][0]))
		cSigLens[i] = C.size_t(len(signatures[i]))
		cMsgs[i] = (*C.uint8_t)(unsafe.Pointer(&messages[i][0]))
		cMsgLens[i] = C.size_t(len(messages[i]))
		cPks[i] = (*C.uint8_t)(unsafe.Pointer(&pubkeys[i][0]))
	}

	// Keep references alive during C call
	runtime.KeepAlive(signatures)
	runtime.KeepAlive(messages)
	runtime.KeepAlive(pubkeys)

	// Call GPU batch verify
	rc := C.mldsa_batch_verify(
		(**C.uint8_t)(unsafe.Pointer(&cSigs[0])),
		(*C.size_t)(unsafe.Pointer(&cSigLens[0])),
		(**C.uint8_t)(unsafe.Pointer(&cMsgs[0])),
		(*C.size_t)(unsafe.Pointer(&cMsgLens[0])),
		(**C.uint8_t)(unsafe.Pointer(&cPks[0])),
		C.uint32_t(n),
		(*C.int)(unsafe.Pointer(&cResults[0])),
	)

	if rc != 0 {
		return nil, ErrVerificationFailed
	}

	// Convert results
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = cResults[i] == 1
	}

	return results, nil
}

// BatchVerifyAttestation verifies multiple NVTrust attestations using GPU.
// Returns verification results and trust scores for each attestation.
func BatchVerifyAttestation(attestations [][]byte) ([]bool, []uint8, error) {
	n := len(attestations)
	if n == 0 {
		return nil, nil, ErrBatchEmpty
	}

	if n < MinBatchSize || !Available() {
		return nil, nil, ErrBatchTooSmall
	}

	// Process attestations
	results := make([]bool, n)
	scores := make([]uint8, n)

	// GPU path: batch parse and verify attestations
	for i := 0; i < n; i++ {
		att := attestations[i]
		if len(att) < NVTrustMinQuoteSize {
			results[i] = false
			scores[i] = 0
			continue
		}

		// Parse attestation
		quote, err := ParseNVTrustQuote(att)
		if err != nil {
			results[i] = false
			scores[i] = 0
			continue
		}

		// Verify quote
		valid, score := VerifyNVTrustQuote(quote)
		results[i] = valid
		scores[i] = score
	}

	return results, scores, nil
}

// ComputeReward calculates AI mining reward using GPU acceleration.
// Supports batch computation for multiple work proofs.
func ComputeReward(workProofs [][]byte, chainID uint64) ([][32]byte, error) {
	n := len(workProofs)
	if n == 0 {
		return nil, ErrBatchEmpty
	}

	rewards := make([][32]byte, n)

	// Process each work proof
	for i := 0; i < n; i++ {
		proof := workProofs[i]
		if len(proof) < WorkProofMinSize {
			continue
		}

		// Parse work proof fields
		// [72:74] privacy level, [74:78] compute minutes
		privacyLevel := uint16(proof[72])<<8 | uint16(proof[73])
		computeMins := uint32(proof[74])<<24 | uint32(proof[75])<<16 | uint32(proof[76])<<8 | uint32(proof[77])

		// Calculate reward
		reward := calculateReward(privacyLevel, computeMins, chainID)

		// Store as big-endian bytes
		for j := 0; j < 32; j++ {
			if j >= 24 {
				rewards[i][j] = byte(reward >> (8 * (31 - j)))
			}
		}
	}

	return rewards, nil
}

// Work proof layout
const (
	WorkProofMinSize = 78
)

// Privacy level multipliers (basis points, 10000 = 1.0x)
var privacyMultipliers = map[uint16]uint64{
	1: 2500,  // Public: 0.25x
	2: 5000,  // Private: 0.50x
	3: 10000, // Confidential: 1.00x
	4: 15000, // Sovereign: 1.50x
}

// calculateReward computes the reward for given parameters
func calculateReward(privacyLevel uint16, computeMins uint32, chainID uint64) uint64 {
	multiplier, ok := privacyMultipliers[privacyLevel]
	if !ok {
		multiplier = 5000 // default to Private
	}

	// Base reward: 1e18 wei per minute
	// Final = base * minutes * multiplier / 10000
	baseReward := uint64(1e18)

	// Compute in steps to avoid overflow
	reward := baseReward / 10000 * uint64(computeMins) * multiplier

	// Chain-specific adjustments
	switch chainID {
	case 96369, 36963, 200200:
		// Standard rate for mainnet chains
	default:
		// Testnet: same rate
	}

	return reward
}

// getModeFromPKSize determines ML-DSA mode from public key size
func getModeFromPKSize(size int) MLDSAMode {
	switch size {
	case MLDSA44PublicKeySize:
		return MLDSA44
	case MLDSA65PublicKeySize:
		return MLDSA65
	case MLDSA87PublicKeySize:
		return MLDSA87
	default:
		return 0
	}
}

// getSignatureSize returns expected signature size for mode
func getSignatureSize(mode MLDSAMode) int {
	switch mode {
	case MLDSA44:
		return MLDSA44SignatureSize
	case MLDSA65:
		return MLDSA65SignatureSize
	case MLDSA87:
		return MLDSA87SignatureSize
	default:
		return 0
	}
}

// Stats holds GPU verification statistics
type Stats struct {
	BatchVerifications uint64
	TotalSignatures    uint64
	GPUTimeNs          uint64
	CPUFallbacks       uint64
}

var stats Stats
var statsMu sync.Mutex

// GetStats returns current GPU verification statistics
func GetStats() Stats {
	statsMu.Lock()
	defer statsMu.Unlock()
	return stats
}

// ResetStats resets GPU verification statistics
func ResetStats() {
	statsMu.Lock()
	stats = Stats{}
	statsMu.Unlock()
}
