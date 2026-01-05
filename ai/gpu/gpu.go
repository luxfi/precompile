//go:build !gpu

// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu provides GPU-accelerated operations for the AI Mining precompile.
// This is the stub implementation for builds without the luxgpu tag.
// The GPU implementation in gpu_cgo.go requires: CGO_ENABLED=1 go build -tags luxgpu
package gpu

import (
	"errors"
	"sync"
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
	MinBatchSize = 4
	MaxBatchSize = 1024

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
	MLDSA44 MLDSAMode = 44
	MLDSA65 MLDSAMode = 65
	MLDSA87 MLDSAMode = 87
)

// Available returns false - GPU not available in stub build.
func Available() bool {
	return false
}

// Backend returns "CPU" for stub builds.
func Backend() string {
	return "CPU"
}

// Threshold returns the minimum batch size for GPU acceleration.
func Threshold() int {
	return MinBatchSize
}

// BatchVerifyMLDSA returns ErrGPUUnavailable in stub builds.
// Caller should fall back to CPU verification.
func BatchVerifyMLDSA(pubkeys, messages, signatures [][]byte) ([]bool, error) {
	return nil, ErrGPUUnavailable
}

// BatchVerifyAttestation returns ErrGPUUnavailable in stub builds.
func BatchVerifyAttestation(attestations [][]byte) ([]bool, []uint8, error) {
	return nil, nil, ErrGPUUnavailable
}

// ComputeReward calculates AI mining reward (CPU implementation).
func ComputeReward(workProofs [][]byte, chainID uint64) ([][32]byte, error) {
	n := len(workProofs)
	if n == 0 {
		return nil, ErrBatchEmpty
	}

	rewards := make([][32]byte, n)

	for i := 0; i < n; i++ {
		proof := workProofs[i]
		if len(proof) < WorkProofMinSize {
			continue
		}

		privacyLevel := uint16(proof[72])<<8 | uint16(proof[73])
		computeMins := uint32(proof[74])<<24 | uint32(proof[75])<<16 | uint32(proof[76])<<8 | uint32(proof[77])

		reward := calculateReward(privacyLevel, computeMins, chainID)

		for j := 0; j < 32; j++ {
			if j >= 24 {
				rewards[i][j] = byte(reward >> (8 * (31 - j)))
			}
		}
	}

	return rewards, nil
}

const WorkProofMinSize = 78

var privacyMultipliers = map[uint16]uint64{
	1: 2500,
	2: 5000,
	3: 10000,
	4: 15000,
}

func calculateReward(privacyLevel uint16, computeMins uint32, chainID uint64) uint64 {
	multiplier, ok := privacyMultipliers[privacyLevel]
	if !ok {
		multiplier = 5000
	}
	baseReward := uint64(1e18)
	reward := baseReward / 10000 * uint64(computeMins) * multiplier
	_ = chainID // unused in stub
	return reward
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

// GetStats returns current statistics
func GetStats() Stats {
	statsMu.Lock()
	defer statsMu.Unlock()
	return stats
}

// ResetStats resets statistics
func ResetStats() {
	statsMu.Lock()
	stats = Stats{}
	statsMu.Unlock()
}
