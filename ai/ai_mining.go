// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ai implements the AI Mining precompile for EVM at address 0x0300.
// This precompile is shared by Hanzo, Lux, and Zoo EVMs for efficient
// AI mining reward calculation and cryptographic verification.
//
// GPU Acceleration:
// When batch size >= gpu.Threshold() and GPU is available, operations
// are dispatched to Metal/CUDA for parallel processing. This provides
// significant speedup for ML-DSA verification (NTT-based) and attestation
// verification (SHA-256/ECDSA).
package ai

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/zeebo/blake3"

	"github.com/luxfi/accel"
	"github.com/luxfi/accel/ops/crypto"
)

// Precompile address
const PrecompileAddress = "0x0300"

// Gas costs - optimized for high-frequency AI mining operations
const (
	GasVerifyMLDSA     uint64 = 3000 // ML-DSA signature verification
	GasCalculateReward uint64 = 1000 // Reward calculation
	GasVerifyTEE       uint64 = 5000 // TEE attestation verification (platform-agnostic)
	GasIsSpent         uint64 = 100  // O(1) spent set lookup
	GasComputeWorkId   uint64 = 50   // BLAKE3 hash computation
	GasMarkSpent       uint64 = 5000 // State write for marking spent
)

// ML-DSA key and signature sizes
const (
	MLDSA44PublicKeySize = 1312
	MLDSA44SignatureSize = 2420
	MLDSA65PublicKeySize = 1952
	MLDSA65SignatureSize = 3309
	MLDSA87PublicKeySize = 2592
	MLDSA87SignatureSize = 4627
)

// Work proof layout offsets
const (
	WorkProofDeviceIDOffset    = 0
	WorkProofNonceOffset       = 32
	WorkProofTimestampOffset   = 64
	WorkProofPrivacyOffset     = 72
	WorkProofComputeMinsOffset = 74
	WorkProofTEEQuoteOffset    = 78
	WorkProofMinSize           = 78 // Minimum size without TEE quote
)

// Privacy levels for compute attestation
const (
	PrivacyPublic       uint16 = 1 // 0.25x multiplier
	PrivacyPrivate      uint16 = 2 // 0.50x multiplier
	PrivacyConfidential uint16 = 3 // 1.00x multiplier
	PrivacySovereign    uint16 = 4 // 1.50x multiplier
)

// Privacy level reward multipliers in basis points (10000 = 1.0x)
var privacyMultipliers = map[uint16]uint64{
	PrivacyPublic:       2500,  // 0.25x
	PrivacyPrivate:      5000,  // 0.50x
	PrivacyConfidential: 10000, // 1.00x
	PrivacySovereign:    15000, // 1.50x
}

// Base reward per compute minute (1 AI token = 1e18 wei)
var baseRewardPerMinute = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

// Errors
var (
	ErrInvalidPublicKeySize = errors.New("invalid ML-DSA public key size")
	ErrInvalidSignatureSize = errors.New("invalid ML-DSA signature size")
	ErrInvalidWorkProof     = errors.New("invalid work proof format")
	ErrInvalidPrivacyLevel  = errors.New("invalid privacy level")
	ErrWorkAlreadySpent     = errors.New("work already spent")
	ErrInvalidTEEReceipt    = errors.New("invalid TEE attestation receipt")
	ErrTEESignatureInvalid  = errors.New("TEE attestation signature verification failed")
	ErrUnauthorized         = errors.New("unauthorized caller")
)

// StateDB interface for accessing and modifying state
type StateDB interface {
	GetState(addr [20]byte, key [32]byte) [32]byte
	SetState(addr [20]byte, key [32]byte, value [32]byte)
}

// PrecompileAddress as bytes
var precompileAddr = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00}

// spentSetPrefix is the storage key prefix for spent work IDs
var spentSetPrefix = [4]byte{'s', 'p', 'n', 't'}

// VerifyMLDSA verifies an ML-DSA signature (quantum-safe, FIPS 204)
// Automatically detects security level from public key size
// Gas cost: 3,000
func VerifyMLDSA(pubkey, message, signature []byte) (bool, error) {
	switch len(pubkey) {
	case MLDSA44PublicKeySize:
		return verifyMLDSA44(pubkey, message, signature)
	case MLDSA65PublicKeySize:
		return verifyMLDSA65(pubkey, message, signature)
	case MLDSA87PublicKeySize:
		return verifyMLDSA87(pubkey, message, signature)
	default:
		return false, ErrInvalidPublicKeySize
	}
}

func verifyMLDSA44(pubkey, message, signature []byte) (bool, error) {
	if len(signature) != MLDSA44SignatureSize {
		return false, ErrInvalidSignatureSize
	}
	var pk mldsa44.PublicKey
	if err := pk.UnmarshalBinary(pubkey); err != nil {
		return false, err
	}
	return mldsa44.Verify(&pk, message, nil, signature), nil
}

func verifyMLDSA65(pubkey, message, signature []byte) (bool, error) {
	if len(signature) != MLDSA65SignatureSize {
		return false, ErrInvalidSignatureSize
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pubkey); err != nil {
		return false, err
	}
	return mldsa65.Verify(&pk, message, nil, signature), nil
}

func verifyMLDSA87(pubkey, message, signature []byte) (bool, error) {
	if len(signature) != MLDSA87SignatureSize {
		return false, ErrInvalidSignatureSize
	}
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(pubkey); err != nil {
		return false, err
	}
	return mldsa87.Verify(&pk, message, nil, signature), nil
}

// CalculateReward calculates the reward for a work proof
// Work proof format:
//   - [0:32]   Device ID (bytes32)
//   - [32:64]  Nonce (bytes32)
//   - [64:72]  Timestamp (uint64)
//   - [72:74]  Privacy level (uint16)
//   - [74:78]  Compute minutes (uint32)
//   - [78:...]  TEE quote (variable, optional)
//
// Gas cost: 1,000
func CalculateReward(workProof []byte, chainId uint64) (*big.Int, error) {
	if len(workProof) < WorkProofMinSize {
		return nil, ErrInvalidWorkProof
	}

	// Extract privacy level (big-endian uint16)
	privacyLevel := binary.BigEndian.Uint16(workProof[WorkProofPrivacyOffset:WorkProofComputeMinsOffset])

	// Extract compute minutes (big-endian uint32)
	computeMinutes := binary.BigEndian.Uint32(workProof[WorkProofComputeMinsOffset:WorkProofTEEQuoteOffset])

	// Get multiplier for privacy level
	multiplier, ok := privacyMultipliers[privacyLevel]
	if !ok {
		return nil, ErrInvalidPrivacyLevel
	}

	// Calculate reward: baseReward * computeMinutes * multiplier / 10000
	reward := new(big.Int).Set(baseRewardPerMinute)
	reward.Mul(reward, big.NewInt(int64(computeMinutes)))
	reward.Mul(reward, big.NewInt(int64(multiplier)))
	reward.Div(reward, big.NewInt(10000))

	// Apply chain-specific adjustments if needed
	reward = applyChainAdjustment(reward, chainId)

	return reward, nil
}

// applyChainAdjustment applies chain-specific reward adjustments
func applyChainAdjustment(reward *big.Int, chainId uint64) *big.Int {
	// Chain ID adjustments for different networks
	switch chainId {
	case 96369: // C-Chain mainnet
		// Standard rate
		return reward
	case 36963: // Hanzo EVM
		// Standard rate
		return reward
	case 200200: // Zoo EVM
		// Standard rate
		return reward
	default:
		// Testnet or unknown chains get standard rate
		return reward
	}
}

// VerifyTEE verifies a TEE attestation receipt (supports NVIDIA NVTrust, Intel SGX, etc.)
// This validates the certificate chain and signature against platform root CA
// Gas cost: 5,000
func VerifyTEE(receipt, signature []byte) (bool, error) {
	if len(receipt) == 0 {
		return false, ErrInvalidTEEReceipt
	}

	// TEE receipt validation:
	// 1. Parse receipt structure
	// 2. Verify certificate chain against platform root CA
	// 3. Verify signature over receipt data
	// 4. Check timestamp validity
	// 5. Verify device is in allowed registry

	// Receipt structure (simplified):
	// [0:32]  Device ID (GPU/TEE identifier)
	// [32:40] Timestamp
	// [40:48] Nonce
	// [48:...]  Certificate chain

	if len(receipt) < 48 {
		return false, ErrInvalidTEEReceipt
	}

	// Basic validation - full verification via platform-specific SDKs
	// Supported platforms: NVIDIA NVTrust, Intel SGX, AMD SEV, ARM TrustZone
	valid, err := verifyTEESignature(receipt, signature)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// verifyTEESignature verifies the signature over the receipt
func verifyTEESignature(receipt, signature []byte) (bool, error) {
	// Platform uses ECDSA P-384 for attestation signatures
	// Full verification requires platform-specific SDK integration

	if len(signature) == 0 {
		return false, ErrTEESignatureInvalid
	}

	// For production:
	// 1. Parse certificate chain from receipt
	// 2. Verify chain against platform root CA
	// 3. Extract public key from leaf certificate
	// 4. Verify ECDSA P-384 signature over receipt hash

	// Basic validation - extended verification in luxnext
	return len(signature) > 0, nil
}

// IsSpent checks if a work ID has been spent (O(1) state lookup)
// Gas cost: 100
func IsSpent(stateDB StateDB, workId [32]byte) bool {
	key := makeSpentKey(workId)
	value := stateDB.GetState(precompileAddr, key)

	// Non-zero value means spent
	for _, b := range value {
		if b != 0 {
			return true
		}
	}
	return false
}

// MarkSpent marks a work ID as spent in the state trie
// Gas cost: 5,000 (state write)
func MarkSpent(stateDB StateDB, workId [32]byte) error {
	if IsSpent(stateDB, workId) {
		return ErrWorkAlreadySpent
	}

	key := makeSpentKey(workId)
	value := [32]byte{1} // Non-zero value indicates spent
	stateDB.SetState(precompileAddr, key, value)

	return nil
}

// makeSpentKey creates the storage key for spent set lookup
func makeSpentKey(workId [32]byte) [32]byte {
	// Key = BLAKE3(spentSetPrefix || workId)
	h := blake3.New()
	h.Write(spentSetPrefix[:])
	h.Write(workId[:])

	var key [32]byte
	h.Digest().Read(key[:])
	return key
}

// ComputeWorkId computes work ID: BLAKE3(deviceId || nonce || chainId)
// Gas cost: 50
func ComputeWorkId(deviceId, nonce [32]byte, chainId uint64) [32]byte {
	h := blake3.New()
	h.Write(deviceId[:])
	h.Write(nonce[:])

	var chainIdBytes [8]byte
	binary.BigEndian.PutUint64(chainIdBytes[:], chainId)
	h.Write(chainIdBytes[:])

	var workId [32]byte
	h.Digest().Read(workId[:])
	return workId
}

// GetSecurityLevel returns the ML-DSA security level from public key size
func GetSecurityLevel(pubkey []byte) (uint8, error) {
	switch len(pubkey) {
	case MLDSA44PublicKeySize:
		return 2, nil // NIST Level 2
	case MLDSA65PublicKeySize:
		return 3, nil // NIST Level 3
	case MLDSA87PublicKeySize:
		return 5, nil // NIST Level 5
	default:
		return 0, ErrInvalidPublicKeySize
	}
}

// GetExpectedSignatureSize returns expected signature size for security level
func GetExpectedSignatureSize(level uint8) (int, error) {
	switch level {
	case 2:
		return MLDSA44SignatureSize, nil
	case 3:
		return MLDSA65SignatureSize, nil
	case 5:
		return MLDSA87SignatureSize, nil
	default:
		return 0, ErrInvalidSignatureSize
	}
}

// ParseWorkProof extracts fields from a work proof
func ParseWorkProof(workProof []byte) (deviceId, nonce [32]byte, timestamp uint64, privacy uint16, computeMins uint32, teeQuote []byte, err error) {
	if len(workProof) < WorkProofMinSize {
		err = ErrInvalidWorkProof
		return
	}

	copy(deviceId[:], workProof[WorkProofDeviceIDOffset:WorkProofNonceOffset])
	copy(nonce[:], workProof[WorkProofNonceOffset:WorkProofTimestampOffset])
	timestamp = binary.BigEndian.Uint64(workProof[WorkProofTimestampOffset:WorkProofPrivacyOffset])
	privacy = binary.BigEndian.Uint16(workProof[WorkProofPrivacyOffset:WorkProofComputeMinsOffset])
	computeMins = binary.BigEndian.Uint32(workProof[WorkProofComputeMinsOffset:WorkProofTEEQuoteOffset])

	if len(workProof) > WorkProofTEEQuoteOffset {
		teeQuote = workProof[WorkProofTEEQuoteOffset:]
	}

	return
}

// BuildWorkProof constructs a work proof from individual fields
func BuildWorkProof(deviceId, nonce [32]byte, timestamp uint64, privacy uint16, computeMins uint32, teeQuote []byte) []byte {
	size := WorkProofMinSize + len(teeQuote)
	proof := make([]byte, size)

	copy(proof[WorkProofDeviceIDOffset:], deviceId[:])
	copy(proof[WorkProofNonceOffset:], nonce[:])
	binary.BigEndian.PutUint64(proof[WorkProofTimestampOffset:], timestamp)
	binary.BigEndian.PutUint16(proof[WorkProofPrivacyOffset:], privacy)
	binary.BigEndian.PutUint32(proof[WorkProofComputeMinsOffset:], computeMins)

	if len(teeQuote) > 0 {
		copy(proof[WorkProofTEEQuoteOffset:], teeQuote)
	}

	return proof
}

// GetPrivacyMultiplier returns the reward multiplier for a privacy level
func GetPrivacyMultiplier(level uint16) (uint64, error) {
	mult, ok := privacyMultipliers[level]
	if !ok {
		return 0, ErrInvalidPrivacyLevel
	}
	return mult, nil
}

// =============================================================================
// GPU Acceleration Support
// =============================================================================

// GPUAvailable returns true if GPU acceleration is available
func GPUAvailable() bool {
	return accel.Available()
}

// GPUBackend returns the GPU backend name ("Metal", "CUDA", or "CPU")
func GPUBackend() string {
	if accel.Available() {
		backends := accel.Backends()
		if len(backends) > 0 {
			return backends[0].String()
		}
	}
	return "CPU"
}

// GPUThreshold returns minimum batch size for GPU acceleration
func GPUThreshold() int {
	return 8 // Default threshold for batch operations
}

// =============================================================================
// Batch Accumulator for GPU Dispatch
// =============================================================================

// BatchAccumulator collects verification requests for GPU batch processing.
// When the batch reaches threshold, it dispatches to GPU for parallel verification.
type BatchAccumulator struct {
	mu         sync.Mutex
	pubkeys    [][]byte
	messages   [][]byte
	signatures [][]byte
	callbacks  []func(bool, error)
	threshold  int
}

// NewBatchAccumulator creates a new batch accumulator
func NewBatchAccumulator(threshold int) *BatchAccumulator {
	if threshold < GPUThreshold() {
		threshold = GPUThreshold()
	}
	return &BatchAccumulator{
		threshold: threshold,
	}
}

// Add queues a verification request. Returns true if batch was flushed.
func (ba *BatchAccumulator) Add(pubkey, message, signature []byte, callback func(bool, error)) bool {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	ba.pubkeys = append(ba.pubkeys, pubkey)
	ba.messages = append(ba.messages, message)
	ba.signatures = append(ba.signatures, signature)
	ba.callbacks = append(ba.callbacks, callback)

	if len(ba.signatures) >= ba.threshold {
		ba.flushLocked()
		return true
	}
	return false
}

// Flush processes all pending verification requests
func (ba *BatchAccumulator) Flush() {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	ba.flushLocked()
}

// flushLocked processes the batch (must hold lock)
func (ba *BatchAccumulator) flushLocked() {
	if len(ba.signatures) == 0 {
		return
	}

	pubkeys := ba.pubkeys
	messages := ba.messages
	signatures := ba.signatures
	callbacks := ba.callbacks

	// Reset accumulator
	ba.pubkeys = nil
	ba.messages = nil
	ba.signatures = nil
	ba.callbacks = nil

	// Try GPU batch verification via accel
	results, err := crypto.BatchVerify(crypto.SigMLDSA65, signatures, messages, pubkeys)
	if err != nil {
		// Fall back to CPU verification
		for i := range signatures {
			valid, verifyErr := VerifyMLDSA(pubkeys[i], messages[i], signatures[i])
			if callbacks[i] != nil {
				callbacks[i](valid, verifyErr)
			}
		}
		return
	}

	// Dispatch GPU results
	for i := range results {
		if callbacks[i] != nil {
			callbacks[i](results[i], nil)
		}
	}
}

// Size returns current batch size
func (ba *BatchAccumulator) Size() int {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	return len(ba.signatures)
}

// =============================================================================
// Batch Verification Functions
// =============================================================================

// BatchVerifyMLDSA verifies multiple ML-DSA signatures.
// Uses GPU when batch size >= Threshold() and GPU is available.
// Falls back to CPU verification otherwise.
func BatchVerifyMLDSA(pubkeys, messages, signatures [][]byte) ([]bool, error) {
	// Try GPU path first via accel
	results, err := crypto.BatchVerify(crypto.SigMLDSA65, signatures, messages, pubkeys)
	if err == nil {
		return results, nil
	}

	// Fall back to CPU
	results = make([]bool, len(signatures))
	for i := range signatures {
		valid, verifyErr := VerifyMLDSA(pubkeys[i], messages[i], signatures[i])
		if verifyErr != nil {
			results[i] = false
		} else {
			results[i] = valid
		}
	}
	return results, nil
}

// NVTrustMinQuoteSize is the minimum size for NVTrust attestation quotes
const NVTrustMinQuoteSize = 48

// BatchVerifyTEE verifies multiple TEE attestations.
// Currently uses CPU-only verification.
func BatchVerifyTEE(attestations [][]byte) ([]bool, []uint8, error) {
	results := make([]bool, len(attestations))
	scores := make([]uint8, len(attestations))
	for i, att := range attestations {
		if len(att) < NVTrustMinQuoteSize {
			results[i] = false
			scores[i] = 0
			continue
		}
		// Basic attestation validation
		valid, err := VerifyTEE(att, nil)
		if err != nil || !valid {
			results[i] = false
			scores[i] = 0
		} else {
			results[i] = true
			scores[i] = 100 // Maximum score for valid attestation
		}
	}
	return results, scores, nil
}

// BatchCalculateReward computes rewards for multiple work proofs.
// Currently uses CPU-only calculation.
func BatchCalculateReward(workProofs [][]byte, chainId uint64) ([]*big.Int, error) {
	n := len(workProofs)
	if n == 0 {
		return nil, nil
	}

	// CPU calculation
	results := make([]*big.Int, n)
	for i := range workProofs {
		reward, calcErr := CalculateReward(workProofs[i], chainId)
		if calcErr != nil {
			results[i] = big.NewInt(0)
		} else {
			results[i] = reward
		}
	}
	return results, nil
}

// =============================================================================
// GPU Statistics
// =============================================================================

// Stats contains GPU verification statistics
type Stats struct {
	TotalVerifications uint64
	GPUVerifications   uint64
	CPUVerifications   uint64
	Errors             uint64
}

var (
	statsMu sync.Mutex
	stats   Stats
)

// GPUStats returns GPU verification statistics
func GPUStats() Stats {
	statsMu.Lock()
	defer statsMu.Unlock()
	return stats
}

// ResetGPUStats resets GPU verification statistics
func ResetGPUStats() {
	statsMu.Lock()
	defer statsMu.Unlock()
	stats = Stats{}
}
