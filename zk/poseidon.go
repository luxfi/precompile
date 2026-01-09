// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/luxfi/geth/common"
)

// poseidon2Hasher is the underlying gnark-crypto hasher
var poseidon2HasherFactory = poseidon2.NewMerkleDamgardHasher

// Precompile addresses for ZK hash operations (Lux Hashing range 0xA0XX)
const (
	Poseidon2Address = "0xA000" // Poseidon2 hash (PQ-friendly)
)

// GPU function overrides - set by poseidon_gpu.go when CGO is enabled
var (
	useGPU            bool
	gpuHashFunc       func(input []byte) ([]byte, error)
	gpuHashPairFunc   func(left, right [32]byte) ([32]byte, error)
	gpuCommitmentFunc func(value, blinding, salt [32]byte) ([32]byte, error)
	gpuNullifierFunc  func(key, commitment, index [32]byte) ([32]byte, error)
)

var (
	ErrInvalidInputLength  = errors.New("invalid input length: must be multiple of 32 bytes")
	ErrTooManyInputs       = errors.New("too many inputs: maximum 16 field elements")
	ErrInvalidFieldElement = errors.New("invalid field element: exceeds BN254 scalar field")
)

// Poseidon2Hasher provides Poseidon2 hash operations for ZK circuits
// Poseidon2 is optimized for ZK proofs and is PQ-resistant (hash-based security)
type Poseidon2Hasher struct {
	// Cache for frequently used hashes
	cache    map[[32]byte][32]byte
	cacheMu  sync.RWMutex
	cacheMax int

	// Statistics
	TotalHashes uint64
	CacheHits   uint64
	CacheMisses uint64
}

// NewPoseidon2Hasher creates a new Poseidon2 hasher
func NewPoseidon2Hasher() *Poseidon2Hasher {
	return &Poseidon2Hasher{
		cache:    make(map[[32]byte][32]byte),
		cacheMax: 10000,
	}
}

// Hash computes Poseidon2 hash of multiple field elements
// Input: concatenated 32-byte field elements (1-16 elements)
// Output: 32-byte hash
// Uses GPU-accelerated version when available (CGO+Metal on macOS)
func (p *Poseidon2Hasher) Hash(input []byte) ([32]byte, error) {
	if len(input) == 0 || len(input)%32 != 0 {
		return [32]byte{}, ErrInvalidInputLength
	}

	numElements := len(input) / 32
	if numElements > 16 {
		return [32]byte{}, ErrTooManyInputs
	}

	// Check cache
	cacheKey := computeCacheKey(input)
	p.cacheMu.RLock()
	if cached, ok := p.cache[cacheKey]; ok {
		p.cacheMu.RUnlock()
		p.CacheHits++
		return cached, nil
	}
	p.cacheMu.RUnlock()
	p.CacheMisses++

	var result [32]byte

	// Use GPU-accelerated version if available
	if useGPU && gpuHashFunc != nil {
		hashBytes, err := gpuHashFunc(input)
		if err != nil {
			return [32]byte{}, err
		}
		copy(result[:], hashBytes)
	} else {
		// Fallback to gnark-crypto (pure Go)
		// Parse field elements
		// Note: We don't strictly validate that input < field modulus
		// as gnark-crypto handles reduction automatically
		elements := make([]fr.Element, numElements)
		for i := 0; i < numElements; i++ {
			var elem fr.Element
			elem.SetBytes(input[i*32 : (i+1)*32])
			elements[i] = elem
		}

		// Compute Poseidon2 hash using Merkle-Damgard construction
		hasher := poseidon2HasherFactory()
		for _, elem := range elements {
			elemBytes := elem.Bytes()
			hasher.Write(elemBytes[:])
		}
		hashBytes := hasher.Sum(nil)
		copy(result[:], hashBytes)
	}

	// Cache result
	p.cacheMu.Lock()
	if len(p.cache) < p.cacheMax {
		p.cache[cacheKey] = result
	}
	p.cacheMu.Unlock()

	p.TotalHashes++
	return result, nil
}

// HashPair computes Poseidon2(left, right) - optimized for Merkle trees
// Uses GPU-accelerated version when available
func (p *Poseidon2Hasher) HashPair(left, right [32]byte) ([32]byte, error) {
	// Use GPU-accelerated version if available
	if useGPU && gpuHashPairFunc != nil {
		return gpuHashPairFunc(left, right)
	}
	// Fallback to Hash with concatenated input
	input := make([]byte, 64)
	copy(input[:32], left[:])
	copy(input[32:], right[:])
	return p.Hash(input)
}

// Commitment creates a Poseidon2-based commitment
// commitment = Poseidon2(value, blindingFactor, salt)
// This replaces Pedersen commitments for PQ security
// Uses GPU-accelerated version when available
func (p *Poseidon2Hasher) Commitment(value, blindingFactor, salt [32]byte) ([32]byte, error) {
	// Use GPU-accelerated version if available
	if useGPU && gpuCommitmentFunc != nil {
		return gpuCommitmentFunc(value, blindingFactor, salt)
	}
	// Fallback to Hash with concatenated input
	input := make([]byte, 96)
	copy(input[:32], value[:])
	copy(input[32:64], blindingFactor[:])
	copy(input[64:], salt[:])
	return p.Hash(input)
}

// NullifierHash computes nullifier for a note
// nullifier = Poseidon2(nullifierKey, noteCommitment, leafIndex)
// Uses GPU-accelerated version when available
func (p *Poseidon2Hasher) NullifierHash(nullifierKey, noteCommitment [32]byte, leafIndex uint64) ([32]byte, error) {
	// Use GPU-accelerated version if available
	if useGPU && gpuNullifierFunc != nil {
		// Convert uint64 to 32-byte big-endian for GPU function
		var indexBytes [32]byte
		leafBytes := new(big.Int).SetUint64(leafIndex).Bytes()
		copy(indexBytes[32-len(leafBytes):], leafBytes)
		return gpuNullifierFunc(nullifierKey, noteCommitment, indexBytes)
	}
	// Fallback to Hash with concatenated input
	input := make([]byte, 96)
	copy(input[:32], nullifierKey[:])
	copy(input[32:64], noteCommitment[:])

	// Encode leaf index as 32-byte big-endian
	leafBytes := new(big.Int).SetUint64(leafIndex).Bytes()
	copy(input[96-len(leafBytes):96], leafBytes)

	return p.Hash(input)
}

// NoteCommitment creates a note commitment for shielded transactions
// commitment = Poseidon2(amount, assetId, owner, blindingFactor)
func (p *Poseidon2Hasher) NoteCommitment(
	amount *big.Int,
	assetId [32]byte,
	owner common.Address,
	blindingFactor [32]byte,
) ([32]byte, error) {
	input := make([]byte, 128)

	// Amount as 32-byte big-endian
	amountBytes := amount.Bytes()
	copy(input[32-len(amountBytes):32], amountBytes)

	// Asset ID
	copy(input[32:64], assetId[:])

	// Owner address (padded to 32 bytes)
	copy(input[64+12:96], owner[:])

	// Blinding factor
	copy(input[96:], blindingFactor[:])

	return p.Hash(input)
}

// MerkleRoot computes Merkle root from leaves using Poseidon2
func (p *Poseidon2Hasher) MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, errors.New("empty leaves")
	}

	// Pad to power of 2
	n := 1
	for n < len(leaves) {
		n *= 2
	}

	paddedLeaves := make([][32]byte, n)
	copy(paddedLeaves, leaves)
	// Zero-pad remaining leaves (default [32]byte{} is zero)

	// Build tree bottom-up
	current := paddedLeaves
	for len(current) > 1 {
		next := make([][32]byte, len(current)/2)
		for i := 0; i < len(next); i++ {
			hash, err := p.HashPair(current[i*2], current[i*2+1])
			if err != nil {
				return [32]byte{}, err
			}
			next[i] = hash
		}
		current = next
	}

	return current[0], nil
}

// MerkleProof generates a Merkle proof for a leaf at given index
func (p *Poseidon2Hasher) MerkleProof(leaves [][32]byte, index int) ([][32]byte, []bool, error) {
	if len(leaves) == 0 || index >= len(leaves) {
		return nil, nil, errors.New("invalid index")
	}

	// Pad to power of 2
	n := 1
	for n < len(leaves) {
		n *= 2
	}

	paddedLeaves := make([][32]byte, n)
	copy(paddedLeaves, leaves)

	var proof [][32]byte
	var isLeft []bool

	current := paddedLeaves
	idx := index
	for len(current) > 1 {
		// Sibling index
		siblingIdx := idx ^ 1
		proof = append(proof, current[siblingIdx])
		isLeft = append(isLeft, idx%2 == 0)

		// Build next level
		next := make([][32]byte, len(current)/2)
		for i := 0; i < len(next); i++ {
			hash, err := p.HashPair(current[i*2], current[i*2+1])
			if err != nil {
				return nil, nil, err
			}
			next[i] = hash
		}
		current = next
		idx = idx / 2
	}

	return proof, isLeft, nil
}

// VerifyMerkleProof verifies a Merkle proof
func (p *Poseidon2Hasher) VerifyMerkleProof(
	leaf [32]byte,
	proof [][32]byte,
	isLeft []bool,
	root [32]byte,
) (bool, error) {
	if len(proof) != len(isLeft) {
		return false, errors.New("proof and isLeft length mismatch")
	}

	current := leaf
	for i := 0; i < len(proof); i++ {
		var left, right [32]byte
		if isLeft[i] {
			left = current
			right = proof[i]
		} else {
			left = proof[i]
			right = current
		}

		hash, err := p.HashPair(left, right)
		if err != nil {
			return false, err
		}
		current = hash
	}

	return current == root, nil
}

// RequiredGas calculates gas cost for Poseidon2 hash
// Base cost + per-element cost
func (p *Poseidon2Hasher) RequiredGas(inputLen int) uint64 {
	if inputLen == 0 || inputLen%32 != 0 {
		return 0
	}
	numElements := uint64(inputLen / 32)
	// Base: 500 gas + 100 per element
	// This is ~3-5x cheaper than keccak256 for small inputs in ZK context
	return 500 + numElements*100
}

// computeCacheKey creates a cache key from input
func computeCacheKey(input []byte) [32]byte {
	if len(input) == 32 {
		var key [32]byte
		copy(key[:], input)
		return key
	}
	// For longer inputs, use first 32 bytes XOR'd with length
	var key [32]byte
	copy(key[:], input[:32])
	key[0] ^= byte(len(input) >> 8)
	key[1] ^= byte(len(input))
	return key
}

// Global instance
var globalPoseidon2 = NewPoseidon2Hasher()

// Poseidon2Hash is the main entry point for the precompile
func Poseidon2Hash(input []byte) ([]byte, error) {
	result, err := globalPoseidon2.Hash(input)
	if err != nil {
		return nil, err
	}
	return result[:], nil
}

// Poseidon2Commitment creates a commitment (value, blinding, salt)
func Poseidon2Commitment(value, blindingFactor, salt [32]byte) ([]byte, error) {
	result, err := globalPoseidon2.Commitment(value, blindingFactor, salt)
	if err != nil {
		return nil, err
	}
	return result[:], nil
}

// GetPoseidon2Stats returns statistics
func GetPoseidon2Stats() (totalHashes, cacheHits, cacheMisses uint64) {
	return globalPoseidon2.TotalHashes, globalPoseidon2.CacheHits, globalPoseidon2.CacheMisses
}
