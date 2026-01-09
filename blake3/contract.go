// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package blake3 implements Blake3 hash precompile for the Lux EVM.
// Address: 0x0504
//
// Blake3 is a fast cryptographic hash function that:
// - Is 6-17x faster than SHA-3 and SHA-256
// - Supports arbitrary-length output (XOF)
// - Is suitable for Merkle tree and KDF use cases
// - Is NOT post-quantum but provides excellent performance
//
// Operations:
// - Hash256: Standard 32-byte hash
// - Hash512: Extended 64-byte hash
// - HashXOF: Extended output function (arbitrary length)
// - HashWithDomain: Domain-separated hash
// - MerkleRoot: Merkle tree root computation
//
// Gas costs are based on input size and operation complexity.
package blake3

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/crypto/hash/blake3"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the address of the Blake3 precompile (Graph/Hashing range 0x0500)
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000004")

	// Singleton instance
	Blake3Precompile = &blake3Precompile{}

	_ contract.StatefulPrecompiledContract = &blake3Precompile{}

	ErrInvalidInput      = errors.New("invalid blake3 input")
	ErrInvalidOperation  = errors.New("invalid operation selector")
	ErrOutputTooLarge    = errors.New("requested output exceeds maximum")
	ErrInvalidDataLength = errors.New("invalid data length")
)

// Output limits
const (
	MaxOutputLength = 1024        // Maximum XOF output in bytes
	MaxInputLength  = 1024 * 1024 // Maximum input: 1MB
	DigestLength32  = 32          // Standard hash length
	DigestLength64  = 64          // Extended hash length
	MaxMerkleLeaves = 1024        // Maximum Merkle tree leaves
)

// Operation selectors (first byte of input)
const (
	OpHash256        = 0x01 // 32-byte hash
	OpHash512        = 0x02 // 64-byte hash
	OpHashXOF        = 0x03 // Arbitrary length output
	OpHashWithDomain = 0x04 // Domain-separated hash
	OpMerkleRoot     = 0x10 // Merkle tree root
	OpDeriveKey      = 0x20 // Key derivation
)

// Gas costs (optimized for high throughput)
const (
	GasBase256       = 100 // Base cost for 32-byte hash
	GasBase512       = 150 // Base cost for 64-byte hash
	GasBaseXOF       = 200 // Base cost for XOF
	GasPerInputWord  = 3   // Per 32-byte input word
	GasPerOutputWord = 5   // Per 32-byte output word (XOF)
	GasDomainSetup   = 50  // Domain separator setup
	GasMerkleBase    = 500 // Merkle tree base cost
	GasMerklePerLeaf = 100 // Per leaf in Merkle tree
	GasDeriveKey     = 300 // Key derivation
)

type blake3Precompile struct{}

// Address returns the precompile address
func (p *blake3Precompile) Address() common.Address {
	return ContractAddress
}

// RequiredGas calculates gas for Blake3 operations
func (p *blake3Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}

	op := input[0]
	dataLen := uint64(len(input) - 1)
	inputWords := (dataLen + 31) / 32

	switch op {
	case OpHash256:
		return GasBase256 + inputWords*GasPerInputWord

	case OpHash512:
		return GasBase512 + inputWords*GasPerInputWord

	case OpHashXOF:
		if len(input) < 5 {
			return 0
		}
		outputLen := binary.BigEndian.Uint32(input[1:5])
		outputWords := (uint64(outputLen) + 31) / 32
		return GasBaseXOF + inputWords*GasPerInputWord + outputWords*GasPerOutputWord

	case OpHashWithDomain:
		return GasDomainSetup + GasBase256 + inputWords*GasPerInputWord

	case OpMerkleRoot:
		if len(input) < 5 {
			return 0
		}
		numLeaves := binary.BigEndian.Uint32(input[1:5])
		return GasMerkleBase + uint64(numLeaves)*GasMerklePerLeaf

	case OpDeriveKey:
		return GasDeriveKey + inputWords*GasPerInputWord

	default:
		return 0
	}
}

// Run executes the Blake3 precompile
func (p *blake3Precompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	// Calculate required gas
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

	switch op {
	case OpHash256:
		return p.hash256(data), remainingGas, nil

	case OpHash512:
		return p.hash512(data), remainingGas, nil

	case OpHashXOF:
		return p.hashXOF(data)

	case OpHashWithDomain:
		return p.hashWithDomain(data)

	case OpMerkleRoot:
		return p.merkleRoot(data)

	case OpDeriveKey:
		return p.deriveKey(data)

	default:
		return nil, remainingGas, ErrInvalidOperation
	}
}

// hash256 computes a 32-byte Blake3 hash
func (p *blake3Precompile) hash256(data []byte) []byte {
	if len(data) > MaxInputLength {
		data = data[:MaxInputLength]
	}
	h := blake3.New()
	h.Write(data)
	result := make([]byte, DigestLength32)
	h.Reader().Read(result)
	return result
}

// hash512 computes a 64-byte Blake3 hash
func (p *blake3Precompile) hash512(data []byte) []byte {
	if len(data) > MaxInputLength {
		data = data[:MaxInputLength]
	}
	digest := blake3.HashBytes(data)
	return digest[:]
}

// hashXOF computes an arbitrary-length hash using XOF mode
// Input format: [4 bytes output_length][data...]
func (p *blake3Precompile) hashXOF(data []byte) ([]byte, uint64, error) {
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

	h := blake3.New()
	h.Write(inputData)
	result := make([]byte, outputLen)
	h.Reader().Read(result)
	return result, 0, nil
}

// hashWithDomain computes a domain-separated hash
// Input format: [1 byte domain_len][domain...][data...]
func (p *blake3Precompile) hashWithDomain(data []byte) ([]byte, uint64, error) {
	if len(data) < 1 {
		return nil, 0, ErrInvalidDataLength
	}

	domainLen := int(data[0])
	if len(data) < 1+domainLen {
		return nil, 0, ErrInvalidDataLength
	}

	domain := string(data[1 : 1+domainLen])
	inputData := data[1+domainLen:]

	if len(inputData) > MaxInputLength {
		inputData = inputData[:MaxInputLength]
	}

	digest := blake3.HashWithDomain(domain, inputData)
	return digest[:DigestLength32], 0, nil
}

// merkleRoot computes a Merkle tree root from leaf hashes
// Input format: [4 bytes num_leaves][32 bytes leaf_0][32 bytes leaf_1]...
func (p *blake3Precompile) merkleRoot(data []byte) ([]byte, uint64, error) {
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
		leaves[i] = data[start : start+DigestLength32]
	}

	// Compute Merkle root
	return p.computeMerkleRoot(leaves), 0, nil
}

// computeMerkleRoot computes the Merkle root recursively
func (p *blake3Precompile) computeMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, DigestLength32)
	}
	if len(leaves) == 1 {
		result := make([]byte, DigestLength32)
		copy(result, leaves[0])
		return result
	}

	// Pad to power of 2 if necessary
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build tree bottom-up
	for len(leaves) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(leaves); i += 2 {
			h := blake3.New()
			h.Write(leaves[i])
			h.Write(leaves[i+1])
			hash := make([]byte, DigestLength32)
			h.Reader().Read(hash)
			nextLevel = append(nextLevel, hash)
		}
		leaves = nextLevel
	}

	return leaves[0]
}

// deriveKey derives a key using Blake3 KDF
// Input format: [1 byte context_len][context...][32 bytes key_material]
func (p *blake3Precompile) deriveKey(data []byte) ([]byte, uint64, error) {
	if len(data) < 1 {
		return nil, 0, ErrInvalidDataLength
	}

	contextLen := int(data[0])
	if len(data) < 1+contextLen+32 {
		return nil, 0, ErrInvalidDataLength
	}

	context := string(data[1 : 1+contextLen])
	keyMaterial := data[1+contextLen : 1+contextLen+32]

	// Use domain-separated hash for KDF
	h := blake3.NewWithDomain("BLAKE3 KDF: " + context)
	h.Write(keyMaterial)
	result := make([]byte, DigestLength32)
	h.Reader().Read(result)
	return result, 0, nil
}
