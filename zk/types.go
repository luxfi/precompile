// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zk provides precompiles for zero-knowledge proof operations.
// These enable privacy-preserving transactions, ZK rollup verification,
// and confidential computing on the Lux EVM.
package zk

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
)

// Precompile addresses for ZK operations
const (
	// Core ZK verification
	ZKVerifyAddress = "0x0900" // Generic ZK proof verification
	Groth16Address  = "0x0901" // Groth16 verifier
	PlonkAddress    = "0x0902" // PLONK verifier
	FflonkAddress   = "0x0903" // fflonk verifier
	Halo2Address    = "0x0904" // Halo2 verifier

	// Commitment schemes
	KZGAddress = "0x0910" // KZG commitments (EIP-4844)
	// PedersenAddress moved to pedersen.go (0x0502)
	// Poseidon2Address in poseidon.go (0x0501)
	IPAAddress = "0x0912" // Inner product arguments

	// Privacy operations
	PrivacyPoolAddress = "0x0920" // Confidential transaction pool
	NullifierAddress   = "0x0921" // Nullifier verification
	CommitmentAddress  = "0x0922" // Commitment verification
	RangeProofAddress  = "0x0923" // Range proof verification

	// Rollup support
	RollupVerifyAddress = "0x0930" // ZK rollup batch verification
	StateRootAddress    = "0x0931" // State root verification
	BatchProofAddress   = "0x0932" // Batch proof aggregation

	// Gas costs
	GasGroth16Verify  = uint64(200000) // Groth16 verification
	GasPlonkVerify    = uint64(250000) // PLONK verification
	GasKZGVerify      = uint64(50000)  // KZG point evaluation
	GasPedersenCommit = uint64(10000)  // Pedersen commitment
	GasNullifierCheck = uint64(5000)   // Nullifier lookup
	GasRangeProof     = uint64(100000) // Range proof verification
	GasRollupVerify   = uint64(500000) // Rollup batch verification
)

// ProofSystem represents a zero-knowledge proof system
type ProofSystem uint8

const (
	ProofSystemGroth16 ProofSystem = iota
	ProofSystemPlonk
	ProofSystemFflonk
	ProofSystemHalo2
	ProofSystemStark
)

// CircuitType represents predefined circuit types
type CircuitType uint8

const (
	CircuitTransfer    CircuitType = iota // Token transfer
	CircuitMint                           // Token minting
	CircuitBurn                           // Token burning
	CircuitSwap                           // DEX swap
	CircuitLiquidity                      // Liquidity provision
	CircuitRollupBatch                    // Rollup batch
	CircuitCustom                         // Custom circuit
)

// VerifyingKey represents a ZK verification key
type VerifyingKey struct {
	KeyID       [32]byte    // Unique key identifier
	ProofSystem ProofSystem // Which proof system
	CircuitType CircuitType // Type of circuit
	Alpha       []byte      // G1 element
	Beta        []byte      // G2 element
	Gamma       []byte      // G2 element
	Delta       []byte      // G2 element
	IC          [][]byte    // Input constraints (G1 elements)
	Hash        [32]byte    // Hash of the key for identification
	Owner       common.Address
	CreatedAt   uint64
}

// Proof represents a zero-knowledge proof
type Proof struct {
	ProofSystem  ProofSystem
	A            []byte // G1 element
	B            []byte // G2 element
	C            []byte // G1 element
	PublicInputs []*big.Int
}

// Commitment represents a cryptographic commitment
type Commitment struct {
	CommitType CommitmentType
	Value      []byte         // Commitment value
	Blinding   []byte         // Blinding factor (if applicable)
	Token      common.Address // Token being committed
	Amount     *big.Int       // Hidden amount
}

// CommitmentType represents the type of commitment scheme
type CommitmentType uint8

const (
	CommitPedersen CommitmentType = iota
	CommitKZG
	CommitIPA
	CommitHash
)

// Nullifier represents a nullifier for double-spend prevention
type Nullifier struct {
	Hash    [32]byte    // Nullifier hash
	SpentAt uint64      // Block height when spent
	SpentTx common.Hash // Transaction that spent it
}

// PrivateInput represents encrypted input for a confidential transaction
type PrivateInput struct {
	Sender        common.Address // Sender address
	Recipient     common.Address // Recipient address
	Token         common.Address // Token address
	Amount        *big.Int       // Encrypted amount
	EncryptedNote []byte         // Encrypted note data
	EphemeralPK   []byte         // Ephemeral public key for decryption
}

// RangeProof proves a value is in a valid range without revealing it
type RangeProof struct {
	Commitment []byte // Value commitment
	ProofData  []byte // Range proof data
	BitLength  uint32 // Maximum bits in the value
}

// ConfidentialPool represents a confidential transaction pool
type ConfidentialPool struct {
	PoolID         [32]byte                 // Pool identifier
	Token          common.Address           // Pool token
	Commitments    map[[32]byte]*Commitment // Active commitments
	Nullifiers     map[[32]byte]*Nullifier  // Spent nullifiers
	MerkleRoot     [32]byte                 // Current merkle root
	MerkleDepth    uint32                   // Tree depth
	TotalDeposits  *big.Int                 // Total deposited
	TotalWithdraws *big.Int                 // Total withdrawn
	Enabled        bool
}

// VerificationResult represents the result of proof verification
type VerificationResult struct {
	Valid        bool
	ProofSystem  ProofSystem
	CircuitType  CircuitType
	PublicInputs []*big.Int
	GasUsed      uint64
}

// Errors
var (
	ErrInvalidProof         = errors.New("invalid proof")
	ErrInvalidVerifyingKey  = errors.New("invalid verifying key")
	ErrProofSystemMismatch  = errors.New("proof system mismatch")
	ErrCircuitMismatch      = errors.New("circuit type mismatch")
	ErrInvalidPublicInputs  = errors.New("invalid public inputs")
	ErrNullifierSpent       = errors.New("nullifier already spent")
	ErrCommitmentNotFound   = errors.New("commitment not found")
	ErrInvalidCommitment    = errors.New("invalid commitment")
	ErrInvalidRangeProof    = errors.New("invalid range proof")
	ErrInvalidStateRoot     = errors.New("invalid state root")
	ErrPoolNotFound         = errors.New("confidential pool not found")
	ErrPoolDisabled         = errors.New("confidential pool disabled")
	ErrInsufficientBalance  = errors.New("insufficient confidential balance")
)
