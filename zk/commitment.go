// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
)

// CommitmentScheme defines the interface for commitment operations
// Both Poseidon2 (PQ-safe) and Pedersen (legacy) implement this
type CommitmentScheme interface {
	// Commit creates a commitment to a value with blinding
	Commit(value, blindingFactor [32]byte) ([32]byte, error)

	// NoteCommitment creates a shielded note commitment
	NoteCommitment(amount *big.Int, assetId [32]byte, owner common.Address, blindingFactor [32]byte) ([32]byte, error)

	// RequiredGas returns gas cost for the operation
	RequiredGas() uint64

	// IsPQSafe returns true if scheme is post-quantum secure
	IsPQSafe() bool
}

// Poseidon2Scheme implements CommitmentScheme using Poseidon2 hashes
type Poseidon2Scheme struct {
	hasher *Poseidon2Hasher
}

// NewPoseidon2Scheme creates a new Poseidon2-based commitment scheme
func NewPoseidon2Scheme() *Poseidon2Scheme {
	return &Poseidon2Scheme{
		hasher: NewPoseidon2Hasher(),
	}
}

func (s *Poseidon2Scheme) Commit(value, blindingFactor [32]byte) ([32]byte, error) {
	var salt [32]byte // Zero salt for simple commitment
	return s.hasher.Commitment(value, blindingFactor, salt)
}

func (s *Poseidon2Scheme) NoteCommitment(amount *big.Int, assetId [32]byte, owner common.Address, blindingFactor [32]byte) ([32]byte, error) {
	return s.hasher.NoteCommitment(amount, assetId, owner, blindingFactor)
}

func (s *Poseidon2Scheme) RequiredGas() uint64 {
	return 800 // 500 base + 3 elements * 100
}

func (s *Poseidon2Scheme) IsPQSafe() bool {
	return true // Hash-based, Grover-resistant with 256-bit security
}

// PedersenScheme implements CommitmentScheme using Pedersen commitments
type PedersenScheme struct {
	committer *PedersenCommitter
}

// NewPedersenScheme creates a new Pedersen-based commitment scheme
func NewPedersenScheme() *PedersenScheme {
	return &PedersenScheme{
		committer: NewPedersenCommitter(),
	}
}

func (s *PedersenScheme) Commit(value, blindingFactor [32]byte) ([32]byte, error) {
	return s.committer.Commit(value, blindingFactor)
}

func (s *PedersenScheme) NoteCommitment(amount *big.Int, assetId [32]byte, owner common.Address, blindingFactor [32]byte) ([32]byte, error) {
	return s.committer.NoteCommitment(amount, assetId, owner, blindingFactor)
}

func (s *PedersenScheme) RequiredGas() uint64 {
	return 6000 // 2 scalar mults + 1 add
}

func (s *PedersenScheme) IsPQSafe() bool {
	return false // Discrete log assumption breaks with quantum
}

// DefaultScheme is Poseidon2 (PQ-safe)
var DefaultScheme CommitmentScheme = NewPoseidon2Scheme()

// SchemeType identifies the commitment scheme
type SchemeType uint8

const (
	SchemePoseidon2 SchemeType = 0 // Default, PQ-safe
	SchemePedersen  SchemeType = 1 // Legacy, NOT PQ-safe
)

// GetScheme returns a commitment scheme by type
func GetScheme(schemeType SchemeType) (CommitmentScheme, error) {
	switch schemeType {
	case SchemePoseidon2:
		return NewPoseidon2Scheme(), nil
	case SchemePedersen:
		return NewPedersenScheme(), nil
	default:
		return nil, errors.New("unknown commitment scheme")
	}
}

// NoteInput represents the inputs to create a shielded note
type NoteInput struct {
	Amount         *big.Int
	AssetID        [32]byte
	Owner          common.Address
	BlindingFactor [32]byte
	SchemeType     SchemeType
}

// Note represents a shielded note (UTXO)
type Note struct {
	Commitment     [32]byte       // The note commitment
	Amount         *big.Int       // Plaintext amount (for owner only)
	AssetID        [32]byte       // Asset identifier
	Owner          common.Address // Note owner
	BlindingFactor [32]byte       // Blinding factor (secret)
	SchemeType     SchemeType     // Which commitment scheme was used
	LeafIndex      uint64         // Position in Merkle tree (set after insertion)
}

// CreateNote creates a new shielded note
func CreateNote(input NoteInput) (*Note, error) {
	scheme, err := GetScheme(input.SchemeType)
	if err != nil {
		return nil, err
	}

	commitment, err := scheme.NoteCommitment(
		input.Amount,
		input.AssetID,
		input.Owner,
		input.BlindingFactor,
	)
	if err != nil {
		return nil, err
	}

	return &Note{
		Commitment:     commitment,
		Amount:         input.Amount,
		AssetID:        input.AssetID,
		Owner:          input.Owner,
		BlindingFactor: input.BlindingFactor,
		SchemeType:     input.SchemeType,
	}, nil
}

// Nullifier computes the nullifier for spending this note
// nullifier = Hash(nullifierKey, commitment, leafIndex)
func (n *Note) Nullifier(nullifierKey [32]byte) ([32]byte, error) {
	if n.SchemeType == SchemePoseidon2 {
		return globalPoseidon2.NullifierHash(nullifierKey, n.Commitment, n.LeafIndex)
	}
	// For Pedersen scheme, still use Poseidon2 for nullifier (it's a hash, not commitment)
	return globalPoseidon2.NullifierHash(nullifierKey, n.Commitment, n.LeafIndex)
}

// TransactionWitness contains the private witness for a shielded transaction
type TransactionWitness struct {
	// Input notes
	InputNotes        []*Note
	InputMerkleProofs [][][32]byte
	InputMerklePaths  [][]bool
	NullifierKeys     [][32]byte

	// Output notes
	OutputNotes []*Note

	// Additional witness data for range proofs, etc.
	RangeProofWitness []byte
}

// PublicInputs contains the public inputs for verification
type PublicInputs struct {
	// Merkle root (state commitment)
	MerkleRoot [32]byte

	// Nullifiers (prevent double-spend)
	Nullifiers [][32]byte

	// Output commitments
	OutputCommitments [][32]byte

	// Asset IDs (public for compliance)
	AssetIDs [][32]byte

	// Fee
	Fee *big.Int

	// Metadata
	PoolID    [32]byte
	ChainID   uint64
	Timestamp uint64
}

// ValidityReceipt is the attestation exported to other chains
type ValidityReceipt struct {
	ReceiptID     [32]byte   // Unique identifier
	MerkleRoot    [32]byte   // State root after this batch
	Nullifiers    [][32]byte // Consumed nullifiers
	PoolID        [32]byte   // Shielded pool
	AssetID       [32]byte   // Token/asset
	SourceChainID uint64     // Z-chain ID
	TargetChainID uint64     // Destination chain
	CircuitID     [32]byte   // STARK/Groth16 circuit version
	Timestamp     uint64     // Block timestamp
	ProofType     ProofType  // STARK (internal) or Groth16 (external)
	ZKProofDigest [32]byte   // Hash of proof (not proof itself)
}

// ProofType distinguishes internal (STARK) vs external (Groth16) proofs
type ProofType uint8

const (
	ProofTypeSTARK   ProofType = 0 // PQ-friendly, for Z-chain
	ProofTypeGroth16 ProofType = 1 // Cheap verification, for external chains
)

// ComputeReceiptID computes the unique receipt identifier
func (r *ValidityReceipt) ComputeReceiptID() ([32]byte, error) {
	// Collect all data
	var data []byte

	data = append(data, r.MerkleRoot[:]...)
	for _, n := range r.Nullifiers {
		data = append(data, n[:]...)
	}
	data = append(data, r.PoolID[:]...)
	data = append(data, r.AssetID[:]...)

	// Use uint64 encoding
	chainBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		chainBytes[7-i] = byte(r.SourceChainID >> (i * 8))
	}
	data = append(data, chainBytes...)

	for i := 0; i < 8; i++ {
		chainBytes[7-i] = byte(r.TargetChainID >> (i * 8))
	}
	data = append(data, chainBytes...)

	data = append(data, r.CircuitID[:]...)

	// Hash with Poseidon2 for consistency
	// But since this is variable length, pad to 32-byte chunks
	paddedLen := ((len(data) + 31) / 32) * 32
	padded := make([]byte, paddedLen)
	copy(padded, data)

	return globalPoseidon2.Hash(padded)
}
