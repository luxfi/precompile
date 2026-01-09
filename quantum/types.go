// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package quantum provides precompiles for post-quantum cryptographic operations.
// These integrate with QuantumVM (Q-Chain) for quantum-safe signatures, including
// Ringtail (lattice-based threshold) and hybrid BLS+PQ signatures.
package quantum

import (
	"errors"

	"github.com/luxfi/geth/common"
)

// Precompile addresses for quantum-safe operations
const (
	// Core quantum signature operations
	QuantumVerifyAddress = "0x0600" // Generic quantum signature verification
	RingtailAddress      = "0x0601" // Ringtail threshold signatures
	MLDSAAddress         = "0x0602" // NIST ML-DSA (Dilithium)
	MLKEMAddress         = "0x0603" // NIST ML-KEM (Kyber)
	SLHDSAAddress        = "0x0604" // NIST SLH-DSA (SPHINCS+)

	// Hybrid operations (classical + PQ)
	HybridBLSRingtailAddress     = "0x0610" // BLS12-381 + Ringtail
	HybridECDSAMLDSAAddress      = "0x0611" // ECDSA + ML-DSA
	HybridSchnorrRingtailAddress = "0x0612" // Schnorr + Ringtail

	// Quantum stamping (Q-Chain integration)
	QuantumStampAddress  = "0x0620" // Quantum timestamp verification
	QuantumAnchorAddress = "0x0621" // Quantum anchor verification

	// BLS operations (classical but often paired with PQ)
	BLSVerifyAddress      = "0x0630" // BLS12-381 signature verification
	BLSAggregateAddress   = "0x0631" // BLS signature aggregation
	BLSMultiVerifyAddress = "0x0632" // BLS multi-signature verification

	// Gas costs
	GasRingtailVerify = uint64(75000)  // Ringtail signature verification
	GasMLDSAVerify    = uint64(50000)  // ML-DSA verification
	GasMLKEMDecap     = uint64(25000)  // ML-KEM decapsulation
	GasSLHDSAVerify   = uint64(100000) // SLH-DSA verification (larger)
	GasHybridVerify   = uint64(100000) // Hybrid signature verification
	GasBLSVerify      = uint64(25000)  // BLS verification
	GasBLSAggregate   = uint64(10000)  // BLS aggregation (per sig)
	GasQuantumStamp   = uint64(50000)  // Quantum stamp verification
)

// QuantumAlgorithm represents a post-quantum algorithm
type QuantumAlgorithm uint8

const (
	AlgRingtail       QuantumAlgorithm = iota // Threshold lattice signatures
	AlgMLDSA44                                // ML-DSA-44 (FIPS 204)
	AlgMLDSA65                                // ML-DSA-65
	AlgMLDSA87                                // ML-DSA-87
	AlgMLKEM512                               // ML-KEM-512 (FIPS 203)
	AlgMLKEM768                               // ML-KEM-768
	AlgMLKEM1024                              // ML-KEM-1024
	AlgSLHDSASHA2128f                         // SLH-DSA-SHA2-128f (FIPS 205)
	AlgSLHDSASHA2192f                         // SLH-DSA-SHA2-192f
	AlgSLHDSASHA2256f                         // SLH-DSA-SHA2-256f
)

// HybridScheme represents a hybrid classical+PQ scheme
type HybridScheme uint8

const (
	HybridBLSRingtail     HybridScheme = iota // BLS + Ringtail
	HybridECDSAMLDSA                          // ECDSA + ML-DSA
	HybridSchnorrRingtail                     // Schnorr + Ringtail
	HybridEd25519MLDSA                        // Ed25519 + ML-DSA
)

// RingtailPublicKey represents a Ringtail threshold public key
type RingtailPublicKey struct {
	KeyID        [32]byte // Unique key identifier
	PublicKey    []byte   // Combined threshold public key
	Threshold    uint32   // t (t+1 signatures required)
	TotalParties uint32   // n (total parties)
	Generation   uint64   // Key generation number
	Parameters   RingtailParams
}

// RingtailParams represents Ringtail security parameters
type RingtailParams struct {
	SecurityLevel uint32 // 128, 192, or 256 bits
	N             uint32 // Ring dimension
	Q             uint64 // Modulus
	Sigma         uint32 // Error distribution width
}

// RingtailSignature represents a Ringtail threshold signature
type RingtailSignature struct {
	KeyID      [32]byte // Signing key identifier
	Signature  []byte   // Threshold signature
	SignerMask []byte   // Bitmask of signers that contributed
	Generation uint64   // Key generation at signing time
}

// MLDSAPublicKey represents an ML-DSA public key
type MLDSAPublicKey struct {
	Mode      uint8  // 44, 65, or 87
	PublicKey []byte // Raw public key bytes
	Hash      [32]byte
}

// MLDSASignature represents an ML-DSA signature
type MLDSASignature struct {
	Mode      uint8  // 44, 65, or 87
	Signature []byte // Raw signature bytes
}

// MLKEMPublicKey represents an ML-KEM encapsulation key
type MLKEMPublicKey struct {
	Mode      uint8  // 512, 768, or 1024
	PublicKey []byte // Encapsulation key
}

// MLKEMCiphertext represents an ML-KEM ciphertext
type MLKEMCiphertext struct {
	Mode       uint8  // Must match key mode
	Ciphertext []byte // Encapsulated key
}

// HybridSignature combines classical and PQ signatures
type HybridSignature struct {
	Scheme          HybridScheme
	ClassicalSig    []byte // ECDSA/BLS/Schnorr signature
	QuantumSig      []byte // Ringtail/ML-DSA signature
	ClassicalPubKey []byte // Classical public key
	QuantumPubKey   []byte // PQ public key
}

// QuantumStamp represents a quantum timestamp from Q-Chain
type QuantumStamp struct {
	StampID     [32]byte           // Unique stamp identifier
	BlockID     [32]byte           // Q-Chain block ID
	BlockHeight uint64             // Q-Chain block height
	Timestamp   uint64             // Unix timestamp
	PChainRef   uint64             // P-Chain block reference
	Message     []byte             // Stamped message/hash
	Signature   *RingtailSignature // Quantum signature
}

// QuantumAnchor anchors data to Q-Chain with quantum proof
type QuantumAnchor struct {
	AnchorID [32]byte // Unique anchor identifier
	DataHash [32]byte // Hash of anchored data
	Stamp    *QuantumStamp
	Proof    []byte // Merkle proof in Q-Chain
	Verified bool
}

// BLSPublicKey represents a BLS12-381 public key
type BLSPublicKey struct {
	PublicKey []byte // G1 or G2 point (depends on scheme)
}

// BLSSignature represents a BLS12-381 signature
type BLSSignature struct {
	Signature []byte // G1 or G2 point (opposite of pubkey)
}

// BLSAggregateSignature represents an aggregated BLS signature
type BLSAggregateSignature struct {
	AggSig      []byte     // Aggregated signature
	PubKeys     [][]byte   // Participating public keys
	Messages    [][32]byte // Messages (if distinct)
	SameMessage bool       // True if all signed same message
}

// QuantumKeyPair represents a quantum key pair
type QuantumKeyPair struct {
	Algorithm  QuantumAlgorithm
	PublicKey  []byte
	PrivateKey []byte         // Only populated for local keys
	Address    common.Address // Derived EVM address
}

// VerificationResult represents the result of quantum signature verification
type VerificationResult struct {
	Valid            bool
	Algorithm        QuantumAlgorithm
	MessageHash      [32]byte
	SignerPublicKey  []byte
	GasUsed          uint64
	HybridComponents *HybridVerificationResult // If hybrid
}

// HybridVerificationResult contains both verification results
type HybridVerificationResult struct {
	ClassicalValid bool
	QuantumValid   bool
	BothRequired   bool // If true, both must be valid
}

// Errors
var (
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrInvalidPublicKey      = errors.New("invalid public key")
	ErrInvalidKeySize        = errors.New("invalid key size for algorithm")
	ErrUnsupportedAlgorithm  = errors.New("unsupported algorithm")
	ErrUnsupportedHybrid     = errors.New("unsupported hybrid scheme")
	ErrThresholdNotMet       = errors.New("threshold not met")
	ErrInvalidParameters     = errors.New("invalid cryptographic parameters")
	ErrDecapsulationFailed   = errors.New("ML-KEM decapsulation failed")
	ErrInvalidStamp          = errors.New("invalid quantum stamp")
	ErrStampExpired          = errors.New("quantum stamp expired")
	ErrInvalidAnchor         = errors.New("invalid quantum anchor")
	ErrBLSVerificationFailed = errors.New("BLS verification failed")
	ErrBLSAggregationFailed  = errors.New("BLS aggregation failed")
	ErrHybridMismatch        = errors.New("hybrid signature scheme mismatch")
	ErrKeyNotFound           = errors.New("quantum key not found")
	ErrInvalidProof          = errors.New("invalid quantum proof")
)

// Security level constants
const (
	SecurityLevel128 = 128
	SecurityLevel192 = 192
	SecurityLevel256 = 256
)

// ML-DSA key sizes (FIPS 204)
const (
	MLDSA44PublicKeySize = 1312
	MLDSA44SecretKeySize = 2560
	MLDSA44SignatureSize = 2420
	MLDSA65PublicKeySize = 1952
	MLDSA65SecretKeySize = 4032
	MLDSA65SignatureSize = 3309
	MLDSA87PublicKeySize = 2592
	MLDSA87SecretKeySize = 4896
	MLDSA87SignatureSize = 4627
)

// ML-KEM key sizes (FIPS 203)
const (
	MLKEM512PublicKeySize   = 800
	MLKEM512SecretKeySize   = 1632
	MLKEM512CiphertextSize  = 768
	MLKEM768PublicKeySize   = 1184
	MLKEM768SecretKeySize   = 2400
	MLKEM768CiphertextSize  = 1088
	MLKEM1024PublicKeySize  = 1568
	MLKEM1024SecretKeySize  = 3168
	MLKEM1024CiphertextSize = 1568
)

// Shared secret size for all ML-KEM variants
const MLKEMSharedSecretSize = 32

// BLS12-381 sizes
const (
	BLSPublicKeySize = 48 // G1 compressed
	BLSSignatureSize = 96 // G2 compressed
	BLSSecretKeySize = 32
)
