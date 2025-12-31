// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package threshold provides precompiles for T-Chain threshold signature integration.
// These precompiles allow EVM contracts to request distributed key generation,
// threshold signing, and key management operations from the ThresholdVM.
package threshold

import (
	"errors"

	"github.com/luxfi/geth/common"
)

// Precompile addresses for threshold operations
const (
	// Core threshold operations
	ThresholdKeygenAddress   = "0x0800" // Distributed key generation
	ThresholdSignAddress     = "0x0801" // Threshold signing
	ThresholdRefreshAddress  = "0x0802" // Key share refresh
	ThresholdReshareAddress  = "0x0803" // Key resharing
	ThresholdVerifyAddress   = "0x0804" // Signature verification

	// Protocol-specific precompiles
	FROSTAddress     = "0x0810" // FROST threshold Schnorr
	CGGMP21Address   = "0x0811" // CGGMP21 threshold ECDSA
	RingtailAddress  = "0x0812" // Post-quantum threshold (lattice)
	LSSAddress       = "0x0813" // Lux Secret Sharing

	// Gas costs
	GasKeygen        = uint64(500000)  // DKG is expensive
	GasSign          = uint64(100000)  // Threshold signing
	GasRefresh       = uint64(250000)  // Share refresh
	GasReshare       = uint64(500000)  // Full reshare
	GasVerify        = uint64(25000)   // Signature verification
	GasGetPublicKey  = uint64(5000)    // Get public key
	GasGetKeyInfo    = uint64(5000)    // Get key metadata
)

// Protocol represents a threshold signature protocol
type Protocol uint8

const (
	ProtocolLSS Protocol = iota      // Lux Secret Sharing
	ProtocolFROST                    // Flexible Round-Optimized Schnorr
	ProtocolCGGMP21                  // CGGMP21 threshold ECDSA
	ProtocolRingtail                 // Post-quantum threshold (lattice-based)
)

// KeyType represents the cryptographic key type
type KeyType uint8

const (
	KeyTypeSecp256k1 KeyType = iota // ECDSA secp256k1
	KeyTypeEd25519                  // EdDSA Ed25519
	KeyTypeBLS12381                 // BLS12-381
	KeyTypeRingtail                 // Post-quantum lattice
	KeyTypeMLDSA                    // NIST ML-DSA
)

// ThresholdKey represents a managed threshold key
type ThresholdKey struct {
	KeyID        [32]byte       // Unique key identifier
	Protocol     Protocol       // Threshold protocol used
	KeyType      KeyType        // Cryptographic key type
	PublicKey    []byte         // Combined public key
	Address      common.Address // Derived EVM address (for ECDSA keys)
	Threshold    uint32         // t (t+1 signatures required)
	TotalParties uint32         // n (total parties)
	Generation   uint64         // Key generation number (increments on reshare)
	CreatedAt    uint64         // Creation timestamp
	LastRefresh  uint64         // Last refresh timestamp
	ExpiresAt    uint64         // Expiration timestamp (0 = no expiry)
	Status       KeyStatus
	Owner        common.Address // Key owner (can be contract)
	Permissions  KeyPermissions // Who can use the key
}

// KeyStatus represents the status of a threshold key
type KeyStatus uint8

const (
	KeyStatusActive KeyStatus = iota
	KeyStatusRefreshing
	KeyStatusResharing
	KeyStatusExpired
	KeyStatusRevoked
)

// KeyPermissions defines who can use a threshold key
type KeyPermissions struct {
	Owner          common.Address   // Primary owner
	AllowedSigners []common.Address // Addresses that can request signatures
	AllowedChains  []uint32         // Chain IDs that can use this key
	MaxSignsPerDay uint64           // Daily signing limit
	SignsToday     uint64           // Signs used today
	LastResetDay   uint64           // Last daily reset
}

// SigningRequest represents a threshold signing request
type SigningRequest struct {
	RequestID    [32]byte       // Unique request ID
	KeyID        [32]byte       // Key to sign with
	MessageHash  [32]byte       // Message hash to sign
	Requester    common.Address // Who requested the signature
	RequestedAt  uint64         // Request timestamp
	ExpiresAt    uint64         // Request expiry
	Status       SigningStatus
	Signature    []byte   // Final threshold signature
	PartialSigs  [][]byte // Partial signatures collected
	PartyCount   uint32   // Number of parties that signed
}

// SigningStatus represents the status of a signing request
type SigningStatus uint8

const (
	SignStatusPending SigningStatus = iota
	SignStatusInProgress
	SignStatusComplete
	SignStatusFailed
	SignStatusExpired
)

// KeygenRequest represents a distributed key generation request
type KeygenRequest struct {
	RequestID    [32]byte       // Unique request ID
	Protocol     Protocol       // Protocol to use
	KeyType      KeyType        // Key type to generate
	Threshold    uint32         // t value
	TotalParties uint32         // n value
	Requester    common.Address // Who requested keygen
	RequestedAt  uint64         // Request timestamp
	ExpiresAt    uint64         // Request expiry
	Status       KeygenStatus
	ResultKeyID  [32]byte // Resulting key ID (when complete)
	Participants [][20]byte // Node IDs participating
}

// KeygenStatus represents the status of a keygen request
type KeygenStatus uint8

const (
	KeygenStatusPending KeygenStatus = iota
	KeygenStatusRound1
	KeygenStatusRound2
	KeygenStatusRound3
	KeygenStatusComplete
	KeygenStatusFailed
)

// RefreshRequest represents a key share refresh request
type RefreshRequest struct {
	RequestID   [32]byte // Unique request ID
	KeyID       [32]byte // Key to refresh
	Requester   common.Address
	RequestedAt uint64
	Status      RefreshStatus
}

// RefreshStatus represents the status of a refresh request
type RefreshStatus uint8

const (
	RefreshStatusPending RefreshStatus = iota
	RefreshStatusInProgress
	RefreshStatusComplete
	RefreshStatusFailed
)

// ReshareRequest represents a key resharing request (change parties)
type ReshareRequest struct {
	RequestID    [32]byte   // Unique request ID
	KeyID        [32]byte   // Key to reshare
	NewThreshold uint32     // New threshold (can be same)
	NewParties   [][20]byte // New party set
	Requester    common.Address
	RequestedAt  uint64
	Status       ReshareStatus
}

// ReshareStatus represents the status of a reshare request
type ReshareStatus uint8

const (
	ReshareStatusPending ReshareStatus = iota
	ReshareStatusInProgress
	ReshareStatusComplete
	ReshareStatusFailed
)

// VerificationResult represents the result of signature verification
type VerificationResult struct {
	Valid       bool
	SignerKeyID [32]byte
	MessageHash [32]byte
	Protocol    Protocol
	KeyType     KeyType
}

// Errors
var (
	ErrKeyNotFound          = errors.New("threshold key not found")
	ErrKeyExpired           = errors.New("threshold key expired")
	ErrKeyRevoked           = errors.New("threshold key revoked")
	ErrKeyBusy              = errors.New("key is busy (refreshing/resharing)")
	ErrRequestNotFound      = errors.New("request not found")
	ErrRequestExpired       = errors.New("request expired")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrInvalidThreshold     = errors.New("invalid threshold (must be < n)")
	ErrInvalidPartyCount    = errors.New("invalid party count")
	ErrInvalidProtocol      = errors.New("unsupported protocol")
	ErrInvalidKeyType       = errors.New("unsupported key type")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrSigningLimitExceeded = errors.New("daily signing limit exceeded")
	ErrInsufficientParties  = errors.New("insufficient parties for threshold")
	ErrKeygenInProgress     = errors.New("keygen already in progress")
	ErrProtocolMismatch     = errors.New("protocol mismatch for operation")
)

// DefaultKeyExpiry is the default key expiration (90 days)
const DefaultKeyExpiry = 90 * 24 * 60 * 60

// MaxThreshold is the maximum supported threshold
const MaxThreshold = 100

// MaxParties is the maximum number of parties
const MaxParties = 150
