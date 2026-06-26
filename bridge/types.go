// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
)

// Supported chain IDs. The canonical numeric ids for the ecosystem and the
// external chains the bridge tracks. Virtual ids (>= 900_000) name non-EVM
// chains for bookkeeping only.
const (
	ChainLux       uint32 = 96369  // Lux mainnet C-Chain
	ChainLuxTest   uint32 = 96368  // Lux testnet
	ChainHanzo     uint32 = 36963  // Hanzo AI mainnet
	ChainHanzoTest uint32 = 36962  // Hanzo testnet
	ChainZoo       uint32 = 200200 // Zoo mainnet
	ChainZooTest   uint32 = 200201 // Zoo testnet
	ChainSPC       uint32 = 36911  // SPC mainnet
	ChainSPCTest   uint32 = 36910  // SPC testnet
	ChainEthereum  uint32 = 1      // Ethereum mainnet
	ChainArbitrum  uint32 = 42161  // Arbitrum One
	ChainOptimism  uint32 = 10     // Optimism
	ChainBase      uint32 = 8453   // Base
	ChainPolygon   uint32 = 137    // Polygon PoS
	ChainBSC       uint32 = 56     // BNB Smart Chain
	ChainAvalanche uint32 = 43114  // Avalanche C-Chain
	ChainPars      uint32 = 6133   // Pars Network mainnet
	ChainParsTest  uint32 = 6132   // Pars Network testnet

	// Non-EVM chains (virtual ids for bridge tracking).
	ChainSolana  uint32 = 900001 // Solana mainnet
	ChainBitcoin uint32 = 900002 // Bitcoin mainnet
	ChainXRP     uint32 = 900003 // XRP Ledger mainnet
	ChainTON     uint32 = 900004 // TON mainnet
)

// BridgeStatus is the on-state lifecycle of a bridge request. The numeric value
// IS the byte persisted in StateDB (request_state.go word 0, byte 0), so the
// enum and the storage layout are one and the same — there is no second mapping.
//
// StatusAbsent (0) is the implicit value of an unwritten slot: a request that
// was never recorded reads back as Absent, which ReadRequest reports as
// ErrRequestNotFound. Every recorded request is Pending until it reaches exactly
// one terminal state (Completed / Refunded / Expired / Failed).
type BridgeStatus uint8

const (
	StatusAbsent    BridgeStatus = 0 // slot never written (== not found)
	StatusPending   BridgeStatus = 1 // recorded, awaiting completion or refund
	StatusCompleted BridgeStatus = 2 // consumed by a quorum-verified completion (terminal)
	StatusRefunded  BridgeStatus = 3 // released after the deadline (terminal)
	StatusExpired   BridgeStatus = 4 // marked expired (terminal)
	StatusFailed    BridgeStatus = 5 // marked failed (terminal)
)

// BridgeRequest is a cross-chain transfer the gateway settles on this chain. It
// is the in-memory view of the StateDB-resident record (request_state.go); every
// field round-trips through storage so the completion digest recomputed at verify
// time is identical to the one the MPC committee attested at record time.
type BridgeRequest struct {
	ID            [32]byte       // unique request id (the StateDB key)
	Status        BridgeStatus   // on-state lifecycle status
	SourceNetwork uint32         // originating network id
	SourceChain   uint32         // originating chain id
	DestNetwork   uint32         // destination network id (this network)
	DestChain     uint32         // destination chain id (this chain)
	Nonce         uint64         // source replay nonce
	Deadline      uint64         // unix-seconds completion deadline (0 => none)
	Recipient     common.Address // destination recipient
	Token         common.Address // asset address (zero => native)
	Amount        *big.Int       // amount to deliver
	CreatedAt     uint64         // block time the request was recorded
	CompletedAt   uint64         // block time the request was resolved
}

// Signature schemes a committee member may use. The scheme byte is stored in the
// member descriptor (committee_state.go) and selects the per-member verifier.
const (
	SchemeSecp256k1 byte = 1 // geth-style ECDSA recover; keyID is the EVM address
	SchemeMLDSA65   byte = 2 // ML-DSA-65 (FIPS 204); pubkey blob stored in state
)

// CommitteeMember is one signer in the state-resident completion committee. For
// secp256k1, KeyID is the member's EVM address and PubKey is empty (the address
// is recovered from the signature). For ML-DSA-65, PubKey holds the 1952-byte
// public key (read from StateDB at verify time, NEVER from calldata) and KeyID
// is an opaque 20-byte fingerprint.
type CommitteeMember struct {
	Scheme byte
	Weight uint64
	KeyID  [20]byte
	PubKey []byte
}

// SignerSig is one member's attestation in a completion proof. Index selects the
// member from the on-state committee snapshot — the public key is read from
// STATE at that index, never supplied by the relayer. This makes a forged-key
// attack impossible: the relayer chooses only which committee members signed, and
// each signature is checked against the key the committee was seeded with.
type SignerSig struct {
	Index uint16
	Sig   []byte
}

// Bridge errors.
var (
	ErrRequestNotFound      = errors.New("bridge: request not found")
	ErrRequestExpired       = errors.New("bridge: request expired")
	ErrRequestAlreadyDone   = errors.New("bridge: request already resolved")
	ErrRequestNotExpired    = errors.New("bridge: request not yet expired")
	ErrRequestExists        = errors.New("bridge: request already recorded")
	ErrInvalidRequest       = errors.New("bridge: invalid request")
	ErrInvalidSignature     = errors.New("bridge: invalid completion signature")
	ErrSignatureThreshold   = errors.New("bridge: completion quorum not met")
	ErrCommitteeUnset       = errors.New("bridge: completion committee not set")
	ErrInvalidCommittee     = errors.New("bridge: invalid committee configuration")
	ErrInvalidScheme        = errors.New("bridge: unknown signature scheme")
	ErrDuplicateSignerIndex = errors.New("bridge: duplicate signer index")
	ErrSignerIndexRange     = errors.New("bridge: signer index out of committee range")
)
