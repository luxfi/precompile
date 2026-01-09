// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
)

// Precompile addresses for B-Chain bridge operations
const (
	// Bridge core operations
	BridgeGatewayAddress    = "0x0440" // Main bridge gateway
	BridgeRouterAddress     = "0x0441" // Cross-chain routing
	BridgeVerifierAddress   = "0x0442" // Message verification
	BridgeLiquidityAddress  = "0x0443" // Liquidity pools
	BridgeFeeManagerAddress = "0x0444" // Fee management
	BridgeSignerAddress     = "0x0445" // MPC signer interface

	// Gas costs
	GasBridgeInitiate    = uint64(100000) // Initiate bridge transfer
	GasBridgeComplete    = uint64(50000)  // Complete bridge on destination
	GasBridgeVerify      = uint64(25000)  // Verify bridge message
	GasBridgeGetStatus   = uint64(5000)   // Query bridge status
	GasBridgeAddLiq      = uint64(75000)  // Add liquidity
	GasBridgeRemoveLiq   = uint64(75000)  // Remove liquidity
	GasSignerGetPubKey   = uint64(10000)  // Get MPC public key
	GasSignerRequestSign = uint64(150000) // Request MPC signature
)

// Supported chain IDs
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
)

// BridgeRequest represents a cross-chain transfer request
type BridgeRequest struct {
	ID           [32]byte       // Unique request ID
	Sender       common.Address // Source chain sender
	Recipient    common.Address // Destination chain recipient
	Token        common.Address // Token address (address(0) for native)
	Amount       *big.Int       // Amount to bridge
	SourceChain  uint32         // Source chain ID
	DestChain    uint32         // Destination chain ID
	Nonce        uint64         // Sender nonce for replay protection
	Deadline     uint64         // Timestamp deadline
	Data         []byte         // Optional calldata for recipient
	Status       BridgeStatus   // Current status
	SourceTxHash common.Hash    // Source chain transaction hash
	DestTxHash   common.Hash    // Destination chain transaction hash
	Signatures   [][]byte       // MPC signatures
	CreatedAt    uint64         // Creation timestamp
	CompletedAt  uint64         // Completion timestamp
}

// BridgeStatus represents the status of a bridge request
type BridgeStatus uint8

const (
	StatusPending BridgeStatus = iota
	StatusSigning
	StatusSigned
	StatusRelaying
	StatusCompleted
	StatusFailed
	StatusExpired
	StatusRefunded
)

// BridgedToken represents a token that can be bridged
type BridgedToken struct {
	LocalAddress  common.Address            // Address on this chain
	RemoteAddress map[uint32]common.Address // Address on remote chains
	Decimals      uint8                     // Token decimals
	Symbol        string                    // Token symbol
	Name          string                    // Token name
	MinBridge     *big.Int                  // Minimum bridge amount
	MaxBridge     *big.Int                  // Maximum bridge amount (per tx)
	DailyLimit    *big.Int                  // Daily bridge limit
	BridgedToday  *big.Int                  // Amount bridged today
	LastReset     uint64                    // Last daily reset timestamp
	Enabled       bool                      // Whether bridging is enabled
}

// LiquidityPool represents a bridge liquidity pool
type LiquidityPool struct {
	Token     common.Address // Pool token
	ChainID   uint32         // Chain ID
	TotalLiq  *big.Int       // Total liquidity
	Available *big.Int       // Available liquidity (not in transit)
	Providers map[common.Address]*LPPosition
	FeeRate   uint32   // Fee in basis points (100 = 1%)
	TotalFees *big.Int // Total fees collected
}

// LPPosition represents a liquidity provider position
type LPPosition struct {
	Provider    common.Address
	Amount      *big.Int
	ShareRatio  *big.Int // Share of pool (scaled by 1e18)
	DepositTime uint64
	PendingFees *big.Int
}

// BridgeMessage is the message format for cross-chain communication
type BridgeMessage struct {
	Version     uint8          // Message version
	MessageType uint8          // Type of message
	SourceChain uint32         // Source chain ID
	DestChain   uint32         // Destination chain ID
	Nonce       uint64         // Message nonce
	Sender      common.Address // Original sender
	Recipient   common.Address // Destination recipient
	Token       common.Address // Token address
	Amount      *big.Int       // Amount
	Data        []byte         // Additional data
	Timestamp   uint64         // Message timestamp
}

// MessageType constants
const (
	MsgTypeTransfer   uint8 = 1 // Token transfer
	MsgTypeMint       uint8 = 2 // Mint wrapped token
	MsgTypeBurn       uint8 = 3 // Burn wrapped token
	MsgTypeUnlock     uint8 = 4 // Unlock native token
	MsgTypeLiquidity  uint8 = 5 // Liquidity operation
	MsgTypeGovernance uint8 = 6 // Governance message
	MsgTypeEmergency  uint8 = 7 // Emergency pause/unpause
)

// SignerInfo represents an MPC signer in the bridge set
type SignerInfo struct {
	NodeID     [20]byte       // Validator node ID
	Address    common.Address // EVM address
	PublicKey  []byte         // MPC public key share
	Bond       *big.Int       // Staked bond (min 100M LUX)
	JoinedAt   uint64         // When joined signer set
	LastActive uint64         // Last activity timestamp
	SignCount  uint64         // Total signatures produced
	SlashCount uint32         // Times slashed
	Status     SignerStatus
}

// SignerStatus represents MPC signer status
type SignerStatus uint8

const (
	SignerActive SignerStatus = iota
	SignerWaitlist
	SignerSlashed
	SignerExited
)

// SignerSet represents the current MPC signer set
type SignerSet struct {
	Signers     []*SignerInfo // Active signers (max 100)
	Waitlist    [][20]byte    // Waitlisted node IDs
	Threshold   uint32        // Required signatures (2/3 of signers)
	Epoch       uint64        // Current epoch
	PublicKey   []byte        // Combined threshold public key
	LastReshare uint64        // Last reshare timestamp
}

// BridgeFeeConfig represents fee configuration
type BridgeFeeConfig struct {
	BaseFee          *big.Int // Base fee per bridge
	PercentFee       uint32   // Fee percentage (basis points)
	MinFee           *big.Int // Minimum fee
	MaxFee           *big.Int // Maximum fee
	LiquidityFee     uint32   // Fee to liquidity providers (basis points)
	ProtocolFee      uint32   // Protocol fee (basis points)
	EmergencyPenalty uint32   // Emergency withdrawal penalty (basis points)
}

// Bridge errors
var (
	ErrBridgeDisabled        = errors.New("bridge is disabled")
	ErrTokenNotSupported     = errors.New("token not supported for bridging")
	ErrChainNotSupported     = errors.New("destination chain not supported")
	ErrAmountTooLow          = errors.New("amount below minimum")
	ErrAmountTooHigh         = errors.New("amount exceeds maximum")
	ErrDailyLimitExceeded    = errors.New("daily bridge limit exceeded")
	ErrInsufficientLiquidity = errors.New("insufficient bridge liquidity")
	ErrInvalidSignature      = errors.New("invalid bridge signature")
	ErrSignatureThreshold    = errors.New("signature threshold not met")
	ErrRequestNotFound       = errors.New("bridge request not found")
	ErrRequestExpired        = errors.New("bridge request expired")
	ErrRequestAlreadyDone    = errors.New("bridge request already completed")
	ErrInvalidMessage        = errors.New("invalid bridge message")
	ErrUnauthorizedSigner    = errors.New("unauthorized signer")
	ErrSignerNotFound        = errors.New("signer not found")
	ErrInsufficientBond      = errors.New("insufficient signer bond")
	ErrAlreadySigner         = errors.New("already in signer set")
	ErrSignerSetFull         = errors.New("signer set is full")
	ErrInvalidNonce          = errors.New("invalid nonce")
	ErrReplayAttack          = errors.New("replay attack detected")
)

// MinSignerBond is the minimum bond required to be a signer (100M LUX)
var MinSignerBond = new(big.Int).Mul(big.NewInt(100_000_000), big.NewInt(1e18))

// MaxSigners is the maximum number of active signers
const MaxSigners = 100
