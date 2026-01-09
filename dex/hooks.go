// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/zeebo/blake3"
)

// HookRegistry manages hook contract registrations and validations
type HookRegistry struct {
	// registeredHooks maps hook addresses to their capabilities
	registeredHooks map[common.Address]HookFlags
}

// NewHookRegistry creates a new hook registry
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		registeredHooks: make(map[common.Address]HookFlags),
	}
}

// HookPermissions contains the flags derived from a hook address
// Following Uniswap v4 pattern where hook address encodes capabilities
type HookPermissions struct {
	BeforeInitialize      bool
	AfterInitialize       bool
	BeforeAddLiquidity    bool
	AfterAddLiquidity     bool
	BeforeRemoveLiquidity bool
	AfterRemoveLiquidity  bool
	BeforeSwap            bool
	AfterSwap             bool
	BeforeDonate          bool
	AfterDonate           bool
	BeforeFlash           bool
	AfterFlash            bool
}

// HookCallResult contains the result of a hook call
type HookCallResult struct {
	Success     bool
	ReturnData  []byte
	GasUsed     uint64
	DeltaChange *BalanceDelta // Optional delta modification by hook
}

// Hook function signatures (4-byte selectors)
var (
	SigBeforeInitialize      = []byte{0x01, 0x00, 0x00, 0x01}
	SigAfterInitialize       = []byte{0x01, 0x00, 0x00, 0x02}
	SigBeforeAddLiquidity    = []byte{0x02, 0x00, 0x00, 0x01}
	SigAfterAddLiquidity     = []byte{0x02, 0x00, 0x00, 0x02}
	SigBeforeRemoveLiquidity = []byte{0x02, 0x00, 0x00, 0x03}
	SigAfterRemoveLiquidity  = []byte{0x02, 0x00, 0x00, 0x04}
	SigBeforeSwap            = []byte{0x03, 0x00, 0x00, 0x01}
	SigAfterSwap             = []byte{0x03, 0x00, 0x00, 0x02}
	SigBeforeDonate          = []byte{0x04, 0x00, 0x00, 0x01}
	SigAfterDonate           = []byte{0x04, 0x00, 0x00, 0x02}
	SigBeforeFlash           = []byte{0x05, 0x00, 0x00, 0x01}
	SigAfterFlash            = []byte{0x05, 0x00, 0x00, 0x02}
)

// Hook errors
var (
	ErrHookNotRegistered     = errors.New("hook not registered")
	ErrHookCallFailed        = errors.New("hook call failed")
	ErrHookInvalidAddress    = errors.New("hook address doesn't match capabilities")
	ErrHookDeltaOverflow     = errors.New("hook delta modification overflow")
	ErrHookUnauthorizedDelta = errors.New("hook not authorized to modify delta")
)

// ValidateHookAddress validates that a hook address encodes the claimed permissions
// Following Uniswap v4, the leading bits of the address encode hook capabilities
func ValidateHookAddress(addr common.Address, permissions HookPermissions) error {
	encoded := EncodeHookPermissions(permissions)

	// Check that the address prefix matches the permissions
	// First 2 bytes of address should match permission flags
	addrFlags := binary.BigEndian.Uint16(addr[0:2])

	if addrFlags != uint16(encoded) {
		return ErrHookInvalidAddress
	}

	return nil
}

// EncodeHookPermissions encodes permissions into a HookFlags bitmap
func EncodeHookPermissions(p HookPermissions) HookFlags {
	var flags HookFlags

	if p.BeforeInitialize {
		flags |= HookBeforeInitialize
	}
	if p.AfterInitialize {
		flags |= HookAfterInitialize
	}
	if p.BeforeAddLiquidity {
		flags |= HookBeforeAddLiquidity
	}
	if p.AfterAddLiquidity {
		flags |= HookAfterAddLiquidity
	}
	if p.BeforeRemoveLiquidity {
		flags |= HookBeforeRemoveLiquidity
	}
	if p.AfterRemoveLiquidity {
		flags |= HookAfterRemoveLiquidity
	}
	if p.BeforeSwap {
		flags |= HookBeforeSwap
	}
	if p.AfterSwap {
		flags |= HookAfterSwap
	}
	if p.BeforeDonate {
		flags |= HookBeforeDonate
	}
	if p.AfterDonate {
		flags |= HookAfterDonate
	}
	if p.BeforeFlash {
		flags |= HookBeforeFlash
	}
	if p.AfterFlash {
		flags |= HookAfterFlash
	}

	return flags
}

// DecodeHookPermissions decodes a HookFlags bitmap into permissions
func DecodeHookPermissions(flags HookFlags) HookPermissions {
	return HookPermissions{
		BeforeInitialize:      flags&HookBeforeInitialize != 0,
		AfterInitialize:       flags&HookAfterInitialize != 0,
		BeforeAddLiquidity:    flags&HookBeforeAddLiquidity != 0,
		AfterAddLiquidity:     flags&HookAfterAddLiquidity != 0,
		BeforeRemoveLiquidity: flags&HookBeforeRemoveLiquidity != 0,
		AfterRemoveLiquidity:  flags&HookAfterRemoveLiquidity != 0,
		BeforeSwap:            flags&HookBeforeSwap != 0,
		AfterSwap:             flags&HookAfterSwap != 0,
		BeforeDonate:          flags&HookBeforeDonate != 0,
		AfterDonate:           flags&HookAfterDonate != 0,
		BeforeFlash:           flags&HookBeforeFlash != 0,
		AfterFlash:            flags&HookAfterFlash != 0,
	}
}

// GetHookPermissionsFromAddress extracts permissions from hook address
func GetHookPermissionsFromAddress(addr common.Address) HookPermissions {
	flags := HookFlags(binary.BigEndian.Uint16(addr[0:2]))
	return DecodeHookPermissions(flags)
}

// HasPermission checks if an address has a specific hook permission
func HasPermission(addr common.Address, flag HookFlags) bool {
	addrFlags := HookFlags(binary.BigEndian.Uint16(addr[0:2]))
	return addrFlags&flag != 0
}

// RegisterHook registers a hook contract with its capabilities
func (hr *HookRegistry) RegisterHook(addr common.Address, flags HookFlags) error {
	// Validate address matches flags
	addrFlags := HookFlags(binary.BigEndian.Uint16(addr[0:2]))
	if addrFlags != flags {
		return ErrHookInvalidAddress
	}

	hr.registeredHooks[addr] = flags
	return nil
}

// GetHookFlags returns the flags for a registered hook
func (hr *HookRegistry) GetHookFlags(addr common.Address) (HookFlags, bool) {
	flags, ok := hr.registeredHooks[addr]
	return flags, ok
}

// IsHookEnabled checks if a specific hook type is enabled for an address
func (hr *HookRegistry) IsHookEnabled(addr common.Address, flag HookFlags) bool {
	flags, ok := hr.registeredHooks[addr]
	if !ok {
		// If not registered, derive from address
		flags = HookFlags(binary.BigEndian.Uint16(addr[0:2]))
	}
	return flags&flag != 0
}

// =========================================================================
// Hook Data Structures for Common Hook Patterns
// =========================================================================

// DynamicFeeHookData contains data for dynamic fee hooks
type DynamicFeeHookData struct {
	BaseFee       uint24 // Base fee in basis points
	VolatilityFee uint24 // Additional fee based on volatility
	TimeDecay     uint64 // Fee decay over time
	LastUpdate    uint64 // Timestamp of last update
}

// TWAPHookData contains data for TWAP oracle hooks
type TWAPHookData struct {
	CumulativePrice0 *big.Int // Cumulative price0 * time
	CumulativePrice1 *big.Int // Cumulative price1 * time
	LastBlockTime    uint64   // Last block timestamp
	LastTick         int24    // Last tick value
	Observations     []TWAPObservation
}

// TWAPObservation is a single TWAP data point
type TWAPObservation struct {
	Timestamp           uint64
	TickCumulative      *big.Int
	SecondsPerLiquidity *big.Int
	Initialized         bool
}

// LimitOrderHookData contains data for limit order hooks
type LimitOrderHookData struct {
	Orders         map[[32]byte]*LimitOrder
	OrdersByTick   map[int24][][32]byte
	ExecutedOrders [][32]byte
}

// LimitOrder represents a limit order in the hook
type LimitOrder struct {
	ID         [32]byte
	Owner      common.Address
	ZeroForOne bool     // Direction
	Tick       int24    // Price tick
	Amount     *big.Int // Amount to swap
	Filled     *big.Int // Amount filled
	Status     LimitOrderStatus
	CreatedAt  uint64
}

// LimitOrderStatus represents the status of a limit order
type LimitOrderStatus uint8

const (
	LimitOrderPending LimitOrderStatus = iota
	LimitOrderPartialFilled
	LimitOrderFilled
	LimitOrderCancelled
)

// MEVProtectionHookData contains data for MEV protection hooks
type MEVProtectionHookData struct {
	CommittedSwaps   map[[32]byte]*CommittedSwap
	RevealedSwaps    map[[32]byte]*RevealedSwap
	CommitmentPeriod uint64 // Blocks to wait before reveal
	MaxSlippage      uint64 // Max allowed slippage (basis points)
}

// CommittedSwap is a committed (hidden) swap
type CommittedSwap struct {
	CommitHash  [32]byte
	Sender      common.Address
	CommitBlock uint64
	Amount      *big.Int // Encrypted or hidden
}

// RevealedSwap is a revealed swap after commitment period
type RevealedSwap struct {
	CommitHash  [32]byte
	Sender      common.Address
	ZeroForOne  bool
	Amount      *big.Int
	MinOutput   *big.Int
	RevealBlock uint64
}

// =========================================================================
// Hook Implementation Helpers
// =========================================================================

// GenerateHookAddress generates a valid hook address for given permissions
// Uses CREATE2-style address derivation
func GenerateHookAddress(deployer common.Address, salt [32]byte, permissions HookPermissions) common.Address {
	flags := EncodeHookPermissions(permissions)

	h := blake3.New()
	h.Write([]byte{0xff}) // CREATE2 prefix
	h.Write(deployer.Bytes())
	h.Write(salt[:])

	// Derive address
	var hash [32]byte
	h.Digest().Read(hash[:])

	// Set permission flags in first 2 bytes
	var addr common.Address
	copy(addr[:], hash[12:32])
	binary.BigEndian.PutUint16(addr[0:2], uint16(flags))

	return addr
}

// PackBeforeSwapParams packs parameters for beforeSwap hook call
func PackBeforeSwapParams(sender common.Address, key PoolKey, params SwapParams, hookData []byte) []byte {
	// Simplified packing - real implementation would use ABI encoding
	data := make([]byte, 0, 256)
	data = append(data, SigBeforeSwap...)
	data = append(data, sender.Bytes()...)
	data = append(data, key.ToBytes()...)

	// Pack swap params
	if params.ZeroForOne {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	amountBytes := make([]byte, 32)
	params.AmountSpecified.FillBytes(amountBytes)
	data = append(data, amountBytes...)

	priceLimitBytes := make([]byte, 32)
	params.SqrtPriceLimitX96.FillBytes(priceLimitBytes)
	data = append(data, priceLimitBytes...)

	data = append(data, hookData...)

	return data
}

// PackAfterSwapParams packs parameters for afterSwap hook call
func PackAfterSwapParams(sender common.Address, key PoolKey, params SwapParams, delta BalanceDelta, hookData []byte) []byte {
	data := make([]byte, 0, 320)
	data = append(data, SigAfterSwap...)
	data = append(data, sender.Bytes()...)
	data = append(data, key.ToBytes()...)

	// Pack swap params
	if params.ZeroForOne {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	amountBytes := make([]byte, 32)
	params.AmountSpecified.FillBytes(amountBytes)
	data = append(data, amountBytes...)

	// Pack delta
	delta0Bytes := make([]byte, 32)
	delta.Amount0.FillBytes(delta0Bytes)
	data = append(data, delta0Bytes...)

	delta1Bytes := make([]byte, 32)
	delta.Amount1.FillBytes(delta1Bytes)
	data = append(data, delta1Bytes...)

	data = append(data, hookData...)

	return data
}

// UnpackHookDeltaReturn unpacks a hook's delta return value
// Hooks can optionally return a modified delta
func UnpackHookDeltaReturn(data []byte) (*BalanceDelta, error) {
	if len(data) < 64 {
		return nil, nil // No delta modification
	}

	amount0 := new(big.Int).SetBytes(data[0:32])
	amount1 := new(big.Int).SetBytes(data[32:64])

	delta := NewBalanceDelta(amount0, amount1)
	return &delta, nil
}

// =========================================================================
// Common Hook Implementations (as examples)
// =========================================================================

// VolatilityFeeCalculator calculates dynamic fees based on volatility
type VolatilityFeeCalculator struct {
	BaseFee         uint24
	MaxFee          uint24
	VolatilityScale uint64
	WindowSize      uint64 // Observation window in seconds
}

// CalculateFee calculates the dynamic fee based on recent price movement
func (vfc *VolatilityFeeCalculator) CalculateFee(observations []TWAPObservation) uint24 {
	if len(observations) < 2 {
		return vfc.BaseFee
	}

	// Calculate price volatility from observations
	// Simplified - real implementation would use proper volatility calculation
	lastObs := observations[len(observations)-1]
	prevObs := observations[len(observations)-2]

	timeDelta := lastObs.Timestamp - prevObs.Timestamp
	if timeDelta == 0 {
		return vfc.BaseFee
	}

	tickDelta := new(big.Int).Sub(lastObs.TickCumulative, prevObs.TickCumulative)
	avgTick := new(big.Int).Div(tickDelta, big.NewInt(int64(timeDelta)))

	// Convert tick movement to volatility fee
	volatilityBps := new(big.Int).Abs(avgTick)
	volatilityBps.Mul(volatilityBps, big.NewInt(int64(vfc.VolatilityScale)))
	volatilityBps.Div(volatilityBps, big.NewInt(10000))

	fee := vfc.BaseFee + uint24(volatilityBps.Uint64())
	if fee > vfc.MaxFee {
		fee = vfc.MaxFee
	}

	return fee
}

// CommitRevealValidator validates commit-reveal MEV protection
type CommitRevealValidator struct {
	CommitmentPeriod uint64
}

// ValidateCommitment checks if a commitment is valid
func (crv *CommitRevealValidator) ValidateCommitment(commit *CommittedSwap, currentBlock uint64) error {
	if currentBlock < commit.CommitBlock+crv.CommitmentPeriod {
		return errors.New("commitment period not elapsed")
	}
	return nil
}

// ValidateReveal checks if a reveal matches its commitment
func (crv *CommitRevealValidator) ValidateReveal(commit *CommittedSwap, reveal *RevealedSwap) error {
	// Verify hash
	h := blake3.New()
	h.Write(reveal.Sender.Bytes())
	if reveal.ZeroForOne {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	amountBytes := make([]byte, 32)
	reveal.Amount.FillBytes(amountBytes)
	h.Write(amountBytes)

	minOutputBytes := make([]byte, 32)
	reveal.MinOutput.FillBytes(minOutputBytes)
	h.Write(minOutputBytes)

	var computedHash [32]byte
	h.Digest().Read(computedHash[:])

	if computedHash != commit.CommitHash {
		return errors.New("reveal does not match commitment")
	}

	return nil
}
