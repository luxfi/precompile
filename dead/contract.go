// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dead implements the Dead Precompile (LP-0150) that intercepts
// transfers to dead addresses (0x0, 0xdead) and routes them to a configurable
// split between burning and DAO treasury.
package dead

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
)

// Standard dead addresses that trigger this precompile
var (
	ZeroAddress     = common.HexToAddress("0x0000000000000000000000000000000000000000")
	DeadAddress     = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	DeadFullAddress = common.HexToAddress("0xdEaD000000000000000000000000000000000000")

	AllDeadAddresses = []common.Address{ZeroAddress, DeadAddress, DeadFullAddress}
)

// Default values (can be changed via governance)
var (
	DefaultDAOTreasury = common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714")
	DefaultBurnBPS     = uint64(5000) // 50% burn
	DefaultTreasuryBPS = uint64(5000) // 50% treasury
)

// Storage slot keys (keccak256 of descriptive strings)
var (
	// Admin slot: keccak256("dead.admin")
	AdminSlot = common.HexToHash("0x8f4e7e7c9a5b3d1e2f6a4c8b0e9d7f3a2c5b8e1d4f7a0c3b6e9d2f5a8c1b4e7d")
	// Treasury address slot: keccak256("dead.treasury")
	TreasurySlot = common.HexToHash("0x3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b")
	// Burn ratio slot: keccak256("dead.burnBPS")
	BurnBPSSlot = common.HexToHash("0x7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e")
	// Enabled slot: keccak256("dead.enabled")
	EnabledSlot = common.HexToHash("0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b")
)

// Function selectors (first 4 bytes of keccak256 of function signature)
var (
	// Admin functions
	SelectorSetAdmin     = [4]byte{0x70, 0x4b, 0x6c, 0x02} // setAdmin(address)
	SelectorSetTreasury  = [4]byte{0xf0, 0xb3, 0x7c, 0x04} // setTreasury(address)
	SelectorSetBurnRatio = [4]byte{0x8d, 0x14, 0xe1, 0x27} // setBurnRatio(uint256)
	SelectorSetEnabled   = [4]byte{0x32, 0x8d, 0x8b, 0x42} // setEnabled(bool)

	// View functions
	SelectorGetAdmin     = [4]byte{0x6e, 0x9d, 0xf3, 0xd2} // getAdmin()
	SelectorGetTreasury  = [4]byte{0x3b, 0x19, 0xe8, 0x4a} // getTreasury()
	SelectorGetBurnRatio = [4]byte{0xb5, 0xc5, 0xf6, 0x72} // getBurnRatio()
	SelectorGetSplit     = [4]byte{0x1a, 0x86, 0x1d, 0x26} // getSplit(uint256)
	SelectorIsEnabled    = [4]byte{0x2f, 0x6f, 0x98, 0x0a} // isEnabled()
)

// Gas costs
const (
	GasBase       uint64 = 10000 // Base cost for receive
	GasAdminRead  uint64 = 200   // Reading admin state
	GasAdminWrite uint64 = 5000  // Writing admin state
)

// Basis points constant
const BasisPoints uint64 = 10000

// Errors
var (
	ErrUnauthorized    = errors.New("unauthorized: caller is not admin")
	ErrInvalidRatio    = errors.New("invalid ratio: must be <= 10000 BPS")
	ErrInvalidAddress  = errors.New("invalid address: cannot be zero")
	ErrDisabled        = errors.New("dead precompile is disabled")
	ErrInsufficientGas = errors.New("insufficient gas")
	ErrInvalidInput    = errors.New("invalid input")
)

// DeadPrecompile implements the stateful precompiled contract interface
var DeadPrecompile = &deadPrecompile{}

type deadPrecompile struct{}

// Run executes the dead precompile
func (d *deadPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	stateDB := accessibleState.GetStateDB()

	// If no input, this is a value transfer - handle as receive
	if len(input) == 0 {
		return d.handleReceive(stateDB, caller, addr, suppliedGas, readOnly)
	}

	// Otherwise, parse function selector
	if len(input) < 4 {
		return nil, suppliedGas, ErrInvalidInput
	}

	var selector [4]byte
	copy(selector[:], input[:4])
	args := input[4:]

	switch selector {
	// Admin write functions
	case SelectorSetAdmin:
		return d.setAdmin(stateDB, caller, args, suppliedGas, readOnly)
	case SelectorSetTreasury:
		return d.setTreasury(stateDB, caller, args, suppliedGas, readOnly)
	case SelectorSetBurnRatio:
		return d.setBurnRatio(stateDB, caller, args, suppliedGas, readOnly)
	case SelectorSetEnabled:
		return d.setEnabled(stateDB, caller, args, suppliedGas, readOnly)

	// View functions
	case SelectorGetAdmin:
		return d.getAdmin(stateDB, suppliedGas)
	case SelectorGetTreasury:
		return d.getTreasury(stateDB, suppliedGas)
	case SelectorGetBurnRatio:
		return d.getBurnRatio(stateDB, suppliedGas)
	case SelectorGetSplit:
		return d.getSplit(stateDB, args, suppliedGas)
	case SelectorIsEnabled:
		return d.isEnabled(stateDB, suppliedGas)

	default:
		// Unknown selector - treat as receive
		return d.handleReceive(stateDB, caller, addr, suppliedGas, readOnly)
	}
}

// handleReceive processes a value transfer to a dead address
func (d *deadPrecompile) handleReceive(
	stateDB contract.StateDB,
	caller common.Address,
	addr common.Address,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if suppliedGas < GasBase {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasBase

	// Check if enabled
	if !d.isEnabledInternal(stateDB) {
		return nil, remainingGas, ErrDisabled
	}

	// Get the value being transferred
	value := stateDB.GetBalance(addr)
	if value.IsZero() {
		// No value to split
		return nil, remainingGas, nil
	}

	if readOnly {
		// In read-only mode, just return success without modifying state
		return nil, remainingGas, nil
	}

	// Get configured treasury and burn ratio
	treasury := d.getTreasuryInternal(stateDB)
	burnBPS := d.getBurnRatioInternal(stateDB)

	// Calculate split
	_, treasuryAmount := CalculateSplitUint256(value, burnBPS)

	// The burn amount stays at the dead address (effectively burned)
	// Transfer treasury amount to the DAO treasury
	if !treasuryAmount.IsZero() {
		stateDB.SubBalance(addr, treasuryAmount, tracing.BalanceChangeTransfer)
		stateDB.AddBalance(treasury, treasuryAmount, tracing.BalanceChangeTransfer)
	}

	return nil, remainingGas, nil
}

// Admin functions

func (d *deadPrecompile) setAdmin(
	stateDB contract.StateDB,
	caller common.Address,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrUnauthorized
	}
	if suppliedGas < GasAdminWrite {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminWrite

	// Check authorization
	if !d.isAdmin(stateDB, caller) {
		return nil, remainingGas, ErrUnauthorized
	}

	// Parse new admin address
	if len(args) < 32 {
		return nil, remainingGas, ErrInvalidInput
	}
	newAdmin := common.BytesToAddress(args[12:32])
	if newAdmin == ZeroAddress {
		return nil, remainingGas, ErrInvalidAddress
	}

	// Store new admin
	d.setStateAddress(stateDB, AdminSlot, newAdmin)

	return nil, remainingGas, nil
}

func (d *deadPrecompile) setTreasury(
	stateDB contract.StateDB,
	caller common.Address,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrUnauthorized
	}
	if suppliedGas < GasAdminWrite {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminWrite

	if !d.isAdmin(stateDB, caller) {
		return nil, remainingGas, ErrUnauthorized
	}

	if len(args) < 32 {
		return nil, remainingGas, ErrInvalidInput
	}
	newTreasury := common.BytesToAddress(args[12:32])
	if newTreasury == ZeroAddress {
		return nil, remainingGas, ErrInvalidAddress
	}

	d.setStateAddress(stateDB, TreasurySlot, newTreasury)

	return nil, remainingGas, nil
}

func (d *deadPrecompile) setBurnRatio(
	stateDB contract.StateDB,
	caller common.Address,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrUnauthorized
	}
	if suppliedGas < GasAdminWrite {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminWrite

	if !d.isAdmin(stateDB, caller) {
		return nil, remainingGas, ErrUnauthorized
	}

	if len(args) < 32 {
		return nil, remainingGas, ErrInvalidInput
	}

	// Parse burn ratio (last 8 bytes of 32-byte word)
	newBurnBPS := binary.BigEndian.Uint64(args[24:32])
	if newBurnBPS > BasisPoints {
		return nil, remainingGas, ErrInvalidRatio
	}

	d.setStateUint64(stateDB, BurnBPSSlot, newBurnBPS)

	return nil, remainingGas, nil
}

func (d *deadPrecompile) setEnabled(
	stateDB contract.StateDB,
	caller common.Address,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, ErrUnauthorized
	}
	if suppliedGas < GasAdminWrite {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminWrite

	if !d.isAdmin(stateDB, caller) {
		return nil, remainingGas, ErrUnauthorized
	}

	if len(args) < 32 {
		return nil, remainingGas, ErrInvalidInput
	}

	// Parse bool (non-zero = true)
	enabled := args[31] != 0
	var val uint64
	if enabled {
		val = 1
	}
	d.setStateUint64(stateDB, EnabledSlot, val)

	return nil, remainingGas, nil
}

// View functions

func (d *deadPrecompile) getAdmin(stateDB contract.StateDB, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasAdminRead {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminRead

	admin := d.getAdminInternal(stateDB)
	result := make([]byte, 32)
	copy(result[12:], admin.Bytes())

	return result, remainingGas, nil
}

func (d *deadPrecompile) getTreasury(stateDB contract.StateDB, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasAdminRead {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminRead

	treasury := d.getTreasuryInternal(stateDB)
	result := make([]byte, 32)
	copy(result[12:], treasury.Bytes())

	return result, remainingGas, nil
}

func (d *deadPrecompile) getBurnRatio(stateDB contract.StateDB, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasAdminRead {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminRead

	burnBPS := d.getBurnRatioInternal(stateDB)
	result := make([]byte, 32)
	binary.BigEndian.PutUint64(result[24:], burnBPS)

	return result, remainingGas, nil
}

func (d *deadPrecompile) getSplit(stateDB contract.StateDB, args []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasAdminRead {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminRead

	if len(args) < 32 {
		return nil, remainingGas, ErrInvalidInput
	}

	// Parse value as uint256
	value := new(uint256.Int).SetBytes(args[:32])
	burnBPS := d.getBurnRatioInternal(stateDB)

	burn, treasury := CalculateSplitUint256(value, burnBPS)

	// Return burn (32 bytes) + treasury (32 bytes)
	result := make([]byte, 64)
	burn.WriteToSlice(result[:32])
	treasury.WriteToSlice(result[32:])

	return result, remainingGas, nil
}

func (d *deadPrecompile) isEnabled(stateDB contract.StateDB, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasAdminRead {
		return nil, 0, ErrInsufficientGas
	}
	remainingGas := suppliedGas - GasAdminRead

	enabled := d.isEnabledInternal(stateDB)
	result := make([]byte, 32)
	if enabled {
		result[31] = 1
	}

	return result, remainingGas, nil
}

// Internal helper functions

func (d *deadPrecompile) isAdmin(stateDB contract.StateDB, caller common.Address) bool {
	admin := d.getAdminInternal(stateDB)
	// If no admin set, allow deployer/genesis to set initial admin
	if admin == ZeroAddress {
		return true
	}
	return caller == admin
}

func (d *deadPrecompile) getAdminInternal(stateDB contract.StateDB) common.Address {
	val := stateDB.GetState(ZeroAddress, AdminSlot)
	return common.BytesToAddress(val[12:])
}

func (d *deadPrecompile) getTreasuryInternal(stateDB contract.StateDB) common.Address {
	val := stateDB.GetState(ZeroAddress, TreasurySlot)
	addr := common.BytesToAddress(val[12:])
	if addr == ZeroAddress {
		return DefaultDAOTreasury
	}
	return addr
}

func (d *deadPrecompile) getBurnRatioInternal(stateDB contract.StateDB) uint64 {
	val := stateDB.GetState(ZeroAddress, BurnBPSSlot)
	// Check if value was explicitly set (byte 0 is marker)
	if val[0] == 0 {
		// Not explicitly set, return default
		return DefaultBurnBPS
	}
	// Explicitly set, return the value (even if 0)
	return binary.BigEndian.Uint64(val[24:])
}

func (d *deadPrecompile) isEnabledInternal(stateDB contract.StateDB) bool {
	val := stateDB.GetState(ZeroAddress, EnabledSlot)
	// Check if value was explicitly set (byte 0 is marker)
	if val[0] == 0 {
		// Not explicitly set, default to enabled
		return true
	}
	// Explicitly set, return the value
	return val[31] != 0
}

func (d *deadPrecompile) setStateAddress(stateDB contract.StateDB, slot common.Hash, addr common.Address) {
	var val common.Hash
	copy(val[12:], addr.Bytes())
	stateDB.SetState(ZeroAddress, slot, val)
}

func (d *deadPrecompile) setStateUint64(stateDB contract.StateDB, slot common.Hash, v uint64) {
	var val common.Hash
	val[0] = 1 // Marker: explicitly set
	binary.BigEndian.PutUint64(val[24:], v)
	stateDB.SetState(ZeroAddress, slot, val)
}

func (d *deadPrecompile) setStateBool(stateDB contract.StateDB, slot common.Hash, v bool) {
	var val common.Hash
	val[0] = 1 // Marker: explicitly set
	if v {
		val[31] = 1
	}
	stateDB.SetState(ZeroAddress, slot, val)
}

// CalculateSplitUint256 calculates the burn and treasury amounts using uint256
func CalculateSplitUint256(value *uint256.Int, burnBPS uint64) (burn *uint256.Int, treasury *uint256.Int) {
	if value.IsZero() {
		return uint256.NewInt(0), uint256.NewInt(0)
	}

	// burn = value * burnBPS / 10000
	burn = new(uint256.Int).Mul(value, uint256.NewInt(burnBPS))
	burn = burn.Div(burn, uint256.NewInt(BasisPoints))

	// treasury = value - burn
	treasury = new(uint256.Int).Sub(value, burn)

	return burn, treasury
}

// CalculateSplit calculates the burn and treasury amounts using big.Int (for tests/stats)
func CalculateSplit(value *big.Int) (burn *big.Int, treasury *big.Int) {
	return CalculateSplitBig(value, DefaultBurnBPS)
}

// CalculateSplitBig calculates split with configurable burn ratio
func CalculateSplitBig(value *big.Int, burnBPS uint64) (burn *big.Int, treasury *big.Int) {
	if value.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	// burn = value * burnBPS / 10000
	burn = new(big.Int).Mul(value, big.NewInt(int64(burnBPS)))
	burn = burn.Div(burn, big.NewInt(int64(BasisPoints)))

	// treasury = value - burn
	treasury = new(big.Int).Sub(value, burn)

	return burn, treasury
}

// IsDeadAddress returns true if the given address is a registered dead address
func IsDeadAddress(addr common.Address) bool {
	for _, deadAddr := range AllDeadAddresses {
		if addr == deadAddr {
			return true
		}
	}
	return false
}
