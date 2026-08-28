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
	"slices"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
	"golang.org/x/crypto/sha3"
)

// keccak returns the Keccak-256 digest of s as a storage slot.
func keccak(s string) common.Hash {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(s))
	var out common.Hash
	copy(out[:], h.Sum(nil))
	return out
}

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

// Storage slots.
//
// The four configuration slots below are fixed constants chosen to be far from
// the low words a Solidity layout occupies. They are NOT digests of anything,
// despite once being commented as keccak256 of "dead.admin" and friends — none
// of them is. That comment was a hazard rather than a description: regenerating
// a slot from the string it claimed would silently move it, orphaning the value
// stored at the old address and leaving the reader an empty word. Their values
// are part of the storage layout, so they are pinned by TestStorageSlotsAre-
// PinnedAndDistinct and must not be recomputed.
var (
	AdminSlot    = common.HexToHash("0x8f4e7e7c9a5b3d1e2f6a4c8b0e9d7f3a2c5b8e1d4f7a0c3b6e9d2f5a8c1b4e7d")
	TreasurySlot = common.HexToHash("0x3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b")
	BurnBPSSlot  = common.HexToHash("0x7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e")
	EnabledSlot  = common.HexToHash("0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b")

	// BurnedSlot records how much of a dead address's balance has already been
	// through the split. Unlike the four above it holds no legacy state, so it
	// is derived the way a slot should be. It is read and written under the dead
	// address being credited, not under ZeroAddress: each address carries its
	// own balance and so its own progress.
	BurnedSlot = keccak("dead.burned")
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
	ErrInvalidInput    = contract.ErrInvalidInput
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

	// Otherwise, parse function selector. A call too short to carry one is
	// still a call, so it is charged; returning the supplied gas untouched
	// would make refused input free to repeat.
	if len(input) < 4 {
		if suppliedGas < GasBase {
			return nil, 0, ErrInsufficientGas
		}
		return nil, suppliedGas - GasBase, ErrInvalidInput
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

	// Only funds that have not already been through the split are eligible. The
	// burned share stays at the dead address forever, so the balance never
	// returns to zero and cannot itself mark progress; splitting the whole
	// balance on every call would re-split what was already burned and walk it
	// into the treasury a fraction at a time, one cheap call after another,
	// until the burn was undone. `burned` is that high-water mark.
	balance := stateDB.GetBalance(addr)
	burned := d.getBurnedInternal(stateDB, addr)
	if balance.Cmp(burned) <= 0 {
		return nil, remainingGas, nil
	}
	fresh := new(uint256.Int).Sub(balance, burned)

	if readOnly {
		// Decline without recording progress, so the split stays pending for a
		// writable call rather than being lost.
		return nil, remainingGas, nil
	}

	// Get configured treasury and burn ratio
	treasury := d.getTreasuryInternal(stateDB)
	burnBPS := d.getBurnRatioInternal(stateDB)

	burnAmount, treasuryAmount := CalculateSplitUint256(fresh, burnBPS)

	// The burn amount stays at the dead address (effectively burned).
	// Transfer treasury amount to the DAO treasury.
	if !treasuryAmount.IsZero() {
		stateDB.SubBalance(addr, treasuryAmount, tracing.BalanceChangeTransfer)
		stateDB.AddBalance(treasury, treasuryAmount, tracing.BalanceChangeTransfer)
	}
	d.setBurned(stateDB, addr, new(uint256.Int).Add(burned, burnAmount))

	return nil, remainingGas, nil
}

// getBurnedInternal reads the amount already burned at addr.
func (d *deadPrecompile) getBurnedInternal(stateDB contract.StateDB, addr common.Address) *uint256.Int {
	val := stateDB.GetState(addr, BurnedSlot)
	return new(uint256.Int).SetBytes(val[:])
}

// setBurned records the amount burned at addr.
func (d *deadPrecompile) setBurned(stateDB contract.StateDB, addr common.Address, v *uint256.Int) {
	stateDB.SetState(addr, BurnedSlot, common.BytesToHash(v.Bytes()))
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
	// An empty slot means no administrator has been provisioned, which is the
	// state of every chain at genesis. Admitting the caller here would hand the
	// first account to send a transaction control of the treasury address and
	// the burn ratio for all three dead addresses, so it refuses instead. An
	// administrator arrives through Configure, from the chain's genesis config;
	// it is provisioned, never claimed.
	if admin == ZeroAddress {
		return false
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
	return slices.Contains(AllDeadAddresses, addr)
}
