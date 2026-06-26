// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package swap is the Lux DEX cross-chain HTLC atomic-swap settlement precompile
// at LP-90A0 (0x...90A0). It implements a genuine hash time-locked contract: an
// asset locked under a SHA-256 hashlock h moves ONLY to the recipient fixed at
// lock time (on revealing a preimage s with SHA256(s)=h) or back to the refund
// address fixed at lock time (after the timeout). There is no owner, no pause, no
// freeze, no upgrade, and no set-balance selector — non-custody (G1) and
// strand-resistance (G4) are STRUCTURAL, not policy. No code path mints: every
// unit paid out was locked by its owner — an ERC-20 via a real transferFrom, or
// native LUX via the msg.value the EVM moved into swapAddr before Run — whose
// OBSERVED inbound delta backs the per-asset reserve ledger (Invariant: reserve).
// Native is a first-class asset (asset == address(0)): its inbound delta is read
// from the real balance (balanceOf(swapAddr) − reserve[native]) and its pay-out is
// a real SubBalance/AddBalance pair, exactly symmetric to the ERC-20 path.
//
// Hashlock is SHA-256 (matching Bitcoin OP_SHA256 and the EVM 0x02 precompile),
// NOT keccak — a single 32-byte preimage unlocks both legs of a cross-chain swap.
// The keccak commit–reveal in dex/hooks.go is a separate same-chain primitive and
// is not reused here.
//
// This precompile reuses the proven-safe transferFrom-delta custody idiom from
// dex/erc20_vault.go (observe balanceOf delta, never trust the requested amount)
// and the standard contract.StatefulPrecompiledContract Run selector dispatch.
package swap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var _ contract.StatefulPrecompiledContract = (*SwapContract)(nil)

// LXSwapAddress is LP-90A0 "LXSwap": the on-Lux HTLC atomic-swap settlement
// precompile, the next free DEX-page address after LP-9090 (LXSettlement).
const LXSwapAddress = "0x00000000000000000000000000000000000090A0"

// swapAddr is the precompile's own address; all persistent state and all locked
// token balances live under it.
var swapAddr = common.HexToAddress(LXSwapAddress)

// methodSelector derives the 4-byte selector (BigEndian uint32 of keccak256(sig)[:4])
// from a canonical ABI signature. The signature string is the SINGLE source of
// truth — no transcribed magic numbers can drift from it.
func methodSelector(sig string) uint32 {
	return binary.BigEndian.Uint32(crypto.Keccak256([]byte(sig))[:contract.SelectorLen])
}

// 4-byte selectors. The trailing hex is the authoritative value (asserted in the
// test suite) but is derived, never hand-entered.
var (
	selLock        = methodSelector("lock(bytes32,address,address,address,uint256,uint64)") // 0x4da2c728
	selClaim       = methodSelector("claim(bytes32,bytes32)")                               // 0x84cc9dfb
	selRefund      = methodSelector("refund(bytes32)")                                      // 0x7249fbb6
	selGetSwap     = methodSelector("getSwap(bytes32)")                                     // 0x3da0e66e
	selGetPreimage = methodSelector("getPreimage(bytes32)")                                 // 0x0f622b04
)

// Status of a swap slot. None means "no swap at this id".
const (
	StatusNone     uint8 = 0
	StatusLocked   uint8 = 1
	StatusClaimed  uint8 = 2
	StatusRefunded uint8 = 3
)

// Gas costs per operation. lock performs a token transferFrom sub-call plus
// several cold SSTOREs; claim/refund a transfer sub-call plus SSTOREs; the views
// are read-only.
const (
	GasLock        uint64 = 60000
	GasClaim       uint64 = 50000
	GasRefund      uint64 = 40000
	GasGetSwap     uint64 = 5000
	GasGetPreimage uint64 = 3000
)

// preimageLen is the fixed preimage size: exactly 32 bytes, for Bitcoin witness
// compatibility (a bytes32 on the EVM legs, a 32-byte push on the BTC leg).
const preimageLen = 32

// Absolute sanity bounds on the timeout, measured from the block timestamp T0.
// These are coarse guards; the relative ordering T_B > T_A + Δ that guarantees
// atomicity is chosen off-chain by the parties and enforced by each party's own
// pre-lock verification (see the design doc, §timeout ordering). All three are
// vars so a chain may tune them via config without forking the ABI.
var (
	// MinSwapAmount is the per-lock dust floor: a lock below it is rejected so the
	// claim/refund gas can never exceed the output (fee-griefing guard). The global
	// default is the minimal sane floor (strictly positive); per-asset tuning is a
	// future configuration concern.
	MinSwapAmount = big.NewInt(1)

	// MinTimeout / MaxTimeout bound (timeout - T0): at least 10 minutes (so a real
	// counterparty has time to act), at most 30 days (so capital is never locked
	// unboundedly).
	MinTimeout uint64 = 600
	MaxTimeout uint64 = 30 * 24 * 60 * 60
)

var (
	ErrReadOnly        = errors.New("swap: cannot modify state in read-only (static) call")
	ErrReentrant       = errors.New("swap: reentrant call rejected")
	ErrShortInput      = errors.New("swap: input shorter than 4-byte selector")
	ErrBadArgs         = errors.New("swap: malformed call arguments")
	ErrUnknownSelector = errors.New("swap: unknown function selector")
	ErrNoBlockContext  = errors.New("swap: block context unavailable")
	ErrOutOfGas        = errors.New("swap: out of gas")

	ErrZeroHashlock      = errors.New("swap: hashlock must be non-zero")
	ErrZeroRecipient     = errors.New("swap: recipient must be non-zero")
	ErrZeroRefund        = errors.New("swap: refund address must be non-zero")
	ErrDustAmount        = errors.New("swap: amount below MinSwapAmount")
	ErrTimeoutBounds     = errors.New("swap: timeout outside [T0+MinTimeout, T0+MaxTimeout]")
	ErrSwapExists        = errors.New("swap: swapId already in use")

	ErrNotLocked        = errors.New("swap: swap is not in the Locked state")
	ErrExpired          = errors.New("swap: timeout passed; claim window closed (refund instead)")
	ErrNotExpired       = errors.New("swap: timeout not yet reached; cannot refund")
	ErrBadPreimage      = errors.New("swap: SHA256(preimage) != hashlock or preimage length != 32")
	ErrReserveUnderflow = errors.New("swap: reserve underflow (conservation invariant breach)")

	ErrVaultUnavailable = errors.New("swap: ERC-20 vault capability unavailable on this StateDB")
	ErrTransferFailed   = errors.New("swap: ERC-20 transfer reverted or returned false")
	ErrDeltaMismatch    = errors.New("swap: observed inbound balance delta != requested amount")
)

// SwapContract is the LP-90A0 HTLC precompile. It holds NO mutable Go state; every
// swap field lives in the EVM trie under swapAddr (see state.go). The zero value is
// ready to use.
type SwapContract struct{}

// Run dispatches by 4-byte selector. Views (getSwap, getPreimage) are permitted in
// read-only calls; the three state transitions (lock, claim, refund) are not, and
// each runs under a global non-reentrant guard so the transferFrom-delta
// measurement and the status flip cannot be corrupted by a malicious token's
// callback (ERC-777-style tokensReceived/tokensToSend).
func (c *SwapContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < contract.SelectorLen {
		return nil, suppliedGas, ErrShortInput
	}
	if accessibleState.GetBlockContext() == nil {
		return nil, suppliedGas, ErrNoBlockContext
	}

	selector := binary.BigEndian.Uint32(input[:contract.SelectorLen])
	data := input[contract.SelectorLen:]

	switch selector {
	case selGetSwap:
		return c.runGetSwap(accessibleState, data, suppliedGas)
	case selGetPreimage:
		return c.runGetPreimage(accessibleState, data, suppliedGas)
	case selLock, selClaim, selRefund:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		db := accessibleState.GetStateDB()
		if !enterGuard(db) {
			return nil, suppliedGas, ErrReentrant
		}
		defer exitGuard(db)
		switch selector {
		case selLock:
			return c.runLock(accessibleState, caller, data, suppliedGas)
		case selClaim:
			return c.runClaim(accessibleState, caller, data, suppliedGas)
		default: // selRefund
			return c.runRefund(accessibleState, caller, data, suppliedGas)
		}
	default:
		return nil, suppliedGas, fmt.Errorf("%w: %#08x", ErrUnknownSelector, selector)
	}
}

// ---------------------------------------------------------------------------
// lock(bytes32 hashlock, address recipient, address refund, address asset,
//      uint256 amount, uint64 timeout) -> bytes32 swapId
// ---------------------------------------------------------------------------

func (c *SwapContract) runLock(
	st contract.AccessibleState,
	caller common.Address,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasLock {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasLock

	// 6 static ABI words.
	if len(data) != 6*32 {
		return nil, gas, fmt.Errorf("%w: lock expects 192 bytes, got %d", ErrBadArgs, len(data))
	}
	var hashlock common.Hash
	copy(hashlock[:], data[0:32])
	recipient := wordAddress(data[32:64])
	refund := wordAddress(data[64:96])
	asset := wordAddress(data[96:128])
	amount := new(big.Int).SetBytes(data[128:160])
	timeout, ok := wordUint64(data[160:192])
	if !ok {
		return nil, gas, fmt.Errorf("%w: timeout exceeds uint64", ErrBadArgs)
	}

	// (2) non-zero hashlock, recipient, refund.
	if hashlock == (common.Hash{}) {
		return nil, gas, ErrZeroHashlock
	}
	if recipient == (common.Address{}) {
		return nil, gas, ErrZeroRecipient
	}
	if refund == (common.Address{}) {
		return nil, gas, ErrZeroRefund
	}
	// (3) dust guard.
	if amount.Cmp(MinSwapAmount) < 0 {
		return nil, gas, ErrDustAmount
	}
	// (4) absolute timeout bounds.
	t0 := st.GetBlockContext().Timestamp()
	if timeout < t0+MinTimeout || timeout > t0+MaxTimeout {
		return nil, gas, fmt.Errorf("%w: T0=%d timeout=%d", ErrTimeoutBounds, t0, timeout)
	}

	db := st.GetStateDB()

	// swapId binds every term plus caller and the monotonic nonce, so identical
	// terms locked twice yield distinct ids and cross-caller collisions are
	// impossible.
	nonce := loadNonce(db)
	swapId := computeSwapID(hashlock, recipient, refund, asset, amount, timeout, caller, nonce)

	// (6, first half) no collision.
	if loadStatus(db, swapId) != StatusNone {
		return nil, gas, ErrSwapExists
	}

	// (5) Move funds IN via the OBSERVED-delta idiom and REQUIRE the inbound delta
	// to equal the requested amount exactly: an HTLC must lock the precise agreed
	// amount the counterparty verified, so a fee-on-transfer / short-delivering
	// token — or a native call carrying the wrong value — is rejected rather than
	// silently locking less. Native (asset == 0) measures the value the EVM already
	// moved into swapAddr (delta = balanceOf − reserve); an ERC-20 pulls via
	// transferFrom. Both yield `delta`, the amount actually delivered.
	var delta *big.Int
	if asset == (common.Address{}) {
		if err := pullExactNative(db, loadReserve(db, asset), amount); err != nil {
			return nil, gas, err
		}
		delta = amount
	} else {
		vault, ok := db.(erc20Vault)
		if !ok {
			return nil, gas, ErrVaultUnavailable
		}
		d, err := pullExact(vault, asset, caller, swapAddr, amount)
		if err != nil {
			return nil, gas, err
		}
		delta = d
	}

	// (6, second half) persist the swap, bump the per-asset reserve by the OBSERVED
	// delta, advance the nonce, emit Locked.
	storeStatus(db, swapId, StatusLocked)
	storeHash(db, swapId, fHashlock, hashlock)
	storeAddress(db, swapId, fRecipient, recipient)
	storeAddress(db, swapId, fRefund, refund)
	storeAddress(db, swapId, fAsset, asset)
	storeAmount(db, swapId, fAmount, amount)
	storeTimeout(db, swapId, timeout)

	addReserve(db, asset, delta)
	storeNonce(db, nonce+1)

	emitLocked(db, swapId, hashlock, recipient, refund, asset, amount, timeout)

	return swapId[:], gas, nil
}

// ---------------------------------------------------------------------------
// claim(bytes32 swapId, bytes32 preimage) -> bool
// ---------------------------------------------------------------------------

func (c *SwapContract) runClaim(
	st contract.AccessibleState,
	caller common.Address,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasClaim {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasClaim

	if len(data) != 2*32 {
		return nil, gas, fmt.Errorf("%w: claim expects 64 bytes, got %d", ErrBadArgs, len(data))
	}
	var swapId common.Hash
	copy(swapId[:], data[0:32])
	var preimage [preimageLen]byte
	copy(preimage[:], data[32:64])

	db := st.GetStateDB()

	// (1) must be Locked.
	if loadStatus(db, swapId) != StatusLocked {
		return nil, gas, ErrNotLocked
	}
	hashlock := loadHash(db, swapId, fHashlock)
	recipient := loadAddress(db, swapId, fRecipient)
	asset := loadAddress(db, swapId, fAsset)
	amount := loadAmount(db, swapId, fAmount)
	timeout := loadTimeout(db, swapId)

	// (2) not expired: claim requires T0 < timeout (disjoint from refund).
	if st.GetBlockContext().Timestamp() >= timeout {
		return nil, gas, ErrExpired
	}
	// (3) SHA256(preimage) == hashlock (preimage length is fixed by the bytes32 arg).
	if !preimageMatches(preimage, hashlock) {
		return nil, gas, ErrBadPreimage
	}

	// EFFECTS BEFORE INTERACTION: flip status, debit the reserve, publish the
	// secret — all before the external pay-out, so a malicious token's callback
	// re-entering claim/refund on this swap sees a non-Locked status and is
	// rejected (no double-spend). The global guard already blocks reentry; this
	// ordering is defence in depth.
	if !subReserve(db, asset, amount) {
		return nil, gas, ErrReserveUnderflow
	}
	storeStatus(db, swapId, StatusClaimed)
	storeHash(db, swapId, fPreimage, common.BytesToHash(preimage[:]))
	storePreimageIdx(db, hashlock, preimage)
	emitClaimed(db, swapId, hashlock, preimage, recipient, amount)

	// INTERACTION: pay the STORED recipient (caller-agnostic — a watchtower may
	// submit) via the single asset-kind-agnostic pay-out dispatcher. On failure the
	// precompile returns an error and the EVM reverts the whole frame, including
	// every effect above.
	if err := payOut(db, asset, recipient, amount); err != nil {
		return nil, gas, err
	}

	return boolWord(true), gas, nil
}

// ---------------------------------------------------------------------------
// refund(bytes32 swapId) -> bool
// ---------------------------------------------------------------------------

func (c *SwapContract) runRefund(
	st contract.AccessibleState,
	caller common.Address,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasRefund {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasRefund

	if len(data) != 32 {
		return nil, gas, fmt.Errorf("%w: refund expects 32 bytes, got %d", ErrBadArgs, len(data))
	}
	var swapId common.Hash
	copy(swapId[:], data[0:32])

	db := st.GetStateDB()

	// (1) must be Locked.
	if loadStatus(db, swapId) != StatusLocked {
		return nil, gas, ErrNotLocked
	}
	refund := loadAddress(db, swapId, fRefund)
	asset := loadAddress(db, swapId, fAsset)
	amount := loadAmount(db, swapId, fAmount)
	timeout := loadTimeout(db, swapId)

	// (2) expired: refund requires T0 >= timeout (disjoint from claim).
	if st.GetBlockContext().Timestamp() < timeout {
		return nil, gas, ErrNotExpired
	}

	// EFFECTS BEFORE INTERACTION (see runClaim).
	if !subReserve(db, asset, amount) {
		return nil, gas, ErrReserveUnderflow
	}
	storeStatus(db, swapId, StatusRefunded)
	emitRefunded(db, swapId, refund, amount)

	// INTERACTION: pay the STORED refund address via the single pay-out dispatcher.
	if err := payOut(db, asset, refund, amount); err != nil {
		return nil, gas, err
	}

	return boolWord(true), gas, nil
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

// runGetSwap returns the ABI-encoded swap tuple:
//
//	(uint8 status, bytes32 hashlock, address recipient, address refund,
//	 address asset, uint256 amount, uint64 timeout, bytes32 preimage)
//
// as 8 left-padded 32-byte words. A None swap returns an all-zero tuple.
func (c *SwapContract) runGetSwap(
	st contract.AccessibleState,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasGetSwap {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasGetSwap
	if len(data) != 32 {
		return nil, gas, fmt.Errorf("%w: getSwap expects 32 bytes, got %d", ErrBadArgs, len(data))
	}
	var swapId common.Hash
	copy(swapId[:], data[0:32])
	db := st.GetStateDB()

	out := make([]byte, 0, 8*32)
	out = append(out, uint8Word(loadStatus(db, swapId))...)
	out = append(out, loadHash(db, swapId, fHashlock).Bytes()...)
	out = append(out, addressWord(loadAddress(db, swapId, fRecipient))...)
	out = append(out, addressWord(loadAddress(db, swapId, fRefund))...)
	out = append(out, addressWord(loadAddress(db, swapId, fAsset))...)
	out = append(out, common.BigToHash(loadAmount(db, swapId, fAmount)).Bytes()...)
	out = append(out, uint64Word(loadTimeout(db, swapId))...)
	out = append(out, loadHash(db, swapId, fPreimage).Bytes()...)
	return out, gas, nil
}

// runGetPreimage returns the revealed preimage for a hashlock (the cross-leg
// secret relay), or bytes32(0) if no swap with that hashlock has been claimed.
func (c *SwapContract) runGetPreimage(
	st contract.AccessibleState,
	data []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasGetPreimage {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasGetPreimage
	if len(data) != 32 {
		return nil, gas, fmt.Errorf("%w: getPreimage expects 32 bytes, got %d", ErrBadArgs, len(data))
	}
	var hashlock common.Hash
	copy(hashlock[:], data[0:32])
	pre := loadPreimageIdx(st.GetStateDB(), hashlock)
	return pre[:], gas, nil
}
