// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle_custody.go is the 0x9999 vault's funds-in / funds-out / balance surface.
// It is SEPARATE from the deprecated 0x9010 ZAP-custody deposit/withdraw (which
// fund a D-Chain ledger via a live client). The 0x9999 vault is the receipt-
// settlement RESERVE: it holds the per-asset balances that back amountOut credits.
//
// THE CONSERVATION MODEL (no mint): every credit a settle performs comes out of
// the vault; the vault is funded by deposits and by the tokenIn legs of prior
// settlements. A settle that cannot be backed reverts (settle9999.go
// ErrSettleUnbacked). Liquidity providers / market-makers fund the vault's
// counterparty side; day-1 the operator seeds it. Withdraw lets a depositor pull
// their own balance back. balanceOf reads a depositor's claim.
//
// These funds-flow handlers move REAL EVM value (native via AddBalance/SubBalance
// on the 0x9999 self-address; ERC-20 via the erc20Vault observed-delta), keyed by
// the SAME injective AssetID the settle path uses, so deposits and settlements
// agree on what an asset is.

// depositorClaimPrefix keys a depositor's per-asset claim on the 0x9999 vault.
// This is the depositor's withdrawable balance (NOT the vault total — the vault
// total is settleVault[asset], which also reflects settlement tokenIn legs).
var depositorClaimPrefix = []byte(settleStateNamespace + "claim")

func depositorClaimKey(account common.Address, assetID [32]byte) common.Hash {
	id := make([]byte, 0, 20+32)
	id = append(id, account.Bytes()...)
	id = append(id, assetID[:]...)
	return makeStorageKey(depositorClaimPrefix, id)
}

func loadDepositorClaim(stateDB StateDB, account common.Address, assetID [32]byte) *big.Int {
	return new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, depositorClaimKey(account, assetID)).Bytes())
}

func storeDepositorClaim(stateDB StateDB, account common.Address, assetID [32]byte, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr9999, depositorClaimKey(account, assetID), w)
}

var (
	ErrSettleDepositShort = errors.New("dex: native deposit requires msg.value == amount")
	ErrSettleClaimShort   = errors.New("dex: withdraw exceeds depositor claim")
)

// runSettleDeposit funds the 0x9999 vault: deposit(address asset, uint256 amount).
// Native (asset == address(0)) requires the EVM to have moved msg.value == amount
// into 0x9999 (the precompile self), which the host call frame does; we VERIFY the
// self-balance covers it and record the claim + vault total. ERC-20 pulls via
// transferFrom (observed-delta). Halt-gated by haltAsset only (a global halt must
// not strand the ability to fund).
func (s *SettleContract) runSettleDeposit(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot deposit in read-only mode")
	}
	if gas < GasSettlement {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasSettlement
	if len(input) < 64 {
		return nil, gasLeft, errors.New("dex: deposit input too short")
	}
	asset := Currency{Address: common.BytesToAddress(input[12:32])}
	amount := new(big.Int).SetBytes(input[32:64])
	if amount.Sign() <= 0 || !isWord(amount) {
		return nil, gasLeft, ErrInvalidAmount
	}
	aid := assetID(asset)
	stateDB := newPoolStateAdapter(state)
	if isHalted(stateDB, makeStorageKey(haltAssetPrefix, aid[:])) {
		return nil, gasLeft, ErrAssetHalted
	}

	if isNativeAsset(aid) {
		amt, of := uint256.FromBig(amount)
		if of {
			return nil, gasLeft, ErrSettleAmountRange
		}
		// The EVM moved msg.value into 0x9999 before this precompile ran; the
		// self-balance must now cover the asserted amount (it would be short if the
		// call did not carry msg.value == amount). We do NOT re-credit; we record the
		// claim against what the vault already received.
		if stateDB.GetBalance(poolManagerAddr9999).Cmp(amt) < 0 {
			return nil, gasLeft, ErrSettleDepositShort
		}
	} else {
		vault, ok := stateDBERC20(stateDB)
		if !ok {
			return nil, gasLeft, ErrSettleERC20Vault
		}
		delta, err := safeTransferTokenFrom(vault, asset.Address, caller, poolManagerAddr9999, amount)
		if err != nil {
			return nil, gasLeft, err
		}
		// Observed-delta: credit what truly arrived (fee-on-transfer safe).
		amount = delta
	}
	// Record the depositor's claim and the vault total for this asset.
	storeDepositorClaim(stateDB, caller, aid, new(big.Int).Add(loadDepositorClaim(stateDB, caller, aid), amount))
	storeSettleVault(stateDB, aid, new(big.Int).Add(loadSettleVault(stateDB, aid), amount))

	out := make([]byte, 32)
	amount.FillBytes(out)
	return out, gasLeft, nil
}

// runSettleWithdraw pulls a depositor's claim back out of the 0x9999 vault:
// withdraw(address asset, uint256 want). Clamps to the depositor's claim AND the
// vault total (defense in depth). NOT gated by the global swap halt — a halt must
// never strand funds; withdraw always works. Returns the realized amount.
func (s *SettleContract) runSettleWithdraw(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot withdraw in read-only mode")
	}
	if gas < GasSettlement {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasSettlement
	if len(input) < 64 {
		return nil, gasLeft, errors.New("dex: withdraw input too short")
	}
	asset := Currency{Address: common.BytesToAddress(input[12:32])}
	want := new(big.Int).SetBytes(input[32:64])
	aid := assetID(asset)
	stateDB := newPoolStateAdapter(state)

	claim := loadDepositorClaim(stateDB, caller, aid)
	realized := new(big.Int).Set(want)
	if realized.Cmp(claim) > 0 {
		realized.Set(claim)
	}
	held := loadSettleVault(stateDB, aid)
	if realized.Cmp(held) > 0 {
		realized.Set(held) // invariant: claim <= held; defense in depth.
	}
	if realized.Sign() <= 0 {
		out := make([]byte, 32)
		return out, gasLeft, nil // nothing to withdraw
	}
	// Debit claim + vault total BEFORE the external value movement (CEI pattern).
	storeDepositorClaim(stateDB, caller, aid, new(big.Int).Sub(claim, realized))
	storeSettleVault(stateDB, aid, new(big.Int).Sub(held, realized))

	if isNativeAsset(aid) {
		amt, of := uint256.FromBig(realized)
		if of {
			return nil, gasLeft, ErrSettleAmountRange
		}
		stateDB.SubBalance(poolManagerAddr9999, amt)
		stateDB.AddBalance(caller, amt)
	} else {
		vault, ok := stateDBERC20(stateDB)
		if !ok {
			return nil, gasLeft, ErrSettleERC20Vault
		}
		if err := safeTransferTokenTo(vault, asset.Address, caller, realized); err != nil {
			return nil, gasLeft, err
		}
	}
	out := make([]byte, 32)
	realized.FillBytes(out)
	return out, gasLeft, nil
}

// runSettleBalanceOf reads a depositor's withdrawable claim: balanceOf(address
// account, address asset). Read-only, no mutation.
func (s *SettleContract) runSettleBalanceOf(
	state contract.AccessibleState, input []byte, gas uint64,
) ([]byte, uint64, error) {
	if gas < GasPoolLookup {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasPoolLookup
	if len(input) < 64 {
		return nil, gasLeft, errors.New("dex: balanceOf input too short")
	}
	account := common.BytesToAddress(input[12:32])
	asset := Currency{Address: common.BytesToAddress(input[44:64])}
	claim := loadDepositorClaim(newPoolStateAdapter(state), account, assetID(asset))
	out := make([]byte, 32)
	claim.FillBytes(out)
	return out, gasLeft, nil
}
