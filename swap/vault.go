// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
)

// erc20Vault is the OPTIONAL capability the host StateDB implements to move ERC-20
// value in and out of the HTLC at swapAddr. It is the exact seam dex/erc20_vault.go
// uses, type-asserted off the StateDB so the core contract.StateDB interface (and
// every mock/adapter that implements it) stays unchanged. A StateDB that does not
// implement it refuses ERC-20 custody cleanly (ErrVaultUnavailable) — it never
// fakes a credit, never mints.
//
//   - TokenBalanceOf(token, owner): the owner's current balance of token.
//   - TransferTokenFrom(token, from, to, amount): pull amount of token from `from`
//     to `to` using the allowance `from` granted (ERC-20 transferFrom). Returns an
//     error on a reverted / false-returning transfer (OZ-safe).
//   - TransferTokenTo(token, to, amount): push amount of token from swapAddr (the
//     precompile self) to `to` (ERC-20 transfer). Same OZ-safe failure semantics.
type erc20Vault interface {
	TokenBalanceOf(token, owner common.Address) *big.Int
	TransferTokenFrom(token, from, to common.Address, amount *big.Int) error
	TransferTokenTo(token, to common.Address, amount *big.Int) error
}

// pullExact pulls `amount` of `asset` from `from` into the vault and verifies the
// OBSERVED inbound balance delta equals `amount` exactly. It measures
// balanceOf(vault)_after − balanceOf(vault)_before (OpenZeppelin SafeERC20 style),
// so a fee-on-transfer / rebasing token that delivers a different amount is
// rejected (ErrDeltaMismatch) rather than locking a wrong amount. Returns the
// observed delta (== amount) for the caller to credit to the reserve.
func pullExact(vault erc20Vault, asset, from, to common.Address, amount *big.Int) (*big.Int, error) {
	before := vault.TokenBalanceOf(asset, to)
	if err := vault.TransferTokenFrom(asset, from, to, amount); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransferFailed, err)
	}
	after := vault.TokenBalanceOf(asset, to)
	delta := new(big.Int).Sub(after, before)
	if delta.Cmp(amount) != 0 {
		return nil, fmt.Errorf("%w: requested %s, observed %s", ErrDeltaMismatch, amount, delta)
	}
	return delta, nil
}

// pushOut pays exactly `amount` of `asset` from the vault to `to`. A reverted /
// false transfer surfaces as ErrTransferFailed; the caller has already debited the
// reserve (effects-before-interaction), so on error the EVM reverts the frame.
func pushOut(vault erc20Vault, asset, to common.Address, amount *big.Int) error {
	if err := vault.TransferTokenTo(asset, to, amount); err != nil {
		return fmt.Errorf("%w: %v", ErrTransferFailed, err)
	}
	return nil
}

// pullExactNative is the native-LUX analog of pullExact: it measures the value the
// current call actually delivered and REQUIRES it to equal `amount` exactly. The
// EVM moved msg.value into swapAddr BEFORE Run (geth Transfer precedes precompile
// execution), and every native-moving path keeps reserve[native] in lock-step with
// the vault's real native balance, so
//
//	delivered = balanceOf(swapAddr) − reserveNative
//
// is exactly the value this call carried — the surplus over the accounted reserve.
// A value==0, short, OR over-delivering call yields delivered != amount and is
// rejected (ErrDeltaMismatch), the same exact-delta safety pullExact gives ERC-20.
// It never mints: delivered is read from real balance, never from the request.
func pullExactNative(db contract.StateDB, reserveNative, amount *big.Int) error {
	delivered := new(big.Int).Sub(db.GetBalance(swapAddr).ToBig(), reserveNative)
	if delivered.Cmp(amount) != 0 {
		return fmt.Errorf("%w: requested %s, delivered %s", ErrDeltaMismatch, amount, delivered)
	}
	return nil
}

// pushOutNative pays exactly `amount` of native LUX from the vault to `to` via a
// real SubBalance/AddBalance pair (no mint, value-conserving). SubBalance is
// uint256-modular and does NOT revert on underflow from a precompile, so an
// explicit guard fails loud (ErrReserveUnderflow) rather than wrapping swapAddr's
// native balance — the caller already debited reserve[native] (CEI), so on error
// the EVM reverts the whole frame.
func pushOutNative(db contract.StateDB, to common.Address, amount *big.Int) error {
	amt, overflow := uint256.FromBig(amount)
	if overflow {
		return ErrTransferFailed
	}
	if db.GetBalance(swapAddr).Cmp(amt) < 0 {
		return ErrReserveUnderflow
	}
	db.SubBalance(swapAddr, amt, tracing.BalanceChangeUnspecified)
	db.AddBalance(to, amt, tracing.BalanceChangeUnspecified)
	return nil
}

// payOut is the single pay-out dispatcher used by BOTH claim and refund: native
// (asset == address(0)) settles via Sub/Add on the EVM balance ledger; an ERC-20
// asset settles via the erc20Vault capability (refused cleanly if absent). One
// function, one place — claim and refund stay identical across both asset kinds.
func payOut(db contract.StateDB, asset, to common.Address, amount *big.Int) error {
	if asset == (common.Address{}) {
		return pushOutNative(db, to, amount)
	}
	vault, ok := db.(erc20Vault)
	if !ok {
		return ErrVaultUnavailable
	}
	return pushOut(vault, asset, to, amount)
}
