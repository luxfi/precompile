// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
)

// Custody plumbing — the observed-delta ERC-20 + native idiom, mirrored from
// swap/vault.go (whose helpers are package-private to swap). This is the
// ESTABLISHED pattern: swap and dex each carry their own ~80-line custody mirror.
// NOTHING here is AMM math; every amount moved was computed by composing dex.* in
// contract.go. No path mints: every unit paid out was first observed inbound.

// erc20Vault is the OPTIONAL capability the host StateDB implements to move ERC-20
// value in and out of the precompile at v3Addr. Type-asserted off the StateDB so
// the core contract.StateDB interface stays unchanged; a StateDB that does not
// implement it refuses ERC-20 custody cleanly rather than faking a credit.
type erc20Vault interface {
	TokenBalanceOf(token, owner common.Address) *big.Int
	TransferTokenFrom(token, from, to common.Address, amount *big.Int) error
	TransferTokenTo(token, to common.Address, amount *big.Int) error
}

// pullExact pulls `amount` of `asset` from `from` into the vault and verifies the
// OBSERVED inbound balance delta equals `amount` exactly (OpenZeppelin SafeERC20
// style: measure balanceOf(to) after−before), so a fee-on-transfer / rebasing
// token that delivers a different amount is rejected rather than crediting a wrong
// amount. Returns the observed delta (== amount) for the caller to credit.
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

// pushOut pays exactly `amount` of `asset` from the vault to `to` (ERC-20 transfer).
func pushOut(vault erc20Vault, asset, to common.Address, amount *big.Int) error {
	if err := vault.TransferTokenTo(asset, to, amount); err != nil {
		return fmt.Errorf("%w: %v", ErrTransferFailed, err)
	}
	return nil
}

// pullExactNative is the native-LUX analog of pullExact: it measures the value the
// current call actually delivered (delivered = balanceOf(v3Addr) − reserveNative,
// the surplus over the accounted reserve — the EVM moved msg.value into v3Addr
// BEFORE Run) and REQUIRES it to equal `amount` exactly. A value==0, short, OR
// over-delivering call is rejected. It never mints: delivered is read from real
// balance, never from the request.
func pullExactNative(db contract.StateDB, reserveNative, amount *big.Int) error {
	delivered := new(big.Int).Sub(db.GetBalance(v3Addr).ToBig(), reserveNative)
	if delivered.Cmp(amount) != 0 {
		return fmt.Errorf("%w: requested %s, delivered %s", ErrDeltaMismatch, amount, delivered)
	}
	return nil
}

// pushOutNative pays exactly `amount` of native LUX from the vault to `to` via a
// real SubBalance/AddBalance pair (no mint, value-conserving). An explicit guard
// fails loud rather than wrapping v3Addr's modular native balance.
func pushOutNative(db contract.StateDB, to common.Address, amount *big.Int) error {
	amt, overflow := uint256.FromBig(amount)
	if overflow {
		return ErrTransferFailed
	}
	if db.GetBalance(v3Addr).Cmp(amt) < 0 {
		return ErrReserveUnderflow
	}
	db.SubBalance(v3Addr, amt, tracing.BalanceChangeUnspecified)
	db.AddBalance(to, amt, tracing.BalanceChangeUnspecified)
	return nil
}

// pullAsset moves `amount` of `asset` INTO the precompile from `from`, crediting
// the per-asset reserve by the OBSERVED inbound delta. Native (asset == 0) reads
// the delta from the real balance the EVM already moved in; an ERC-20 pulls via
// transferFrom. One function, both asset kinds — the mint/swap-in money path.
func pullAsset(db contract.StateDB, asset, from common.Address, amount *big.Int) error {
	if amount.Sign() == 0 {
		return nil
	}
	if asset == (common.Address{}) {
		if err := pullExactNative(db, loadReserve(db, asset), amount); err != nil {
			return err
		}
		addReserve(db, asset, amount)
		return nil
	}
	vault, ok := db.(erc20Vault)
	if !ok {
		return ErrVaultUnavailable
	}
	delta, err := pullExact(vault, asset, from, v3Addr, amount)
	if err != nil {
		return err
	}
	addReserve(db, asset, delta)
	return nil
}

// payAsset moves `amount` of `asset` OUT of the precompile to `to`, debiting the
// per-asset reserve FIRST (effects-before-interaction). subReserve refuses a
// pay-out that exceeds holdings (conservation breach). One function, both asset
// kinds — the burn-collect / swap-out money path.
func payAsset(db contract.StateDB, asset, to common.Address, amount *big.Int) error {
	if amount.Sign() == 0 {
		return nil
	}
	if !subReserve(db, asset, amount) {
		return ErrReserveUnderflow
	}
	if asset == (common.Address{}) {
		return pushOutNative(db, to, amount)
	}
	vault, ok := db.(erc20Vault)
	if !ok {
		return ErrVaultUnavailable
	}
	return pushOut(vault, asset, to, amount)
}
