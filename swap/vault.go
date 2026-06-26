// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
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
