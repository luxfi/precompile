// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
)

// erc20_vault.go GENERALIZES the native-LUX custody rail to real ERC-20 tokens by
// REUSING the SAME two primitives the native rail uses — the atomic vault
// lock/release and the ZAP relay — with ONE substitution: where native uses the
// EVM's native balance (GetBalance/AddBalance/SubBalance on 0x9010) to hold the
// locked asset, an ERC-20 uses the token contract's own balance (transferFrom INTO
// 0x9010, transfer OUT of 0x9010), measured by the OBSERVED balance delta.
//
// Everything else is shared with native verbatim: the (txHash, asset, amount)
// idempotency binding (custodyBindKey already folds asset.Address, so a native
// address(0) op and an ERC-20 op NEVER collide), the R3 zero-ref guard, the
// asset-generic clob_deposit/clob_withdraw frame (assetID maps the token address
// INJECTIVELY to its full 32-byte D-Chain id; native maps to the all-zero id —
// distinct assets never collide on the ledger key), and the mint guards in the
// ZAP engine. The net-new is ONLY the C-Chain token movement leg.
//
// THE SHARPEST CORRECTNESS EDGE — OBSERVED DELTA, NOT REQUESTED AMOUNT:
// a fee-on-transfer or rebasing token delivers LESS than `amount` into the vault.
// Crediting the requested `amount` to the D-Chain ledger while the vault received
// less would mint an UNBACKED claim and break conservation. So the deposit credits
// the OBSERVED delta (balanceOf(vault)_after − balanceOf(vault)_before), never the
// requested amount. This mirrors how OpenZeppelin's SafeERC20 callers measure the
// realized transfer for non-standard tokens. The withdraw releases exactly the
// realized D-Chain burn and refuses if the vault cannot back it (the ERC-20 analog
// of releaseNativeFromVault's vault-underflow guard).

// erc20Vault is the OPTIONAL capability a StateDB implements to move ERC-20 value
// in and out of the 0x9010 vault. It is the token analog of the native
// GetBalance/AddBalance/SubBalance methods the StateDB already exposes, kept as a
// SEPARATE capability (type-asserted, exactly like txIdentified and custodyEngine)
// so the core StateDB interface — and every existing mock/adapter that implements
// it — stays unchanged. A StateDB that does not implement erc20Vault refuses
// ERC-20 custody cleanly (ErrERC20VaultUnavailable), never faking a credit.
//
// SEMANTICS (each method is the safe, OZ-style boundary):
//   - TokenBalanceOf(token, owner): the owner's CURRENT balance of `token`, read
//     from the token contract. The deposit measures the vault's balance with this
//     before and after the pull to derive the OBSERVED delta.
//   - TransferTokenFrom(token, from, to, amount): pull `amount` of `token` from
//     `from` to `to`, using the allowance `from` granted (the ERC-20 transferFrom).
//     Returns an error on a reverted / false-returning transfer (OZ-safe: a token
//     that returns false or reverts is a FAILED transfer, never silently ignored).
//   - TransferTokenTo(token, to, amount): push `amount` of `token` from the vault
//     (0x9010, the precompile self) to `to` (the ERC-20 transfer). Same OZ-safe
//     failure semantics.
//
// PRODUCTION BINDING: these are EVM sub-calls into the token contract. The
// concrete binding lives in the host StateDB adapter (poolStateAdapter), forwarded
// to the EVM via the precompile execution environment. See poolStateAdapter and
// the build note there for the one external wire this seam needs.
type erc20Vault interface {
	TokenBalanceOf(token, owner common.Address) *big.Int
	TransferTokenFrom(token, from, to common.Address, amount *big.Int) error
	TransferTokenTo(token, to common.Address, amount *big.Int) error
}

// vaultLedgerPrefix keys the precompile's OWN per-token record of how much of each
// ERC-20 the 0x9010 vault holds against D-Chain claims. It lives in 0x9010's state
// (poolManagerAddr), NOT in the token contract's storage — the precompile NEVER
// pokes an ERC-20's balance slots (that path broke autoSettle and is forbidden).
// This ledger is the per-token conservation accumulator: vaultLedger[token] is the
// sum the vault locked via deposits minus what it released via withdraws, and the
// conservation invariant pins it to the real token balance of the vault.
var vaultLedgerPrefix = []byte("vlt2") // ERC-20 vault per-token holdings ledger

var (
	// ErrERC20VaultUnavailable is returned when an ERC-20 custody op is attempted
	// against a StateDB that does not implement the erc20Vault capability (e.g. a
	// non-EVM caller or a test double without token support). It refuses rather than
	// mint an unbacked D-Chain credit — the same fail-secure posture as the native
	// unfunded-deposit refusal.
	ErrERC20VaultUnavailable = errors.New("dex: ERC-20 vault capability unavailable on this StateDB")

	// ErrERC20TransferFailed is returned when the token's transferFrom/transfer
	// reverts or returns false (OZ-safe semantics). No D-Chain credit/burn is
	// recorded — the custody op aborts with nothing moved on either side.
	ErrERC20TransferFailed = errors.New("dex: ERC-20 transfer failed (reverted or returned false)")

	// ErrERC20ZeroDelta is returned when a deposit's transferFrom delivered nothing
	// to the vault (observed delta <= 0). Crediting zero is a no-op that would still
	// burn an idempotency binding for an empty deposit; refuse so the caller learns
	// the transfer did not fund the vault.
	ErrERC20ZeroDelta = errors.New("dex: ERC-20 deposit observed zero balance delta (transfer did not fund the vault)")
)

// safeTransferTokenFrom is the SINGLE, DRY transferFrom path both legs route
// through (OpenZeppelin SafeERC20.safeTransferFrom semantics). It pulls `amount`
// of `token` from `from` into the vault and returns the OBSERVED delta the vault
// actually received — measured as balanceOf(vault)_after − balanceOf(vault)_before
// — so a fee-on-transfer / rebasing token is credited for what truly arrived, not
// the requested amount. A reverted / false transfer surfaces as
// ErrERC20TransferFailed; a non-positive observed delta surfaces as
// ErrERC20ZeroDelta. This is the ONLY place the deposit leg moves a token in.
func safeTransferTokenFrom(vault erc20Vault, token, from, to common.Address, amount *big.Int) (*big.Int, error) {
	before := vault.TokenBalanceOf(token, to)
	if err := vault.TransferTokenFrom(token, from, to, amount); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrERC20TransferFailed, err)
	}
	after := vault.TokenBalanceOf(token, to)
	// OBSERVED delta — the realized credit, robust to fee-on-transfer/rebasing.
	delta := new(big.Int).Sub(after, before)
	if delta.Sign() <= 0 {
		return nil, ErrERC20ZeroDelta
	}
	return delta, nil
}

// safeTransferTokenTo is the SINGLE, DRY transfer-out path the withdraw leg routes
// through (OpenZeppelin SafeERC20.safeTransfer semantics). It pushes exactly
// `amount` of `token` from the vault to `to`. A reverted / false transfer surfaces
// as ErrERC20TransferFailed. The vault-underflow guard (vault holds < amount) is
// enforced by the caller BEFORE this is reached (releaseTokenFromVault), the ERC-20
// analog of releaseNativeFromVault's check, so a release can never drain another
// account's backing.
func safeTransferTokenTo(vault erc20Vault, token, to common.Address, amount *big.Int) error {
	if err := vault.TransferTokenTo(token, to, amount); err != nil {
		return fmt.Errorf("%w: %v", ErrERC20TransferFailed, err)
	}
	return nil
}

// loadVaultLedger reads the precompile's recorded ERC-20 vault holdings for a
// token (0 if none). This is 0x9010's OWN view of how much of the token it locked
// against D-Chain claims, used by the withdraw underflow guard and the per-token
// conservation invariant.
func loadVaultLedger(stateDB StateDB, token common.Address) *big.Int {
	v := stateDB.GetState(poolManagerAddr, makeStorageKey(vaultLedgerPrefix, token.Bytes()))
	return new(big.Int).SetBytes(v[:])
}

// storeVaultLedger writes the precompile's recorded ERC-20 vault holdings for a
// token. Holdings are a uint256 word; a deposit adds the observed delta, a withdraw
// subtracts the realized release.
func storeVaultLedger(stateDB StateDB, token common.Address, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr, makeStorageKey(vaultLedgerPrefix, token.Bytes()), w)
}

// lockTokenIntoVault is the C-Chain LOCK leg of an ERC-20 DEPOSIT — the token
// analog of lockNativeIntoVault. Where native relies on the EVM having pre-moved
// msg.value into 0x9010 and merely VERIFIES the vault holds it, an ERC-20 has no
// pre-transfer, so this leg performs the transferFrom (the caller granted 0x9010 an
// allowance) and MEASURES the observed delta the vault actually received. It then
// records that delta in the precompile's per-token vault ledger. Returns the
// OBSERVED delta — the amount the D-Chain ledger must be credited (never the
// requested amount, so fee-on-transfer tokens cannot mint an unbacked claim).
func (pm *PoolManager) lockTokenIntoVault(stateDB StateDB, vault erc20Vault, caller common.Address, token common.Address, amount *big.Int) (*big.Int, error) {
	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("%w: deposit amount must be positive", ErrInvalidAmount)
	}
	// Pull the token into the vault and measure what truly arrived (observed delta).
	delta, err := safeTransferTokenFrom(vault, token, caller, poolManagerAddr, amount)
	if err != nil {
		return nil, err
	}
	if !delta.IsUint64() {
		// The D-Chain ledger keys balances by uint64 units; an observed delta beyond
		// that range cannot be credited 1:1. Refuse rather than truncate (a truncated
		// credit would strand the untracked remainder in the vault).
		return nil, fmt.Errorf("%w: observed delta exceeds uint64 ledger range", ErrInvalidAmount)
	}
	// Record the locked holdings in the precompile's per-token ledger (0x9010's own
	// state — never the token's slots). available[*][token] + locked[*][token] on the
	// D-Chain now has this much real token backing in the vault.
	cur := loadVaultLedger(stateDB, token)
	storeVaultLedger(stateDB, token, new(big.Int).Add(cur, delta))
	return delta, nil
}

// releaseTokenFromVault is the C-Chain RELEASE leg of an ERC-20 WITHDRAW — the
// token analog of releaseNativeFromVault. It refuses to release more than the vault
// holds for the token (the underflow guard: under the conservation invariant the
// vault always holds >= the realized D-Chain burn, so this is defense in depth),
// debits the precompile's per-token vault ledger, then transfers exactly `amount`
// of the token from the vault to the recipient. This is the only direction the
// vault ever pays out a token, and only against a realized ledger burn.
func (pm *PoolManager) releaseTokenFromVault(stateDB StateDB, vault erc20Vault, recipient common.Address, token common.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return nil
	}
	held := loadVaultLedger(stateDB, token)
	if held.Cmp(amount) < 0 {
		// The vault cannot back this release. Under the invariant this is impossible;
		// refusing prevents paying out a token the vault does not hold for this asset.
		return fmt.Errorf("%w: vault holds %s of token < release %s (invariant breach)", ErrInsufficientBalance, held, amount)
	}
	// Debit the per-token ledger FIRST (state before external effect), then pay out.
	storeVaultLedger(stateDB, token, new(big.Int).Sub(held, amount))
	if err := safeTransferTokenTo(vault, token, recipient, amount); err != nil {
		return err
	}
	return nil
}
