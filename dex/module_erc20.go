// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"fmt"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// module_erc20.go binds the erc20Vault capability (erc20_vault.go) to the EVM by
// sub-calling the token contract for transferFrom / transfer / balanceOf. This is
// the C-Chain token-movement leg of ERC-20 settlement — the analog of the EVM moving
// msg.value into 0x9999 for native LUX. The settle path type-asserts the StateDB for
// erc20Vault (stateDBERC20); poolStateAdapter satisfies it here, so the rail is live
// whenever the precompile execution environment exposes a Call surface (the
// callableEnv seam below).
//
// ─────────────────────────────────────────────────────────────────────────────
// THE ONE EXTERNAL WIRE (now landed):
//
// A precompile can only sub-call a contract through the EVM execution environment.
// The geth EVM environment (vm.PrecompileEnvironment) HAS a Call method, but the
// adapter chain that reaches the external DEX precompile USED TO narrow it away —
// accessibleStateBridge.GetPrecompileEnv() returned nil, so this seam got nil and an
// ERC-20 deposit/withdraw refused with ErrERC20VaultUnavailable (fail-secure: never
// minting an unbacked claim). The forwarding now lands in luxfi/evm, kept OFF the
// shared, many-implementer contract.PrecompileEnvironment interface (Call is an
// optional concrete capability this seam type-asserts, not an interface widening):
//
//	geth vm.PrecompileEnvironment{Call,...}                       <- has Call
//	  └─> evm/core accessibleStateAdapter.GetPrecompileEnv()      <- now EXPOSES the geth env
//	        └─> evm/registry accessibleStateBridge.GetPrecompileEnv()
//	              -> *precompileEnvBridge{ReadOnly(), Call(...)}   <- forwards Call
//	                    └─> luxfi/precompile contract.PrecompileEnvironment
//	                          + the optional Call this callableEnv asserts
//
// CALLER SEMANTICS (a money-path correctness edge): the sub-call is made with the
// precompile SELF (0x9999) as the token's msg.sender — NO caller proxying. A deposit
// pulls via transferFrom against the allowance the depositor granted the VAULT
// (approve(0x9999, amount)); a withdraw pushes via transfer from the vault's own
// balance. Proxying the original EOA caller would make the token check the wrong
// allowance/balance and break the pull — so the bridge forwards Call WITHOUT
// WithUNSAFECallerAddressProxying.
//
// The precompile-rail ERC-20 deposit/withdraw is COMPLETE and conserving (observed-
// delta credit, per-token vault ledger, vault-underflow guard, idempotency, custody
// reentrancy guard) and is proven end-to-end: the in-state-vault path by the existing
// suite, and the live Call seam by settle_erc20_callseam_test.go (deposit -> balanceOf
// -> withdraw against a token reached only via Call, asserting conservation). On a
// host that wires no Call surface (a non-EVM caller / harness) it still refuses
// cleanly. Native LUX custody is unaffected (it uses the StateDB balance directly).
// ─────────────────────────────────────────────────────────────────────────────

// callableEnv is the OPTIONAL Call surface this seam type-asserts on the precompile
// execution environment. It mirrors geth vm.PrecompileEnvironment.Call exactly so a
// concrete env that forwards Call satisfies it with no shared-interface change. The
// value is nil/value-less (custody moves no native value through these sub-calls);
// the token contract is the callee.
type callableEnv interface {
	Call(addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, gasLeft uint64, err error)
}

// erc20GasBudget caps the gas a single token sub-call may consume. ERC-20
// transfer/transferFrom/balanceOf on a well-behaved token are well under this; a
// token that needs more is treated as a failed transfer (fail-secure). The
// custody selector already debited GasSettlement from the precompile's budget; this
// is the inner sub-call allowance.
const erc20GasBudget uint64 = 100_000

// ERC-20 method selectors (keccak256(sig)[:4]).
var (
	selERC20BalanceOf    = crypto.Keccak256([]byte("balanceOf(address)"))[:4]
	selERC20Transfer     = crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
	selERC20TransferFrom = crypto.Keccak256([]byte("transferFrom(address,address,uint256)"))[:4]
)

// callable returns the EVM Call surface for token sub-calls, or nil if this
// execution environment does not expose one (see the wiring note above). When nil,
// the erc20Vault methods fail-secure: balance reads return 0 and transfers error,
// so the custody legs refuse rather than mint/strand.
func (a *poolStateAdapter) callable() callableEnv {
	if a.accessibleState == nil {
		return nil
	}
	env := a.accessibleState.GetPrecompileEnv()
	if env == nil {
		return nil
	}
	c, ok := env.(callableEnv)
	if !ok {
		return nil
	}
	return c
}

// TokenBalanceOf reads owner's balance of token via a balanceOf(address)
// sub-call. A reverted / malformed return yields 0 (fail-secure: an unreadable
// balance makes the observed delta non-positive, which refuses the deposit rather
// than crediting an unverified amount).
func (a *poolStateAdapter) TokenBalanceOf(token, owner common.Address) *big.Int {
	c := a.callable()
	if c == nil {
		return big.NewInt(0)
	}
	input := make([]byte, 0, 4+32)
	input = append(input, selERC20BalanceOf...)
	input = append(input, common.LeftPadBytes(owner.Bytes(), 32)...)
	ret, _, err := c.Call(token, input, erc20GasBudget, nil)
	if err != nil || len(ret) < 32 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(ret[:32])
}

// TransferTokenFrom pulls amount of token from `from` to `to` via a
// transferFrom(address,address,uint256) sub-call, using the allowance `from`
// granted to 0x9010 (the precompile self). OZ-safe: a revert OR a false bool
// return is a FAILED transfer (errors); a no-return-data success (non-compliant
// tokens that return nothing) is accepted, matching SafeERC20.
func (a *poolStateAdapter) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	c := a.callable()
	if c == nil {
		return ErrERC20VaultUnavailable
	}
	input := make([]byte, 0, 4+96)
	input = append(input, selERC20TransferFrom...)
	input = append(input, common.LeftPadBytes(from.Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(to.Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(amount.Bytes(), 32)...)
	ret, _, err := c.Call(token, input, erc20GasBudget, nil)
	return checkERC20Return(ret, err)
}

// TransferTokenTo pushes amount of token from the vault (0x9010, the precompile
// self) to `to` via a transfer(address,uint256) sub-call. Same OZ-safe semantics
// as TransferTokenFrom.
func (a *poolStateAdapter) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	c := a.callable()
	if c == nil {
		return ErrERC20VaultUnavailable
	}
	input := make([]byte, 0, 4+64)
	input = append(input, selERC20Transfer...)
	input = append(input, common.LeftPadBytes(to.Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(amount.Bytes(), 32)...)
	ret, _, err := c.Call(token, input, erc20GasBudget, nil)
	return checkERC20Return(ret, err)
}

// checkERC20Return applies OpenZeppelin SafeERC20 return semantics to a
// transfer/transferFrom result:
//   - a non-nil call error (revert) is a failed transfer;
//   - return data present and decoding to a single ABI bool that is false is a
//     failed transfer (tokens that signal failure via the bool);
//   - return data present and true, OR no return data at all (non-compliant tokens
//     that return nothing on success), is a success.
func checkERC20Return(ret []byte, callErr error) error {
	if callErr != nil {
		return fmt.Errorf("token call reverted: %w", callErr)
	}
	if len(ret) == 0 {
		// Non-compliant token returned no data; treat as success (SafeERC20 does).
		return nil
	}
	if len(ret) < 32 {
		return fmt.Errorf("token returned malformed data (%d bytes)", len(ret))
	}
	// ABI bool is right-aligned in a 32-byte word; nonzero => true.
	for _, b := range ret[:32] {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("token transfer returned false")
}

// Compile-time assertion: poolStateAdapter satisfies the erc20Vault capability the
// PoolManager type-asserts for ERC-20 custody.
var _ erc20Vault = (*poolStateAdapter)(nil)

// (kept here so a refactor of contract.AccessibleState that drops GetPrecompileEnv
// is caught at build time rather than silently disabling ERC-20 custody.)
var _ = func(s contract.AccessibleState) contract.PrecompileEnvironment { return s.GetPrecompileEnv() }
