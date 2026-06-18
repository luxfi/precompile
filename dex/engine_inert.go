// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/geth/common"
)

// inertEngine is the package-default Engine. It performs NO matching and holds
// NO state: every operation returns ErrDEXBackendNotConfigured so that a chain
// which deploys the LP-9010 precompile but has not wired a real backend reverts
// cleanly instead of silently running a wrong matcher.
//
// Why this is the default (decomplect, doc line 20): the V4 PoolManager facade
// is a CENTRAL LIMIT ORDER BOOK, not an AMM. The previous default — an embedded
// Uniswap-V4 concentrated-liquidity AMM — was both the WRONG engine and a
// SECOND matcher living on the EVM side, duplicating the d-chain's authority.
// There is exactly ONE matcher in the tree (the d-chain, reached over ZAP);
// the EVM precompile holds zero canonical DEX state. Until the venue installs
// the ZAP backend (SetBackend(NewZAPEngine(...)) when dex-zap-endpoint is set),
// 0x9010 is inert.
//
// Contract: never panics, never moves value, never fabricates a fill. Every
// method is a pure error return — the safe default for an unconfigured venue.
type inertEngine struct{}

// Compile-time assertion: inertEngine satisfies the Engine contract. It does NOT
// implement poolRouter — there is no canonical pool to route to.
var _ Engine = (*inertEngine)(nil)

// newInertEngine constructs the default no-backend engine.
func newInertEngine() *inertEngine { return &inertEngine{} }

// Brand identifies the unconfigured state in boot logs / error wrapping. It is
// intentionally generic and brand-free — no venue is wired.
func (inertEngine) Brand() string { return "DEX (no backend configured)" }

// Initialize refuses: no backend means no market can be created.
func (inertEngine) Initialize(_ *big.Int) (int24, error) {
	return 0, ErrDEXBackendNotConfigured
}

// Swap refuses: there is no matcher to submit a marketable order to.
func (inertEngine) Swap(_ *PoolState, _ SwapParams) (BalanceDelta, error) {
	return ZeroBalanceDelta(), ErrDEXBackendNotConfigured
}

// ModifyLiquidity refuses: there is no book to rest or pull an order on.
func (inertEngine) ModifyLiquidity(_ *PoolState, _ common.Address, _ ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrDEXBackendNotConfigured
}

// Donate refuses: a CLOB has no shared pool to gift into, and no backend is
// wired regardless.
func (inertEngine) Donate(_ *PoolState, _, _ *big.Int) (BalanceDelta, error) {
	return ZeroBalanceDelta(), ErrDEXBackendNotConfigured
}

// Quote returns zero: with no backend there is no book to read a price from.
// Quote is a read-only estimate, so it returns a benign zero rather than an
// error (the caller treats zero as "no route"), keeping router fallbacks sane.
func (inertEngine) Quote(_ *Pool, _ *big.Int, _ bool) *big.Int {
	return big.NewInt(0)
}
