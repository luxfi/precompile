// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"math/big"

	"github.com/luxfi/geth/common"
)

// DChainClient is the precompile's handle to the node-LOCAL D-Chain (dexvm).
//
// THE MODEL (decomplected — one concern, one name): D is a normal Lux chain
// running dexvm, validated by an authorized subset (the --dex-validator opt-in +
// NFT authz at the chain-create/validate level, NOT here). The LP-9010 precompile
// is ONLY an ON-RAMP from the C-Chain to that D-Chain: it SUBMITS DEX operations
// to the local D-Chain or VERIFIES committed D receipts. It is NOT a matcher and
// NOT a backend selector. The matcher is the dexvm the validators run.
//
// This interface is the canonical seam that surface migrates onto. It is the
// Stage-1 target (see the package design): the synchronous V4 swap path is moved
// off the live-query Engine surface and onto SubmitSwapOrder (Pattern A: a
// C tx records a D-Chain order order; the local dexvm executes it under D
// consensus; the result settles asynchronously through the D->C atomic boundary)
// or GetReceipt (Pattern B: a C tx carries a committed D receipt that 0x9010
// deterministically verifies). Both are consensus-safe; a SYNCHRONOUS in-block
// fill via a live query to a separate chain's moving book is NOT (it forks: two
// validators executing the same C block at different instants observe different
// fills => divergent StateRoot).
//
// CONSENSUS-SAFETY RULE: an implementation MUST NOT make C-Chain consensus state
// depend on a live query whose result is not already committed/certified. The
// transport is loopback to the co-located dexvm (the dexvm is RPC-served; the
// precompile is a leaf library that cannot — and must not — reach up into the
// node chain manager). A remote / standalone venue is never a valid target.
type DChainClient interface {
	// SubmitOrder records a resting (maker) order order on the local D-Chain
	// and returns its order id. The order rests under D consensus; it is not
	// matched synchronously here.
	SubmitOrder(ctx context.Context, o Order) (orderID uint64, err error)

	// SubmitSwapOrder records a marketable (taker) swap ORDER on the local
	// D-Chain (Pattern A) and returns a receipt id the caller polls / observes
	// for the asynchronous settlement. It does NOT return an in-block fill.
	SubmitSwapOrder(ctx context.Context, in SwapOrder) (receiptID [32]byte, err error)

	// GetMarket returns the committed market (order book) metadata for marketID,
	// a read of already-committed D state (safe to fold into a C read path).
	GetMarket(ctx context.Context, marketID [32]byte) (Market, error)

	// GetReceipt returns a committed D receipt for a prior order (Pattern B:
	// the C side deterministically verifies it before applying the C effect).
	GetReceipt(ctx context.Context, receiptID [32]byte) (Receipt, error)
}

// Order is a resting (maker) limit-order order submitted to the local D-Chain.
// Identity (maker) is bound by the C tx caller; size/price are the V4-derived
// resting parameters. (Field set intentionally minimal for the Stage-1 seam; the
// frozen wire frame lives in engine_zap.go.)
type Order struct {
	MarketID [32]byte
	Maker    common.Address
	Side     uint8
	Price    *big.Int
	Size     *big.Int
}

// SwapOrder is a marketable (taker) swap order submitted to the local D-Chain.
// The taker is the C tx caller; the D-Chain settles the realized fills through
// the atomic D->C boundary, NOT into C StateDB synchronously.
type SwapOrder struct {
	MarketID [32]byte
	Taker    common.Address
	Params   SwapParams
}

// Market is committed market metadata read back from the local D-Chain.
type Market struct {
	MarketID    [32]byte
	Base        Currency
	Quote       Currency
	Initialized bool
}

// Receipt is a committed D receipt for an order (Pattern B verification target).
// Fills are the D-Chain's confirmed executions; the reserved Sig is the d-chain
// fill-attestation (P3Q -> starkfri) that makes verification trustless.
type Receipt struct {
	ReceiptID [32]byte
	Delta     BalanceDelta
	Sig       []byte
}

// dchainUnavailable is the precompile's client when the node-LOCAL D-Chain is not
// reachable. It performs NO matching and holds NO state: every operation returns
// ErrDChainUnavailable so that a node which serves the LP-9010 path but is not
// running its local dexvm D-Chain reverts cleanly — it never fabricates a fill
// and never masks the absent chain as a missing pool.
//
// This is NOT a "backend mode" and NOT a selectable engine. It is the honest
// default for a precompile whose backing chain is absent: the local D-Chain MUST
// be running for 0x9010 to serve DEX operations; until it is, the on-ramp is
// closed. It implements the transitional Engine surface (the live surface the
// PoolManager calls today) so the precompile remains a clean revert.
//
// Contract: never panics, never moves value, never fabricates a fill.
type dchainUnavailable struct{}

// Compile-time assertion: dchainUnavailable satisfies the live Engine surface. It
// does NOT implement custodyEngine / poolRouter / cancelAuthority — there is no
// local D-Chain to route to or fund against.
var _ Engine = (*dchainUnavailable)(nil)

// newDChainUnavailable constructs the no-local-D-Chain client.
func newDChainUnavailable() *dchainUnavailable { return &dchainUnavailable{} }

// Brand identifies the closed-on-ramp state in boot logs / error wrapping.
func (dchainUnavailable) Brand() string { return "DEX (local D-Chain unavailable)" }

// Initialize refuses: no local D-Chain means no market can be created.
func (dchainUnavailable) Initialize(_ *big.Int) (int24, error) {
	return 0, ErrDChainUnavailable
}

// Swap refuses: there is no local D-Chain to submit a marketable order to.
func (dchainUnavailable) Swap(_ *PoolState, _ common.Address, _ SwapParams) (BalanceDelta, error) {
	return ZeroBalanceDelta(), ErrDChainUnavailable
}

// ModifyLiquidity refuses: there is no local D-Chain book to rest or pull on.
func (dchainUnavailable) ModifyLiquidity(_ *PoolState, _ common.Address, _ ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrDChainUnavailable
}

// Donate refuses: a CLOB has no shared pool to gift into, and no local D-Chain
// is reachable regardless.
func (dchainUnavailable) Donate(_ *PoolState, _, _ *big.Int) (BalanceDelta, error) {
	return ZeroBalanceDelta(), ErrDChainUnavailable
}

// Quote returns zero: with no local D-Chain there is no book to read a price
// from. Quote is a read-only estimate, so it returns a benign zero rather than
// an error (the caller treats zero as "no route"), keeping router fallbacks sane.
func (dchainUnavailable) Quote(_ *Pool, _ *big.Int, _ bool) *big.Int {
	return big.NewInt(0)
}
