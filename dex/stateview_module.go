// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// stateview_module.go is 0x9997 — the read-only STATE VIEW. It aggregates the
// 0x9999 market registry, the per-account reserve (available/locked), the resting-
// order book metadata, and the receipt/halt/verifier registries into clean getters.
// It is the read counterpart to the 0x9999 write surface.
//
// WRITE-INCAPABILITY (same boundary as the Quoter): every read goes through
// readOnlyView (GetState only). There is NO write path out of this module — a CALL
// with readOnly==false cannot mutate consensus state. The engine read-path (for
// richer depth) is off-consensus + write-isolated, exactly as in the Quoter.

var stateViewConfigKey = "dexStateViewConfig"

// StateViewContract is the 0x9997 read-only VIEW precompile. Carries no state.
type StateViewContract struct{}

var _ contract.StatefulPrecompiledContract = (*StateViewContract)(nil)

// StateViewPrecompile is the singleton 0x9997 contract.
var StateViewPrecompile = &StateViewContract{}

var stateViewAddr = common.HexToAddress(DEXStateViewAddress)

// StateViewModule registers the 0x9997 read-only StateView.
var StateViewModule = modules.Module{
	ConfigKey:    stateViewConfigKey,
	Address:      stateViewAddr,
	Contract:     StateViewPrecompile,
	Configurator: &stateViewConfigurator{},
}

type stateViewConfigurator struct{}

// StateView selectors (keccak4 of the view signatures).
var (
	SelectorGetPool          uint32
	SelectorGetPoolId        uint32
	SelectorGetSlot0         uint32
	SelectorGetLiquidity     uint32
	SelectorGetPosition      uint32
	SelectorGetMarket        uint32
	SelectorGetBestBidAsk    uint32
	SelectorGetDepth         uint32
	SelectorGetOpenOrders    uint32
	SelectorGetReceiptStatus uint32
	SelectorGetHaltStatus    uint32
)

func init() {
	SelectorGetPool = keccak4("getPool((address,address,uint24,int24,address))")
	SelectorGetPoolId = keccak4("getPoolId((address,address,uint24,int24,address))")
	SelectorGetSlot0 = keccak4("getSlot0(bytes32)")
	SelectorGetLiquidity = keccak4("getLiquidity(bytes32)")
	SelectorGetPosition = keccak4("getPosition(bytes32)")
	SelectorGetMarket = keccak4("getMarket(bytes32)")
	SelectorGetBestBidAsk = keccak4("getBestBidAsk(bytes32)")
	SelectorGetDepth = keccak4("getDepth(bytes32,uint256)")
	SelectorGetOpenOrders = keccak4("getOpenOrders(address)")
	SelectorGetReceiptStatus = keccak4("getReceiptStatus(bytes32)")
	SelectorGetHaltStatus = keccak4("getHaltStatus(bytes32)")

	if err := modules.RegisterModule(StateViewModule); err != nil {
		panic(err)
	}
}

func (*stateViewConfigurator) MakeConfig() precompileconfig.Config { return &StateViewConfig{} }

func (c *stateViewConfigurator) Configure(
	_ precompileconfig.ChainConfig, _ precompileconfig.Config, _ contract.StateDB, _ contract.ConfigurationBlockContext,
) error {
	return nil // stateless, read-only.
}

// StateViewConfig activates the 0x9997 view (no parameters).
type StateViewConfig struct {
	precompileconfig.Upgrade
}

func (c *StateViewConfig) Key() string                                 { return stateViewConfigKey }
func (c *StateViewConfig) Timestamp() *uint64                          { return c.Upgrade.Timestamp() }
func (c *StateViewConfig) IsDisabled() bool                            { return c.Upgrade.Disable }
func (c *StateViewConfig) Verify(_ precompileconfig.ChainConfig) error { return nil }
func (c *StateViewConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*StateViewConfig)
	return ok && c.Upgrade.Equal(&other.Upgrade)
}

const GasStateView uint64 = 800 // a few SLOAD-equivalents per view.

var (
	ErrViewNoMarket = errors.New("dex: view for an unregistered market")
	ErrViewBadInput = errors.New("dex: view input too short")
)

// Run dispatches the 0x9997 read-only view surface. Read-only by construction.
func (v *StateViewContract) Run(
	state contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 4 {
		return nil, suppliedGas, errors.New("dex: stateview input too short")
	}
	if state.GetBlockContext() == nil {
		return nil, suppliedGas, errors.New("dex: block context unavailable")
	}
	selector := uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
	data := input[4:]
	if suppliedGas < GasStateView {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := suppliedGas - GasStateView
	rv := readOnlyView{state: state}

	switch selector {
	case SelectorGetPoolId:
		key, err := DecodePoolKey(data)
		if err != nil {
			return nil, gasLeft, err
		}
		id := key.ID()
		out := make([]byte, 32)
		copy(out, id[:])
		return out, gasLeft, nil

	case SelectorGetPool, SelectorGetMarket:
		// getPool/getMarket: by PoolKey (getPool) or by poolID (getMarket).
		var poolID [32]byte
		if selector == SelectorGetMarket {
			if len(data) < 32 {
				return nil, gasLeft, ErrViewBadInput
			}
			copy(poolID[:], data[:32])
		} else {
			key, err := DecodePoolKey(data)
			if err != nil {
				return nil, gasLeft, err
			}
			poolID = key.ID()
		}
		rec := loadMarket(rv, poolID)
		if rec.Status != MarketStatusActive {
			return nil, gasLeft, ErrViewNoMarket
		}
		return encodeMarketRecord(rec), gasLeft, nil

	case SelectorGetSlot0:
		// getSlot0(poolID) -> (sqrtPriceX96, tick).
		rec, err := requireMarketByID(rv, data)
		if err != nil {
			return nil, gasLeft, err
		}
		out := make([]byte, 64)
		if rec.SqrtPriceX96 != nil {
			rec.SqrtPriceX96.FillBytes(out[0:32])
		}
		copy(out[32:64], encodeInt24Word(rec.Tick))
		return out, gasLeft, nil

	case SelectorGetLiquidity:
		// getLiquidity(poolID): the C-side registry holds no AMM liquidity figure
		// (liquidity lives on the D book). Prefer the engine read-path; else 0 with a
		// flag is misleading, so we return the resting maker locked-total for the
		// pool's assets as the C-visible "depth". Read-only.
		rec, err := requireMarketByID(rv, data)
		if err != nil {
			return nil, gasLeft, err
		}
		liq := engineLiquidity(rec)
		out := make([]byte, 32)
		if liq != nil {
			liq.FillBytes(out)
		}
		return out, gasLeft, nil

	case SelectorGetPosition:
		// getPosition(orderID) -> (owner, lockedAsset, lockedAmount, tickLower, tickUpper, status).
		if len(data) < 32 {
			return nil, gasLeft, ErrViewBadInput
		}
		var orderID [32]byte
		copy(orderID[:], data[:32])
		o := loadRestingOrder(rv, orderID)
		return encodeRestingOrder(orderID, o), gasLeft, nil

	case SelectorGetBestBidAsk:
		// getBestBidAsk(poolID) -> (bestBid, bestAsk). Engine read-path if present;
		// else the registry spot price for both sides (a coarse C-side reference) +
		// a flag. We return (bid, ask, fromBook).
		rec, err := requireMarketByID(rv, data)
		if err != nil {
			return nil, gasLeft, err
		}
		bid, ask, fromBook := engineBestBidAsk(rec)
		out := make([]byte, 96)
		if bid != nil {
			bid.FillBytes(out[0:32])
		}
		if ask != nil {
			ask.FillBytes(out[32:64])
		}
		if fromBook {
			out[95] = 1
		}
		return out, gasLeft, nil

	case SelectorGetDepth:
		// getDepth(poolID, levels) -> (depthBase, depthQuote, fromBook). Engine read-
		// path if present; else 0 depth with fromBook=false (never faked).
		if len(data) < 32 {
			return nil, gasLeft, ErrViewBadInput
		}
		rec, err := requireMarketByID(rv, data[:32])
		if err != nil {
			return nil, gasLeft, err
		}
		base, quote, fromBook := engineDepth(rec)
		out := make([]byte, 96)
		if base != nil {
			base.FillBytes(out[0:32])
		}
		if quote != nil {
			quote.FillBytes(out[32:64])
		}
		if fromBook {
			out[95] = 1
		}
		return out, gasLeft, nil

	case SelectorGetOpenOrders:
		// getOpenOrders(owner) -> bytes32[] orderIDs (OPEN only). Deterministic
		// enumeration via the ownerOrders index; skips CLOSED/CANCELLED.
		if len(data) < 32 {
			return nil, gasLeft, ErrViewBadInput
		}
		owner := common.BytesToAddress(data[12:32])
		ids := OwnerOrderIDs(rv, owner)
		open := make([][32]byte, 0, len(ids))
		for _, id := range ids {
			if loadRestingOrder(rv, id).Status == OrderStatusOpen {
				open = append(open, id)
			}
		}
		// Per-order gas (each is an SLOAD-equivalent).
		extra := GasStateView * uint64(len(ids))
		if suppliedGas < GasStateView+extra {
			return nil, 0, errors.New("dex: out of gas")
		}
		return encodeBytes32Array(open), suppliedGas - GasStateView - extra, nil

	case SelectorGetReceiptStatus:
		// getReceiptStatus(objectID) -> bool consumed. In the native seam this reports
		// whether a D->C atomic settlement object id has already been consumed (the
		// one-time settlement guard), the native analog of the prior receipt-consumed
		// view.
		if len(data) < 32 {
			return nil, gasLeft, ErrViewBadInput
		}
		var rid ids.ID
		copy(rid[:], data[:32])
		out := make([]byte, 32)
		if isClaimConsumed(rv, rid) {
			out[31] = 1
		}
		return out, gasLeft, nil

	case SelectorGetHaltStatus:
		// getHaltStatus(scopeID) -> (globalHalted, scopeHalted). scopeID is checked
		// against the market/asset halt slots (the BLS-era validatorSet halt is gone);
		// reports whether the global halt is on AND whether the given id is halted as a
		// market or asset.
		if len(data) < 32 {
			return nil, gasLeft, ErrViewBadInput
		}
		var id [32]byte
		copy(id[:], data[:32])
		out := make([]byte, 64)
		if isHalted(rv, haltGlobalKey) {
			out[31] = 1
		}
		if isHalted(rv, makeStorageKey(haltMarketPrefix, id[:])) ||
			isHalted(rv, makeStorageKey(haltAssetPrefix, id[:])) {
			out[63] = 1
		}
		return out, gasLeft, nil

	default:
		return nil, gasLeft, errors.New("dex: unknown 0x9997 stateview selector")
	}
}

// requireMarketByID loads a market by a 32-byte poolID slice or reverts ErrViewNoMarket.
func requireMarketByID(rv readOnlyView, data []byte) (MarketRecord, error) {
	if len(data) < 32 {
		return MarketRecord{}, ErrViewBadInput
	}
	var poolID [32]byte
	copy(poolID[:], data[:32])
	rec := loadMarket(rv, poolID)
	if rec.Status != MarketStatusActive {
		return MarketRecord{}, ErrViewNoMarket
	}
	return rec, nil
}

// encodeMarketRecord ABI-packs (status, sqrtPriceX96, tick, currency0, currency1,
// fee, tickSpacing, creator) — 8 words.
func encodeMarketRecord(rec MarketRecord) []byte {
	out := make([]byte, 32*8)
	out[31] = byte(rec.Status)
	if rec.SqrtPriceX96 != nil {
		rec.SqrtPriceX96.FillBytes(out[32:64])
	}
	copy(out[64:96], encodeInt24Word(rec.Tick))
	copy(out[96+12:128], rec.Currency0.Bytes())
	copy(out[128+12:160], rec.Currency1.Bytes())
	putWordUint64(out[160:192], uint64(rec.Fee))
	copy(out[192:224], encodeInt24Word(rec.TickSpacing))
	copy(out[224+12:256], rec.Creator.Bytes())
	return out
}

// encodeRestingOrder ABI-packs (orderID, owner, lockedAsset, lockedAmount,
// tickLower, tickUpper, status) — 7 words.
func encodeRestingOrder(orderID [32]byte, o RestingOrder) []byte {
	out := make([]byte, 32*7)
	copy(out[0:32], orderID[:])
	copy(out[32+12:64], o.Owner.Bytes())
	copy(out[64:96], o.LockedAsset[:])
	if o.LockedAmt != nil {
		o.LockedAmt.FillBytes(out[96:128])
	}
	copy(out[128:160], encodeInt24Word(o.TickLower))
	copy(out[160:192], encodeInt24Word(o.TickUpper))
	out[223] = byte(o.Status)
	return out
}

// encodeBytes32Array ABI-encodes a bytes32[]: offset(0x20) | length | elements.
func encodeBytes32Array(ids [][32]byte) []byte {
	out := make([]byte, 64+len(ids)*32)
	out[31] = 0x20
	putWordUint64(out[32:64], uint64(len(ids)))
	for i, id := range ids {
		copy(out[64+i*32:64+i*32+32], id[:])
	}
	return out
}

// engineLiquidity / engineBestBidAsk / engineDepth are the DETERMINISTIC C-side
// references the read views return. They DO NOT read the live D engine: a view must
// be a pure function of (input, StateDB) so every validator computes the identical
// output. (Earlier these branched on DEXPrecompile.poolManager.engine — a live,
// per-node-divergent read; even though the views are write-incapable, returning a
// non-deterministic number that a reading contract could act on is a latent fork,
// so the live-D branch is removed. The C registry holds no resting-book depth, so
// depth/liquidity are reported as the honest C reference with fromBook=false.)

// engineLiquidity returns the C-visible liquidity reference. The C registry holds
// no AMM liquidity figure (liquidity lives on the D book), so this is 0 —
// deterministic and honest, never a live-engine probe.
func engineLiquidity(_ MarketRecord) *big.Int {
	return big.NewInt(0)
}

func engineBestBidAsk(rec MarketRecord) (bid, ask *big.Int, fromBook bool) {
	// Project the registry spot price for both sides as a coarse C-side reference and
	// report fromBook=false. We do NOT fabricate a book — the spot is the registry
	// price, explicitly flagged as not-from-book. Deterministic (no engine read).
	if rec.SqrtPriceX96 == nil || rec.SqrtPriceX96.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0), false
	}
	// spot price of token1 per token0 = sqrtP^2 / 2^192, scaled to 1e18 for display.
	sq := new(big.Int).Mul(rec.SqrtPriceX96, rec.SqrtPriceX96)
	scaled := new(big.Int).Mul(sq, big.NewInt(1e18))
	spot := scaled.Rsh(scaled, 192)
	return spot, spot, false
}

func engineDepth(_ MarketRecord) (base, quote *big.Int, fromBook bool) {
	// No resting-book depth on the C side; report zero with fromBook=false rather
	// than fake levels or probe a per-node-divergent live engine. Deterministic.
	return big.NewInt(0), big.NewInt(0), false
}
