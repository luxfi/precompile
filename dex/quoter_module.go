// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// quoter_module.go is 0x9998 — the swap-quote VIEW. It is ADVISORY and
// NON-AUTHORITATIVE: a quote is a preview, NOT a promise. A real swap STILL needs a
// certified DFillReceipt settled at 0x9999; the Quoter never produces one.
//
// ════════════════════════════════════════════════════════════════════════════
// STRUCTURAL WRITE-INCAPABILITY (the security boundary — read this loudly):
//
// The Quoter handler is STRUCTURALLY INCAPABLE OF WRITING. It never receives a
// write-capable state surface: every read goes through readOnlyView (GetState only,
// no SetState, no balance mutation, no AddLog). So even a `CALL` (not STATICCALL)
// that reaches 0x9998 with readOnly==false CANNOT mutate consensus state. This
// matters because the Quoter MAY read the LIVE D-Chain book (engine.Quote) when an
// engine is wired — a live, off-consensus, per-node read. If that read could feed a
// WRITE, consensus would fork (different nodes see different book states). It
// cannot: there is no write path out of this module. The live-D read is therefore
// safe precisely because it is write-isolated. This is the same fork-safety
// principle as the swap path (verify, don't query — and here, query but never
// commit), enforced by construction rather than by discipline.
// ════════════════════════════════════════════════════════════════════════════
//
// When NO engine is wired (a non-D node), the Quoter falls back to the C-side
// marketRegistry price + a single-tick swap_math projection. That fallback is
// deterministic and write-free; it is a coarse preview (a single ComputeSwapStep
// against the registered price, no resting-book depth), which is honest for an
// advisory quote. The depth-aware views (quoteWithDepth/quoteAgainstBook) return
// the registry-projection number with a "depth-unavailable" flag when no engine is
// present (see the per-method comments) — they never fabricate book depth.

var quoterConfigKey = "dexQuoterConfig"

// QuoterContract is the 0x9998 VIEW precompile. It carries NO mutable state and NO
// write surface — only the read-path. The singleton holds nothing.
type QuoterContract struct{}

var _ contract.StatefulPrecompiledContract = (*QuoterContract)(nil)

// QuoterPrecompile is the singleton 0x9998 contract.
var QuoterPrecompile = &QuoterContract{}

var quoterAddr = common.HexToAddress(DEXQuoterAddress)

// QuoterModule registers the 0x9998 read-only Quoter.
var QuoterModule = modules.Module{
	ConfigKey:    quoterConfigKey,
	Address:      quoterAddr,
	Contract:     QuoterPrecompile,
	Configurator: &quoterConfigurator{},
}

type quoterConfigurator struct{}

// Quoter (0x9998) selectors (keccak4 of the view signatures). Named SelQ* to stay
// distinct from the legacy LXRouter placeholder selectors in router.go (those are
// the deprecated 0x9012 surface, NOT this canonical Quoter). Quotes take (PoolKey,
// amount, zeroForOne).
var (
	SelQExactInput        uint32
	SelQExactOutput       uint32
	SelQExactInputSingle  uint32
	SelQExactOutputSingle uint32
	SelQAgainstBook       uint32
	SelQWithDepth         uint32
	SelQWithFees          uint32
	SelQWithSlippage      uint32
)

func init() {
	SelQExactInputSingle = keccak4("quoteExactInputSingle((address,address,uint24,int24,address),uint256,bool)")
	SelQExactOutputSingle = keccak4("quoteExactOutputSingle((address,address,uint24,int24,address),uint256,bool)")
	SelQExactInput = keccak4("quoteExactInput((address,address,uint24,int24,address),uint256,bool)")
	SelQExactOutput = keccak4("quoteExactOutput((address,address,uint24,int24,address),uint256,bool)")
	SelQAgainstBook = keccak4("quoteAgainstBook((address,address,uint24,int24,address),uint256,bool)")
	SelQWithDepth = keccak4("quoteWithDepth((address,address,uint24,int24,address),uint256,bool)")
	SelQWithFees = keccak4("quoteWithFees((address,address,uint24,int24,address),uint256,bool)")
	SelQWithSlippage = keccak4("quoteWithSlippage((address,address,uint24,int24,address),uint256,bool)")

	if err := modules.RegisterModule(QuoterModule); err != nil {
		panic(err)
	}
}

func (*quoterConfigurator) MakeConfig() precompileconfig.Config { return &QuoterConfig{} }

func (c *quoterConfigurator) Configure(
	_ precompileconfig.ChainConfig, _ precompileconfig.Config, _ contract.StateDB, _ contract.ConfigurationBlockContext,
) error {
	// The Quoter is stateless and read-only: nothing to configure or persist.
	return nil
}

// QuoterConfig activates the 0x9998 view. It has no parameters (no controller — a
// read-only view needs no governance authority).
type QuoterConfig struct {
	precompileconfig.Upgrade
}

func (c *QuoterConfig) Key() string                                 { return quoterConfigKey }
func (c *QuoterConfig) Timestamp() *uint64                          { return c.Upgrade.Timestamp() }
func (c *QuoterConfig) IsDisabled() bool                            { return c.Upgrade.Disable }
func (c *QuoterConfig) Verify(_ precompileconfig.ChainConfig) error { return nil }
func (c *QuoterConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*QuoterConfig)
	return ok && c.Upgrade.Equal(&other.Upgrade)
}

// GasQuoteView is the read cost of a single quote (cheaper than a swap; a few
// SLOAD-equivalents + arithmetic).
const GasQuoteView uint64 = 3_000

var (
	ErrQuoteNoMarket   = errors.New("dex: quote for an unregistered market (initialize first)")
	ErrQuoteBadInput   = errors.New("dex: quote input too short (need PoolKey, amount, zeroForOne)")
	ErrQuoteZeroAmount = errors.New("dex: quote amount must be positive")
)

// Run dispatches the 0x9998 read-only quote surface. EVERY path is read-only by
// construction — see the file header. readOnly is ignored for write-safety (there
// is no write to gate); it is observed only to keep the signature contract.
func (q *QuoterContract) Run(
	state contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool,
) ([]byte, uint64, error) {
	cur := contract.Read(input)
	selector, err := cur.Uint32()
	if err != nil {
		return nil, suppliedGas, errors.New("dex: quoter input too short")
	}
	if state.GetBlockContext() == nil {
		return nil, suppliedGas, errors.New("dex: block context unavailable")
	}
	data := cur.Rest()

	switch selector {
	case SelQExactInput, SelQExactInputSingle:
		return q.quote(state, data, suppliedGas, true /*exactIn*/, quoteModePlain)
	case SelQExactOutput, SelQExactOutputSingle:
		return q.quote(state, data, suppliedGas, false /*exactOut*/, quoteModePlain)
	case SelQAgainstBook:
		return q.quote(state, data, suppliedGas, true, quoteModeBook)
	case SelQWithDepth:
		return q.quote(state, data, suppliedGas, true, quoteModeDepth)
	case SelQWithFees:
		return q.quote(state, data, suppliedGas, true, quoteModeFees)
	case SelQWithSlippage:
		return q.quote(state, data, suppliedGas, true, quoteModeSlippage)
	default:
		return nil, suppliedGas, errors.New("dex: unknown 0x9998 quoter selector")
	}
}

type quoteMode uint8

const (
	quoteModePlain    quoteMode = iota // amountOut only
	quoteModeBook                      // amountOut from the live book (engine) if present
	quoteModeDepth                     // amountOut + depthAvailable flag
	quoteModeFees                      // amountOut + feeAmount
	quoteModeSlippage                  // amountOut + slippage projection
)

// quote is the SINGLE read-only quote computation all 8 view selectors route
// through (DRY). It decodes (PoolKey, amount, zeroForOne), reads the market via the
// READ-ONLY view, and projects an output — preferring the live engine book, else
// the C-side registry projection. It NEVER writes.
func (q *QuoterContract) quote(
	state contract.AccessibleState, data []byte, gas uint64, exactIn bool, mode quoteMode,
) ([]byte, uint64, error) {
	if gas < GasQuoteView {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasQuoteView
	if len(data) < 160+32+32 {
		return nil, gasLeft, ErrQuoteBadInput
	}
	key, err := DecodePoolKey(data[:160])
	if err != nil {
		return nil, gasLeft, err
	}
	amount := new(big.Int).SetBytes(data[160:192])
	zeroForOne := data[223] == 1
	if amount.Sign() <= 0 {
		return nil, gasLeft, ErrQuoteZeroAmount
	}

	// READ-ONLY view of state: GetState only, no write surface (structural).
	rv := readOnlyView{state: state}
	rec := loadMarket(rv, key.ID())
	if rec.Status != MarketStatusActive {
		return nil, gasLeft, ErrQuoteNoMarket
	}

	// DETERMINISTIC C-side projection ONLY. A view must be a pure function of
	// (input, StateDB) so every validator computes the identical output — a live-D
	// engine read (even write-isolated) returns per-node-divergent numbers that a
	// reading contract could act on, so it is not used here. The C-side registry has
	// no resting-book depth, so depthAvailable is always false (never faked).
	amountOut := projectSingleTick(rec, amount, zeroForOne, exactIn)

	feeAmount := feeOnInput(amount, rec.Fee)
	switch mode {
	case quoteModeFees:
		return encodeTwoWords(amountOut, feeAmount), gasLeft, nil
	case quoteModeDepth:
		// No live book on a consensus view: the C-fallback has no resting-book depth,
		// so depthAvailable is always false (never faked).
		return encodeWordAndBool(amountOut, false), gasLeft, nil
	case quoteModeSlippage:
		// slippage = |spot*amount - amountOut| projection vs the zero-impact spot. We
		// return (amountOut, spotOut) so the caller computes the bps it cares about.
		spotOut := spotOutput(rec, amount, zeroForOne)
		return encodeTwoWords(amountOut, spotOut), gasLeft, nil
	default: // plain, book
		out := make([]byte, 32)
		amountOut.FillBytes(out)
		return out, gasLeft, nil
	}
}

// projectSingleTick is the C-side deterministic fallback quote at the registered
// price with no tick crossing. It is a COARSE preview (no resting depth, no
// multi-tick walk) — honest for an advisory quote when the node has no D book.
//
// exactIn selects which question is asked. Given an input, the output it buys;
// given a desired output, the input it costs. Those are inverses of one
// price-and-fee map, not one number: at price p the first scales by p and the
// second by 1/p, and the fee comes off the input in the first and is grossed onto
// it in the second.
func projectSingleTick(rec MarketRecord, amount *big.Int, zeroForOne, exactIn bool) *big.Int {
	if exactIn {
		return spotOutputFeeAdjusted(rec, amount, zeroForOne)
	}
	return spotInputForOutput(rec, amount, zeroForOne)
}

// spotInputForOutput inverts spotOutputFeeAdjusted: the smallest input that buys
// amountOut at the registered spot price. Every step rounds UP, so the quoted input
// always covers the output asked for and no smaller input does — a quote of what a
// taker must supply may overstate by a unit, but one that understates is a quote
// that cannot fill. Returns 0 for a market carrying no price, matching spotOutput.
func spotInputForOutput(rec MarketRecord, amountOut *big.Int, zeroForOne bool) *big.Int {
	if amountOut.Sign() <= 0 || rec.SqrtPriceX96 == nil || rec.SqrtPriceX96.Sign() == 0 {
		return big.NewInt(0)
	}
	sq := new(big.Int).Mul(rec.SqrtPriceX96, rec.SqrtPriceX96) // price = sq / 2^192
	var net *big.Int
	if zeroForOne {
		// out1 = floor(net0 * sq / 2^192)  =>  net0 = ceil(out1 * 2^192 / sq)
		net = UnsafeDivRoundingUp(new(big.Int).Lsh(amountOut, 192), sq)
	} else {
		// out0 = floor(net1 * 2^192 / sq)  =>  net1 = ceil(out0 * sq / 2^192)
		net = UnsafeDivRoundingUp(new(big.Int).Mul(amountOut, sq), new(big.Int).Lsh(bigOne, 192))
	}
	// The fee comes off the input, so net = in - floor(in*fee/1e6), which is
	// ceil(in*(1e6-fee)/1e6). The smallest in reaching net is therefore
	// ceil(((net-1)*1e6 + 1) / (1e6-fee)). FeeMax is a tenth of the denominator, so
	// the divisor is never zero.
	den := new(big.Int).Sub(feeDenominator, big.NewInt(int64(rec.Fee)))
	num := new(big.Int).Mul(new(big.Int).Sub(net, bigOne), feeDenominator)
	return UnsafeDivRoundingUp(num.Add(num, bigOne), den)
}

// spotOutput projects amount through the registered spot price with NO fee and NO
// slippage (the zero-impact reference used by quoteWithSlippage). price = (sqrtP/2^96)^2.
func spotOutput(rec MarketRecord, amount *big.Int, zeroForOne bool) *big.Int {
	if rec.SqrtPriceX96 == nil || rec.SqrtPriceX96.Sign() == 0 {
		return big.NewInt(0)
	}
	// out = amount * price (zeroForOne: token0->token1, multiply by price);
	//       amount / price (oneForZero). price = sqrtP^2 / 2^192.
	sq := new(big.Int).Mul(rec.SqrtPriceX96, rec.SqrtPriceX96) // sqrtP^2
	if zeroForOne {
		// out1 = amount0 * sqrtP^2 / 2^192
		num := new(big.Int).Mul(amount, sq)
		return num.Rsh(num, 192)
	}
	// out0 = amount1 * 2^192 / sqrtP^2
	num := new(big.Int).Lsh(amount, 192)
	if sq.Sign() == 0 {
		return big.NewInt(0)
	}
	return num.Div(num, sq)
}

// spotOutputFeeAdjusted is spotOutput with the LP fee deducted from the input first.
func spotOutputFeeAdjusted(rec MarketRecord, amount *big.Int, zeroForOne bool) *big.Int {
	net := new(big.Int).Sub(amount, feeOnInput(amount, rec.Fee))
	return spotOutput(rec, net, zeroForOne)
}

// feeOnInput is the LP fee charged on an input amount: amount * feePips / 1e6.
func feeOnInput(amount *big.Int, feePips uint24) *big.Int {
	f := new(big.Int).Mul(amount, big.NewInt(int64(feePips)))
	return f.Div(f, feeDenominator)
}

// encodeTwoWords ABI-packs two uint256 results.
func encodeTwoWords(a, b *big.Int) []byte {
	out := make([]byte, 64)
	if a != nil && a.Sign() > 0 {
		a.FillBytes(out[0:32])
	}
	if b != nil && b.Sign() > 0 {
		b.FillBytes(out[32:64])
	}
	return out
}

// encodeWordAndBool ABI-packs (uint256, bool).
func encodeWordAndBool(a *big.Int, flag bool) []byte {
	out := make([]byte, 64)
	if a != nil && a.Sign() > 0 {
		a.FillBytes(out[0:32])
	}
	if flag {
		out[63] = 1
	}
	return out
}

// readOnlyView adapts an AccessibleState to the stateKV READ surface WITHOUT
// exposing SetState. It is the structural write-incapability: a Quoter/StateView
// handler holds a readOnlyView, so there is no method on it that can mutate state.
// SetState is present only to satisfy the stateKV interface (the registry loaders
// take stateKV) and PANICS if ever called — a write attempt is a programming error,
// not a silent corruption. In practice no read-path helper calls SetState, so the
// panic is unreachable; it exists as a tripwire.
type readOnlyView struct {
	state contract.AccessibleState
}

func (r readOnlyView) GetState(addr common.Address, key common.Hash) common.Hash {
	return r.state.GetStateDB().GetState(addr, key)
}

// SetState is the tripwire: a read-only view must never write. The view is only ever
// passed to read helpers (loadMarket/loadRestingOrder/...), none of which call
// SetState, so this is unreachable by construction. If a future refactor wires a
// writing helper to a view, this panics loudly in tests rather than corrupting
// consensus state.
func (r readOnlyView) SetState(common.Address, common.Hash, common.Hash) {
	panic("dex: read-only view attempted a state write (0x9998/0x9997 are write-incapable by design)")
}
