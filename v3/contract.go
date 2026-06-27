// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package v3 is the Lux native concentrated-liquidity AMM precompile "LXConcentrated"
// at LP-90A1 (0x…90A1), the next free DEX-page address after the LP-90A0 swap HTLC.
// It is a faithful native port of the Uniswap V3 concentrated-liquidity engine —
// tick ranges, the tick-crossing swap loop, per-position fee growth — with every
// piece of AMM MATH COMPOSED from package dex (the exact Uniswap magic constants and
// 512-bit MulDiv already live there). This package reimplements NONE of that math; it
// orchestrates it and owns only: state layout, the swap/mint/burn/collect flow, token
// custody, ABI dispatch, gas, and events.
//
// Composed verbatim from dex (the single source of AMM math truth):
//   - tick_math.go        GetSqrtRatioAtTick, GetTickAtSqrtRatio
//   - sqrt_price_math.go  GetAmount0Delta, GetAmount1Delta (+ the next-price helpers
//     via ComputeSwapStep)
//   - swap_math.go        ComputeSwapStep (the per-step engine; V4 sign convention)
//   - liquidity_amounts.go GetAmountsForLiquidity (mint/burn token amounts)
//   - full_math.go        MulDiv (fee-growth accrual)
//   - tick_bitmap_math.go Compress, TickBitmapPosition, FlipTick,
//     NextInitializedTickWithinOneWord
//   - types.go            PoolKey, Currency, Position, TickInfo, TickBitmap,
//     PositionKey, Q128, MinTick, MaxTick, Min/MaxSqrtRatio,
//     fee tiers + tick spacings
//
// DELIBERATE DEVIATIONS FROM LITERAL UNISWAP V3 (each forced by the precompile model,
// documented so they are not mistaken for drift):
//
//  1. SINGLETON keyed by dex.PoolKey. Uniswap V3 deploys one contract per pool; a
//     precompile is one fixed address. So, exactly like the Lux V4 dex precompile,
//     this serves MANY pools keyed by PoolKey(token0,token1,fee,tickSpacing). Hooks
//     are forced to zero (a V3 engine has none). poolId == dex.PoolKey.ID().
//  2. OBSERVED-DELTA custody instead of V3 mint/swap CALLBACKS. There is no
//     uniswapV3MintCallback / swapCallback; tokens move via the proven swap/vault.go
//     idiom — pull funds IN by measuring the real balanceOf delta (or native msg.value
//     surplus), pay funds OUT via transfer / Sub-Add. No path mints.
//  3. mint/burn token amounts via dex.GetAmountsForLiquidity (round-DOWN, the dex
//     helper's convention) for BOTH directions, so mint and burn are exact inverses
//     of principal at equal price. V3-core rounds mint UP (pool-favourable); the
//     symmetric round-down here is conservation-safe because the per-asset reserve
//     ledger + subReserve underflow guard make a pay-out structurally unable to exceed
//     holdings, and the swap loop's amounts are independently pool-favourable
//     (amountIn rounds up, amountOut rounds down inside dex.ComputeSwapStep).
//  4. Position owner == caller (no recipient indirection). You may only mint/burn/
//     collect your OWN position; a manager builds its own sub-ledger above this.
//  5. Events carry `bytes32 indexed poolId` (singleton) and keep ticks in data to fit
//     the 4-topic budget (see events.go).
package v3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/dex"
)

var _ contract.StatefulPrecompiledContract = (*V3Contract)(nil)

// LXConcentratedAddress is LP-90A1 "LXConcentrated": the native Uniswap-V3
// concentrated-liquidity AMM, the next free DEX-page address after LP-90A0 (LXSwap).
const LXConcentratedAddress = "0x00000000000000000000000000000000000090A1"

// v3Addr is the precompile's own address; all pool state and all custodied token
// balances live under it.
var v3Addr = common.HexToAddress(LXConcentratedAddress)

// methodSelector derives the 4-byte selector (BigEndian uint32 of keccak256(sig)[:4])
// from a canonical ABI signature — the signature string is the SINGLE source of truth
// (mirrors swap.go), so no transcribed magic number can drift from it.
func methodSelector(sig string) uint32 {
	return binary.BigEndian.Uint32(crypto.Keccak256([]byte(sig))[:contract.SelectorLen])
}

// poolKeyABI is the canonical ABI fragment for a PoolKey as a static tuple:
// (token0 address, token1 address, fee uint24, tickSpacing int24). It is encoded
// in-place as 4 consecutive 32-byte words at the head of every call's arguments.
const poolKeyABI = "(address,address,uint24,int24)"

// 4-byte selectors. The trailing hex is the authoritative value (asserted in the
// test suite via methodSelector) but is DERIVED, never hand-entered.
var (
	selInitialize = methodSelector("initialize" + poolKeyABI + ",uint160)")                  // create a pool
	selMint       = methodSelector("mint" + poolKeyABI + ",int24,int24,uint128)")            // add liquidity
	selBurn       = methodSelector("burn" + poolKeyABI + ",int24,int24,uint128)")            // remove liquidity
	selCollect    = methodSelector("collect" + poolKeyABI + ",int24,int24,uint128,uint128)") // withdraw owed
	selSwap       = methodSelector("swap" + poolKeyABI + ",bool,int256,uint160)")            // tick-crossing swap

	selSlot0     = methodSelector("slot0" + poolKeyABI + ")")
	selLiquidity = methodSelector("liquidity" + poolKeyABI + ")")
	selTicks     = methodSelector("ticks" + poolKeyABI + ",int24)")
	selPositions = methodSelector("positions" + poolKeyABI + ",address,int24,int24)")
)

// Gas costs. The four money-moving ops perform several cold SSTOREs plus a token
// transfer sub-call; swap additionally meters per tick-crossing step so an
// adversarial multi-tick swap is bounded by gas, not by a flat charge.
const (
	GasInitialize uint64 = 60_000
	GasMint       uint64 = 90_000
	GasBurn       uint64 = 70_000
	GasCollect    uint64 = 50_000
	GasSwapBase   uint64 = 60_000
	GasSwapStep   uint64 = 3_000
	GasView       uint64 = 5_000
)

var (
	ErrReadOnly        = errors.New("v3: cannot modify state in read-only (static) call")
	ErrReentrant       = errors.New("v3: reentrant call rejected")
	ErrShortInput      = errors.New("v3: input shorter than 4-byte selector")
	ErrBadArgs         = errors.New("v3: malformed call arguments")
	ErrUnknownSelector = errors.New("v3: unknown function selector")
	ErrOutOfGas        = errors.New("v3: out of gas")

	ErrCurrencyOrder      = errors.New("v3: currency0 must be strictly less than currency1")
	ErrInvalidFee         = errors.New("v3: fee must be in [0, 1_000_000)")
	ErrInvalidTickSpacing = errors.New("v3: tickSpacing must be in [1, 16384]")
	ErrTickMisaligned     = errors.New("v3: tick not aligned to tickSpacing")
	ErrZeroAmount         = errors.New("v3: amount must be positive")
	ErrAmountTooLarge     = errors.New("v3: liquidity amount exceeds uint128")
	ErrInsufficientLiq    = errors.New("v3: position liquidity below requested burn")
	ErrLiquidityUnderflow = errors.New("v3: liquidity underflow (state-corruption guard)")

	ErrVaultUnavailable = errors.New("v3: ERC-20 vault capability unavailable on this StateDB")
	ErrTransferFailed   = errors.New("v3: ERC-20 transfer reverted or returned false")
	ErrDeltaMismatch    = errors.New("v3: observed inbound balance delta != requested amount")
	ErrReserveUnderflow = errors.New("v3: reserve underflow (conservation invariant breach)")
)

var (
	maxFee      = big.NewInt(1_000_000)
	maxSpacing  = big.NewInt(16384)
	maxUint128  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	tickLowerBI = big.NewInt(int64(dex.MinTick))
	tickUpperBI = big.NewInt(int64(dex.MaxTick))
)

// V3Contract is the LP-90A1 concentrated-liquidity precompile. It holds NO mutable Go
// state; every field lives in the EVM trie under v3Addr (see state.go). The zero value
// is ready to use.
type V3Contract struct{}

// Run dispatches by 4-byte selector. The four read views (slot0, liquidity, ticks,
// positions) are permitted in read-only calls; the five state transitions
// (initialize, mint, burn, collect, swap) are not, and each runs under a global
// non-reentrant guard so the observed-delta custody measurement and the state
// mutation cannot be corrupted by a malicious token's reentrant callback.
func (c *V3Contract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < contract.SelectorLen {
		return nil, suppliedGas, ErrShortInput
	}
	selector := binary.BigEndian.Uint32(input[:contract.SelectorLen])
	data := input[contract.SelectorLen:]

	switch selector {
	case selSlot0:
		return c.runSlot0(accessibleState, data, suppliedGas)
	case selLiquidity:
		return c.runLiquidity(accessibleState, data, suppliedGas)
	case selTicks:
		return c.runTicks(accessibleState, data, suppliedGas)
	case selPositions:
		return c.runPositions(accessibleState, data, suppliedGas)
	case selInitialize, selMint, selBurn, selCollect, selSwap:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		db := accessibleState.GetStateDB()
		if !enterGuard(db) {
			return nil, suppliedGas, ErrReentrant
		}
		defer exitGuard(db)
		switch selector {
		case selInitialize:
			return c.runInitialize(accessibleState, data, suppliedGas)
		case selMint:
			return c.runMint(accessibleState, caller, data, suppliedGas)
		case selBurn:
			return c.runBurn(accessibleState, caller, data, suppliedGas)
		case selCollect:
			return c.runCollect(accessibleState, caller, data, suppliedGas)
		default: // selSwap
			return c.runSwap(accessibleState, caller, data, suppliedGas)
		}
	default:
		return nil, suppliedGas, fmt.Errorf("%w: %#08x", ErrUnknownSelector, selector)
	}
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

// parsePoolKey decodes a static-tuple PoolKey from the first 128 bytes of an
// argument blob and returns it together with its poolId (== dex.PoolKey.ID()).
// It validates the canonical V3/V4 well-formedness (sorted currencies, fee and
// tickSpacing in range) so a malformed key cannot address state.
func parsePoolKey(data []byte) (dex.PoolKey, common.Hash, error) {
	if len(data) < 128 {
		return dex.PoolKey{}, common.Hash{}, fmt.Errorf("%w: poolKey needs 128 bytes", ErrBadArgs)
	}
	c0 := common.BytesToAddress(data[12:32])
	c1 := common.BytesToAddress(data[44:64])
	if bytes.Compare(c0.Bytes(), c1.Bytes()) >= 0 {
		return dex.PoolKey{}, common.Hash{}, ErrCurrencyOrder
	}
	fee := new(big.Int).SetBytes(data[64:96])
	if fee.Sign() < 0 || fee.Cmp(maxFee) >= 0 {
		return dex.PoolKey{}, common.Hash{}, ErrInvalidFee
	}
	ts := wordToInt(common.BytesToHash(data[96:128]))
	if ts.Cmp(big.NewInt(1)) < 0 || ts.Cmp(maxSpacing) > 0 {
		return dex.PoolKey{}, common.Hash{}, ErrInvalidTickSpacing
	}
	pk := dex.PoolKey{
		Currency0:   dex.Currency{Address: c0},
		Currency1:   dex.Currency{Address: c1},
		Fee:         uint32(fee.Uint64()),
		TickSpacing: int32(ts.Int64()),
		Hooks:       common.Address{},
	}
	id := pk.ID()
	return pk, common.BytesToHash(id[:]), nil
}

// parseTick decodes a signed int24 tick from a 32-byte word, REQUIRING it to lie in
// the usable [MinTick, MaxTick] band before any int32 truncation — so a huge word
// cannot wrap into an in-range tick.
func parseTick(word []byte) (int32, error) {
	v := wordToInt(common.BytesToHash(word))
	if v.Cmp(tickLowerBI) < 0 || v.Cmp(tickUpperBI) > 0 {
		return 0, dex.ErrTickOutOfRange
	}
	return int32(v.Int64()), nil
}

// validateTickRange enforces the V3 position bounds: lower < upper, both within the
// usable band, both aligned to the pool's tick spacing.
func validateTickRange(lower, upper, tickSpacing int32) error {
	if lower >= upper {
		return dex.ErrInvalidTickRange
	}
	if lower < dex.MinTick || upper > dex.MaxTick {
		return dex.ErrTickOutOfRange
	}
	if lower%tickSpacing != 0 || upper%tickSpacing != 0 {
		return ErrTickMisaligned
	}
	return nil
}

// ---------------------------------------------------------------------------
// initialize(poolKey, uint160 sqrtPriceX96) -> int24 tick
// ---------------------------------------------------------------------------

func (c *V3Contract) runInitialize(st contract.AccessibleState, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasInitialize {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasInitialize
	if len(data) != 128+32 {
		return nil, gas, fmt.Errorf("%w: initialize expects 160 bytes, got %d", ErrBadArgs, len(data))
	}
	pk, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	sqrtPriceX96 := wordToUint(common.BytesToHash(data[128:160]))

	db := st.GetStateDB()
	if isInitialized(db, poolId) {
		return nil, gas, dex.ErrPoolAlreadyInitialized
	}
	if sqrtPriceX96.Cmp(dex.MinSqrtRatio) < 0 || sqrtPriceX96.Cmp(dex.MaxSqrtRatio) >= 0 {
		return nil, gas, dex.ErrInvalidSqrtPrice
	}
	// Compose dex tick math for the initial tick.
	tick, err := dex.GetTickAtSqrtRatio(sqrtPriceX96)
	if err != nil {
		return nil, gas, err
	}

	storeSqrtPrice(db, poolId, sqrtPriceX96)
	storePoolTick(db, poolId, tick)
	// liquidity, feeGrowthGlobal{0,1} default to zero.

	emitInitialize(db, poolId, pk.Currency0.Address, pk.Currency1.Address, pk.Fee, pk.TickSpacing, tick, sqrtPriceX96)
	return intWord(big.NewInt(int64(tick))).Bytes(), gas, nil
}

// ---------------------------------------------------------------------------
// mint(poolKey, int24 tickLower, int24 tickUpper, uint128 amount) -> (uint256 amount0, uint256 amount1)
// ---------------------------------------------------------------------------

func (c *V3Contract) runMint(st contract.AccessibleState, caller common.Address, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasMint {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasMint
	if len(data) != 128+3*32 {
		return nil, gas, fmt.Errorf("%w: mint expects 224 bytes, got %d", ErrBadArgs, len(data))
	}
	pk, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	tickLower, err := parseTick(data[128:160])
	if err != nil {
		return nil, gas, err
	}
	tickUpper, err := parseTick(data[160:192])
	if err != nil {
		return nil, gas, err
	}
	amount := wordToUint(common.BytesToHash(data[192:224]))

	db := st.GetStateDB()
	if !isInitialized(db, poolId) {
		return nil, gas, dex.ErrPoolNotInitialized
	}
	if err := validateTickRange(tickLower, tickUpper, pk.TickSpacing); err != nil {
		return nil, gas, err
	}
	if amount.Sign() <= 0 {
		return nil, gas, ErrZeroAmount
	}
	if amount.Cmp(maxUint128) > 0 {
		return nil, gas, ErrAmountTooLarge
	}

	amount0, amount1, err := modifyLiquidity(db, pk, poolId, caller, tickLower, tickUpper, amount)
	if err != nil {
		return nil, gas, err
	}

	// Pull the owed tokens IN via the observed-delta custody idiom (no callback).
	if err := pullAsset(db, pk.Currency0.Address, caller, amount0); err != nil {
		return nil, gas, err
	}
	if err := pullAsset(db, pk.Currency1.Address, caller, amount1); err != nil {
		return nil, gas, err
	}

	emitMint(db, poolId, caller, tickLower, tickUpper, amount, amount0, amount1)

	out := make([]byte, 0, 64)
	out = append(out, uintWord(amount0).Bytes()...)
	out = append(out, uintWord(amount1).Bytes()...)
	return out, gas, nil
}

// ---------------------------------------------------------------------------
// burn(poolKey, int24 tickLower, int24 tickUpper, uint128 amount) -> (uint256 amount0, uint256 amount1)
// V3 semantics: burn does NOT transfer; it credits the freed principal (and any
// accrued fees) to the position's tokensOwed. collect performs the transfer.
// ---------------------------------------------------------------------------

func (c *V3Contract) runBurn(st contract.AccessibleState, caller common.Address, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasBurn {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasBurn
	if len(data) != 128+3*32 {
		return nil, gas, fmt.Errorf("%w: burn expects 224 bytes, got %d", ErrBadArgs, len(data))
	}
	pk, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	tickLower, err := parseTick(data[128:160])
	if err != nil {
		return nil, gas, err
	}
	tickUpper, err := parseTick(data[160:192])
	if err != nil {
		return nil, gas, err
	}
	amount := wordToUint(common.BytesToHash(data[192:224]))

	db := st.GetStateDB()
	if !isInitialized(db, poolId) {
		return nil, gas, dex.ErrPoolNotInitialized
	}
	if err := validateTickRange(tickLower, tickUpper, pk.TickSpacing); err != nil {
		return nil, gas, err
	}
	if amount.Sign() <= 0 {
		return nil, gas, ErrZeroAmount
	}

	posKey := dex.PositionKey(caller, tickLower, tickUpper, salt)
	if loadPosition(db, poolId, posKey).Liquidity.Cmp(amount) < 0 {
		return nil, gas, ErrInsufficientLiq
	}

	amount0, amount1, err := modifyLiquidity(db, pk, poolId, caller, tickLower, tickUpper, new(big.Int).Neg(amount))
	if err != nil {
		return nil, gas, err
	}

	// Credit the freed principal to tokensOwed (collect transfers it). The fee
	// accrual already happened inside modifyLiquidity -> updatePosition.
	if amount0.Sign() > 0 || amount1.Sign() > 0 {
		pos := loadPosition(db, poolId, posKey)
		pos.TokensOwed0 = new(big.Int).Add(pos.TokensOwed0, amount0)
		pos.TokensOwed1 = new(big.Int).Add(pos.TokensOwed1, amount1)
		storePosition(db, poolId, posKey, pos)
	}

	emitBurn(db, poolId, caller, tickLower, tickUpper, amount, amount0, amount1)

	out := make([]byte, 0, 64)
	out = append(out, uintWord(amount0).Bytes()...)
	out = append(out, uintWord(amount1).Bytes()...)
	return out, gas, nil
}

// ---------------------------------------------------------------------------
// collect(poolKey, int24 tickLower, int24 tickUpper, uint128 amount0Req, uint128 amount1Req)
//   -> (uint128 amount0, uint128 amount1)
// ---------------------------------------------------------------------------

func (c *V3Contract) runCollect(st contract.AccessibleState, caller common.Address, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasCollect {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasCollect
	if len(data) != 128+4*32 {
		return nil, gas, fmt.Errorf("%w: collect expects 256 bytes, got %d", ErrBadArgs, len(data))
	}
	pk, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	tickLower, err := parseTick(data[128:160])
	if err != nil {
		return nil, gas, err
	}
	tickUpper, err := parseTick(data[160:192])
	if err != nil {
		return nil, gas, err
	}
	amount0Req := wordToUint(common.BytesToHash(data[192:224]))
	amount1Req := wordToUint(common.BytesToHash(data[224:256]))

	db := st.GetStateDB()
	posKey := dex.PositionKey(caller, tickLower, tickUpper, salt)
	pos := loadPosition(db, poolId, posKey)

	amount0 := bigMin(amount0Req, pos.TokensOwed0)
	amount1 := bigMin(amount1Req, pos.TokensOwed1)

	// EFFECTS BEFORE INTERACTION: debit owed and reserve before paying out, so a
	// reentrant token callback sees the reduced balances (the global guard already
	// blocks reentry; this ordering is defence in depth).
	pos.TokensOwed0 = new(big.Int).Sub(pos.TokensOwed0, amount0)
	pos.TokensOwed1 = new(big.Int).Sub(pos.TokensOwed1, amount1)
	storePosition(db, poolId, posKey, pos)

	if err := payAsset(db, pk.Currency0.Address, caller, amount0); err != nil {
		return nil, gas, err
	}
	if err := payAsset(db, pk.Currency1.Address, caller, amount1); err != nil {
		return nil, gas, err
	}

	emitCollect(db, poolId, caller, tickLower, tickUpper, amount0, amount1)

	out := make([]byte, 0, 64)
	out = append(out, uintWord(amount0).Bytes()...)
	out = append(out, uintWord(amount1).Bytes()...)
	return out, gas, nil
}

// ---------------------------------------------------------------------------
// swap(poolKey, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96)
//   -> (int256 amount0, int256 amount1)
//
// The tick-crossing loop. V4 sign convention: amountSpecified < 0 = exact input,
// > 0 = exact output. The per-step engine (dex.ComputeSwapStep) and the next-tick
// search (dex.NextInitializedTickWithinOneWord) are composed verbatim; this function
// owns only the loop, fee-growth accrual, tick crossing, and settlement.
// ---------------------------------------------------------------------------

func (c *V3Contract) runSwap(st contract.AccessibleState, caller common.Address, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasSwapBase {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasSwapBase
	if len(data) != 128+3*32 {
		return nil, gas, fmt.Errorf("%w: swap expects 224 bytes, got %d", ErrBadArgs, len(data))
	}
	pk, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	zeroForOne := wordToUint(common.BytesToHash(data[128:160])).Sign() != 0
	amountSpecified := wordToInt(common.BytesToHash(data[160:192]))
	sqrtPriceLimit := wordToUint(common.BytesToHash(data[192:224]))

	db := st.GetStateDB()
	if !isInitialized(db, poolId) {
		return nil, gas, dex.ErrPoolNotInitialized
	}
	if amountSpecified.Sign() == 0 {
		return nil, gas, ErrZeroAmount
	}

	sqrtPrice := loadSqrtPrice(db, poolId)
	tick := loadPoolTick(db, poolId)
	liquidity := loadLiquidity(db, poolId)
	fg0 := loadFeeGrowthGlobal0(db, poolId)
	fg1 := loadFeeGrowthGlobal1(db, poolId)

	// Price-limit invariant (Uniswap V3 Pool.swap require()).
	if zeroForOne {
		if sqrtPriceLimit.Cmp(sqrtPrice) >= 0 || sqrtPriceLimit.Cmp(dex.MinSqrtRatio) <= 0 {
			return nil, gas, dex.ErrInvalidSqrtPrice
		}
	} else {
		if sqrtPriceLimit.Cmp(sqrtPrice) <= 0 || sqrtPriceLimit.Cmp(dex.MaxSqrtRatio) >= 0 {
			return nil, gas, dex.ErrInvalidSqrtPrice
		}
	}

	feePips := pk.Fee
	exactInput := amountSpecified.Sign() < 0
	amountRemaining := new(big.Int).Set(amountSpecified)
	totalIn := big.NewInt(0)  // input consumed, incl. fee
	totalOut := big.NewInt(0) // output produced

	for amountRemaining.Sign() != 0 && sqrtPrice.Cmp(sqrtPriceLimit) != 0 {
		if gas < GasSwapStep {
			return nil, 0, ErrOutOfGas
		}
		gas -= GasSwapStep

		sqrtPriceStart := new(big.Int).Set(sqrtPrice)

		// Next initialized tick (composed) and its price (composed).
		tickNext, initialized := nextInitializedTick(db, poolId, tick, pk.TickSpacing, zeroForOne)
		if tickNext < dex.MinTick {
			tickNext = dex.MinTick
		} else if tickNext > dex.MaxTick {
			tickNext = dex.MaxTick
		}
		sqrtPriceNextTick, err := dex.GetSqrtRatioAtTick(tickNext)
		if err != nil {
			return nil, gas, err
		}

		// Clamp the step target to the price limit.
		target := new(big.Int).Set(sqrtPriceNextTick)
		if zeroForOne {
			if target.Cmp(sqrtPriceLimit) < 0 {
				target = new(big.Int).Set(sqrtPriceLimit)
			}
		} else {
			if target.Cmp(sqrtPriceLimit) > 0 {
				target = new(big.Int).Set(sqrtPriceLimit)
			}
		}

		// The per-step swap engine — composed verbatim.
		step := dex.ComputeSwapStep(sqrtPrice, target, liquidity, amountRemaining, feePips)

		consumed := new(big.Int).Add(step.AmountIn, step.FeeAmount)
		if exactInput {
			amountRemaining = new(big.Int).Add(amountRemaining, consumed)
		} else {
			amountRemaining = new(big.Int).Sub(amountRemaining, step.AmountOut)
		}
		totalIn = new(big.Int).Add(totalIn, consumed)
		totalOut = new(big.Int).Add(totalOut, step.AmountOut)

		// Fees accrue to the INPUT token's global accumulator, on the liquidity that
		// was active DURING the step (before any crossing).
		if liquidity.Sign() > 0 && step.FeeAmount.Sign() > 0 {
			growth := dex.MulDiv(step.FeeAmount, dex.Q128, liquidity)
			if zeroForOne {
				fg0 = add256(fg0, growth)
			} else {
				fg1 = add256(fg1, growth)
			}
		}

		sqrtPrice = step.SqrtRatioNextX96

		switch {
		case sqrtPrice.Cmp(sqrtPriceNextTick) == 0:
			// Reached the tick boundary: cross it (if initialized) and step the tick.
			if initialized {
				net := crossTick(db, poolId, tickNext, fg0, fg1)
				if zeroForOne {
					net = new(big.Int).Neg(net)
				}
				liquidity = new(big.Int).Add(liquidity, net)
				if liquidity.Sign() < 0 {
					return nil, gas, ErrLiquidityUnderflow
				}
			}
			if zeroForOne {
				tick = tickNext - 1
			} else {
				tick = tickNext
			}
		case sqrtPrice.Cmp(sqrtPriceStart) != 0:
			// Partial step (stopped at the limit or ran out of input): recompute tick.
			t, err := dex.GetTickAtSqrtRatio(sqrtPrice)
			if err != nil {
				return nil, gas, err
			}
			tick = t
		}
	}

	// Persist the new pool state.
	storeSqrtPrice(db, poolId, sqrtPrice)
	storePoolTick(db, poolId, tick)
	storeLiquidity(db, poolId, liquidity)
	storeFeeGrowthGlobal0(db, poolId, fg0)
	storeFeeGrowthGlobal1(db, poolId, fg1)

	// Settle: pull the consumed input, push the produced output (observed-delta).
	inAsset, outAsset := pk.Currency1.Address, pk.Currency0.Address
	if zeroForOne {
		inAsset, outAsset = pk.Currency0.Address, pk.Currency1.Address
	}
	if err := pullAsset(db, inAsset, caller, totalIn); err != nil {
		return nil, gas, err
	}
	if err := payAsset(db, outAsset, caller, totalOut); err != nil {
		return nil, gas, err
	}

	// Signed deltas: + = pool received from user, − = pool paid to user.
	var amount0, amount1 *big.Int
	if zeroForOne {
		amount0 = new(big.Int).Set(totalIn)
		amount1 = new(big.Int).Neg(totalOut)
	} else {
		amount0 = new(big.Int).Neg(totalOut)
		amount1 = new(big.Int).Set(totalIn)
	}

	emitSwap(db, poolId, caller, amount0, amount1, sqrtPrice, liquidity, tick)

	out := make([]byte, 0, 64)
	out = append(out, intWord(amount0).Bytes()...)
	out = append(out, intWord(amount1).Bytes()...)
	return out, gas, nil
}

// ---------------------------------------------------------------------------
// modifyLiquidity is the shared mint/burn core (V3 Pool._modifyPosition). It updates
// the two boundary ticks, the tick bitmap, the position (accruing fees), and the
// pool's active liquidity, then returns the |amount0|, |amount1| of principal moved.
// Token custody (pull on mint, owed-credit on burn) is the caller's concern.
// ---------------------------------------------------------------------------

func modifyLiquidity(
	db contract.StateDB,
	pk dex.PoolKey,
	poolId common.Hash,
	owner common.Address,
	tickLower, tickUpper int32,
	liquidityDelta *big.Int,
) (amount0, amount1 *big.Int, err error) {
	sqrtPrice := loadSqrtPrice(db, poolId)
	currentTick := loadPoolTick(db, poolId)
	fg0 := loadFeeGrowthGlobal0(db, poolId)
	fg1 := loadFeeGrowthGlobal1(db, poolId)

	// Composed dex tick math for the range boundaries.
	sqrtLower, err := dex.GetSqrtRatioAtTick(tickLower)
	if err != nil {
		return nil, nil, err
	}
	sqrtUpper, err := dex.GetSqrtRatioAtTick(tickUpper)
	if err != nil {
		return nil, nil, err
	}

	// Update both boundary ticks (V3 ordering: ticks BEFORE getFeeGrowthInside, so a
	// freshly-initialized tick's feeGrowthOutside is set first).
	flippedLower := updateTick(db, poolId, tickLower, currentTick, liquidityDelta, false, fg0, fg1)
	flippedUpper := updateTick(db, poolId, tickUpper, currentTick, liquidityDelta, true, fg0, fg1)
	if flippedLower {
		flipTickBitmap(db, poolId, tickLower, pk.TickSpacing)
	}
	if flippedUpper {
		flipTickBitmap(db, poolId, tickUpper, pk.TickSpacing)
	}

	// Update the position: accrues fees into tokensOwed, then adjusts liquidity.
	inside0, inside1 := getFeeGrowthInside(db, poolId, tickLower, tickUpper, currentTick, fg0, fg1)
	if err := updatePosition(db, poolId, owner, tickLower, tickUpper, liquidityDelta, inside0, inside1); err != nil {
		return nil, nil, err
	}

	// On removal, clear any tick that flipped to uninitialized (V3 Tick.clear).
	if liquidityDelta.Sign() < 0 {
		if flippedLower {
			clearTickInfo(db, poolId, tickLower)
		}
		if flippedUpper {
			clearTickInfo(db, poolId, tickUpper)
		}
	}

	// Token amounts for the principal, and the pool's active-liquidity change. Amounts
	// are computed with dex.GetAmountsForLiquidity (round-down; see package doc §3).
	amount0 = big.NewInt(0)
	amount1 = big.NewInt(0)
	absLiq := new(big.Int).Abs(liquidityDelta)
	if absLiq.Sign() > 0 {
		amount0, amount1 = dex.GetAmountsForLiquidity(sqrtPrice, sqrtLower, sqrtUpper, absLiq)
		// The pool's active liquidity changes ONLY when its current tick is in range.
		if currentTick >= tickLower && currentTick < tickUpper {
			newLiq := new(big.Int).Add(loadLiquidity(db, poolId), liquidityDelta)
			if newLiq.Sign() < 0 {
				return nil, nil, ErrLiquidityUnderflow
			}
			storeLiquidity(db, poolId, newLiq)
		}
	}
	return amount0, amount1, nil
}

// updateTick applies a signed liquidity delta to one tick (V3 Tick.update), returning
// whether the tick flipped between initialized and uninitialized.
func updateTick(db stateRW, poolId common.Hash, tick, currentTick int32, liquidityDelta *big.Int, upper bool, fg0, fg1 *big.Int) bool {
	info := loadTickInfo(db, poolId, tick)
	grossBefore := info.LiquidityGross
	grossAfter := new(big.Int).Add(grossBefore, liquidityDelta)
	flipped := (grossAfter.Sign() == 0) != (grossBefore.Sign() == 0)

	if grossBefore.Sign() == 0 {
		// First reference: by convention all growth so far is "below" the tick if the
		// tick is at or below the current tick.
		if tick <= currentTick {
			info.FeeGrowthOutside0X128 = new(big.Int).Set(fg0)
			info.FeeGrowthOutside1X128 = new(big.Int).Set(fg1)
		}
	}
	info.LiquidityGross = grossAfter
	// liquidityNet: lower ticks add the delta, upper ticks subtract it.
	if upper {
		info.LiquidityNet = new(big.Int).Sub(info.LiquidityNet, liquidityDelta)
	} else {
		info.LiquidityNet = new(big.Int).Add(info.LiquidityNet, liquidityDelta)
	}
	storeTickInfo(db, poolId, tick, info)
	return flipped
}

// getFeeGrowthInside computes the fee growth INSIDE a tick range (V3
// Tick.getFeeGrowthInside), all in 256-bit modular arithmetic.
func getFeeGrowthInside(db stateRW, poolId common.Hash, tickLower, tickUpper, currentTick int32, fg0, fg1 *big.Int) (inside0, inside1 *big.Int) {
	lower := loadTickInfo(db, poolId, tickLower)
	upper := loadTickInfo(db, poolId, tickUpper)

	var below0, below1, above0, above1 *big.Int
	if currentTick >= tickLower {
		below0 = lower.FeeGrowthOutside0X128
		below1 = lower.FeeGrowthOutside1X128
	} else {
		below0 = sub256(fg0, lower.FeeGrowthOutside0X128)
		below1 = sub256(fg1, lower.FeeGrowthOutside1X128)
	}
	if currentTick < tickUpper {
		above0 = upper.FeeGrowthOutside0X128
		above1 = upper.FeeGrowthOutside1X128
	} else {
		above0 = sub256(fg0, upper.FeeGrowthOutside0X128)
		above1 = sub256(fg1, upper.FeeGrowthOutside1X128)
	}
	inside0 = sub256(sub256(fg0, below0), above0)
	inside1 = sub256(sub256(fg1, below1), above1)
	return
}

// updatePosition accrues owed fees on a position's existing liquidity, then applies
// the signed liquidity delta (V3 Position.update). Fee accrual composes dex.MulDiv.
func updatePosition(db stateRW, poolId common.Hash, owner common.Address, tickLower, tickUpper int32, liquidityDelta, inside0, inside1 *big.Int) error {
	posKey := dex.PositionKey(owner, tickLower, tickUpper, salt)
	pos := loadPosition(db, poolId, posKey)

	if pos.Liquidity.Sign() > 0 {
		// owed += L * (feeGrowthInsideNow − feeGrowthInsideLast) / 2^128, the delta
		// taken mod 2^256 so it is the true (small) growth even across a wrap.
		owed0 := dex.MulDiv(sub256(inside0, pos.FeeGrowthInside0LastX128), pos.Liquidity, dex.Q128)
		owed1 := dex.MulDiv(sub256(inside1, pos.FeeGrowthInside1LastX128), pos.Liquidity, dex.Q128)
		pos.TokensOwed0 = new(big.Int).Add(pos.TokensOwed0, owed0)
		pos.TokensOwed1 = new(big.Int).Add(pos.TokensOwed1, owed1)
	}

	newLiq := new(big.Int).Add(pos.Liquidity, liquidityDelta)
	if newLiq.Sign() < 0 {
		return ErrLiquidityUnderflow
	}
	pos.Liquidity = newLiq
	pos.FeeGrowthInside0LastX128 = inside0
	pos.FeeGrowthInside1LastX128 = inside1
	storePosition(db, poolId, posKey, pos)
	return nil
}

// crossTick flips a tick's feeGrowthOutside accumulators as the swap price crosses it
// (V3 Tick.cross) and returns its liquidityNet.
func crossTick(db stateRW, poolId common.Hash, tick int32, fg0, fg1 *big.Int) *big.Int {
	info := loadTickInfo(db, poolId, tick)
	info.FeeGrowthOutside0X128 = sub256(fg0, info.FeeGrowthOutside0X128)
	info.FeeGrowthOutside1X128 = sub256(fg1, info.FeeGrowthOutside1X128)
	storeTickInfo(db, poolId, tick, info)
	return info.LiquidityNet
}

// ---------------------------------------------------------------------------
// Read-only views. Permitted in static calls; they take no guard and never write.
// ---------------------------------------------------------------------------

// slot0(poolKey) -> (uint160 sqrtPriceX96, int24 tick).
func (c *V3Contract) runSlot0(st contract.AccessibleState, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasView {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasView
	_, poolId, err := parsePoolKey(data)
	if err != nil {
		return nil, gas, err
	}
	db := st.GetStateDB()
	out := make([]byte, 0, 64)
	out = append(out, uintWord(loadSqrtPrice(db, poolId)).Bytes()...)
	out = append(out, intWord(big.NewInt(int64(loadPoolTick(db, poolId)))).Bytes()...)
	return out, gas, nil
}

// liquidity(poolKey) -> uint128.
func (c *V3Contract) runLiquidity(st contract.AccessibleState, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasView {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasView
	_, poolId, err := parsePoolKey(data)
	if err != nil {
		return nil, gas, err
	}
	return uintWord(loadLiquidity(st.GetStateDB(), poolId)).Bytes(), gas, nil
}

// ticks(poolKey, int24 tick) -> (uint128 liquidityGross, int128 liquidityNet,
// uint256 feeGrowthOutside0X128, uint256 feeGrowthOutside1X128).
func (c *V3Contract) runTicks(st contract.AccessibleState, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasView {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasView
	if len(data) != 128+32 {
		return nil, gas, fmt.Errorf("%w: ticks expects 160 bytes, got %d", ErrBadArgs, len(data))
	}
	_, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	tick, err := parseTick(data[128:160])
	if err != nil {
		return nil, gas, err
	}
	info := loadTickInfo(st.GetStateDB(), poolId, tick)
	out := make([]byte, 0, 128)
	out = append(out, uintWord(info.LiquidityGross).Bytes()...)
	out = append(out, intWord(info.LiquidityNet).Bytes()...)
	out = append(out, uintWord(info.FeeGrowthOutside0X128).Bytes()...)
	out = append(out, uintWord(info.FeeGrowthOutside1X128).Bytes()...)
	return out, gas, nil
}

// positions(poolKey, address owner, int24 tickLower, int24 tickUpper)
//
//	-> (uint128 liquidity, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128,
//	    uint128 tokensOwed0, uint128 tokensOwed1).
func (c *V3Contract) runPositions(st contract.AccessibleState, data []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < GasView {
		return nil, 0, ErrOutOfGas
	}
	gas := suppliedGas - GasView
	if len(data) != 128+3*32 {
		return nil, gas, fmt.Errorf("%w: positions expects 224 bytes, got %d", ErrBadArgs, len(data))
	}
	_, poolId, err := parsePoolKey(data[:128])
	if err != nil {
		return nil, gas, err
	}
	owner := common.BytesToAddress(data[140:160])
	tickLower, err := parseTick(data[160:192])
	if err != nil {
		return nil, gas, err
	}
	tickUpper, err := parseTick(data[192:224])
	if err != nil {
		return nil, gas, err
	}
	pos := loadPosition(st.GetStateDB(), poolId, dex.PositionKey(owner, tickLower, tickUpper, salt))
	out := make([]byte, 0, 160)
	out = append(out, uintWord(pos.Liquidity).Bytes()...)
	out = append(out, uintWord(pos.FeeGrowthInside0LastX128).Bytes()...)
	out = append(out, uintWord(pos.FeeGrowthInside1LastX128).Bytes()...)
	out = append(out, uintWord(pos.TokensOwed0).Bytes()...)
	out = append(out, uintWord(pos.TokensOwed1).Bytes()...)
	return out, gas, nil
}

// bigMin returns a fresh copy of the smaller of a, b.
func bigMin(a, b *big.Int) *big.Int {
	if a.Cmp(b) <= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}
