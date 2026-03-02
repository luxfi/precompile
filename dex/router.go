// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
)

// SwapVenue identifies the liquidity source for a swap hop.
type SwapVenue uint8

const (
	VenueV4Native SwapVenue = iota // Precompile pool (LXPool)
	VenueV3                        // Uniswap V3 concentrated liquidity contract
	VenueV2                        // Uniswap V2 constant product contract
)

// Router gas costs
const (
	GasQuote          uint64 = 5_000  // Quote without execution
	GasSingleSwap     uint64 = 15_000 // Single-hop routed swap
	GasMultiHopBase   uint64 = 15_000 // Multi-hop base cost
	GasMultiHopPerHop uint64 = 10_000 // Additional cost per hop
	GasRouteLookup    uint64 = 3_000  // Route discovery
)

// Router method selectors
const (
	SelectorExactInputSingle      uint32 = 0x0A000000
	SelectorExactInput            uint32 = 0x0A000001
	SelectorExactOutputSingle     uint32 = 0x0A000002
	SelectorExactOutput           uint32 = 0x0A000003
	SelectorQuoteExactInputSingle uint32 = 0x0B000000
	SelectorQuoteExactInput       uint32 = 0x0B000001
	SelectorGetBestRoute          uint32 = 0x0C000000
)

// Well-known V3/V2 factory and router addresses (deployed contracts on C-chain).
// These are used for STATICCALL-based quote fallback when V4 lacks liquidity.
var (
	// V3 contracts (Uniswap V3 style, deployed via standard contracts)
	v3QuoterAddr common.Address // Set via router config if deployed
	v3FactoryAddr common.Address

	// V2 contracts (Uniswap V2 style, deployed via standard contracts)
	v2RouterAddr  common.Address
	v2FactoryAddr common.Address
)

// SwapExactInputSingleParams for a single-hop exact-input swap through the router.
type SwapExactInputSingleParams struct {
	TokenIn           common.Address
	TokenOut          common.Address
	AmountIn          *big.Int
	AmountOutMinimum  *big.Int
	Fee               uint24 // Preferred fee tier (0 = auto-select)
	SqrtPriceLimitX96 *big.Int
	Deadline          uint64
}

// SwapExactInputParams for multi-hop exact-input swap.
type SwapExactInputParams struct {
	Path             []common.Address // Alternating tokens: [tokenIn, tokenMid..., tokenOut]
	AmountIn         *big.Int
	AmountOutMinimum *big.Int
	Deadline         uint64
}

// QuoteResult holds the result of a route quote.
type QuoteResult struct {
	AmountOut *big.Int
	Venue     SwapVenue
	PoolID    [32]byte       // V4 pool ID (zero for V3/V2)
	PoolAddr  common.Address // V3/V2 pool address (zero for V4)
	GasEstimate uint64
}

// LXRouter implements unified V2/V3/V4 swap routing.
// It queries V4 native pools first (zero-cost precompile state lookup),
// then falls back to V3 and V2 deployed contracts via STATICCALL.
type LXRouter struct {
	poolManager *PoolManager
}

// NewLXRouter creates a router linked to the singleton PoolManager.
func NewLXRouter(pm *PoolManager) *LXRouter {
	return &LXRouter{poolManager: pm}
}

// =========================================================================
// Exact Input Single (best venue, single hop)
// =========================================================================

// ExactInputSingle routes a single-hop swap through the best available venue.
func (r *LXRouter) ExactInputSingle(
	stateDB StateDB,
	caller common.Address,
	params SwapExactInputSingleParams,
) (*big.Int, SwapVenue, error) {
	// 1. Try V4 native pools first (cheapest)
	amountOut, poolID, poolKey, err := r.quoteV4(stateDB, params.TokenIn, params.TokenOut, params.AmountIn, params.Fee)
	if err == nil && amountOut.Sign() > 0 && (params.AmountOutMinimum == nil || amountOut.Cmp(params.AmountOutMinimum) >= 0) {
		// F8: Execute through V4 with the actual PoolKey (not empty)
		delta, execErr := r.executeV4Swap(stateDB, caller, poolID, poolKey, params.TokenIn, params.TokenOut, params.AmountIn, params.SqrtPriceLimitX96)
		if execErr == nil {
			return delta, VenueV4Native, nil
		}
		// V4 execution failed, fall through to V3/V2
	}

	// 2. Try V3 (concentrated liquidity)
	v3Amount, v3Err := r.quoteV3(stateDB, params.TokenIn, params.TokenOut, params.AmountIn, params.Fee)
	if v3Err == nil && v3Amount.Sign() > 0 {
		// V3 available — check if better than V4 quote
		if amountOut == nil || v3Amount.Cmp(amountOut) > 0 {
			if params.AmountOutMinimum == nil || v3Amount.Cmp(params.AmountOutMinimum) >= 0 {
				return v3Amount, VenueV3, nil
			}
		}
	}

	// 3. Try V2 (constant product)
	v2Amount, v2Err := r.quoteV2(stateDB, params.TokenIn, params.TokenOut, params.AmountIn)
	if v2Err == nil && v2Amount.Sign() > 0 {
		if params.AmountOutMinimum == nil || v2Amount.Cmp(params.AmountOutMinimum) >= 0 {
			return v2Amount, VenueV2, nil
		}
	}

	// No venue has sufficient liquidity
	if amountOut != nil && amountOut.Sign() > 0 {
		// V4 had some liquidity but below minimum
		return amountOut, VenueV4Native, fmt.Errorf("insufficient output amount: got %s, want >= %s", amountOut, params.AmountOutMinimum)
	}

	return big.NewInt(0), VenueV4Native, ErrInsufficientLiquidity
}

// =========================================================================
// Exact Input Multi-hop
// =========================================================================

// ExactInput routes a multi-hop swap, picking the best venue per hop.
func (r *LXRouter) ExactInput(
	stateDB StateDB,
	caller common.Address,
	params SwapExactInputParams,
) (*big.Int, error) {
	if len(params.Path) < 2 {
		return nil, fmt.Errorf("path must have at least 2 tokens")
	}

	currentAmount := new(big.Int).Set(params.AmountIn)

	for i := 0; i < len(params.Path)-1; i++ {
		tokenIn := params.Path[i]
		tokenOut := params.Path[i+1]

		hopParams := SwapExactInputSingleParams{
			TokenIn:  tokenIn,
			TokenOut: tokenOut,
			AmountIn: currentAmount,
		}

		hopOut, _, err := r.ExactInputSingle(stateDB, caller, hopParams)
		if err != nil {
			return nil, fmt.Errorf("hop %d (%s -> %s) failed: %w", i, tokenIn.Hex(), tokenOut.Hex(), err)
		}

		currentAmount = hopOut
	}

	if params.AmountOutMinimum != nil && currentAmount.Cmp(params.AmountOutMinimum) < 0 {
		return nil, fmt.Errorf("insufficient output: got %s, want >= %s", currentAmount, params.AmountOutMinimum)
	}

	return currentAmount, nil
}

// =========================================================================
// Quote Functions (read-only, no state changes)
// =========================================================================

// QuoteExactInputSingle returns the expected output amount without executing.
func (r *LXRouter) QuoteExactInputSingle(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
	fee uint24,
) ([]QuoteResult, error) {
	results := make([]QuoteResult, 0, 3)

	// Quote V4
	v4Amount, poolID, _, err := r.quoteV4(stateDB, tokenIn, tokenOut, amountIn, fee)
	if err == nil && v4Amount.Sign() > 0 {
		results = append(results, QuoteResult{
			AmountOut:   v4Amount,
			Venue:       VenueV4Native,
			PoolID:      poolID,
			GasEstimate: GasSwap,
		})
	}

	// Quote V3
	v3Amount, err := r.quoteV3(stateDB, tokenIn, tokenOut, amountIn, fee)
	if err == nil && v3Amount.Sign() > 0 {
		results = append(results, QuoteResult{
			AmountOut:   v3Amount,
			Venue:       VenueV3,
			GasEstimate: 150_000, // typical V3 swap gas
		})
	}

	// Quote V2
	v2Amount, err := r.quoteV2(stateDB, tokenIn, tokenOut, amountIn)
	if err == nil && v2Amount.Sign() > 0 {
		results = append(results, QuoteResult{
			AmountOut:   v2Amount,
			Venue:       VenueV2,
			GasEstimate: 100_000, // typical V2 swap gas
		})
	}

	if len(results) == 0 {
		return nil, ErrInsufficientLiquidity
	}

	return results, nil
}

// GetBestRoute finds the optimal route across all venues.
func (r *LXRouter) GetBestRoute(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
) (*QuoteResult, error) {
	quotes, err := r.QuoteExactInputSingle(stateDB, tokenIn, tokenOut, amountIn, 0)
	if err != nil {
		return nil, err
	}

	// Find best output
	var best *QuoteResult
	for i := range quotes {
		if best == nil || quotes[i].AmountOut.Cmp(best.AmountOut) > 0 {
			best = &quotes[i]
		}
	}

	return best, nil
}

// =========================================================================
// V4 Native Pool Queries (precompile state, zero-cost)
// =========================================================================

// quoteV4 checks all V4 pools for the given pair and returns the best quote.
// Returns the best output amount, pool ID, pool key, and any error.
func (r *LXRouter) quoteV4(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
	preferredFee uint24,
) (*big.Int, [32]byte, PoolKey, error) {
	// Sort currencies
	var c0, c1 Currency
	var zeroForOne bool
	if tokenIn.Hex() < tokenOut.Hex() {
		c0 = Currency{Address: tokenIn}
		c1 = Currency{Address: tokenOut}
		zeroForOne = true
	} else {
		c0 = Currency{Address: tokenOut}
		c1 = Currency{Address: tokenIn}
		zeroForOne = false
	}

	// Try standard fee tiers
	feeTiers := []uint24{Fee001, Fee005, Fee030, Fee100}
	if preferredFee > 0 {
		// Put preferred fee first
		feeTiers = append([]uint24{preferredFee}, feeTiers...)
	}

	tickSpacings := map[uint24]int24{
		Fee001: TickSpacing001,
		Fee005: TickSpacing005,
		Fee030: TickSpacing030,
		Fee100: TickSpacing100,
	}

	var bestAmount *big.Int
	var bestPoolID [32]byte
	var bestKey PoolKey

	for _, fee := range feeTiers {
		ts, ok := tickSpacings[fee]
		if !ok {
			ts = TickSpacing030 // default
		}

		key := PoolKey{
			Currency0:   c0,
			Currency1:   c1,
			Fee:         fee,
			TickSpacing: ts,
			Hooks:       common.Address{}, // no hooks for standard routing
		}

		poolID := key.ID()
		pool := r.poolManager.getPool(stateDB, poolID)

		if !pool.IsInitialized() || pool.Liquidity.Sign() <= 0 {
			continue
		}

		// Calculate expected output
		var output *big.Int
		if zeroForOne {
			output = r.poolManager.calculateSwapOutput(pool, amountIn, true)
		} else {
			output = r.poolManager.calculateSwapOutput(pool, amountIn, false)
		}

		if output.Sign() > 0 && (bestAmount == nil || output.Cmp(bestAmount) > 0) {
			bestAmount = output
			bestPoolID = poolID
			bestKey = key
		}
	}

	if bestAmount == nil || bestAmount.Sign() <= 0 {
		return big.NewInt(0), [32]byte{}, PoolKey{}, ErrPoolNotFound
	}

	return bestAmount, bestPoolID, bestKey, nil
}

// executeV4Swap executes a swap through a specific V4 pool, mutating pool state.
// F8: Accepts the actual PoolKey so fees and tick spacing are applied correctly.
func (r *LXRouter) executeV4Swap(
	stateDB StateDB,
	caller common.Address,
	poolID [32]byte,
	key PoolKey,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
	sqrtPriceLimitX96 *big.Int,
) (*big.Int, error) {
	pool, ok := r.poolManager.pools[poolID]
	if !ok {
		return nil, ErrPoolNotFound
	}

	// Determine direction
	zeroForOne := tokenIn.Hex() < tokenOut.Hex()

	// Set price limit if not specified
	if sqrtPriceLimitX96 == nil || sqrtPriceLimitX96.Sign() == 0 {
		if zeroForOne {
			sqrtPriceLimitX96 = new(big.Int).Add(MinSqrtRatio, big.NewInt(1))
		} else {
			sqrtPriceLimitX96 = new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1))
		}
	}

	// Build swap params
	params := SwapParams{
		ZeroForOne:        zeroForOne,
		AmountSpecified:   amountIn,
		SqrtPriceLimitX96: sqrtPriceLimitX96,
	}

	// Execute via pool manager's swap math
	delta, newTick, err := r.poolManager.executeSwap(pool, key, params)
	if err != nil {
		return nil, err
	}

	// Update pool state
	pool.Tick = newTick
	r.poolManager.setPool(stateDB, poolID, pool)

	// Return output amount (the side the caller receives is negative in delta)
	if zeroForOne {
		if delta.Amount1.Sign() < 0 {
			return new(big.Int).Neg(delta.Amount1), nil
		}
		return delta.Amount1, nil
	}
	if delta.Amount0.Sign() < 0 {
		return new(big.Int).Neg(delta.Amount0), nil
	}
	return delta.Amount0, nil
}

// =========================================================================
// V3 Fallback (STATICCALL to deployed contracts)
// =========================================================================

// quoteV3 queries a V3 QuoterV2 contract for a swap quote.
// Returns (0, nil) if V3 is not deployed or has no liquidity.
func (r *LXRouter) quoteV3(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
	fee uint24,
) (*big.Int, error) {
	if v3QuoterAddr == (common.Address{}) {
		return big.NewInt(0), fmt.Errorf("V3 quoter not configured")
	}

	// In production, this would STATICCALL the V3 QuoterV2 contract:
	// quoteExactInputSingle(QuoteExactInputSingleParams)
	// For now, return zero — V3 contracts need to be deployed first.
	return big.NewInt(0), fmt.Errorf("V3 not deployed")
}

// =========================================================================
// V2 Fallback (STATICCALL to deployed contracts)
// =========================================================================

// quoteV2 queries a V2 Router for a swap quote.
// Returns (0, nil) if V2 is not deployed or has no liquidity.
func (r *LXRouter) quoteV2(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
) (*big.Int, error) {
	if v2RouterAddr == (common.Address{}) {
		return big.NewInt(0), fmt.Errorf("V2 router not configured")
	}

	// In production, this would STATICCALL the V2 Router:
	// getAmountsOut(amountIn, [tokenIn, tokenOut])
	// For now, return zero — V2 contracts need to be deployed first.
	return big.NewInt(0), fmt.Errorf("V2 not deployed")
}

// =========================================================================
// ABI Encoding/Decoding
// =========================================================================

// DecodeExactInputSingleParams decodes router input for ExactInputSingle.
// Format: tokenIn(20) + tokenOut(20) + amountIn(32) + amountOutMin(32) + fee(3) + sqrtPriceLimit(32) + deadline(8)
func DecodeExactInputSingleParams(input []byte) (SwapExactInputSingleParams, error) {
	if len(input) < 107 { // 20+20+32+32+3
		return SwapExactInputSingleParams{}, fmt.Errorf("input too short for ExactInputSingle")
	}

	params := SwapExactInputSingleParams{
		TokenIn:          common.BytesToAddress(input[0:20]),
		TokenOut:         common.BytesToAddress(input[20:40]),
		AmountIn:         new(big.Int).SetBytes(input[40:72]),
		AmountOutMinimum: new(big.Int).SetBytes(input[72:104]),
	}

	var feeBytes [4]byte
	copy(feeBytes[1:], input[104:107])
	params.Fee = binary.BigEndian.Uint32(feeBytes[:])

	if len(input) >= 139 {
		params.SqrtPriceLimitX96 = new(big.Int).SetBytes(input[107:139])
	}

	if len(input) >= 147 {
		params.Deadline = binary.BigEndian.Uint64(input[139:147])
	}

	return params, nil
}

// DecodeExactInputParams decodes router input for ExactInput (multi-hop).
// Format: numTokens(1) + tokens(numTokens*20) + amountIn(32) + amountOutMin(32) + deadline(8)
func DecodeExactInputParams(input []byte) (SwapExactInputParams, error) {
	if len(input) < 1 {
		return SwapExactInputParams{}, fmt.Errorf("input too short")
	}

	numTokens := int(input[0])
	if numTokens < 2 {
		return SwapExactInputParams{}, fmt.Errorf("path must have at least 2 tokens")
	}

	expectedLen := 1 + numTokens*20 + 32 + 32
	if len(input) < expectedLen {
		return SwapExactInputParams{}, fmt.Errorf("input too short for ExactInput")
	}

	params := SwapExactInputParams{
		Path: make([]common.Address, numTokens),
	}

	offset := 1
	for i := 0; i < numTokens; i++ {
		params.Path[i] = common.BytesToAddress(input[offset : offset+20])
		offset += 20
	}

	params.AmountIn = new(big.Int).SetBytes(input[offset : offset+32])
	offset += 32
	params.AmountOutMinimum = new(big.Int).SetBytes(input[offset : offset+32])
	offset += 32

	if len(input) >= offset+8 {
		params.Deadline = binary.BigEndian.Uint64(input[offset : offset+8])
	}

	return params, nil
}

// DecodeQuoteParams decodes a quote request.
// Format: tokenIn(20) + tokenOut(20) + amountIn(32) + fee(3)
func DecodeQuoteParams(input []byte) (common.Address, common.Address, *big.Int, uint24, error) {
	if len(input) < 72 { // 20+20+32
		return common.Address{}, common.Address{}, nil, 0, fmt.Errorf("input too short for quote")
	}

	tokenIn := common.BytesToAddress(input[0:20])
	tokenOut := common.BytesToAddress(input[20:40])
	amountIn := new(big.Int).SetBytes(input[40:72])

	var fee uint24
	if len(input) >= 75 {
		var feeBytes [4]byte
		copy(feeBytes[1:], input[72:75])
		fee = binary.BigEndian.Uint32(feeBytes[:])
	}

	return tokenIn, tokenOut, amountIn, fee, nil
}

// EncodeQuoteResults encodes quote results for return.
// Per result: venue(1) + amountOut(32) + poolID(32) + gasEstimate(8) = 73 bytes
func EncodeQuoteResults(results []QuoteResult) []byte {
	out := make([]byte, 1+len(results)*73) // count(1) + results
	out[0] = byte(len(results))

	for i, r := range results {
		offset := 1 + i*73
		out[offset] = byte(r.Venue)
		copy(out[offset+1:offset+33], common.LeftPadBytes(r.AmountOut.Bytes(), 32))
		copy(out[offset+33:offset+65], r.PoolID[:])
		binary.BigEndian.PutUint64(out[offset+65:offset+73], r.GasEstimate)
	}

	return out
}

// EncodeSwapResult encodes a swap result for return.
// Format: amountOut(32) + venue(1)
func EncodeSwapResult(amountOut *big.Int, venue SwapVenue) []byte {
	out := make([]byte, 33)
	copy(out[0:32], common.LeftPadBytes(amountOut.Bytes(), 32))
	out[32] = byte(venue)
	return out
}
