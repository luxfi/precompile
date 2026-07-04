// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	lx "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
)

// SwapVenue identifies the liquidity source for a swap hop.
type SwapVenue uint8

const (
	VenueV4Native SwapVenue = iota // Precompile pool (LXPool)
	VenueV3                        // Uniswap V3 concentrated liquidity contract
	VenueV2                        // Uniswap V2 constant product contract
	VenueExternal                  // Off-chain venue (Alpaca, IBKR, Binance, etc.)
)

// Router gas costs
const (
	GasQuoteBase      uint64 = 5_000  // Quote base cost (single hop)
	GasQuotePerHop    uint64 = 5_000  // Additional quote cost per hop
	GasQuote          uint64 = 5_000  // Single-hop quote
	GasSingleSwap     uint64 = 50_000 // Single-hop routed swap
	GasMultiHopBase   uint64 = 50_000 // Multi-hop base cost
	GasMultiHopPerHop uint64 = 50_000 // Additional cost per hop
	GasRouteLookup    uint64 = 5_000  // Route discovery
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
	v3QuoterAddr  common.Address // Set via router config if deployed
	v3FactoryAddr common.Address

	// V2 contracts (Uniswap V2 style, deployed via standard contracts)
	v2RouterAddr  common.Address
	v2FactoryAddr common.Address
)

// PathKey describes one hop in a V4 multi-hop path.
// Matches Uniswap V4 periphery PathKey struct:
//
//	struct PathKey {
//	    Currency intermediateCurrency;
//	    uint24 fee;
//	    int24 tickSpacing;
//	    IHooks hooks;
//	    bytes hookData;
//	}
type PathKey struct {
	IntermediateCurrency common.Address // Output token of this hop
	Fee                  uint24         // Pool fee tier
	TickSpacing          int24          // Pool tick spacing
	Hooks                common.Address // Hook contract (zero = no hooks)
}

// PathKeySize is the byte size of a single encoded PathKey (20 + 3 + 3 + 20 = 46 bytes).
const PathKeySize = 46

// SwapExactInputSingleParams for a single-hop exact-input swap through the router.
type SwapExactInputSingleParams struct {
	TokenIn           common.Address
	TokenOut          common.Address
	AmountIn          *big.Int
	AmountOutMinimum  *big.Int
	Fee               uint24 // Preferred fee tier (0 = auto-select)
	TickSpacing       int24  // Preferred tick spacing (0 = derive from fee)
	Hooks             common.Address
	SqrtPriceLimitX96 *big.Int
	Deadline          uint64
}

// SwapExactInputParams for multi-hop exact-input swap.
// Supports two path formats:
//   - V4 binary path: Path is nil, PathKeys + CurrencyIn are set
//   - Simple path: Path is set (address list), PathKeys is nil
type SwapExactInputParams struct {
	// Simple path format: [tokenIn, tokenMid..., tokenOut]
	Path []common.Address

	// V4 path format: CurrencyIn + sequence of PathKeys
	CurrencyIn common.Address
	PathKeys   []PathKey

	AmountIn         *big.Int
	AmountOutMinimum *big.Int
	Deadline         uint64
}

// SwapExactOutputSingleParams for a single-hop exact-output swap.
type SwapExactOutputSingleParams struct {
	TokenIn           common.Address
	TokenOut          common.Address
	AmountOut         *big.Int
	AmountInMaximum   *big.Int
	Fee               uint24
	TickSpacing       int24
	Hooks             common.Address
	SqrtPriceLimitX96 *big.Int
	Deadline          uint64
}

// SwapExactOutputParams for multi-hop exact-output swap.
type SwapExactOutputParams struct {
	// Simple path format: [tokenOut, ..., tokenIn] (reversed)
	Path []common.Address

	// V4 path format
	CurrencyOut common.Address
	PathKeys    []PathKey

	AmountOut       *big.Int
	AmountInMaximum *big.Int
	Deadline        uint64
}

// QuoteResult holds the result of a route quote.
type QuoteResult struct {
	AmountOut   *big.Int
	Venue       SwapVenue
	PoolID      [32]byte       // V4 pool ID (zero for V3/V2)
	PoolAddr    common.Address // V3/V2 pool address (zero for V4)
	GasEstimate uint64
}

// ExternalVenue represents an off-chain execution venue (Alpaca, IBKR, Binance, etc.).
// The actual execution happens off-chain via the Lux Broker; this interface is the
// on-chain quote hook that the ATS/Broker registers to provide indicative prices.
//
// Implementations live off-chain. On-chain, the router only sees quotes provided
// by registered venue contracts. Actual fills are settled via FillAttestation (LP-9090).
type ExternalVenue interface {
	// VenueID returns a unique identifier for this venue.
	VenueID() [32]byte

	// Quote returns an indicative output amount for the given input.
	// This is a read-only call; execution happens off-chain.
	Quote(stateDB StateDB, tokenIn, tokenOut common.Address, amountIn *big.Int) (*big.Int, error)
}

// SmartOrderRouter finds best execution across all on-chain and off-chain venues.
// The on-chain component queries V4 pools, V3/V2 contracts, and registered external
// venue quote contracts. The off-chain ATS/Broker can split orders across venues.
type SmartOrderRouter struct {
	PoolManager *PoolManager            // On-chain V4 pools
	V2Pairs     map[common.Address]bool // Known V2 pair addresses
	Venues      []ExternalVenue         // Registered external venue quoters
}

// LXRouter implements unified V2/V3/V4 swap routing.
// It queries V4 native pools first (zero-cost precompile state lookup),
// then falls back to V3 and V2 deployed contracts via STATICCALL.
type LXRouter struct {
	poolManager *PoolManager
	venues      []ExternalVenue
}

// NewLXRouter creates a router linked to the singleton PoolManager.
func NewLXRouter(pm *PoolManager) *LXRouter {
	return &LXRouter{poolManager: pm}
}

// RegisterVenue adds an external venue quoter to the router.
func (r *LXRouter) RegisterVenue(v ExternalVenue) {
	r.venues = append(r.venues, v)
}

// =========================================================================
// Deadline check
// =========================================================================

// ErrDeadlineExpired is returned when block.timestamp exceeds the caller's deadline.
var ErrDeadlineExpired = fmt.Errorf("transaction deadline expired")

// ErrSlippageExceeded is returned when output does not meet the minimum.
var ErrSlippageExceeded = fmt.Errorf("slippage: insufficient output amount")

// ErrExcessiveInput is returned when the required input exceeds the maximum.
var ErrExcessiveInput = fmt.Errorf("slippage: excessive input amount")

// ErrNoOnChainLiquidity is returned when execution requires on-chain settlement
// but no on-chain pool (V4/V3/V2) can fill the order. External venues are quote-only
// and settle via FillAttestation (LP-9090), not through the router execution path.
var ErrNoOnChainLiquidity = fmt.Errorf("no on-chain liquidity available for execution")

// MaxPathLength is the maximum number of hops allowed in a multi-hop swap path.
// This prevents gas exhaustion attacks via excessively long paths.
const MaxPathLength = 5

// checkDeadline returns an error if the deadline is set and the current block
// number exceeds it. Deadline of 0 means no deadline.
func checkDeadline(stateDB StateDB, deadline uint64) error {
	if deadline == 0 {
		return nil
	}
	if stateDB.GetBlockNumber() > deadline {
		return ErrDeadlineExpired
	}
	return nil
}

// =========================================================================
// Exact Input Single (best venue, single hop)
// =========================================================================

// =========================================================================
// Exact Input Multi-hop
// =========================================================================

// =========================================================================
// Exact Output Single
// =========================================================================

// =========================================================================
// Exact Output Multi-hop
// =========================================================================

// =========================================================================
// Quote Functions (read-only, no state changes)
// =========================================================================

// QuoteExactInputSingle returns the expected output amount without executing.
// Read-only: does not modify state.
func (r *LXRouter) QuoteExactInputSingle(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
	fee uint24,
) ([]QuoteResult, error) {
	results := make([]QuoteResult, 0, 4)

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

	// Quote external venues
	for _, v := range r.venues {
		extAmount, extErr := v.Quote(stateDB, tokenIn, tokenOut, amountIn)
		if extErr == nil && extAmount.Sign() > 0 {
			results = append(results, QuoteResult{
				AmountOut:   extAmount,
				Venue:       VenueExternal,
				PoolID:      v.VenueID(),
				GasEstimate: GasFillAttestation, // settlement via FillAttestation
			})
		}
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
	if bytes.Compare(tokenIn[:], tokenOut[:]) < 0 {
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

		// Calculate expected output via the single routed quote path: the ZAP
		// backend reads its canonical D-Chain pool; an inert backend returns zero.
		var output *big.Int
		if zeroForOne {
			output = r.poolManager.calculateSwapOutput(stateDB, key, poolID, amountIn, true)
		} else {
			output = r.poolManager.calculateSwapOutput(stateDB, key, poolID, amountIn, false)
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

// tickSpacingForFee returns the canonical tick spacing for a given fee tier.
func tickSpacingForFee(fee uint24) int24 {
	switch fee {
	case Fee001:
		return TickSpacing001
	case Fee005:
		return TickSpacing005
	case Fee030:
		return TickSpacing030
	case Fee100:
		return TickSpacing100
	default:
		return TickSpacing030 // default
	}
}

// sortedPoolKey constructs a PoolKey with currencies in canonical sort order.
func sortedPoolKey(tokenA, tokenB common.Address, fee uint24, tickSpacing int24, hooks common.Address) PoolKey {
	var c0, c1 Currency
	if bytes.Compare(tokenA[:], tokenB[:]) < 0 {
		c0 = Currency{Address: tokenA}
		c1 = Currency{Address: tokenB}
	} else {
		c0 = Currency{Address: tokenB}
		c1 = Currency{Address: tokenA}
	}
	return PoolKey{
		Currency0:   c0,
		Currency1:   c1,
		Fee:         fee,
		TickSpacing: tickSpacing,
		Hooks:       hooks,
	}
}

// absInt returns the absolute value of a *big.Int as a new allocation.
func absInt(v *big.Int) *big.Int {
	if v.Sign() < 0 {
		return new(big.Int).Neg(v)
	}
	return new(big.Int).Set(v)
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

// quoteV2 resolves a swap quote against the NATIVE constant-product AMM.
//
// The V2 venue is the 0.30% constant-product pool (the Uniswap-V2 standard fee):
// its reserves are bound per-pair via BindAMMPool and read from 0x9999 storage
// (swap_amm_pool.go), and the output is the canonical xy=k curve from
// lx.ConstantProductOut — the SAME math the dexcore AMM source uses, so there is
// exactly one constant-product implementation. When V2 is unconfigured, no pool is
// bound, or amountIn falls outside the native AMM's uint64 domain, this returns
// (0, error) so the router falls through to other venues — that fall-through is
// correct routing behaviour, not a failure.
func (r *LXRouter) quoteV2(
	stateDB StateDB,
	tokenIn, tokenOut common.Address,
	amountIn *big.Int,
) (*big.Int, error) {
	if v2RouterAddr == (common.Address{}) {
		return big.NewInt(0), fmt.Errorf("V2 router not configured")
	}

	// Canonical V2 pool key for the pair == the 0.30% constant-product pool.
	poolID := sortedPoolKey(tokenIn, tokenOut, Fee030, TickSpacing030, common.Address{}).ID()

	store := newEVMStore(stateDB)
	base, quote, _, ok := readAMMRow(store, poolID)
	if !ok || base == 0 || quote == 0 {
		return big.NewInt(0), fmt.Errorf("no V2 liquidity bound")
	}

	// Orient reserves by sort order. The AMM row stores base = reserve of currency0,
	// quote = reserve of currency1, where currency0 < currency1 by address. When tokenIn
	// is currency0 (zeroForOne) the input reserve is base; otherwise it is quote.
	zeroForOne := bytes.Compare(tokenIn[:], tokenOut[:]) < 0
	var rx, ry uint64
	if zeroForOne {
		rx, ry = base, quote
	} else {
		rx, ry = quote, base
	}

	// The native AMM is uint64-domain (reserves are uint64). An amountIn beyond uint64
	// is outside that domain — fall through rather than truncate.
	if !amountIn.IsUint64() {
		return big.NewInt(0), fmt.Errorf("V2 amountIn exceeds native AMM uint64 domain")
	}

	out := lx.ConstantProductOut(rx, ry, amountIn.Uint64())
	return new(big.Int).SetUint64(out), nil
}

// =========================================================================
// V4 Binary Path Encoding/Decoding
// =========================================================================

// EncodePathKey encodes a single PathKey to 46 bytes:
//
//	intermediateCurrency (20) + fee (3) + tickSpacing (3) + hooks (20)
func EncodePathKey(pk PathKey) []byte {
	out := make([]byte, PathKeySize)
	copy(out[0:20], pk.IntermediateCurrency.Bytes())

	var feeBytes [4]byte
	binary.BigEndian.PutUint32(feeBytes[:], uint32(pk.Fee))
	copy(out[20:23], feeBytes[1:4]) // uint24

	tsBytes := int24ToBytes(pk.TickSpacing)
	copy(out[23:26], tsBytes)

	copy(out[26:46], pk.Hooks.Bytes())
	return out
}

// DecodePathKey decodes a single PathKey from 46 bytes.
func DecodePathKey(data []byte) (PathKey, error) {
	if len(data) < PathKeySize {
		return PathKey{}, fmt.Errorf("path key data too short: need %d, got %d", PathKeySize, len(data))
	}
	pk := PathKey{
		IntermediateCurrency: common.BytesToAddress(data[0:20]),
	}
	var feeBytes [4]byte
	copy(feeBytes[1:], data[20:23])
	pk.Fee = binary.BigEndian.Uint32(feeBytes[:])

	pk.TickSpacing = decodeInt24(data[23:26])
	pk.Hooks = common.BytesToAddress(data[26:46])
	return pk, nil
}

// EncodePath encodes a full V4 path: currencyIn (20) + N PathKeys (N*46).
func EncodePath(currencyIn common.Address, keys []PathKey) []byte {
	out := make([]byte, 20+len(keys)*PathKeySize)
	copy(out[0:20], currencyIn.Bytes())
	for i, pk := range keys {
		copy(out[20+i*PathKeySize:20+(i+1)*PathKeySize], EncodePathKey(pk))
	}
	return out
}

// DecodePath decodes a V4 binary path into currencyIn + []PathKey.
// Path format: currencyIn (20) + N * PathKey (N * 46).
func DecodePath(data []byte) (common.Address, []PathKey, error) {
	if len(data) < 20 {
		return common.Address{}, nil, fmt.Errorf("path too short")
	}
	currencyIn := common.BytesToAddress(data[0:20])
	remaining := data[20:]
	if len(remaining)%PathKeySize != 0 {
		return common.Address{}, nil, fmt.Errorf("path data length %d not a multiple of PathKey size %d", len(remaining), PathKeySize)
	}
	numHops := len(remaining) / PathKeySize
	if numHops == 0 {
		return common.Address{}, nil, fmt.Errorf("path must have at least 1 hop")
	}
	keys := make([]PathKey, numHops)
	for i := range numHops {
		pk, err := DecodePathKey(remaining[i*PathKeySize : (i+1)*PathKeySize])
		if err != nil {
			return common.Address{}, nil, fmt.Errorf("decode path key %d: %w", i, err)
		}
		keys[i] = pk
	}
	return currencyIn, keys, nil
}

// =========================================================================
// ABI Encoding/Decoding
// =========================================================================

// DecodeExactInputSingleParams decodes router input for ExactInputSingle.
// Format: tokenIn(20) + tokenOut(20) + amountIn(32) + amountOutMin(32) + fee(3) + tickSpacing(3) + hooks(20) + sqrtPriceLimit(32) + deadline(8)
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

	offset := 107

	// tickSpacing (3 bytes, optional)
	if len(input) >= offset+3 {
		params.TickSpacing = decodeInt24(input[offset : offset+3])
		offset += 3
	}

	// hooks (20 bytes, optional)
	if len(input) >= offset+20 {
		params.Hooks = common.BytesToAddress(input[offset : offset+20])
		offset += 20
	}

	// sqrtPriceLimit (32 bytes, optional)
	if len(input) >= offset+32 {
		params.SqrtPriceLimitX96 = new(big.Int).SetBytes(input[offset : offset+32])
		offset += 32
	}

	// deadline (8 bytes, optional)
	if len(input) >= offset+8 {
		params.Deadline = binary.BigEndian.Uint64(input[offset : offset+8])
	}

	return params, nil
}

// DecodeExactInputParams decodes router input for ExactInput (multi-hop).
//
// Two formats are supported, distinguished by the first byte:
//
// V4 path format (byte 0 == 0xFF):
//
//	0xFF(1) + pathLen(2) + path(pathLen) + amountIn(32) + amountOutMin(32) + deadline(8)
//	path = currencyIn(20) + N * PathKey(46)
//
// Simple format (byte 0 < 0xFF):
//
//	numTokens(1) + tokens(numTokens*20) + amountIn(32) + amountOutMin(32) + deadline(8)
func DecodeExactInputParams(input []byte) (SwapExactInputParams, error) {
	if len(input) < 1 {
		return SwapExactInputParams{}, fmt.Errorf("input too short")
	}

	// V4 binary path format
	if input[0] == 0xFF {
		if len(input) < 3 {
			return SwapExactInputParams{}, fmt.Errorf("input too short for V4 path header")
		}
		pathLen := int(binary.BigEndian.Uint16(input[1:3]))
		if len(input) < 3+pathLen+64 {
			return SwapExactInputParams{}, fmt.Errorf("input too short for V4 ExactInput")
		}

		currencyIn, pathKeys, err := DecodePath(input[3 : 3+pathLen])
		if err != nil {
			return SwapExactInputParams{}, fmt.Errorf("decode V4 path: %w", err)
		}

		offset := 3 + pathLen
		params := SwapExactInputParams{
			CurrencyIn:       currencyIn,
			PathKeys:         pathKeys,
			AmountIn:         new(big.Int).SetBytes(input[offset : offset+32]),
			AmountOutMinimum: new(big.Int).SetBytes(input[offset+32 : offset+64]),
		}
		offset += 64
		if len(input) >= offset+8 {
			params.Deadline = binary.BigEndian.Uint64(input[offset : offset+8])
		}
		return params, nil
	}

	// Simple address-list format
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
	for i := range numTokens {
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

// DecodeExactOutputSingleParams decodes router input for ExactOutputSingle.
// Format: tokenIn(20) + tokenOut(20) + amountOut(32) + amountInMax(32) + fee(3) + tickSpacing(3) + hooks(20) + sqrtPriceLimit(32) + deadline(8)
func DecodeExactOutputSingleParams(input []byte) (SwapExactOutputSingleParams, error) {
	if len(input) < 107 { // 20+20+32+32+3
		return SwapExactOutputSingleParams{}, fmt.Errorf("input too short for ExactOutputSingle")
	}

	params := SwapExactOutputSingleParams{
		TokenIn:         common.BytesToAddress(input[0:20]),
		TokenOut:        common.BytesToAddress(input[20:40]),
		AmountOut:       new(big.Int).SetBytes(input[40:72]),
		AmountInMaximum: new(big.Int).SetBytes(input[72:104]),
	}

	var feeBytes [4]byte
	copy(feeBytes[1:], input[104:107])
	params.Fee = binary.BigEndian.Uint32(feeBytes[:])

	offset := 107

	if len(input) >= offset+3 {
		params.TickSpacing = decodeInt24(input[offset : offset+3])
		offset += 3
	}
	if len(input) >= offset+20 {
		params.Hooks = common.BytesToAddress(input[offset : offset+20])
		offset += 20
	}
	if len(input) >= offset+32 {
		params.SqrtPriceLimitX96 = new(big.Int).SetBytes(input[offset : offset+32])
		offset += 32
	}
	if len(input) >= offset+8 {
		params.Deadline = binary.BigEndian.Uint64(input[offset : offset+8])
	}

	return params, nil
}

// DecodeExactOutputParams decodes router input for ExactOutput (multi-hop).
// Uses same format discriminator as DecodeExactInputParams.
func DecodeExactOutputParams(input []byte) (SwapExactOutputParams, error) {
	if len(input) < 1 {
		return SwapExactOutputParams{}, fmt.Errorf("input too short")
	}

	// V4 binary path format
	if input[0] == 0xFF {
		if len(input) < 3 {
			return SwapExactOutputParams{}, fmt.Errorf("input too short for V4 path header")
		}
		pathLen := int(binary.BigEndian.Uint16(input[1:3]))
		if len(input) < 3+pathLen+64 {
			return SwapExactOutputParams{}, fmt.Errorf("input too short for V4 ExactOutput")
		}

		currencyOut, pathKeys, err := DecodePath(input[3 : 3+pathLen])
		if err != nil {
			return SwapExactOutputParams{}, fmt.Errorf("decode V4 path: %w", err)
		}

		offset := 3 + pathLen
		params := SwapExactOutputParams{
			CurrencyOut:     currencyOut,
			PathKeys:        pathKeys,
			AmountOut:       new(big.Int).SetBytes(input[offset : offset+32]),
			AmountInMaximum: new(big.Int).SetBytes(input[offset+32 : offset+64]),
		}
		offset += 64
		if len(input) >= offset+8 {
			params.Deadline = binary.BigEndian.Uint64(input[offset : offset+8])
		}
		return params, nil
	}

	// Simple address-list format
	numTokens := int(input[0])
	if numTokens < 2 {
		return SwapExactOutputParams{}, fmt.Errorf("path must have at least 2 tokens")
	}

	expectedLen := 1 + numTokens*20 + 32 + 32
	if len(input) < expectedLen {
		return SwapExactOutputParams{}, fmt.Errorf("input too short for ExactOutput")
	}

	params := SwapExactOutputParams{
		Path: make([]common.Address, numTokens),
	}

	offset := 1
	for i := range numTokens {
		params.Path[i] = common.BytesToAddress(input[offset : offset+20])
		offset += 20
	}

	params.AmountOut = new(big.Int).SetBytes(input[offset : offset+32])
	offset += 32
	params.AmountInMaximum = new(big.Int).SetBytes(input[offset : offset+32])
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
