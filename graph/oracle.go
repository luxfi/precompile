// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"encoding/json"
	"math/big"
)

// =====================================
// Oracle Query Helpers
// =====================================

// Price feed query IDs for quick access
const (
	// Core price feeds
	QueryOracleETHPrice    QueryID = 0x1001 // ETH/USD price
	QueryOracleLUXPrice    QueryID = 0x1002 // LUX/USD price
	QueryOracleBTCPrice    QueryID = 0x1003 // BTC/USD price
	QueryOracleTokenPrice  QueryID = 0x1004 // Any token price by address

	// AMM-derived prices (TWAP)
	QueryTWAPPrice         QueryID = 0x1010 // Time-weighted average price
	QuerySpotPrice         QueryID = 0x1011 // Current spot price from pool

	// Aggregated feeds
	QueryAllPrices         QueryID = 0x1020 // All major token prices
	QueryPriceHistory      QueryID = 0x1021 // Price history for charting
)

// OracleQueries contains pre-built GraphQL queries for price feeds
var OracleQueries = map[QueryID]QueryTemplate{
	QueryOracleETHPrice: {
		ID:      QueryOracleETHPrice,
		Query:   `query { bundle(id: "1") { ethPriceUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 0,
	},
	QueryOracleLUXPrice: {
		ID:      QueryOracleLUXPrice,
		Query:   `query { bundle(id: "1") { luxPriceUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 0,
	},
	QueryOracleTokenPrice: {
		ID:      QueryOracleTokenPrice,
		Query:   `query($token: String!) { token(id: $token) { derivedETH derivedLUX symbol decimals } bundle(id: "1") { ethPriceUSD luxPriceUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryTWAPPrice: {
		ID:      QueryTWAPPrice,
		Query:   `query($pool: String!, $period: Int!) { poolHourDatas(first: $period, where: { pool: $pool }, orderBy: periodStartUnix, orderDirection: desc) { token0Price token1Price periodStartUnix } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 2,
	},
	QuerySpotPrice: {
		ID:      QuerySpotPrice,
		Query:   `query($pool: String!) { pool(id: $pool) { token0Price token1Price sqrtPrice tick token0 { symbol decimals } token1 { symbol decimals } } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryAllPrices: {
		ID:      QueryAllPrices,
		Query:   `query { bundle(id: "1") { ethPriceUSD luxPriceUSD } tokens(first: 20, orderBy: totalValueLockedUSD, orderDirection: desc) { id symbol derivedETH totalValueLockedUSD } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 0,
	},
	QueryPriceHistory: {
		ID:      QueryPriceHistory,
		Query:   `query($token: String!, $days: Int!) { tokenDayDatas(first: $days, where: { token: $token }, orderBy: date, orderDirection: desc) { date priceUSD open high low close volumeUSD } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 2,
	},
}

// =====================================
// AMM Query Helpers
// =====================================

// AMM query IDs
const (
	// Pool queries
	QueryAMMPoolByTokens   QueryID = 0x2001 // Find pool by token pair
	QueryAMMPoolLiquidity  QueryID = 0x2002 // Pool liquidity depth
	QueryAMMPoolFees       QueryID = 0x2003 // Pool fee tier and earned fees
	QueryAMMPoolVolume     QueryID = 0x2004 // Pool volume stats

	// Position queries
	QueryAMMMyPositions    QueryID = 0x2010 // User's LP positions
	QueryAMMPositionValue  QueryID = 0x2011 // Position value + fees earned
	QueryAMMPositionRange  QueryID = 0x2012 // Position tick range

	// Swap queries
	QueryAMMQuote          QueryID = 0x2020 // Get swap quote
	QueryAMMRoute          QueryID = 0x2021 // Best route for swap
	QueryAMMRecentSwaps    QueryID = 0x2022 // Recent swaps in pool

	// Liquidity queries
	QueryAMMTickLiquidity  QueryID = 0x2030 // Liquidity at each tick
	QueryAMMLiquidityDepth QueryID = 0x2031 // Order book style depth
)

// AMMQueries contains pre-built GraphQL queries for AMM data
var AMMQueries = map[QueryID]QueryTemplate{
	QueryAMMPoolByTokens: {
		ID:      QueryAMMPoolByTokens,
		Query:   `query($token0: String!, $token1: String!) { pools(where: { token0: $token0, token1: $token1 }) { id feeTier liquidity sqrtPrice tick volumeUSD totalValueLockedUSD token0Price token1Price } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 2,
	},
	QueryAMMPoolLiquidity: {
		ID:      QueryAMMPoolLiquidity,
		Query:   `query($pool: String!) { pool(id: $pool) { liquidity sqrtPrice tick totalValueLockedToken0 totalValueLockedToken1 totalValueLockedUSD } ticks(first: 100, where: { pool: $pool }, orderBy: tickIdx) { tickIdx liquidityNet liquidityGross price0 price1 } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 1,
	},
	QueryAMMPoolFees: {
		ID:      QueryAMMPoolFees,
		Query:   `query($pool: String!) { pool(id: $pool) { feeTier feeGrowthGlobal0X128 feeGrowthGlobal1X128 collectedFeesToken0 collectedFeesToken1 collectedFeesUSD feesUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryAMMPoolVolume: {
		ID:      QueryAMMPoolVolume,
		Query:   `query($pool: String!) { pool(id: $pool) { volumeToken0 volumeToken1 volumeUSD txCount } poolDayDatas(first: 7, where: { pool: $pool }, orderBy: date, orderDirection: desc) { date volumeUSD tvlUSD feesUSD } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 1,
	},
	QueryAMMMyPositions: {
		ID:      QueryAMMMyPositions,
		Query:   `query($owner: String!) { positions(where: { owner: $owner, liquidity_gt: "0" }) { id pool { id token0 { symbol } token1 { symbol } feeTier } tickLower { tickIdx price0 } tickUpper { tickIdx price0 } liquidity depositedToken0 depositedToken1 collectedFeesToken0 collectedFeesToken1 } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 1,
	},
	QueryAMMPositionValue: {
		ID:      QueryAMMPositionValue,
		Query:   `query($positionId: String!) { position(id: $positionId) { liquidity depositedToken0 depositedToken1 withdrawnToken0 withdrawnToken1 collectedToken0 collectedToken1 collectedFeesToken0 collectedFeesToken1 pool { token0Price token1Price token0 { decimals symbol } token1 { decimals symbol } } } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryAMMQuote: {
		ID:      QueryAMMQuote,
		Query:   `query($tokenIn: String!, $tokenOut: String!, $amount: String!) { quote(tokenIn: $tokenIn, tokenOut: $tokenOut, amountIn: $amount) { amountOut priceImpact route { pools { id feeTier } } gasEstimate } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 3,
	},
	QueryAMMRecentSwaps: {
		ID:      QueryAMMRecentSwaps,
		Query:   `query($pool: String!, $count: Int!) { swaps(first: $count, where: { pool: $pool }, orderBy: timestamp, orderDirection: desc) { timestamp sender recipient amount0 amount1 amountUSD sqrtPriceX96 tick } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 2,
	},
	QueryAMMTickLiquidity: {
		ID:      QueryAMMTickLiquidity,
		Query:   `query($pool: String!, $tickLower: Int!, $tickUpper: Int!) { ticks(where: { pool: $pool, tickIdx_gte: $tickLower, tickIdx_lte: $tickUpper }, orderBy: tickIdx) { tickIdx liquidityNet liquidityGross price0 price1 } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 3,
	},
}

// =====================================
// Response Types
// =====================================

// PriceResponse represents a token price query result
type PriceResponse struct {
	TokenAddress string   `json:"tokenAddress"`
	Symbol       string   `json:"symbol"`
	PriceUSD     *big.Int `json:"priceUSD"`     // 18 decimals
	PriceETH     *big.Int `json:"priceETH"`     // 18 decimals
	PriceLUX     *big.Int `json:"priceLUX"`     // 18 decimals
	Timestamp    uint64   `json:"timestamp"`
	Source       string   `json:"source"`       // "pool", "oracle", "twap"
}

// PoolInfoResponse represents pool information
type PoolInfoResponse struct {
	PoolAddress   string   `json:"poolAddress"`
	Token0        string   `json:"token0"`
	Token1        string   `json:"token1"`
	Token0Symbol  string   `json:"token0Symbol"`
	Token1Symbol  string   `json:"token1Symbol"`
	FeeTier       uint32   `json:"feeTier"`
	Liquidity     *big.Int `json:"liquidity"`
	SqrtPriceX96  *big.Int `json:"sqrtPriceX96"`
	Tick          int32    `json:"tick"`
	Token0Price   *big.Int `json:"token0Price"`   // 18 decimals
	Token1Price   *big.Int `json:"token1Price"`   // 18 decimals
	TVL_USD       *big.Int `json:"tvlUSD"`        // 18 decimals
	Volume24h_USD *big.Int `json:"volume24hUSD"` // 18 decimals
	Fees24h_USD   *big.Int `json:"fees24hUSD"`   // 18 decimals
}

// QuoteResponse represents a swap quote
type QuoteResponse struct {
	AmountIn     *big.Int `json:"amountIn"`
	AmountOut    *big.Int `json:"amountOut"`
	PriceImpact  *big.Int `json:"priceImpact"`  // basis points (10000 = 100%)
	GasEstimate  uint64   `json:"gasEstimate"`
	Route        []string `json:"route"`        // pool addresses
	FeeTiers     []uint32 `json:"feeTiers"`
}

// PositionResponse represents an LP position
type PositionResponse struct {
	PositionID    string   `json:"positionId"`
	Owner         string   `json:"owner"`
	PoolAddress   string   `json:"poolAddress"`
	Token0        string   `json:"token0"`
	Token1        string   `json:"token1"`
	TickLower     int32    `json:"tickLower"`
	TickUpper     int32    `json:"tickUpper"`
	Liquidity     *big.Int `json:"liquidity"`
	Amount0       *big.Int `json:"amount0"`
	Amount1       *big.Int `json:"amount1"`
	FeesEarned0   *big.Int `json:"feesEarned0"`
	FeesEarned1   *big.Int `json:"feesEarned1"`
	ValueUSD      *big.Int `json:"valueUSD"`      // 18 decimals
	InRange       bool     `json:"inRange"`
}

// =====================================
// Helper Functions
// =====================================

// ParsePriceResponse parses a GraphQL price response
func ParsePriceResponse(data []byte) (*PriceResponse, error) {
	var resp struct {
		Data struct {
			Token struct {
				DerivedETH string `json:"derivedETH"`
				DerivedLUX string `json:"derivedLUX"`
				Symbol     string `json:"symbol"`
				Decimals   int    `json:"decimals"`
			} `json:"token"`
			Bundle struct {
				EthPriceUSD string `json:"ethPriceUSD"`
				LuxPriceUSD string `json:"luxPriceUSD"`
			} `json:"bundle"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	// Calculate USD price from derivedETH * ethPriceUSD
	derivedETH, _ := new(big.Float).SetString(resp.Data.Token.DerivedETH)
	ethPrice, _ := new(big.Float).SetString(resp.Data.Bundle.EthPriceUSD)

	priceFloat := new(big.Float).Mul(derivedETH, ethPrice)

	// Convert to 18 decimal integer
	scale := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	priceScaled := new(big.Float).Mul(priceFloat, scale)
	priceUSD, _ := priceScaled.Int(nil)

	return &PriceResponse{
		Symbol:   resp.Data.Token.Symbol,
		PriceUSD: priceUSD,
		Source:   "pool",
	}, nil
}

// ParsePoolInfoResponse parses a GraphQL pool response
func ParsePoolInfoResponse(data []byte) (*PoolInfoResponse, error) {
	var resp struct {
		Data struct {
			Pool struct {
				ID                    string `json:"id"`
				Token0                struct{ Symbol string } `json:"token0"`
				Token1                struct{ Symbol string } `json:"token1"`
				FeeTier               int    `json:"feeTier"`
				Liquidity             string `json:"liquidity"`
				SqrtPrice             string `json:"sqrtPrice"`
				Tick                  int    `json:"tick"`
				Token0Price           string `json:"token0Price"`
				Token1Price           string `json:"token1Price"`
				TotalValueLockedUSD   string `json:"totalValueLockedUSD"`
				VolumeUSD             string `json:"volumeUSD"`
			} `json:"pool"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	liquidity, _ := new(big.Int).SetString(resp.Data.Pool.Liquidity, 10)
	sqrtPrice, _ := new(big.Int).SetString(resp.Data.Pool.SqrtPrice, 10)

	return &PoolInfoResponse{
		PoolAddress:  resp.Data.Pool.ID,
		Token0Symbol: resp.Data.Pool.Token0.Symbol,
		Token1Symbol: resp.Data.Pool.Token1.Symbol,
		FeeTier:      uint32(resp.Data.Pool.FeeTier),
		Liquidity:    liquidity,
		SqrtPriceX96: sqrtPrice,
		Tick:         int32(resp.Data.Pool.Tick),
	}, nil
}

// init registers oracle and AMM queries
func init() {
	// Add oracle queries to predefined queries
	for id, q := range OracleQueries {
		PredefinedQueries[id] = q
	}

	// Add AMM queries to predefined queries
	for id, q := range AMMQueries {
		PredefinedQueries[id] = q
	}
}
