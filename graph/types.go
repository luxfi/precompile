// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package graph implements G-Chain GraphQL precompile for Lux EVMs.
// This enables native low-latency GraphQL queries from any EVM chain
// to the unified G-Chain query layer.
package graph

import (
	"errors"
)

// Gas costs for GraphQL operations.
//
// The address of this precompile has exactly one spelling: ContractGraphQLAddress in
// module.go, which is what the module registers.
const (
	// Query operations
	GasQueryBase       uint64 = 5_000  // Base cost for any query
	GasQuerySimple     uint64 = 10_000 // Simple single-entity query
	GasQueryComplex    uint64 = 25_000 // Complex multi-entity query
	GasQueryCrossChain uint64 = 50_000 // Cross-chain aggregation query, per target chain

	// GasPerByte prices every caller-supplied and every returned byte.
	GasPerByte uint64 = 3
)

// Errors
var (
	ErrInvalidQuery         = errors.New("invalid GraphQL query")
	ErrQueryTooLarge        = errors.New("query exceeds maximum size")
	ErrGasExceeded          = errors.New("gas limit exceeded for query")
	ErrClientNotInitialized = errors.New("graph client not initialized")
)

// Maximum limits
const (
	MaxQuerySize    = 4096  // Max query string size in bytes
	MaxResponseSize = 65536 // Max response size in bytes (64KB)

	// MaxTargetChains bounds the multi-chain fan-out. TargetChains is decoded straight
	// out of caller-supplied JSON and drives one client.QueryChain call per entry, so
	// without a cap the loop count — and the gas arithmetic derived from it — are both
	// caller-controlled and unbounded.
	MaxTargetChains = 16
)

// ChainID constants for cross-chain queries
const (
	ChainIDLuxMainnet   uint64 = 96369
	ChainIDLuxTestnet   uint64 = 96368
	ChainIDZooMainnet   uint64 = 200200
	ChainIDZooTestnet   uint64 = 200201
	ChainIDSPCMainnet   uint64 = 36911
	ChainIDSPCTestnet   uint64 = 36910
	ChainIDHanzoMainnet uint64 = 36963
	ChainIDHanzoTestnet uint64 = 36962
)

// QueryRequest represents a GraphQL query request
type QueryRequest struct {
	// Query is the GraphQL query string
	Query string

	// Variables is a JSON-encoded map of query variables
	Variables []byte

	// OperationName is the optional operation name
	OperationName string

	// TargetChains specifies which chains to query (empty = all)
	TargetChains []uint64
}

// QueryResponse represents a GraphQL query response
type QueryResponse struct {
	// Data contains the query result as JSON
	Data []byte

	// Errors contains any errors that occurred
	Errors []QueryError

	// GasUsed is the total gas consumed
	GasUsed uint64
}

// QueryError represents a GraphQL error
type QueryError struct {
	Message   string
	Path      []string
	Locations []Location
}

// Location represents a position in the query
type Location struct {
	Line   uint32
	Column uint32
}

// =====================================
// Pre-defined Query Templates
// =====================================

// Common queries that can be called with minimal gas
// These are optimized paths for frequently used operations

// QueryID represents a pre-defined query
type QueryID uint16

const (
	// Chain queries
	QueryIDChainInfo     QueryID = 0x0001
	QueryIDBlockByHash   QueryID = 0x0002
	QueryIDBlockByNumber QueryID = 0x0003

	// Account queries
	QueryIDBalance     QueryID = 0x0101
	QueryIDAccountInfo QueryID = 0x0102

	// DEX queries - Factory
	QueryIDFactory QueryID = 0x0201
	QueryIDBundle  QueryID = 0x0202

	// DEX queries - Tokens
	QueryIDToken      QueryID = 0x0301
	QueryIDTokens     QueryID = 0x0302
	QueryIDTokenPrice QueryID = 0x0303

	// DEX queries - Pools
	QueryIDPool        QueryID = 0x0401
	QueryIDPools       QueryID = 0x0402
	QueryIDPoolTicks   QueryID = 0x0403
	QueryIDPoolDayData QueryID = 0x0404

	// DEX queries - Pairs (v2)
	QueryIDPair        QueryID = 0x0501
	QueryIDPairs       QueryID = 0x0502
	QueryIDPairDayData QueryID = 0x0503

	// DEX queries - Positions
	QueryIDPosition         QueryID = 0x0601
	QueryIDPositions        QueryID = 0x0602
	QueryIDPositionsByOwner QueryID = 0x0603

	// DEX queries - Swaps
	QueryIDSwaps        QueryID = 0x0701
	QueryIDSwapsByPool  QueryID = 0x0702
	QueryIDSwapsByToken QueryID = 0x0703

	// Cross-chain queries
	QueryIDAllChainsTVL    QueryID = 0x0F01
	QueryIDAllChainsVolume QueryID = 0x0F02
)

// QueryTemplate defines a pre-optimized query
type QueryTemplate struct {
	ID      QueryID
	Query   string
	GasCost uint64
	MaxArgs int
}

// PredefinedQueries contains all optimized query templates
var PredefinedQueries = map[QueryID]QueryTemplate{
	QueryIDChainInfo: {
		ID:      QueryIDChainInfo,
		Query:   `query { chainInfo { vmName version readOnly supportedChains } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 0,
	},
	QueryIDBalance: {
		ID:      QueryIDBalance,
		Query:   `query($address: String!) { balance(address: $address) }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryIDFactory: {
		ID:      QueryIDFactory,
		Query:   `query { factory(id: "1") { poolCount pairCount txCount totalVolumeUSD totalValueLockedUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 0,
	},
	QueryIDBundle: {
		ID:      QueryIDBundle,
		Query:   `query { bundle(id: "1") { ethPriceUSD luxPriceUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 0,
	},
	QueryIDToken: {
		ID:      QueryIDToken,
		Query:   `query($id: String!) { token(id: $id) { id symbol name decimals volumeUSD totalValueLockedUSD derivedETH } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryIDTokens: {
		ID:      QueryIDTokens,
		Query:   `query($first: Int, $orderBy: String) { tokens(first: $first, orderBy: $orderBy) { id symbol name volumeUSD totalValueLockedUSD } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 2,
	},
	QueryIDPool: {
		ID:      QueryIDPool,
		Query:   `query($id: String!) { pool(id: $id) { id token0 { symbol } token1 { symbol } feeTier liquidity sqrtPrice tick volumeUSD totalValueLockedUSD } }`,
		GasCost: GasQuerySimple,
		MaxArgs: 1,
	},
	QueryIDPools: {
		ID:      QueryIDPools,
		Query:   `query($first: Int) { pools(first: $first) { id token0 { symbol } token1 { symbol } feeTier volumeUSD totalValueLockedUSD } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 1,
	},
	QueryIDPositions: {
		ID:      QueryIDPositions,
		Query:   `query($owner: String!) { positions(where: { owner: $owner }) { id tokenId pool { id } tickLower tickUpper liquidity } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 1,
	},
	QueryIDSwaps: {
		ID:      QueryIDSwaps,
		Query:   `query($first: Int) { swaps(first: $first, orderBy: timestamp, orderDirection: desc) { id timestamp amount0 amount1 amountUSD pool { token0 { symbol } token1 { symbol } } } }`,
		GasCost: GasQueryComplex,
		MaxArgs: 1,
	},
	QueryIDAllChainsTVL: {
		ID:      QueryIDAllChainsTVL,
		Query:   `query { allChains { chainId tvlUSD poolCount } }`,
		GasCost: GasQueryCrossChain,
		MaxArgs: 0,
	},
}
