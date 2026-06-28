// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/luxfi/geth/common"
)

// StateDB interface for accessing EVM state
type StateDB interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	SetState(addr common.Address, key common.Hash, value common.Hash)
}

// GChainClient interface for communication with G-Chain
type GChainClient interface {
	// Query executes a GraphQL query against G-Chain
	Query(ctx context.Context, query string, variables map[string]any) ([]byte, error)

	// QueryChain executes a query against a specific chain
	QueryChain(ctx context.Context, chainID uint64, query string, variables map[string]any) ([]byte, error)
}

// Precompile address
var graphQLAddr = common.HexToAddress(GraphQLAddress)

// Storage key prefixes
var (
	cachePrefix  = []byte("gcache")
	statsPrefix  = []byte("gstats")
	configPrefix = []byte("gconf")
)

// GraphQLPrecompile implements the G-Chain GraphQL query interface
// This precompile enables any EVM contract to execute GraphQL queries
// against the unified G-Chain query layer.
type GraphQLPrecompile struct {
	// client is the connection to G-Chain. It is set ONCE during VM init
	// (SetGraphVMClient), before the precompile is ever invoked in consensus, and is
	// read-only thereafter — so the Run path holds no lock and shares no mutable state.
	client GChainClient

	// config holds runtime configuration, set once at Configure time and read-only
	// during execution.
	config *Config
}

// QueryStats is retained for response-shape compatibility only. A precompile may not
// accumulate process-global counters: they diverge across validators (and across a single
// node's restarts) and would leak nondeterministic data into consensus output. getStats
// therefore always returns the zero value — see runGetStats.
type QueryStats struct {
	TotalQueries    uint64
	CacheHits       uint64
	CacheMisses     uint64
	TotalGasUsed    uint64
	AvgResponseTime time.Duration
}

// Config holds precompile configuration
type Config struct {
	// MaxCacheSize is the maximum number of cache entries
	MaxCacheSize int

	// DefaultCacheTTL is the default cache time-to-live
	DefaultCacheTTL time.Duration

	// QueryTimeout is the maximum query execution time
	QueryTimeout time.Duration

	// GChainEndpoint is the G-Chain GraphQL endpoint
	GChainEndpoint string
}

// NewGraphQLPrecompile creates a new GraphQL precompile instance
func NewGraphQLPrecompile(client GChainClient) *GraphQLPrecompile {
	return &GraphQLPrecompile{
		client: client,
		config: &Config{
			MaxCacheSize:    1000,
			DefaultCacheTTL: 10 * time.Second,
			QueryTimeout:    5 * time.Second,
			GChainEndpoint:  "http://localhost:9650/ext/bc/G/graphql",
		},
	}
}

// makeStorageKey creates a storage key from prefix and data
func makeStorageKey(prefix []byte, data []byte) common.Hash {
	h := sha256.New()
	h.Write(prefix)
	h.Write(data)
	var key common.Hash
	copy(key[:], h.Sum(nil))
	return key
}

// =========================================================================
// Core Query Methods
// =========================================================================

// Query executes a GraphQL query and returns the result. It is the main entry point for
// EVM contracts and is a DETERMINISTIC, STATELESS function of (input, local G-Chain DB):
//   - no time.Now()/wall-clock (it forked on per-validator clock skew),
//   - no process-global cache (a warm-vs-cold node returned stale-vs-fresh data and
//     different gas — both consensus-visible),
//   - no process-global stats counters (cross-tx mutable state, returned on-chain),
//   - no goroutines (scheduler order is nondeterministic),
//   - a nil client returns a typed error instead of panicking the dispatch path.
//
// Every validator therefore computes the same bytes for the same block state.
func (p *GraphQLPrecompile) Query(
	stateDB StateDB,
	caller common.Address,
	req QueryRequest,
	gasLimit uint64,
) (QueryResponse, error) {
	// Validate query
	if err := p.validateQuery(req); err != nil {
		return QueryResponse{}, err
	}

	// Fail CLOSED if the client was never wired (the default instance holds a nil
	// client until SetGraphVMClient runs at VM init). A nil-interface call below would
	// panic, and a panic in the precompile dispatch path is unrecovered — it halts every
	// validator that processed the tx. Return a typed error instead.
	if p.client == nil {
		return QueryResponse{}, ErrClientNotInitialized
	}

	// Gas cost is a pure function of the query (no cache-hit discount), so it is
	// identical on every node.
	gasCost := p.calculateGasCost(req)
	if gasCost > gasLimit {
		return QueryResponse{}, ErrGasExceeded
	}

	var variables map[string]any
	if len(req.Variables) > 0 {
		if err := json.Unmarshal(req.Variables, &variables); err != nil {
			return QueryResponse{}, ErrInvalidQuery
		}
	}

	// No wall-clock deadline: a context timeout fires nondeterministically (a slow node
	// times out while a fast one succeeds) and forks the chain. The query is a bounded
	// local-DB read, already gated by gas.
	ctx := context.Background()

	var result []byte
	var err error
	switch {
	case len(req.TargetChains) == 0:
		// Query all chains via the G-Chain unified layer.
		result, err = p.client.Query(ctx, req.Query, variables)
	case len(req.TargetChains) == 1:
		// Query a specific chain.
		result, err = p.client.QueryChain(ctx, req.TargetChains[0], req.Query, variables)
	default:
		// Multi-chain query (sequential, deterministic).
		result, err = p.executeMultiChainQuery(ctx, req, variables)
	}

	if err != nil {
		return QueryResponse{
			Errors:  []QueryError{{Message: err.Error()}},
			GasUsed: gasCost,
		}, nil
	}

	// Validate response size
	if len(result) > MaxResponseSize {
		return QueryResponse{}, ErrQueryTooLarge
	}

	responseGas := uint64(len(result)) * GasPerByte
	return QueryResponse{
		Data:    result,
		GasUsed: gasCost + responseGas,
	}, nil
}

// QueryPredefined executes a pre-defined query template
// This provides lower gas costs for common queries
func (p *GraphQLPrecompile) QueryPredefined(
	stateDB StateDB,
	caller common.Address,
	queryID QueryID,
	args [][]byte,
	gasLimit uint64,
) (QueryResponse, error) {
	template, ok := PredefinedQueries[queryID]
	if !ok {
		return QueryResponse{}, ErrInvalidQuery
	}

	if len(args) > template.MaxArgs {
		return QueryResponse{}, ErrInvalidQuery
	}

	if template.GasCost > gasLimit {
		return QueryResponse{}, ErrGasExceeded
	}

	// Build variables from args
	variables := make(map[string]any)
	argNames := []string{"address", "id", "first", "orderBy", "owner"}
	for i, arg := range args {
		if i < len(argNames) {
			variables[argNames[i]] = string(arg)
		}
	}

	varsJSON, _ := json.Marshal(variables)

	req := QueryRequest{
		Query:     template.Query,
		Variables: varsJSON,
	}

	return p.Query(stateDB, caller, req, gasLimit)
}

// =========================================================================
// Helper Methods
// =========================================================================

// validateQuery validates the query request
func (p *GraphQLPrecompile) validateQuery(req QueryRequest) error {
	if len(req.Query) == 0 {
		return ErrInvalidQuery
	}
	if len(req.Query) > MaxQuerySize {
		return ErrQueryTooLarge
	}
	return nil
}

// calculateGasCost estimates the gas cost for a query
func (p *GraphQLPrecompile) calculateGasCost(req QueryRequest) uint64 {
	// Base cost
	cost := GasQueryBase

	// Add cost based on query complexity
	queryLen := len(req.Query)
	if queryLen > 500 {
		cost += GasQueryComplex
	} else {
		cost += GasQuerySimple
	}

	// Add cost for cross-chain queries
	if len(req.TargetChains) > 1 {
		cost += GasQueryCrossChain * uint64(len(req.TargetChains))
	}

	// Add cost for variables
	cost += uint64(len(req.Variables)) * GasPerByte

	return cost
}

// executeMultiChainQuery executes a query across multiple chains SEQUENTIALLY. The
// consensus path must be free of goroutines: scheduler order is nondeterministic, and the
// previous concurrent version let whichever goroutine raced first win the "first error"
// slot — so different validators could surface different errors (or partial result sets)
// and fork. Iterating TargetChains in order makes both the result map and the first error
// deterministic; json.Marshal then sorts the integer keys, so the bytes are identical
// everywhere.
func (p *GraphQLPrecompile) executeMultiChainQuery(
	ctx context.Context,
	req QueryRequest,
	variables map[string]any,
) ([]byte, error) {
	results := make(map[uint64]json.RawMessage)
	var firstErr error

	for _, chainID := range req.TargetChains {
		result, err := p.client.QueryChain(ctx, chainID, req.Query, variables)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		results[chainID] = json.RawMessage(result)
	}

	if firstErr != nil && len(results) == 0 {
		return nil, firstErr
	}

	combined := map[string]any{
		"data": results,
	}
	return json.Marshal(combined)
}

// =========================================================================
// View Methods
// =========================================================================

// GetStats returns query statistics. Precompiles cannot keep process-global counters
// (they diverge across validators), so this is always the deterministic zero value.
func (p *GraphQLPrecompile) GetStats() *QueryStats {
	return &QueryStats{}
}

// GetConfig returns the current (immutable) configuration.
func (p *GraphQLPrecompile) GetConfig() *Config {
	return p.config
}

// =========================================================================
// EVM Precompile Interface
// =========================================================================

// RequiredGas returns the gas required for the input
func (p *GraphQLPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasQueryBase
	}

	// Parse method selector
	selector := binary.BigEndian.Uint32(input[:4])

	switch selector {
	case 0x01: // query(bytes)
		return GasQueryComplex
	case 0x02: // queryPredefined(uint16, bytes[])
		return GasQuerySimple
	case 0x03: // getStats()
		return GasQueryBase
	default:
		return GasQueryComplex
	}
}

// Run executes the precompile
func (p *GraphQLPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, ErrInvalidQuery
	}

	selector := binary.BigEndian.Uint32(input[:4])

	switch selector {
	case 0x01: // query(bytes)
		return p.runQuery(input[4:])
	case 0x02: // queryPredefined(uint16, bytes[])
		return p.runQueryPredefined(input[4:])
	case 0x03: // getStats()
		return p.runGetStats()
	default:
		return nil, fmt.Errorf("unknown method: %x", selector)
	}
}

// runQuery handles the query method call
func (p *GraphQLPrecompile) runQuery(input []byte) ([]byte, error) {
	// Decode QueryRequest from input
	var req QueryRequest
	if err := json.Unmarshal(input, &req); err != nil {
		return nil, ErrInvalidQuery
	}

	// Execute query (uses default gas limit)
	resp, err := p.Query(nil, common.Address{}, req, 1_000_000)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// runQueryPredefined handles the queryPredefined method call
func (p *GraphQLPrecompile) runQueryPredefined(input []byte) ([]byte, error) {
	if len(input) < 2 {
		return nil, ErrInvalidQuery
	}

	queryID := QueryID(binary.BigEndian.Uint16(input[:2]))

	// Parse args (simple format: length-prefixed byte arrays)
	var args [][]byte
	offset := 2
	for offset < len(input) {
		if offset+4 > len(input) {
			break
		}
		argLen := binary.BigEndian.Uint32(input[offset : offset+4])
		offset += 4
		if offset+int(argLen) > len(input) {
			break
		}
		args = append(args, input[offset:offset+int(argLen)])
		offset += int(argLen)
	}

	resp, err := p.QueryPredefined(nil, common.Address{}, queryID, args, 1_000_000)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// runGetStats handles the getStats method call. It returns the deterministic zero stats
// (telemetry counters are not consensus state).
func (p *GraphQLPrecompile) runGetStats() ([]byte, error) {
	return json.Marshal(p.GetStats())
}

// =========================================================================
// Solidity Interface (for documentation)
// =========================================================================

// Solidity interface:
//
// interface IGraphQL {
//     struct QueryRequest {
//         string query;
//         bytes variables;
//         string operationName;
//         uint64[] targetChains;
//     }
//
//     struct QueryResponse {
//         bytes data;
//         QueryError[] errors;
//         uint64 gasUsed;
//     }
//
//     struct QueryError {
//         string message;
//         string[] path;
//     }
//
//     function query(QueryRequest calldata req) external returns (QueryResponse memory);
//     function queryPredefined(uint16 queryId, bytes[] calldata args) external returns (bytes memory);
//     function getStats() external view returns (uint64 totalQueries, uint64 cacheHits, uint64 cacheMisses);
//
//     // Pre-defined query IDs
//     uint16 constant QUERY_CHAIN_INFO = 0x0001;
//     uint16 constant QUERY_BALANCE = 0x0101;
//     uint16 constant QUERY_FACTORY = 0x0201;
//     uint16 constant QUERY_BUNDLE = 0x0202;
//     uint16 constant QUERY_TOKEN = 0x0301;
//     uint16 constant QUERY_TOKENS = 0x0302;
//     uint16 constant QUERY_POOL = 0x0401;
//     uint16 constant QUERY_POOLS = 0x0402;
//     uint16 constant QUERY_POSITIONS = 0x0601;
//     uint16 constant QUERY_SWAPS = 0x0701;
//     uint16 constant QUERY_ALL_CHAINS_TVL = 0x0F01;
// }
