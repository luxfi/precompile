// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// GChainClient interface for communication with G-Chain
type GChainClient interface {
	// Query executes a GraphQL query against G-Chain
	Query(ctx context.Context, query string, variables map[string]any) ([]byte, error)

	// QueryChain executes a query against a specific chain
	QueryChain(ctx context.Context, chainID uint64, query string, variables map[string]any) ([]byte, error)
}

// Method selectors.
const (
	selectorQuery      uint32 = 0x01 // query(bytes)
	selectorPredefined uint32 = 0x02 // queryPredefined(uint16, bytes[])
	selectorStats      uint32 = 0x03 // getStats()
)

// complexQueryLength is the query length above which the complex tier applies.
const complexQueryLength = 500

// GraphQLPrecompile implements the G-Chain GraphQL query interface
// This precompile enables any EVM contract to execute GraphQL queries
// against the unified G-Chain query layer.
//
// It is a pure read: it touches no EVM state and does not consult the caller, which is why
// neither appears in the signatures below. There is nothing here for a readOnly context to
// forbid and nothing for an access check to gate.
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

// =========================================================================
// Gas
// =========================================================================

// maxResponseGas is the price of the largest response the precompile may return. It is the
// allowance reserved against a response that does not exist yet; see gasForInput.
const maxResponseGas = uint64(MaxResponseSize) * GasPerByte

// requestGas prices everything the caller controls that is knowable BEFORE any work
// happens: the query bytes, the variable bytes, and the per-chain fan-out. Bytes cost
// GasPerByte wherever they appear, so there is one rule rather than one per field. It reads
// no state, no clock and no client, so every validator computes the same figure.
func requestGas(req QueryRequest) uint64 {
	cost := GasQueryBase
	if len(req.Query) > complexQueryLength {
		cost += GasQueryComplex
	} else {
		cost += GasQuerySimple
	}
	// Each additional target chain is another round trip through the client; the fan-out
	// is capped by validateQuery, which is what keeps this product bounded.
	if len(req.TargetChains) > 1 {
		cost += GasQueryCrossChain * uint64(len(req.TargetChains))
	}
	cost += uint64(len(req.Query)+len(req.Variables)) * GasPerByte
	return cost
}

// gasForInput is the gas reserved before the precompile does anything, and the figure
// RequiredGas reports.
//
// Response size is only known once the work is done, so charging for it afterwards would
// mean the node had already performed work it might not be paid for. Instead the caller is
// charged the worst case — requestGas plus the largest response the precompile is allowed
// to return — before execution starts, and refunded down to the actual figure afterwards.
// A query therefore never runs unless its caller has already paid for the largest result it
// could produce, so there is no deduction that can come up short and no path on which work
// is performed for free. The refund is a pure function of a deterministic result.
//
// gasForInput reads only the calldata: no state, no client, no clock.
func gasForInput(input []byte) uint64 {
	if len(input) < 4 {
		return GasQueryBase
	}
	body := input[4:]
	// Decoding the body is itself work proportional to its length, so it is priced even
	// when it fails and nothing further is attempted.
	decodeGas := GasQueryBase + uint64(len(body))*GasPerByte

	switch binary.BigEndian.Uint32(input[:4]) {
	case selectorQuery:
		req, err := decodeQuery(body)
		if err != nil {
			return decodeGas
		}
		return requestGas(req) + maxResponseGas
	case selectorPredefined:
		req, err := decodePredefined(body)
		if err != nil {
			return decodeGas
		}
		return requestGas(req) + maxResponseGas
	case selectorStats:
		return GasQueryBase
	default:
		return decodeGas
	}
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
//
// gasLimit is the caller's budget. On the precompile dispatch path it is the reservation
// already taken by RequiredGas; a direct caller of this method supplies its own.
func (p *GraphQLPrecompile) Query(req QueryRequest, gasLimit uint64) (QueryResponse, error) {
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
	gasCost := requestGas(req)
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

	// Validate response size. This bound is what makes the upfront reservation total:
	// the response term can never exceed the allowance already taken.
	if len(result) > MaxResponseSize {
		return QueryResponse{}, ErrQueryTooLarge
	}

	return QueryResponse{
		Data:    result,
		GasUsed: gasCost + uint64(len(result))*GasPerByte,
	}, nil
}

// QueryPredefined executes a pre-defined query template
// This provides lower gas costs for common queries
func (p *GraphQLPrecompile) QueryPredefined(queryID QueryID, args [][]byte, gasLimit uint64) (QueryResponse, error) {
	req, err := expandPredefined(queryID, args)
	if err != nil {
		return QueryResponse{}, err
	}
	return p.Query(req, gasLimit)
}

// =========================================================================
// Decoding
// =========================================================================

// decodeQuery decodes selector-0x01 calldata. Pricing and execution share it, so the gas
// reserved is always computed from the same request that is subsequently run.
func decodeQuery(body []byte) (QueryRequest, error) {
	var req QueryRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return QueryRequest{}, ErrInvalidQuery
	}
	return req, nil
}

// decodePredefined decodes selector-0x02 calldata into the request its template expands to.
// Pricing and execution share it for the same reason as decodeQuery.
func decodePredefined(body []byte) (QueryRequest, error) {
	if len(body) < 2 {
		return QueryRequest{}, ErrInvalidQuery
	}
	args, err := decodeArgs(body[2:])
	if err != nil {
		return QueryRequest{}, err
	}
	return expandPredefined(QueryID(binary.BigEndian.Uint16(body[:2])), args)
}

// decodeArgs parses length-prefixed byte arrays. A truncated tail is REFUSED rather than
// silently accepted as a shorter argument list: a caller must not be able to change which
// arguments a query is expanded with by cutting its calldata short.
func decodeArgs(body []byte) ([][]byte, error) {
	var args [][]byte
	for offset := 0; offset < len(body); {
		if offset+4 > len(body) {
			return nil, ErrInvalidQuery
		}
		argLen := int(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4
		if argLen < 0 || offset+argLen > len(body) {
			return nil, ErrInvalidQuery
		}
		args = append(args, body[offset:offset+argLen])
		offset += argLen
	}
	return args, nil
}

// argNames binds positional arguments to template variable names.
var argNames = []string{"address", "id", "first", "orderBy", "owner"}

// expandPredefined turns a template ID plus positional arguments into the request that will
// actually be executed. It is the single expander: gas is computed from its output and so
// is the query that runs, so the two cannot disagree.
func expandPredefined(queryID QueryID, args [][]byte) (QueryRequest, error) {
	template, ok := PredefinedQueries[queryID]
	if !ok {
		return QueryRequest{}, ErrInvalidQuery
	}
	if len(args) > template.MaxArgs {
		return QueryRequest{}, ErrInvalidQuery
	}

	variables := make(map[string]any, len(args))
	for i, arg := range args {
		if i < len(argNames) {
			variables[argNames[i]] = string(arg)
		}
	}
	// json.Marshal sorts map keys, so the encoding is byte-identical on every validator.
	varsJSON, err := json.Marshal(variables)
	if err != nil {
		return QueryRequest{}, ErrInvalidQuery
	}

	return QueryRequest{Query: template.Query, Variables: varsJSON}, nil
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
	// The fan-out drives one client round trip per entry and one GasQueryCrossChain term
	// per entry. Capping the slice bounds both the loop and the arithmetic.
	if len(req.TargetChains) > MaxTargetChains {
		return ErrQueryTooLarge
	}
	return nil
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

// RequiredGas returns the gas that must be reserved before Run is allowed to execute.
func (p *GraphQLPrecompile) RequiredGas(input []byte) uint64 {
	return gasForInput(input)
}

// Run executes the precompile and reports the gas actually consumed, which is never more
// than the RequiredGas reserved for the same input.
func (p *GraphQLPrecompile) Run(input []byte) ([]byte, uint64, error) {
	if len(input) < 4 {
		return nil, GasQueryBase, ErrInvalidQuery
	}

	body := input[4:]
	decodeGas := GasQueryBase + uint64(len(body))*GasPerByte

	switch binary.BigEndian.Uint32(input[:4]) {
	case selectorQuery:
		req, err := decodeQuery(body)
		if err != nil {
			return nil, decodeGas, err
		}
		return p.run(req)
	case selectorPredefined:
		req, err := decodePredefined(body)
		if err != nil {
			return nil, decodeGas, err
		}
		return p.run(req)
	case selectorStats:
		out, err := p.runGetStats()
		return out, GasQueryBase, err
	default:
		return nil, decodeGas, fmt.Errorf("unknown method: %x", input[:4])
	}
}

// run executes an already-decoded request under the reservation RequiredGas took for it.
//
// A response carrying GraphQL errors is surfaced as a Go error so the EVM call reverts:
// returning empty data with no error would leave a caller unable to tell a failed query
// from a genuinely empty result.
func (p *GraphQLPrecompile) run(req QueryRequest) ([]byte, uint64, error) {
	reserved := requestGas(req) + maxResponseGas
	resp, err := p.Query(req, reserved)
	if err != nil {
		return nil, reserved, err
	}
	if len(resp.Errors) > 0 {
		return nil, resp.GasUsed, fmt.Errorf("graphql: %s", resp.Errors[0].Message)
	}
	return resp.Data, resp.GasUsed, nil
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
