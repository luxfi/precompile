// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// queryInput encodes a QueryRequest as calldata for selector 0x01.
func queryInput(t *testing.T, req QueryRequest) []byte {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	input := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(input[:4], 0x01)
	copy(input[4:], body)
	return input
}

// charged runs the registered contract and reports what the caller actually paid.
func charged(t *testing.T, c *GraphQLContract, input []byte, supplied uint64) uint64 {
	t.Helper()
	_, remaining, err := c.Run(nil, common.Address{}, ContractGraphQLAddress, input, supplied, false)
	require.NoError(t, err)
	require.LessOrEqual(t, remaining, supplied, "a run may never hand back more gas than it was given")
	return supplied - remaining
}

// TestGraphQL_GasScalesWithResponseSize is the flat-fee regression.
//
// The precompile computed a size-aware price (calculateGasCost + len(result)*GasPerByte)
// and returned it in QueryResponse.GasUsed, but the dispatch path discarded the whole
// response except .Data and charged only the flat per-selector RequiredGas. A query
// returning 1 byte and a query returning MaxResponseSize bytes therefore cost exactly the
// same: caller-controlled work at a constant price.
func TestGraphQL_GasScalesWithResponseSize(t *testing.T) {
	req := QueryRequest{Query: "query { chainInfo { vmName } }"}
	input := queryInput(t, req)

	small := &GraphQLContract{precompile: NewGraphQLPrecompile(
		&stubClient{result: []byte(`{"a":1}`)})}
	big := &GraphQLContract{precompile: NewGraphQLPrecompile(
		&stubClient{result: []byte(`{"a":"` + strings.Repeat("x", MaxResponseSize-10) + `"}`)})}

	cheap := charged(t, small, input, 10_000_000)
	dear := charged(t, big, input, 10_000_000)

	require.Greater(t, dear, cheap,
		"a larger response must cost more gas than a smaller one for the identical query")
	// The gap must be the real per-byte price, not a rounding artefact.
	require.GreaterOrEqual(t, dear-cheap, uint64(MaxResponseSize-32)*GasPerByte)
}

// TestGraphQL_GasScalesWithQuerySize proves the request side is priced too: a long query
// costs more than a short one against the same (fixed) response.
func TestGraphQL_GasScalesWithQuerySize(t *testing.T) {
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(&stubClient{result: []byte(`{"a":1}`)})}

	short := charged(t, c, queryInput(t, QueryRequest{Query: "query{a}"}), 10_000_000)
	long := charged(t, c, queryInput(t, QueryRequest{
		Query: "query{" + strings.Repeat("a", 1000) + "}",
	}), 10_000_000)

	require.Greater(t, long, short, "a longer query must cost more gas")
	require.GreaterOrEqual(t, long-short, GasQueryComplex-GasQuerySimple)
}

// TestGraphQL_GasScalesWithVariablesSize proves caller-supplied variables are priced per
// byte on the path that actually charges.
func TestGraphQL_GasScalesWithVariablesSize(t *testing.T) {
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})}

	bare := charged(t, c, queryInput(t, QueryRequest{Query: "query{a}"}), 10_000_000)
	vars, err := json.Marshal(map[string]string{"k": strings.Repeat("v", 2000)})
	require.NoError(t, err)
	loaded := charged(t, c, queryInput(t, QueryRequest{Query: "query{a}", Variables: vars}), 10_000_000)

	require.Greater(t, loaded, bare, "caller-supplied variables must be priced")
	require.GreaterOrEqual(t, loaded-bare, uint64(len(vars))*GasPerByte)
}

// TestGraphQL_MultiChainGasScalesWithTargetChains is the unbounded-work regression, and the
// sharpest form of the flat fee. TargetChains is decoded straight out of caller JSON and
// drives one client.QueryChain call per entry with no cap; the discarded formula priced each
// at GasQueryCrossChain while the charged fee was a constant. N chains of work for the price
// of one.
func TestGraphQL_MultiChainGasScalesWithTargetChains(t *testing.T) {
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(&stubClient{result: []byte(`{"tvl":1}`)})}

	two := charged(t, c, queryInput(t, QueryRequest{
		Query: "query{tvl}", TargetChains: []uint64{1, 2},
	}), 100_000_000)
	many := charged(t, c, queryInput(t, QueryRequest{
		Query: "query{tvl}", TargetChains: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}), 100_000_000)

	require.Greater(t, many, two, "each additional target chain is another DB query and must be paid for")
	require.GreaterOrEqual(t, many-two, 8*GasQueryCrossChain)
}

// TestGraphQL_TargetChainsCapped proves the fan-out loop is bounded, not merely priced. An
// uncapped loop over caller JSON is a latency hazard on the consensus path even when the
// gas arithmetic is right, and it is what let the gas figure grow without bound.
func TestGraphQL_TargetChainsCapped(t *testing.T) {
	stub := &stubClient{result: []byte(`{}`)}
	p := NewGraphQLPrecompile(stub)

	chains := make([]uint64, MaxTargetChains+1)
	for i := range chains {
		chains[i] = uint64(i)
	}
	_, err := p.Query(QueryRequest{Query: "query{a}", TargetChains: chains}, 1<<62)
	require.ErrorIs(t, err, ErrQueryTooLarge)
	require.Empty(t, stub.calls, "a rejected request must not perform any chain query")

	// Exactly at the cap is accepted.
	stub2 := &stubClient{result: []byte(`{}`)}
	p2 := NewGraphQLPrecompile(stub2)
	_, err = p2.Query(QueryRequest{Query: "query{a}", TargetChains: chains[:MaxTargetChains]}, 1<<62)
	require.NoError(t, err)
	require.Len(t, stub2.calls, MaxTargetChains)
}

// TestGraphQL_UpfrontBoundCoversActual is the property that makes charge-then-refund safe:
// for every input, the gas reserved before any work is performed is at least the gas
// finally charged. If it were ever less the caller would receive work it had not paid for.
func TestGraphQL_UpfrontBoundCoversActual(t *testing.T) {
	// Single-chain shapes return the stub body verbatim, so the response term can be swept
	// right up to the cap.
	single := []QueryRequest{
		{Query: "query{a}"},
		{Query: strings.Repeat("q", MaxQuerySize)},
		{Query: "query{a}", TargetChains: []uint64{7}},
		{Query: "query{a}", Variables: []byte(`{"k":"v"}`)},
	}
	for _, n := range []int{0, 1, 7, 1024, MaxResponseSize - 1, MaxResponseSize} {
		c := &GraphQLContract{precompile: NewGraphQLPrecompile(&stubClient{result: jsonBlob(n)})}
		for _, req := range single {
			input := queryInput(t, req)
			bound := c.precompile.RequiredGas(input)
			used := charged(t, c, input, 1<<40)
			require.LessOrEqual(t, used, bound,
				"charged %d exceeds the %d reserved upfront for response size %d", used, bound, n)
		}
	}

	// The multi-chain shape wraps one body per chain, so its combined result must stay
	// under the cap for the call to succeed at all.
	for _, chains := range [][]uint64{{1, 2}, {1, 2, 3}, make([]uint64, MaxTargetChains)} {
		for i := range chains {
			chains[i] = uint64(i + 1)
		}
		c := &GraphQLContract{precompile: NewGraphQLPrecompile(&stubClient{result: jsonBlob(64)})}
		input := queryInput(t, QueryRequest{Query: "query{a}", TargetChains: chains})
		bound := c.precompile.RequiredGas(input)
		used := charged(t, c, input, 1<<40)
		require.LessOrEqual(t, used, bound, "charged %d exceeds the %d reserved for %d chains",
			used, bound, len(chains))
	}
}

// jsonBlob builds a JSON string literal of exactly n bytes (empty for n < 2).
func jsonBlob(n int) []byte {
	if n < 2 {
		return nil
	}
	return []byte(`"` + strings.Repeat("x", n-2) + `"`)
}

// TestGraphQL_OversizedResponseRefusedAndCharged proves the response cap is enforced and
// that overrunning it is not free. The oversized body is only discovered after the client
// has produced it, so the caller pays the full reservation it agreed to.
func TestGraphQL_OversizedResponseRefusedAndCharged(t *testing.T) {
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(
		&stubClient{result: jsonBlob(MaxResponseSize + 1)})}
	input := queryInput(t, QueryRequest{Query: "query{a}"})
	reserved := c.precompile.RequiredGas(input)

	const supplied = 10_000_000
	out, remaining, err := c.Run(nil, common.Address{}, ContractGraphQLAddress, input, supplied, false)
	require.ErrorIs(t, err, ErrQueryTooLarge)
	require.Nil(t, out)
	require.Equal(t, uint64(supplied)-reserved, remaining,
		"a failed run consumes exactly the reservation — no refund, no over-charge")
}

// TestGraphQL_InsufficientGasDoesNoWork proves the reservation is enforced before the work,
// not after: a caller that cannot cover the upfront bound never reaches the client.
func TestGraphQL_InsufficientGasDoesNoWork(t *testing.T) {
	stub := &stubClient{result: []byte(`{}`)}
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(stub)}
	input := queryInput(t, QueryRequest{Query: "query{a}", TargetChains: []uint64{1, 2, 3}})

	bound := c.precompile.RequiredGas(input)
	_, remaining, err := c.Run(nil, common.Address{}, ContractGraphQLAddress, input, bound-1, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
	require.Zero(t, remaining, "a refused call refunds nothing")
	require.Empty(t, stub.calls, "no chain may be queried when the reservation is not met")
}

// TestGraphQL_RequiredGasIsPureFunctionOfInput proves the reservation depends only on the
// bytes the caller supplied — it never consults the client, the config or any state — so
// every validator reserves the same amount.
func TestGraphQL_RequiredGasIsPureFunctionOfInput(t *testing.T) {
	input := queryInput(t, QueryRequest{Query: "query{a}", TargetChains: []uint64{9, 8}})

	wired := NewGraphQLPrecompile(&stubClient{result: []byte(`{"big":true}`)})
	unwired := NewGraphQLPrecompile(nil)
	require.Equal(t, unwired.RequiredGas(input), wired.RequiredGas(input))

	for i := 0; i < 50; i++ {
		require.Equal(t, wired.RequiredGas(input), wired.RequiredGas(input))
	}
}
