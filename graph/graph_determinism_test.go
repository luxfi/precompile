// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// stubClient is a deterministic in-memory GChainClient for consensus-path tests. It records
// the order in which chains are queried so we can assert sequential (non-goroutine)
// execution.
type stubClient struct {
	calls    []uint64
	result   []byte
	perChain map[uint64][]byte
	errOn    map[uint64]error
}

func (s *stubClient) Query(_ context.Context, _ string, _ map[string]any) ([]byte, error) {
	return s.result, nil
}

func (s *stubClient) QueryChain(_ context.Context, chainID uint64, _ string, _ map[string]any) ([]byte, error) {
	s.calls = append(s.calls, chainID)
	if e, ok := s.errOn[chainID]; ok {
		return nil, e
	}
	if r, ok := s.perChain[chainID]; ok {
		return r, nil
	}
	return s.result, nil
}

// TestGraphQL_NilClientReturnsTypedErrorNotPanic is the chain-halt regression. The default
// precompile holds a nil client until VM init wires one; before the fix, invoking it called
// a method on the nil interface and PANICKED in the unrecovered precompile dispatch path,
// halting every validator that processed the tx. It must now return a typed error.
func TestGraphQL_NilClientReturnsTypedErrorNotPanic(t *testing.T) {
	p := NewGraphQLPrecompile(nil)

	require.NotPanics(t, func() {
		_, err := p.Query(nil, common.Address{}, QueryRequest{Query: "query { chainInfo }"}, 1_000_000)
		require.ErrorIs(t, err, ErrClientNotInitialized)
	})

	// Same guarantee through the registered StatefulPrecompiledContract dispatch path.
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(nil)}
	reqBytes, err := json.Marshal(QueryRequest{Query: "query { chainInfo }"})
	require.NoError(t, err)
	input := make([]byte, 4+len(reqBytes))
	binary.BigEndian.PutUint32(input[:4], 0x01)
	copy(input[4:], reqBytes)

	require.NotPanics(t, func() {
		_, _, runErr := c.Run(nil, common.Address{}, ContractGraphQLAddress, input, 1_000_000, true)
		require.ErrorIs(t, runErr, ErrClientNotInitialized)
	})
}

// TestGraphQL_DeterministicAcrossRuns proves the Run path carries no wall-clock and no
// cross-tx cache: the same query against the same client yields byte-identical Data AND an
// identical GasUsed on every invocation. Before the fix the second call hit the in-memory
// cache and returned a different (discounted) GasUsed — a consensus-visible divergence
// between a warm and a cold validator.
func TestGraphQL_DeterministicAcrossRuns(t *testing.T) {
	client := &stubClient{result: []byte(`{"chainInfo":{"vmName":"graphvm"}}`)}
	p := NewGraphQLPrecompile(client)
	req := QueryRequest{Query: "query { chainInfo { vmName } }"}

	first, err := p.Query(nil, common.Address{}, req, 1_000_000)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		got, err := p.Query(nil, common.Address{}, req, 1_000_000)
		require.NoError(t, err)
		require.Equal(t, first.Data, got.Data, "data must be identical across runs")
		require.Equal(t, first.GasUsed, got.GasUsed, "gas must be identical across runs (no cache discount)")
	}
}

// TestGraphQL_MultiChainSequentialDeterministic proves the multi-chain path runs
// sequentially in TargetChains order (no goroutines) and emits byte-identical output every
// time. The concurrent version it replaced let goroutines populate the result set and the
// "first error" in scheduler-random order, so different validators could fork.
func TestGraphQL_MultiChainSequentialDeterministic(t *testing.T) {
	req := QueryRequest{
		Query:        "query { tvl }",
		TargetChains: []uint64{96369, 200200, 36963}, // deliberately not sorted
	}

	var golden []byte
	for run := 0; run < 50; run++ {
		client := &stubClient{
			perChain: map[uint64][]byte{
				96369:  []byte(`{"tvl":1}`),
				200200: []byte(`{"tvl":2}`),
				36963:  []byte(`{"tvl":3}`),
			},
		}
		p := NewGraphQLPrecompile(client)

		resp, err := p.Query(nil, common.Address{}, req, 10_000_000)
		require.NoError(t, err)

		// Chains are visited in exactly the request order — proof of sequential execution.
		require.Equal(t, []uint64{96369, 200200, 36963}, client.calls)

		if run == 0 {
			golden = resp.Data
		} else {
			require.Equal(t, golden, resp.Data, "multi-chain output must be byte-identical across runs")
		}
	}

	// And the combined payload is well-formed JSON with all three chains present.
	var combined map[string]any
	require.NoError(t, json.Unmarshal(golden, &combined))
	data, ok := combined["data"].(map[string]any)
	require.True(t, ok)
	require.Len(t, data, 3)
}

// TestGraphQL_MultiChainFirstErrorDeterministic proves the surfaced error is the FIRST in
// request order (deterministic), not whichever goroutine raced first.
func TestGraphQL_MultiChainFirstErrorDeterministic(t *testing.T) {
	errA := errors.New("chain A failed")
	errB := errors.New("chain B failed")
	req := QueryRequest{
		Query:        "query { tvl }",
		TargetChains: []uint64{11, 22},
	}

	for i := 0; i < 20; i++ {
		client := &stubClient{errOn: map[uint64]error{11: errA, 22: errB}}
		p := NewGraphQLPrecompile(client)
		resp, err := p.Query(nil, common.Address{}, req, 10_000_000)
		// Both chains errored and none produced a result -> the FIRST error (chain 11) wins.
		require.NoError(t, err) // surfaced as a QueryError, not a Go error
		require.Len(t, resp.Errors, 1)
		require.Equal(t, errA.Error(), resp.Errors[0].Message)
	}
}
