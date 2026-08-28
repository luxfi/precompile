// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/stretchr/testify/require"
)

func newExecutor(t *testing.T) *QueryExecutor {
	t.Helper()
	db := memdb.New()
	t.Cleanup(func() { _ = db.Close() })
	return NewQueryExecutor(db, &GConfig{MaxQueryDepth: 10, MaxResultSize: 1 << 20})
}

// TestExecute_ResolverOrderIsDeterministic is the consensus-fork regression. Execute
// returns on the FIRST resolver whose name the query mentions; it used to pick that
// resolver by ranging the resolver map, and Go randomises map iteration. Two registered
// resolvers that both match one query therefore resolved differently on different
// validators — and this value is consensus output.
//
// The assertion is not "some resolver wins" but "the same one wins every time", which is
// the only property that keeps validators in agreement.
func TestExecute_ResolverOrderIsDeterministic(t *testing.T) {
	const query = `query { alpha beta gamma delta epsilon }`

	first := ""
	for run := 0; run < 200; run++ {
		e := newExecutor(t)
		// Registration order is varied so a map that happened to be insertion-ordered
		// would not hide the defect either.
		names := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
		if run%2 == 1 {
			names = []string{"epsilon", "delta", "gamma", "beta", "alpha"}
		}
		for _, n := range names {
			e.RegisterResolver(n, constResolver(n))
		}

		resp := e.Execute(context.Background(), &GraphQLRequest{Query: query})
		require.Empty(t, resp.Errors)
		data, ok := resp.Data.(map[string]any)
		require.True(t, ok)
		require.Len(t, data, 1, "the first matching resolver wins and returns immediately")

		var winner string
		for k := range data {
			winner = k
		}
		if run == 0 {
			first = winner
		}
		require.Equal(t, first, winner,
			"the winning resolver must not depend on map iteration order")
	}
	require.Equal(t, "alpha", first, "ties resolve in name order")
}

func constResolver(v string) ResolverFunc {
	return func(context.Context, database.Database, map[string]any) (any, error) {
		return v, nil
	}
}

// TestExecute_ResolverErrorSurfaces proves a resolver failure becomes a GraphQL error and
// does not leak a half-built data map.
func TestExecute_ResolverErrorSurfaces(t *testing.T) {
	e := newExecutor(t)
	boom := errors.New("resolver exploded")
	e.RegisterResolver("alpha", func(context.Context, database.Database, map[string]any) (any, error) {
		return nil, boom
	})

	resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { alpha }`})
	require.Len(t, resp.Errors, 1)
	require.Equal(t, boom.Error(), resp.Errors[0].Message)
	require.Nil(t, resp.Data)
}

// TestExecute_ResolverReceivesVariablesAndDB proves the resolver is handed the executor's
// own database and the request's variables, not zero values.
func TestExecute_ResolverReceivesVariablesAndDB(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	e := NewQueryExecutor(db, nil)

	var gotDB database.Database
	var gotVars map[string]any
	e.RegisterResolver("alpha", func(_ context.Context, d database.Database, v map[string]any) (any, error) {
		gotDB, gotVars = d, v
		return "ok", nil
	})

	vars := map[string]any{"id": "42"}
	resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { alpha }`, Variables: vars})
	require.Empty(t, resp.Errors)
	require.Equal(t, db, gotDB)
	require.Equal(t, vars, gotVars)
}

// TestExecute_UninitialisedFailsClosed proves neither a nil executor nor one without a
// database panics on the dispatch path — a panic there is unrecovered and halts the node.
func TestExecute_UninitialisedFailsClosed(t *testing.T) {
	for name, e := range map[string]*QueryExecutor{
		"nil executor": nil,
		"nil database": NewQueryExecutor(nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			var resp *GraphQLResponse
			require.NotPanics(t, func() {
				resp = e.Execute(context.Background(), &GraphQLRequest{Query: `query { chainInfo }`})
			})
			require.Len(t, resp.Errors, 1)
			require.Equal(t, "executor not initialized", resp.Errors[0].Message)
			require.Nil(t, resp.Data)
		})
	}
}

// TestExecute_BuiltinFields covers every built-in the executor answers, and proves an
// unknown field is refused rather than silently returning an empty result set.
func TestExecute_BuiltinFields(t *testing.T) {
	e := newExecutor(t)

	t.Run("chainInfo", func(t *testing.T) {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { chainInfo { vmName } }`})
		require.Empty(t, resp.Errors)
		info := resp.Data.(map[string]any)["chainInfo"].(map[string]any)
		require.Equal(t, "graphvm", info["vmName"])
		require.Equal(t, "1.0.0", info["version"])
		require.Equal(t, true, info["readOnly"])
	})

	t.Run("balance", func(t *testing.T) {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { balance(address: "0x1") }`})
		require.Empty(t, resp.Errors)
		require.Equal(t, "0", resp.Data.(map[string]any)["balance"])
	})

	t.Run("chains", func(t *testing.T) {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { chains { id } }`})
		require.Empty(t, resp.Errors)
		require.Len(t, resp.Data.(map[string]any)["chains"], 1)
	})

	t.Run("several at once", func(t *testing.T) {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { chainInfo { vmName } balance chains }`})
		require.Empty(t, resp.Errors)
		require.Len(t, resp.Data.(map[string]any), 3)
	})

	t.Run("unknown field refused", func(t *testing.T) {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { nonsense }`})
		require.Len(t, resp.Errors, 1)
		require.Equal(t, "unknown field in query", resp.Errors[0].Message)
		require.Nil(t, resp.Data)
	})

	t.Run("empty query refused", func(t *testing.T) {
		resp := e.Execute(context.Background(), &GraphQLRequest{Query: ""})
		require.Len(t, resp.Errors, 1)
	})
}

// TestExecute_IsDeterministic proves repeated execution of one query yields an identical
// result — no clock, no counter, no iteration-order dependence anywhere in the path.
func TestExecute_IsDeterministic(t *testing.T) {
	e := newExecutor(t)
	req := &GraphQLRequest{Query: `query { chainInfo { vmName } balance chains }`}

	golden := e.Execute(context.Background(), req)
	for i := 0; i < 100; i++ {
		require.Equal(t, golden, e.Execute(context.Background(), req))
	}
}

// TestContainsField pins the matching rule, including the near-miss that a bare substring
// check would get wrong: a field name is only matched when a delimiter follows it, so
// "chain" must not match the field "chainInfo".
func TestContainsField(t *testing.T) {
	cases := []struct {
		query, field string
		want         bool
	}{
		{`query { chainInfo { vmName } }`, "chainInfo", true},
		{`query { balance }`, "balance", true},
		{`query{balance}`, "balance", true},
		{"query {\n\tbalance\n}", "balance", true},
		{`query { balance(address: "x") }`, "balance", true},
		{`query { chainInfo }`, "chain", false}, // prefix of a longer field
		{`query { chains }`, "chainInfo", false},
		{`query { balance }`, "", false},
		{``, "balance", false},
		{`balance`, "balance", false}, // no delimiter follows: end of string
		{`xbalance{}`, "balance", true},
		// The first occurrence has no delimiter after it; a later one does. A scan that
		// gave up on the first hit would answer false.
		{`balanceX and balance }`, "balance", true},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, containsField(c.query, c.field),
			"containsField(%q, %q)", c.query, c.field)
	}
}

// TestGetDB proves the accessor reports the executor's database and tolerates a nil
// receiver.
func TestGetDB(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	require.Equal(t, db, NewQueryExecutor(db, nil).GetDB())
	require.Nil(t, NewQueryExecutor(nil, nil).GetDB())

	var nilExec *QueryExecutor
	require.Nil(t, nilExec.GetDB())
}

// TestRegisterResolver proves registration replaces by name and tolerates a nil receiver.
func TestRegisterResolver(t *testing.T) {
	e := newExecutor(t)
	e.RegisterResolver("alpha", constResolver("first"))
	e.RegisterResolver("alpha", constResolver("second"))

	resp := e.Execute(context.Background(), &GraphQLRequest{Query: `query { alpha }`})
	require.Equal(t, "second", resp.Data.(map[string]any)["alpha"])

	var nilExec *QueryExecutor
	require.NotPanics(t, func() { nilExec.RegisterResolver("alpha", constResolver("x")) })

	// A zero-value executor has no resolver map; registering must not panic or allocate
	// one behind the caller's back.
	bare := &QueryExecutor{}
	require.NotPanics(t, func() { bare.RegisterResolver("alpha", constResolver("x")) })
	require.Nil(t, bare.resolvers)
}

// TestNewQueryExecutor proves the constructor wires exactly what it is given.
func TestNewQueryExecutor(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	cfg := &GConfig{MaxQueryDepth: 3, MaxCacheSize: 7, QueryTimeout: 11, MaxResultSize: 13, QueryTimeoutMs: 17}

	e := NewQueryExecutor(db, cfg)
	require.Equal(t, db, e.db)
	require.Same(t, cfg, e.config)
	require.NotNil(t, e.resolvers)
	require.Empty(t, e.resolvers)
}
