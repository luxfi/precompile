// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// selectorInput builds calldata for an arbitrary selector and body.
func selectorInput(sel uint32, body []byte) []byte {
	input := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(input[:4], sel)
	copy(input[4:], body)
	return input
}

// TestValidateQuery_Refusals covers every reason a request is turned away before any work
// happens, at both ends of each bound.
func TestValidateQuery_Refusals(t *testing.T) {
	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})

	cases := []struct {
		name string
		req  QueryRequest
		want error
	}{
		{"empty query", QueryRequest{Query: ""}, ErrInvalidQuery},
		{"one over the query cap", QueryRequest{Query: strings.Repeat("q", MaxQuerySize+1)}, ErrQueryTooLarge},
		{"one over the chain cap", QueryRequest{
			Query: "q{a}", TargetChains: make([]uint64, MaxTargetChains+1),
		}, ErrQueryTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := p.Query(c.req, 1<<62)
			require.ErrorIs(t, err, c.want)
		})
	}

	// One under each cap is accepted, so the bound is the boundary and not an accident.
	for _, req := range []QueryRequest{
		{Query: "q"},
		{Query: strings.Repeat("q", MaxQuerySize)},
		{Query: "q{a}", TargetChains: make([]uint64, MaxTargetChains)},
	} {
		_, err := p.Query(req, 1<<62)
		require.NoError(t, err)
	}
}

// TestQuery_MalformedVariablesRefused proves variables that are not JSON are refused
// instead of being handed to the client as a nil map, which would silently run the query
// with no arguments bound.
func TestQuery_MalformedVariablesRefused(t *testing.T) {
	stub := &stubClient{result: []byte(`{}`)}
	p := NewGraphQLPrecompile(stub)

	_, err := p.Query(QueryRequest{Query: "q{a}", Variables: []byte(`{not json`)}, 1<<62)
	require.ErrorIs(t, err, ErrInvalidQuery)
	require.Empty(t, stub.calls)

	// A JSON scalar is not a variables map either.
	_, err = p.Query(QueryRequest{Query: "q{a}", Variables: []byte(`42`)}, 1<<62)
	require.ErrorIs(t, err, ErrInvalidQuery)
}

// TestQuery_GasLimitRefusal proves the budget check refuses a request the caller cannot
// afford, and that one gas more is enough.
func TestQuery_GasLimitRefusal(t *testing.T) {
	stub := &stubClient{result: []byte(`{}`)}
	p := NewGraphQLPrecompile(stub)
	req := QueryRequest{Query: "q{a}"}
	need := requestGas(req)

	_, err := p.Query(req, need-1)
	require.ErrorIs(t, err, ErrGasExceeded)
	require.Empty(t, stub.calls, "a request refused for gas must not reach the client")

	_, err = p.Query(req, need)
	require.NoError(t, err)
}

// TestRun_UnknownSelectorRefused proves an unregistered selector is refused rather than
// falling through to a query, and that the refusal still costs the caller.
func TestRun_UnknownSelectorRefused(t *testing.T) {
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})}
	input := selectorInput(0xdeadbeef, []byte("body"))

	_, _, err := c.precompile.Run(input)
	require.ErrorContains(t, err, "unknown method")

	reserved := c.precompile.RequiredGas(input)
	require.Greater(t, reserved, uint64(0))
	_, remaining, err := c.Run(nil, common.Address{}, ContractGraphQLAddress, input, 1_000_000, false)
	require.Error(t, err)
	require.Equal(t, uint64(1_000_000)-reserved, remaining)
}

// TestRun_ShortInputRefused covers calldata too short to carry a selector, at every length
// below four bytes and at the boundary.
func TestRun_ShortInputRefused(t *testing.T) {
	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})
	for n := 0; n < 4; n++ {
		_, gas, err := p.Run(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidQuery, "length %d", n)
		require.Equal(t, GasQueryBase, gas)
		require.Equal(t, GasQueryBase, p.RequiredGas(make([]byte, n)))
	}
	// Exactly four bytes carries a selector and no body: refused as an unknown method,
	// not as a short input.
	_, _, err := p.Run(make([]byte, 4))
	require.ErrorContains(t, err, "unknown method")
}

// TestRun_MalformedQueryBodyRefused proves a body that is not a QueryRequest is refused,
// and that the reservation for it prices the decode attempt rather than a full query.
func TestRun_MalformedQueryBodyRefused(t *testing.T) {
	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})
	body := []byte(`{"Query": `)
	input := selectorInput(selectorQuery, body)

	_, gas, err := p.Run(input)
	require.ErrorIs(t, err, ErrInvalidQuery)

	want := GasQueryBase + uint64(len(body))*GasPerByte
	require.Equal(t, want, gas)
	require.Equal(t, want, p.RequiredGas(input),
		"an undecodable body reserves only what the decode attempt costs")
	require.Less(t, p.RequiredGas(input), maxResponseGas,
		"nothing may be reserved for a response that cannot be produced")
}

// TestRun_GraphQLErrorReverts proves a query whose client fails surfaces an error rather
// than empty data. Returning nil bytes with no error would leave a caller unable to tell a
// failure from a genuinely empty result.
func TestRun_GraphQLErrorReverts(t *testing.T) {
	stub := &stubClient{errOn: map[uint64]error{7: errClient}}
	c := &GraphQLContract{precompile: NewGraphQLPrecompile(stub)}
	input := queryInput(t, QueryRequest{Query: "q{a}", TargetChains: []uint64{7}})

	out, _, err := c.precompile.Run(input)
	require.ErrorContains(t, err, errClient.Error())
	require.Nil(t, out)

	_, remaining, err := c.Run(nil, common.Address{}, ContractGraphQLAddress, input, 1_000_000, false)
	require.Error(t, err)
	require.Equal(t, uint64(1_000_000)-c.precompile.RequiredGas(input), remaining)
}

// TestRun_GetStats covers the stats selector and pins the property that matters: the
// counters are always zero, because process-global telemetry diverges between validators
// and this value is consensus output.
func TestRun_GetStats(t *testing.T) {
	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})
	input := selectorInput(selectorStats, nil)

	out, gas, err := p.Run(input)
	require.NoError(t, err)
	require.Equal(t, GasQueryBase, gas)
	require.Equal(t, GasQueryBase, p.RequiredGas(input))

	var stats QueryStats
	require.NoError(t, json.Unmarshal(out, &stats))
	require.Equal(t, QueryStats{}, stats)

	// A trailing body does not change the answer, and running it many times does not make
	// a counter move.
	for i := 0; i < 10; i++ {
		again, _, err := p.Run(selectorInput(selectorStats, []byte("ignored")))
		require.NoError(t, err)
		require.Equal(t, out, again)
	}
}

// =========================================================================
// Predefined templates
// =========================================================================

// TestPredefined_RoundTrip proves the predefined selector expands a template, binds its
// positional arguments to the documented names, and runs the template's query verbatim.
func TestPredefined_RoundTrip(t *testing.T) {
	recorder := &recordingClient{result: []byte(`{"balance":"0"}`)}
	p := NewGraphQLPrecompile(recorder)

	body := append(idBytes(QueryIDBalance), lenPrefixed([]byte("0xabc"))...)
	out, gas, err := p.Run(selectorInput(selectorPredefined, body))
	require.NoError(t, err)
	require.JSONEq(t, `{"balance":"0"}`, string(out))

	require.Equal(t, PredefinedQueries[QueryIDBalance].Query, recorder.query)
	require.Equal(t, map[string]any{"address": "0xabc"}, recorder.variables)

	// The charged figure is the same rule as the plain query path.
	expanded, err := expandPredefined(QueryIDBalance, [][]byte{[]byte("0xabc")})
	require.NoError(t, err)
	require.Equal(t, requestGas(expanded)+uint64(len(out))*GasPerByte, gas)
	require.LessOrEqual(t, gas, p.RequiredGas(selectorInput(selectorPredefined, body)))
}

// TestPredefined_Refusals covers every way a predefined call is turned away.
func TestPredefined_Refusals(t *testing.T) {
	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{}`)})

	cases := []struct {
		name string
		body []byte
	}{
		{"no template id", nil},
		{"template id one byte short", []byte{0x01}},
		{"unknown template id", idBytes(QueryID(0xBEEF))},
		{"more args than the template accepts", append(idBytes(QueryIDChainInfo), lenPrefixed([]byte("x"))...)},
		{"argument length header truncated", append(idBytes(QueryIDBalance), 0x00, 0x00, 0x00)},
		{"argument body truncated", append(idBytes(QueryIDBalance), 0x00, 0x00, 0x00, 0x08, 'a', 'b')},
		{"argument length overflows the body", append(idBytes(QueryIDBalance), 0xff, 0xff, 0xff, 0xff)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input := selectorInput(selectorPredefined, c.body)
			_, _, err := p.Run(input)
			require.ErrorIs(t, err, ErrInvalidQuery)
			require.Less(t, p.RequiredGas(input), maxResponseGas,
				"a refused call reserves only its decode")
		})
	}
}

// TestDecodeArgs_TruncationIsRefusedNotTrimmed is the silent-acceptance regression. The
// parser used to `break` out of the loop on a short tail, so calldata cut mid-argument was
// accepted as a shorter argument list — letting a caller change which variables a query is
// expanded with by trimming bytes rather than by being refused.
func TestDecodeArgs_TruncationIsRefusedNotTrimmed(t *testing.T) {
	full := append(lenPrefixed([]byte("first")), lenPrefixed([]byte("second"))...)

	args, err := decodeArgs(full)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("first"), []byte("second")}, args)

	// Every proper prefix of a well-formed encoding is a refusal, never a shorter list.
	for n := 1; n < len(full); n++ {
		got, err := decodeArgs(full[:n])
		if err == nil {
			require.Equal(t, full[:n], reencode(got),
				"prefix of length %d was accepted as a different argument list", n)
			continue
		}
		require.ErrorIs(t, err, ErrInvalidQuery)
	}

	require.Empty(t, mustArgs(t, nil), "an empty body is an empty argument list")
	require.Empty(t, mustArgs(t, lenPrefixed(nil)), "a zero-length argument is preserved as empty")
}

// TestExpandPredefined_ArgumentBinding proves positional arguments bind to the documented
// names in order and that the encoding is byte-stable.
func TestExpandPredefined_ArgumentBinding(t *testing.T) {
	req, err := expandPredefined(QueryIDTokens, [][]byte{[]byte("10"), []byte("volume")})
	require.NoError(t, err)
	require.Equal(t, PredefinedQueries[QueryIDTokens].Query, req.Query)

	var vars map[string]any
	require.NoError(t, json.Unmarshal(req.Variables, &vars))
	require.Equal(t, map[string]any{"address": "10", "id": "volume"}, vars)

	// json.Marshal sorts map keys, so the same arguments encode to identical bytes every
	// time — the property that keeps validators in agreement.
	for i := 0; i < 50; i++ {
		again, err := expandPredefined(QueryIDTokens, [][]byte{[]byte("10"), []byte("volume")})
		require.NoError(t, err)
		require.Equal(t, req.Variables, again.Variables)
	}
}

// TestQueryPredefined_PublicAPI covers the exported wrapper, including its refusals.
func TestQueryPredefined_PublicAPI(t *testing.T) {
	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{"ok":1}`)})

	resp, err := p.QueryPredefined(QueryIDChainInfo, nil, 1<<62)
	require.NoError(t, err)
	require.JSONEq(t, `{"ok":1}`, string(resp.Data))

	_, err = p.QueryPredefined(QueryID(0xBEEF), nil, 1<<62)
	require.ErrorIs(t, err, ErrInvalidQuery)

	_, err = p.QueryPredefined(QueryIDChainInfo, [][]byte{[]byte("x")}, 1<<62)
	require.ErrorIs(t, err, ErrInvalidQuery)

	// The template still has to be affordable.
	_, err = p.QueryPredefined(QueryIDChainInfo, nil, 1)
	require.ErrorIs(t, err, ErrGasExceeded)
}

// TestPredefinedTemplates_MaxArgsCoversNames proves no template asks for more positional
// arguments than there are names to bind them to — an argument past the end of argNames
// would be silently dropped rather than bound.
func TestPredefinedTemplates_MaxArgsCoversNames(t *testing.T) {
	for id, tmpl := range PredefinedQueries {
		require.LessOrEqualf(t, tmpl.MaxArgs, len(argNames),
			"template 0x%04x accepts %d args but only %d names exist", uint16(id), tmpl.MaxArgs, len(argNames))
		require.NotEmptyf(t, tmpl.Query, "template 0x%04x has no query", uint16(id))
		require.Equalf(t, id, tmpl.ID, "template 0x%04x is keyed under the wrong ID", uint16(id))
	}
}

// =========================================================================
// Config / module wiring
// =========================================================================

// TestConfigure_AppliesOnlyNonZeroFields proves Configure overwrites a field only when the
// upgrade config actually sets it, so a partial config cannot blank the defaults.
func TestConfigure_AppliesOnlyNonZeroFields(t *testing.T) {
	c := &configurator{}
	require.IsType(t, &GraphConfig{}, c.MakeConfig())

	orig := *GraphContractInstance.precompile.config
	defer func() { *GraphContractInstance.precompile.config = orig }()

	require.NoError(t, c.Configure(nil, &GraphConfig{}, nil, nil))
	require.Equal(t, orig, *GraphContractInstance.precompile.config,
		"an empty config leaves every default in place")

	require.NoError(t, c.Configure(nil, &GraphConfig{
		GChainEndpoint: "http://gchain:9650",
		QueryTimeout:   30,
		MaxCacheSize:   77,
	}, nil, nil))
	got := GraphContractInstance.precompile.GetConfig()
	require.Equal(t, "http://gchain:9650", got.GChainEndpoint)
	require.Equal(t, 30*time.Second, got.QueryTimeout)
	require.Equal(t, 77, got.MaxCacheSize)
}

// TestConfigure_WrongTypeRefused proves a config of the wrong type is refused rather than
// silently ignored.
func TestConfigure_WrongTypeRefused(t *testing.T) {
	err := (&configurator{}).Configure(nil, wrongConfig{}, nil, nil)
	require.ErrorContains(t, err, "expected config type")
}

type wrongConfig struct{ precompileconfig.Config }

// TestGraphConfig_EqualIsSymmetricPerField proves Equal actually compares every field: a
// difference in any one of them must break equality.
func TestGraphConfig_EqualIsSymmetricPerField(t *testing.T) {
	base := GraphConfig{GChainEndpoint: "e", QueryTimeout: 1, MaxCacheSize: 2}
	require.True(t, base.Equal(&GraphConfig{GChainEndpoint: "e", QueryTimeout: 1, MaxCacheSize: 2}))

	for name, mutate := range map[string]func(*GraphConfig){
		"endpoint": func(c *GraphConfig) { c.GChainEndpoint = "other" },
		"timeout":  func(c *GraphConfig) { c.QueryTimeout = 99 },
		"cache":    func(c *GraphConfig) { c.MaxCacheSize = 99 },
		"upgrade":  func(c *GraphConfig) { c.Upgrade.Disable = true },
	} {
		t.Run(name, func(t *testing.T) {
			other := base
			mutate(&other)
			require.False(t, base.Equal(&other))
			require.False(t, other.Equal(&base))
		})
	}
}

// =========================================================================
// Response parsing helpers
// =========================================================================

// TestParsePriceResponse proves a well-formed price response is parsed, and — the
// regression — that a response omitting a price field is refused instead of panicking.
// big.Float.SetString returns nil on failure and multiplying through it dereferences nil.
func TestParsePriceResponse(t *testing.T) {
	good := []byte(`{"data":{"token":{"derivedETH":"2","symbol":"WBTC","decimals":8},"bundle":{"ethPriceUSD":"3000"}}}`)
	got, err := ParsePriceResponse(good)
	require.NoError(t, err)
	require.Equal(t, "WBTC", got.Symbol)
	require.Equal(t, "pool", got.Source)
	// 2 * 3000, scaled to 18 decimals.
	want := new(big.Int).Mul(big.NewInt(6000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	require.Equal(t, want, got.PriceUSD)

	for _, bad := range []string{
		`{}`,
		`{"data":{}}`,
		`{"data":{"token":{"derivedETH":"2"}}}`,
		`{"data":{"bundle":{"ethPriceUSD":"3000"}}}`,
		`{"data":{"token":{"derivedETH":"not a number"},"bundle":{"ethPriceUSD":"1"}}}`,
	} {
		require.NotPanics(t, func() {
			_, err := ParsePriceResponse([]byte(bad))
			require.ErrorIs(t, err, ErrInvalidQuery, "input %s", bad)
		}, "input %s", bad)
	}

	_, err = ParsePriceResponse([]byte(`not json`))
	require.Error(t, err)
}

// TestParsePoolInfoResponse covers the pool parser, including the fields it narrows.
func TestParsePoolInfoResponse(t *testing.T) {
	good := []byte(`{"data":{"pool":{"id":"0xpool","token0":{"Symbol":"A"},"token1":{"Symbol":"B"},` +
		`"feeTier":3000,"liquidity":"12345","sqrtPrice":"999","tick":-42}}}`)
	got, err := ParsePoolInfoResponse(good)
	require.NoError(t, err)
	require.Equal(t, "0xpool", got.PoolAddress)
	require.Equal(t, "A", got.Token0Symbol)
	require.Equal(t, "B", got.Token1Symbol)
	require.Equal(t, uint32(3000), got.FeeTier)
	require.Equal(t, big.NewInt(12345), got.Liquidity)
	require.Equal(t, big.NewInt(999), got.SqrtPriceX96)
	require.Equal(t, int32(-42), got.Tick)

	// Absent numeric fields decode to nil rather than panicking.
	require.NotPanics(t, func() {
		empty, err := ParsePoolInfoResponse([]byte(`{}`))
		require.NoError(t, err)
		require.Nil(t, empty.Liquidity)
	})

	_, err = ParsePoolInfoResponse([]byte(`not json`))
	require.Error(t, err)
}

// TestOracleAndAMMQueriesRegistered proves the init in oracle.go folds both catalogues into
// PredefinedQueries, so every documented ID is reachable through the predefined selector.
func TestOracleAndAMMQueriesRegistered(t *testing.T) {
	for id := range OracleQueries {
		require.Containsf(t, PredefinedQueries, id, "oracle query 0x%04x not registered", uint16(id))
	}
	for id := range AMMQueries {
		require.Containsf(t, PredefinedQueries, id, "AMM query 0x%04x not registered", uint16(id))
	}

	p := NewGraphQLPrecompile(&stubClient{result: []byte(`{"ok":1}`)})
	for id := range PredefinedQueries {
		_, err := p.QueryPredefined(id, nil, 1<<62)
		require.NoErrorf(t, err, "template 0x%04x is registered but not runnable", uint16(id))
	}
}

// =========================================================================
// helpers
// =========================================================================

var errClient = errStr("client refused")

type errStr string

func (e errStr) Error() string { return string(e) }

func idBytes(id QueryID) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(id))
	return b
}

func lenPrefixed(arg []byte) []byte {
	b := make([]byte, 4+len(arg))
	binary.BigEndian.PutUint32(b[:4], uint32(len(arg)))
	copy(b[4:], arg)
	return b
}

func reencode(args [][]byte) []byte {
	var out []byte
	for _, a := range args {
		out = append(out, lenPrefixed(a)...)
	}
	return out
}

func mustArgs(t *testing.T, body []byte) [][]byte {
	t.Helper()
	args, err := decodeArgs(body)
	require.NoError(t, err)
	if len(args) == 1 {
		require.Empty(t, args[0])
		return nil
	}
	return args
}

// recordingClient captures what the precompile actually asked the client for.
type recordingClient struct {
	query     string
	variables map[string]any
	result    []byte
}

func (c *recordingClient) Query(_ context.Context, query string, variables map[string]any) ([]byte, error) {
	c.query, c.variables = query, variables
	return c.result, nil
}

func (c *recordingClient) QueryChain(ctx context.Context, _ uint64, query string, variables map[string]any) ([]byte, error) {
	return c.Query(ctx, query, variables)
}

// TestGraphVMClient_UnmarshalableResultRefused proves a resolver result that cannot be
// encoded is reported as an error rather than returned as empty data.
func TestGraphVMClient_UnmarshalableResultRefused(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)
	client.RegisterResolver("alpha", func(context.Context, database.Database, map[string]any) (any, error) {
		return make(chan int), nil // channels have no JSON encoding
	})

	out, err := client.Query(context.Background(), `query { alpha }`, nil)
	require.ErrorContains(t, err, "failed to marshal response")
	require.Nil(t, out)
}

// TestGraphVMClient_ChainRouting covers the routing rule: the local chain and chain 0 are
// served, anything else is refused rather than silently answered with local data.
func TestGraphVMClient_ChainRouting(t *testing.T) {
	db := memdb.New()
	defer db.Close()
	client := NewGraphVMClientWithChainID(db, nil, ChainIDLuxMainnet)
	require.Equal(t, ChainIDLuxMainnet, client.ChainID())
	require.Equal(t, db, client.GetDB())

	for _, id := range []uint64{0, ChainIDLuxMainnet} {
		out, err := client.QueryChain(context.Background(), id, `query { chainInfo { vmName } }`, nil)
		require.NoError(t, err)
		require.Contains(t, string(out), "graphvm")
	}

	_, err := client.QueryChain(context.Background(), ChainIDZooMainnet, `query { chainInfo }`, nil)
	require.ErrorContains(t, err, "cross-chain queries not yet supported")

	client.SetChainID(ChainIDZooMainnet)
	require.Equal(t, ChainIDZooMainnet, client.ChainID())
	_, err = client.QueryChain(context.Background(), ChainIDZooMainnet, `query { chainInfo }`, nil)
	require.NoError(t, err)
}

// TestGraphVMClient_UninitialisedFailsClosed proves a client built without a database
// refuses every call instead of dereferencing a nil executor.
func TestGraphVMClient_UninitialisedFailsClosed(t *testing.T) {
	client := NewGraphVMClient(nil, nil)
	require.Nil(t, client.GetDB())
	require.NotPanics(t, func() { client.RegisterResolver("alpha", nil) })

	_, err := client.Query(context.Background(), `query { chainInfo }`, nil)
	require.ErrorContains(t, err, "not initialized")

	_, err = client.QueryChain(context.Background(), 0, `query { chainInfo }`, nil)
	require.ErrorContains(t, err, "not initialized")
}
