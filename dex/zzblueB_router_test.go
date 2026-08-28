// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	lx "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// zzblueB_router_test.go interrogates the LP-9012 router as an ATTACKER reaches it:
// through RouterContract.Run, the dispatch a chain hands raw calldata to. Four
// questions are asked and answered by measurement, not by walking lines:
//
//  1. Does any handler read bytes the caller did not declare? (soundness)
//  2. Is the route a caller gets a FUNCTION of the calldata, or of map order?
//     (determinism — two validators must agree)
//  3. Is the best-of-N comparison total, and is the empty set refused rather than
//     answered with a zero route?
//  4. What does a refusal cost, and is that cost the same for every refusal?

// =========================================================================
// Fixtures
// =========================================================================

// blueBPoisoned returns b with attacker-controlled SPARE CAPACITY behind it.
//
// This is the production shape, not a curiosity: every geth CALL variant reaches a
// precompile via scope.Memory.GetPtr(off, size), which is the two-index slice
// m.store[off:off+size] with no CopyBytes on the path. cap(input) is therefore the
// rest of EVM memory, which the caller filled with MSTORE. A decoder that slices
// past len does NOT panic in production — it silently reads bytes the caller chose.
// So every length check is asserted against a POISONED buffer, where a read past
// len yields 0xA5 rather than a crash, and the verdict is compared to the clean one.
func blueBPoisoned(b []byte, spare int) []byte {
	full := make([]byte, len(b)+spare)
	for i := range full {
		full[i] = 0xA5
	}
	copy(full, b)
	return full[:len(b)]
}

// blueBVerdict is everything a caller observes from one Run: the bytes, the gas
// left, and the error. Two inputs that differ only in undeclared bytes must produce
// an identical verdict in all three.
type blueBVerdict struct {
	out []byte
	gas uint64
	err string
	ok  bool // err == nil
}

func blueBRun(c *RouterContract, st contract.AccessibleState, in []byte, gas uint64, readOnly bool) blueBVerdict {
	out, left, err := c.Run(st, common.HexToAddress("0x1111111111111111111111111111111111111111"),
		lxRouterAddr, in, gas, readOnly)
	v := blueBVerdict{out: out, gas: left, ok: err == nil}
	if err != nil {
		v.err = err.Error()
	}
	return v
}

// blueBNoBlock is an AccessibleState with NO block context — the shape a host hands
// a precompile outside block execution. Every handler dereferences
// GetBlockContext().Number(), so the guard in Run is load-bearing: without it this
// state is a nil dereference, i.e. a validator panic reachable from calldata.
type blueBNoBlock struct{ *nativeAtomicState }

func (blueBNoBlock) GetBlockContext() contract.BlockContext { return nil }

var _ contract.AccessibleState = blueBNoBlock{}

// blueBLive builds a RouterContract whose pool manager has a LIVE quoting engine.
// The registered singleton's engine is dchainUnavailable, whose Quote returns zero
// by design, so no V4 route can ever price through it; a local instance runs the
// IDENTICAL Run dispatch over a manager that can. Hermetic: no package singleton is
// touched.
func blueBLive() (*RouterContract, *PoolManager) {
	pm := NewPoolManager(&mockEngine{})
	return &RouterContract{router: NewLXRouter(pm)}, pm
}

// blueBAddr renders a distinct, sort-ordered token address: blueBAddr(1) < blueBAddr(2).
func blueBAddr(n byte) common.Address {
	var a common.Address
	a[0] = n
	a[19] = n
	return a
}

// blueBPool initializes a pool at (fee, tickSpacing) and funds it with in-range
// liquidity, returning its canonical pool ID. Fee-parameterised because the whole
// point of the determinism tests is to stand four fee tiers side by side.
func blueBPool(t testing.TB, pm *PoolManager, sdb StateDB, a, b common.Address, fee uint24, ts int24) [32]byte {
	t.Helper()
	key := sortedPoolKey(a, b, fee, ts, common.Address{})
	_, err := pm.Initialize(sdb, key, new(big.Int).Set(Q96), nil)
	require.NoErrorf(t, err, "initialize fee=%d spacing=%d", fee, ts)
	// -6000..6000 is divisible by every standard spacing (1, 10, 60, 200) and
	// straddles tick 0, which is the tick at price 1.0 — so the liquidity is ACTIVE.
	_, _, err = pm.ModifyLiquidity(sdb, testLP, key, ModifyLiquidityParams{
		TickLower:      -6000,
		TickUpper:      6000,
		LiquidityDelta: big.NewInt(1_000_000),
	}, nil)
	require.NoErrorf(t, err, "modifyLiquidity fee=%d spacing=%d", fee, ts)
	return key.ID()
}

// blueBBindV2 binds the native constant-product reserves the router's V2 venue reads.
func blueBBindV2(t testing.TB, sdb stateKV, a, b common.Address, base, quote uint64, feeBps uint32) {
	t.Helper()
	id := sortedPoolKey(a, b, Fee030, TickSpacing030, common.Address{}).ID()
	require.NoError(t, BindAMMPool(newEVMStore(sdb), id, base, quote, feeBps))
}

// blueBQuoteBody is the quote argument tail: tokenIn(20) | tokenOut(20) | amountIn(32) | fee(3).
func blueBQuoteBody(tokenIn, tokenOut common.Address, amountIn *big.Int, fee uint24) []byte {
	out := make([]byte, 0, 75)
	out = append(out, tokenIn.Bytes()...)
	out = append(out, tokenOut.Bytes()...)
	amt := make([]byte, 32)
	amountIn.FillBytes(amt)
	out = append(out, amt...)
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], fee)
	return append(out, f[1:4]...)
}

// blueBSimple is the address-list ExactInput tail:
// numTokens(1) | tokens | amountIn(32) | amountOutMin(32) | deadline(8).
func blueBSimple(tokens []common.Address, amountIn *big.Int) []byte {
	out := []byte{byte(len(tokens))}
	for _, tk := range tokens {
		out = append(out, tk.Bytes()...)
	}
	amt := make([]byte, 32)
	amountIn.FillBytes(amt)
	out = append(out, amt...)
	out = append(out, make([]byte, 32)...) // amountOutMinimum
	return append(out, make([]byte, 8)...) // deadline
}

// blueBV4 is the binary-path ExactInput tail:
// 0xFF | pathLen(2) | path | amountIn(32) | amountOutMin(32) | deadline(8).
func blueBV4(currencyIn common.Address, keys []PathKey, amountIn *big.Int) []byte {
	path := EncodePath(currencyIn, keys)
	out := make([]byte, 0, 3+len(path)+72)
	out = append(out, 0xFF)
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(path)))
	out = append(out, hdr...)
	out = append(out, path...)
	amt := make([]byte, 32)
	amountIn.FillBytes(amt)
	out = append(out, amt...)
	out = append(out, make([]byte, 32)...)
	return append(out, make([]byte, 8)...)
}

func blueBCall(sel uint32, body []byte) []byte {
	return append(selectorBytes(sel), body...)
}

// blueBQuote is one decoded entry of EncodeQuoteResults' wire form.
type blueBQuote struct {
	venue  SwapVenue
	amount *big.Int
	poolID [32]byte
	gas    uint64
}

// blueBDecodeQuotes parses the router's quote answer: count(1) then 73 bytes each of
// venue(1) | amountOut(32) | poolID(32) | gasEstimate(8). It asserts the buffer
// length AGREES with the count byte — a decoder that trusted one over the other
// would hide the encoder's count-byte truncation (see TestBlueBEncodeQuoteResults...).
func blueBDecodeQuotes(t testing.TB, out []byte) []blueBQuote {
	t.Helper()
	require.NotEmpty(t, out, "a quote answer always carries at least the count byte")
	n := int(out[0])
	require.Lenf(t, out, 1+n*73, "count byte %d must agree with the buffer length", n)
	qs := make([]blueBQuote, n)
	for i := range n {
		o := 1 + i*73
		qs[i].venue = SwapVenue(out[o])
		qs[i].amount = new(big.Int).SetBytes(out[o+1 : o+33])
		copy(qs[i].poolID[:], out[o+33:o+65])
		qs[i].gas = binary.BigEndian.Uint64(out[o+65 : o+73])
	}
	return qs
}

// blueBStorage deep-copies the MockStateDB storage trie so a view can be proven not
// to have written to it.
func blueBStorage(m *MockStateDB) map[common.Address]map[common.Hash]common.Hash {
	cp := make(map[common.Address]map[common.Hash]common.Hash, len(m.states))
	for addr, slots := range m.states {
		inner := make(map[common.Hash]common.Hash, len(slots))
		for k, v := range slots {
			inner[k] = v
		}
		cp[addr] = inner
	}
	return cp
}

// blueBSelectors is the router's complete dispatch surface plus a selector that is
// not on it. Every dispatch property below is asserted over ALL of them, so a new
// arm cannot be added without answering the same questions.
var blueBSelectors = []struct {
	name string
	sel  uint32
}{
	{"exactInputSingle", SelectorExactInputSingle},
	{"exactInput", SelectorExactInput},
	{"exactOutputSingle", SelectorExactOutputSingle},
	{"exactOutput", SelectorExactOutput},
	{"quoteExactInputSingle", SelectorQuoteExactInputSingle},
	{"quoteExactInput", SelectorQuoteExactInput},
	{"getBestRoute", SelectorGetBestRoute},
	{"unknown", 0xDEADBEEF},
}

// =========================================================================
// 1. The dispatch reads only what the caller declared
// =========================================================================

// TestBlueBRouterVerdictIgnoresUndeclaredBytes is the soundness property for the
// whole front door: for EVERY selector and EVERY truncation of a well-formed body,
// the answer must depend only on input[:len(input)]. The same bytes are fed twice —
// once as an exactly-sized slice, once with 512 bytes of 0xA5 spare capacity behind
// them — and the two verdicts (bytes, gas, error) must be identical.
//
// A difference is not cosmetic: it means the handler priced or refused a swap using
// bytes the caller never paid calldata gas for and never committed to, which an
// attacker chooses freely via MSTORE. A panic under poison is the same bug caught
// one slice later.
func TestBlueBRouterVerdictIgnoresUndeclaredBytes(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	withV2Configured(t)
	blueBBindV2(t, h.state.stateDB, blueBAddr(1), blueBAddr(2), 1_000_000, 2_000_000, 30)

	c, pm := blueBLive()
	blueBPool(t, pm, h.state.stateDB, blueBAddr(1), blueBAddr(2), Fee030, TickSpacing030)

	bodies := map[string][]byte{
		"quote":      blueBQuoteBody(blueBAddr(1), blueBAddr(2), big.NewInt(1_000), Fee030),
		"simplePath": blueBSimple([]common.Address{blueBAddr(1), blueBAddr(2), blueBAddr(3)}, big.NewInt(1_000)),
		"v4Path": blueBV4(blueBAddr(1), []PathKey{
			{IntermediateCurrency: blueBAddr(2), Fee: Fee030, TickSpacing: TickSpacing030},
		}, big.NewInt(1_000)),
	}

	for _, s := range blueBSelectors {
		for shape, body := range bodies {
			full := blueBCall(s.sel, body)
			for cut := 0; cut <= len(full); cut++ {
				clean := full[:cut]
				dirty := blueBPoisoned(clean, 512)

				var got, want blueBVerdict
				require.NotPanicsf(t, func() { want = blueBRun(c, h.state, clean, 1_000_000, true) },
					"%s/%s cut=%d: a clean input must not panic", s.name, shape, cut)
				require.NotPanicsf(t, func() { got = blueBRun(c, h.state, dirty, 1_000_000, true) },
					"%s/%s cut=%d: poisoned spare capacity must not be reachable", s.name, shape, cut)

				require.Equalf(t, want.ok, got.ok, "%s/%s cut=%d: verdict flipped on undeclared bytes", s.name, shape, cut)
				require.Equalf(t, want.err, got.err, "%s/%s cut=%d: error text depends on undeclared bytes", s.name, shape, cut)
				require.Equalf(t, want.gas, got.gas, "%s/%s cut=%d: gas depends on undeclared bytes", s.name, shape, cut)
				require.Equalf(t, want.out, got.out, "%s/%s cut=%d: OUTPUT depends on undeclared bytes", s.name, shape, cut)
			}
		}
	}
}

// TestBlueBRouterNeedsABlockContext: every surviving handler dereferences
// GetBlockContext().Number(), so Run's nil check is the only thing between a host
// that has no block context and a validator panic. Assert it fires for EVERY
// selector — including the retired value selectors and an unknown one, which need no
// block context at all — because the check sits ahead of the dispatch. Ordering is
// part of the property: a 3-byte input is still refused for its LENGTH first, since
// that check comes first and must not be reordered behind a dereference.
func TestBlueBRouterNeedsABlockContext(t *testing.T) {
	h := newSettleHarness(t)
	st := blueBNoBlock{h.state}
	c := RouterPrecompile // the registered singleton — what a chain dispatches to

	body := blueBQuoteBody(blueBAddr(1), blueBAddr(2), big.NewInt(1), Fee030)
	for _, s := range blueBSelectors {
		v := blueBRun(c, st, blueBCall(s.sel, body), 1_000_000, true)
		require.Falsef(t, v.ok, "%s must be refused without a block context", s.name)
		require.Equalf(t, "block context unavailable", v.err,
			"%s must be refused by the block-context check, ahead of its own handler", s.name)
		require.Nilf(t, v.out, "%s must return nothing", s.name)
		require.Equalf(t, uint64(1_000_000), v.gas, "%s: the check is not work and charges nothing", s.name)
	}

	// Length is checked BEFORE the block context: a stub input keeps its own refusal.
	for n := range 4 {
		v := blueBRun(c, st, make([]byte, n), 1_000_000, true)
		require.Falsef(t, v.ok, "a %d-byte input carries no selector", n)
		require.Equalf(t, "input too short", v.err,
			"a %d-byte input must be refused for its length, not for the block context", n)
	}

	// And with a block context present, the same calls get PAST the check.
	for _, s := range blueBSelectors {
		v := blueBRun(c, h.state, blueBCall(s.sel, body), 1_000_000, true)
		require.NotEqualf(t, "block context unavailable", v.err,
			"%s must not report a missing block context when one is present", s.name)
	}
}

// =========================================================================
// 2. Route selection is a function of the calldata, not of map order
// =========================================================================

// TestBlueBRouteChoiceIsDeterministicUnderTies is the consensus property. quoteV4
// scans four fee tiers and keeps the strict maximum, so when several tiers price
// IDENTICALLY the answer is decided entirely by the ORDER of the scan. If that order
// came from ranging a map, two validators would pick different pools from the same
// calldata and fork.
//
// The setup forces the worst case: four pools, one per standard tier, all with the
// same liquidity, quoted by an engine whose price does not depend on the pool — a
// perfect four-way tie. The winner must be the FIRST tier of the fixed scan slice
// (Fee001), every time, including from a cold pool manager that shares nothing but
// the state trie with the warm one (the just-restarted-validator case).
func TestBlueBRouteChoiceIsDeterministicUnderTies(t *testing.T) {
	h := newSettleHarness(t)
	tin, tout := blueBAddr(1), blueBAddr(2)

	c, pm := blueBLive()
	tiers := []struct {
		fee uint24
		ts  int24
	}{{Fee001, TickSpacing001}, {Fee005, TickSpacing005}, {Fee030, TickSpacing030}, {Fee100, TickSpacing100}}
	ids := make(map[uint24][32]byte, len(tiers))
	for _, tr := range tiers {
		ids[tr.fee] = blueBPool(t, pm, h.state.stateDB, tin, tout, tr.fee, tr.ts)
	}

	// All four tiers must genuinely tie, or the test proves nothing about ordering.
	quoted := blueBDecodeQuotes(t, func() []byte {
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(tin, tout, big.NewInt(1_000), 0)), 1_000_000, true)
		require.True(t, v.ok, "a funded pair must quote: %s", v.err)
		return v.out
	}())
	require.Len(t, quoted, 1, "only the V4 venue is live here")
	require.Equal(t, VenueV4Native, quoted[0].venue)
	require.Equal(t, ids[Fee001], quoted[0].poolID,
		"a four-way tie must resolve to the FIRST tier of the fixed scan order, not to whichever the map yielded")

	// Stable across repeats on one manager AND across independently built managers
	// with cold caches — the two validators that must agree.
	want := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
		blueBQuoteBody(tin, tout, big.NewInt(1_000), 0)), 1_000_000, true)
	for i := range 64 {
		cold, _ := blueBLive()
		for _, target := range []*RouterContract{c, cold} {
			got := blueBRun(target, h.state, blueBCall(SelectorQuoteExactInputSingle,
				blueBQuoteBody(tin, tout, big.NewInt(1_000), 0)), 1_000_000, true)
			require.Equalf(t, want.out, got.out, "run %d: the same calldata must yield the same bytes", i)
			require.Equalf(t, want.gas, got.gas, "run %d: the same calldata must cost the same", i)
		}
	}

	// A caller's preferred tier goes to the FRONT of the scan, so it wins the tie —
	// deterministically, and only among equals. Sweep every tier.
	for _, tr := range tiers {
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(tin, tout, big.NewInt(1_000), tr.fee)), 1_000_000, true)
		require.Truef(t, v.ok, "preferred fee %d must still quote: %s", tr.fee, v.err)
		qs := blueBDecodeQuotes(t, v.out)
		require.Lenf(t, qs, 1, "preferred fee %d", tr.fee)
		require.Equalf(t, ids[tr.fee], qs[0].poolID,
			"preferring tier %d must select tier %d's pool", tr.fee, tr.fee)
		// Repeat: the preference must not flap either.
		for range 16 {
			again := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
				blueBQuoteBody(tin, tout, big.NewInt(1_000), tr.fee)), 1_000_000, true)
			require.Equalf(t, v.out, again.out, "preferred fee %d must be stable", tr.fee)
		}
	}
}

// TestBlueBUnknownFeeTierCannotSteerTheRoute: the preferred fee is caller-supplied
// and unvalidated, and an unrecognised tier has no tick spacing, so quoteV4 falls
// back to the standard spacing and builds a pool key nobody opened. That key must
// simply miss — an attacker must not be able to change WHICH pool a quote prices by
// naming a tier that does not exist.
func TestBlueBUnknownFeeTierCannotSteerTheRoute(t *testing.T) {
	h := newSettleHarness(t)
	tin, tout := blueBAddr(1), blueBAddr(2)
	c, pm := blueBLive()
	want := blueBPool(t, pm, h.state.stateDB, tin, tout, Fee030, TickSpacing030)

	base := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
		blueBQuoteBody(tin, tout, big.NewInt(1_000), 0)), 1_000_000, true)
	require.True(t, base.ok, "the standard-tier pool must quote: %s", base.err)
	require.Equal(t, want, blueBDecodeQuotes(t, base.out)[0].poolID)

	// Every unrecognised tier, including the extremes of the uint24 domain, must
	// leave the answer untouched.
	for _, fee := range []uint24{1, 7, 99, 101, 2999, 3001, 9999, 10001, FeeMax, 1<<24 - 1} {
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(tin, tout, big.NewInt(1_000), fee)), 1_000_000, true)
		require.Truef(t, v.ok, "unknown fee %d must not break the quote: %s", fee, v.err)
		require.Equalf(t, base.out, v.out,
			"unknown fee %d must not change which pool is priced", fee)
	}

	// The fallback spacing is not arbitrary — it decides which pool a non-standard
	// tier can even name. A pool opened at fee 12345 is reachable from the router
	// ONLY if it uses the standard spacing, because that is what the router assumes
	// for a tier it does not know. Open one at the standard spacing and one at a
	// different spacing, and only the first is findable.
	const oddFee uint24 = 12_345
	findable := blueBPool(t, pm, h.state.stateDB, tin, tout, oddFee, TickSpacing030)
	hidden := blueBPool(t, pm, h.state.stateDB, tin, tout, oddFee, TickSpacing100)
	require.NotEqual(t, findable, hidden, "the two pools must be distinct")

	v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
		blueBQuoteBody(tin, tout, big.NewInt(1_000), oddFee)), 1_000_000, true)
	require.True(t, v.ok, "a pool at a non-standard tier and the standard spacing is quotable: %s", v.err)
	require.Equal(t, findable, blueBDecodeQuotes(t, v.out)[0].poolID,
		"an unknown fee tier resolves at the STANDARD tick spacing — that is the fallback, and it is load-bearing")

	// The pool at the same fee but a different spacing stays invisible: no request
	// the router accepts can reach it, because the caller cannot name a spacing.
	for _, fee := range []uint24{oddFee, Fee001, Fee005, Fee030, Fee100, 0} {
		q := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(tin, tout, big.NewInt(1_000), fee)), 1_000_000, true)
		require.Truef(t, q.ok, "fee %d: %s", fee, q.err)
		for _, got := range blueBDecodeQuotes(t, q.out) {
			require.NotEqualf(t, hidden, got.poolID,
				"fee %d: a pool whose spacing is not the one derived from its fee is unreachable", fee)
		}
	}
}

// =========================================================================
// 3. Best-of-N is total, and the empty set is refused
// =========================================================================

// TestBlueBBestRouteIsAMaximumAndRefusesTheEmptySet pins three things about the
// route-discovery view that a caller's money depends on:
//
//   - With NO venue able to price the pair, the call must ERROR. It must not answer
//     with a syntactically valid, zero-amount route — a caller that checks only the
//     return length would read that as "route found, output 0".
//   - When venues do price it, the answer must be the MAXIMUM over the full quote
//     list the sibling selector returns — checked by decoding both answers, so the
//     two selectors cannot disagree.
//   - The tie-break must be total and stable: equal outputs resolve to the same
//     venue every time.
func TestBlueBBestRouteIsAMaximumAndRefusesTheEmptySet(t *testing.T) {
	h := newSettleHarness(t)
	withV2Configured(t)
	tin, tout := blueBAddr(1), blueBAddr(2)
	c, pm := blueBLive()

	// (a) Nothing bound anywhere: refused, with no bytes at all.
	v := blueBRun(c, h.state, blueBCall(SelectorGetBestRoute,
		blueBQuoteBody(tin, tout, big.NewInt(1_000), 0)), 1_000_000, true)
	require.False(t, v.ok, "a pair no venue can price must be refused")
	require.Nil(t, v.out, "a refused route must return NO bytes — never a zero route a caller reads as valid")
	require.Equal(t, uint64(1_000_000)-GasRouteLookup, v.gas, "the lookup fee is charged even on refusal")

	// (b) Exact tie between V4 and V2. mockEngine prices amountIn/2, so amountIn=2
	// gives 1; reserves (2,2) give ConstantProductOut(2,2,2) = 2*2/(2+2) = 1.
	blueBPool(t, pm, h.state.stateDB, tin, tout, Fee030, TickSpacing030)
	blueBBindV2(t, h.state.stateDB, tin, tout, 2, 2, 30)
	require.Equal(t, uint64(1), lx.ConstantProductOut(2, 2, 2), "the tie fixture must actually tie")

	all := blueBDecodeQuotes(t, func() []byte {
		q := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(tin, tout, big.NewInt(2), 0)), 1_000_000, true)
		require.True(t, q.ok, "both venues price this pair: %s", q.err)
		return q.out
	}())
	require.Len(t, all, 2, "V4 and V2 must both appear")
	require.Equal(t, VenueV4Native, all[0].venue, "V4 is quoted first")
	require.Equal(t, VenueV2, all[1].venue)
	require.Equal(t, 0, all[0].amount.Cmp(all[1].amount), "the fixture must be an exact tie")

	best := blueBRun(c, h.state, blueBCall(SelectorGetBestRoute,
		blueBQuoteBody(tin, tout, big.NewInt(2), 0)), 1_000_000, true)
	require.True(t, best.ok, "a priced pair must route: %s", best.err)
	bq := blueBDecodeQuotes(t, best.out)
	require.Len(t, bq, 1, "a best route is exactly one result")
	require.Equal(t, VenueV4Native, bq[0].venue, "a tie resolves to the first venue quoted, every time")
	for range 32 {
		again := blueBRun(c, h.state, blueBCall(SelectorGetBestRoute,
			blueBQuoteBody(tin, tout, big.NewInt(2), 0)), 1_000_000, true)
		require.Equal(t, best.out, again.out, "a tie must not flap between venues")
	}

	// (c) The comparison is a real maximum, not a venue preference: make V2 strictly
	// better and it must win; make it strictly worse and V4 must win back.
	for _, tc := range []struct {
		name        string
		base, quote uint64
		amountIn    int64
		wantVenue   SwapVenue
	}{
		{"v2 strictly better", 1_000_000, 100_000_000, 1_000, VenueV2},
		{"v2 strictly worse", 1_000_000, 2, 1_000, VenueV4Native},
	} {
		blueBBindV2(t, h.state.stateDB, tin, tout, tc.base, tc.quote, 30)
		got := blueBRun(c, h.state, blueBCall(SelectorGetBestRoute,
			blueBQuoteBody(tin, tout, big.NewInt(tc.amountIn), 0)), 1_000_000, true)
		require.Truef(t, got.ok, "%s: %s", tc.name, got.err)
		chosen := blueBDecodeQuotes(t, got.out)[0]
		require.Equalf(t, tc.wantVenue, chosen.venue, "%s: the best route must be the maximum", tc.name)

		// Cross-check against the full list from the sibling selector.
		list := blueBDecodeQuotes(t, func() []byte {
			q := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
				blueBQuoteBody(tin, tout, big.NewInt(tc.amountIn), 0)), 1_000_000, true)
			require.Truef(t, q.ok, "%s: %s", tc.name, q.err)
			return q.out
		}())
		max := new(big.Int)
		for _, q := range list {
			if q.amount.Cmp(max) > 0 {
				max = q.amount
			}
		}
		require.Equalf(t, 0, chosen.amount.Cmp(max),
			"%s: getBestRoute must return the maximum of quoteExactInputSingle", tc.name)
	}
}

// TestBlueBV2QuoteDiscardsTheBoundFee is a MISPRICING, not a coverage note. The AMM
// row a market binds carries a fee in basis points, quoteV2 reads it — and drops it
// on the floor (`base, quote, _, ok := readAMMRow`). lx.ConstantProductOut takes no
// fee argument, so the V2 venue is quoted on a FEE-FREE curve while its comment
// calls it "the 0.30% constant-product pool".
//
// Consequence on a live chain: the V2 arm's quote is systematically high by the
// pool's fee, so getBestRoute prefers V2 over a correctly-priced venue whenever the
// true difference is smaller than that fee. These are advisory views today, but the
// number they publish is the number an integrator sizes a swap with.
func TestBlueBV2QuoteDiscardsTheBoundFee(t *testing.T) {
	h := newSettleHarness(t)
	withV2Configured(t)
	tin, tout := blueBAddr(3), blueBAddr(4)
	c, _ := blueBLive()

	in := blueBCall(SelectorQuoteExactInputSingle, blueBQuoteBody(tin, tout, big.NewInt(1_000), 0))

	var answers []string
	for _, feeBps := range []uint32{0, 1, 30, 300, 5_000, 10_000} {
		blueBBindV2(t, h.state.stateDB, tin, tout, 1_000_000, 2_000_000, feeBps)
		v := blueBRun(c, h.state, in, 1_000_000, true)
		require.Truef(t, v.ok, "feeBps=%d must quote: %s", feeBps, v.err)
		qs := blueBDecodeQuotes(t, v.out)
		require.Lenf(t, qs, 1, "feeBps=%d", feeBps)
		require.Equal(t, VenueV2, qs[0].venue)
		answers = append(answers, qs[0].amount.String())
	}
	for i := range answers {
		require.Equalf(t, answers[0], answers[i],
			"the bound fee is read and discarded: every feeBps quotes identically (%v)", answers)
	}
	// And that identical answer is the ZERO-fee curve, to the unit.
	require.Equal(t, answers[0], new(big.Int).SetUint64(lx.ConstantProductOut(1_000_000, 2_000_000, 1_000)).String(),
		"the V2 quote is the fee-free xy=k output even for a pool bound at 100% fee")
}

// TestBlueBQuoteV3HasNoSuccessPath: quoteV3 returns a non-nil error on BOTH of its
// arms — unconfigured, and configured-but-undeployed. There is no third arm. So the
// V3 branch of QuoteExactInputSingle can never append a result, and no caller can
// ever be routed to VenueV3, however the chain is configured.
//
// This is why router.go's V3 append is unreachable. Asserted as a property over the
// configuration space rather than left as an uncovered line.
func TestBlueBQuoteV3HasNoSuccessPath(t *testing.T) {
	h := newSettleHarness(t)
	prevQuoter, prevFactory := v3QuoterAddr, v3FactoryAddr
	t.Cleanup(func() { v3QuoterAddr, v3FactoryAddr = prevQuoter, prevFactory })

	c, pm := blueBLive()
	tin, tout := blueBAddr(1), blueBAddr(2)
	blueBPool(t, pm, h.state.stateDB, tin, tout, Fee030, TickSpacing030)
	withV2Configured(t)
	blueBBindV2(t, h.state.stateDB, tin, tout, 1_000_000, 2_000_000, 30)

	for _, quoter := range []common.Address{
		{}, // unconfigured
		common.HexToAddress("0x0000000000000000000000000000000000009013"),
		common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
		lxRouterAddr,
	} {
		v3QuoterAddr, v3FactoryAddr = quoter, quoter

		amount, err := NewLXRouter(pm).quoteV3(h.state.stateDB, tin, tout, big.NewInt(1_000), Fee030)
		require.Errorf(t, err, "quoter %s: quoteV3 has no success arm", quoter.Hex())
		require.Equalf(t, 0, amount.Sign(), "quoter %s: a failed V3 quote must be zero", quoter.Hex())

		// And through the front door: no answer ever carries VenueV3.
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(tin, tout, big.NewInt(1_000), Fee030)), 1_000_000, true)
		require.Truef(t, v.ok, "quoter %s: %s", quoter.Hex(), v.err)
		for _, q := range blueBDecodeQuotes(t, v.out) {
			require.NotEqualf(t, VenueV3, q.venue,
				"quoter %s: a V3 route cannot exist while quoteV3 always errors", quoter.Hex())
		}
	}
}

// TestBlueBQuoteV4PricesOnePoolWhicheverWayTheCallerNamesIt: the pair (A,B) and the
// pair (B,A) are the same pool. quoteV4 sorts the currencies to build the key and
// keeps the caller's direction separately, so both orderings must resolve to the
// SAME pool id — if the sort were skipped, a pair would have two pools and half the
// liquidity would be invisible from one side.
func TestBlueBQuoteV4PricesOnePoolWhicheverWayTheCallerNamesIt(t *testing.T) {
	h := newSettleHarness(t)
	lo, hi := blueBAddr(1), blueBAddr(2)
	c, pm := blueBLive()
	id := blueBPool(t, pm, h.state.stateDB, lo, hi, Fee030, TickSpacing030)

	for _, d := range []struct {
		name           string
		tokenIn, tOut  common.Address
		wantZeroForOne bool
	}{
		{"ascending (zeroForOne)", lo, hi, true},
		{"descending (oneForZero)", hi, lo, false},
	} {
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle,
			blueBQuoteBody(d.tokenIn, d.tOut, big.NewInt(1_000), Fee030)), 1_000_000, true)
		require.Truef(t, v.ok, "%s must price: %s", d.name, v.err)
		qs := blueBDecodeQuotes(t, v.out)
		require.Lenf(t, qs, 1, "%s", d.name)
		require.Equalf(t, id, qs[0].poolID, "%s must price the SAME pool", d.name)
		require.Positivef(t, qs[0].amount.Sign(), "%s must return a positive quote", d.name)

		// The direction flag really is derived from the ordering, not fixed.
		amount, poolID, key, err := NewLXRouter(pm).quoteV4(h.state.stateDB, d.tokenIn, d.tOut, big.NewInt(1_000), Fee030)
		require.NoErrorf(t, err, "%s", d.name)
		require.Equalf(t, id, poolID, "%s", d.name)
		require.Equalf(t, lo, key.Currency0.Address, "%s: currency0 is the LOWER address regardless of call order", d.name)
		require.Equalf(t, hi, key.Currency1.Address, "%s", d.name)
		require.Positivef(t, amount.Sign(), "%s", d.name)
	}
}

// =========================================================================
// 4. Multi-hop: every hop paid for is a hop walked, and the answer composes
// =========================================================================

// TestBlueBMultiHopComposesEveryHop proves the multi-hop quote is a COMPOSITION and
// not a first-hop answer wearing a multi-hop price. Both encodings are checked
// against a value computed independently in the test:
//
//   - simple path A->B->C over two bound constant-product pools: the answer must be
//     ConstantProductOut applied twice, chained.
//   - V4 binary path over two live pools priced at half: the answer must be in/4.
//
// A router that walked one hop and returned would still pass a "positive output"
// test; it cannot pass this one.
func TestBlueBMultiHopComposesEveryHop(t *testing.T) {
	h := newSettleHarness(t)
	withV2Configured(t)
	a, b, cAddr := blueBAddr(1), blueBAddr(2), blueBAddr(3)

	t.Run("simple path over the native AMM", func(t *testing.T) {
		const (
			r1x, r1y uint64 = 1_000_000, 2_000_000
			r2x, r2y uint64 = 5_000_000, 3_000_000
			amountIn uint64 = 10_000
		)
		blueBBindV2(t, h.state.stateDB, a, b, r1x, r1y, 30)
		blueBBindV2(t, h.state.stateDB, b, cAddr, r2x, r2y, 30)

		hop1 := lx.ConstantProductOut(r1x, r1y, amountIn)
		want := lx.ConstantProductOut(r2x, r2y, hop1)
		require.Positive(t, want, "the fixture must produce a positive two-hop output")

		v := blueBRun(RouterPrecompile, h.state, blueBCall(SelectorQuoteExactInput,
			blueBSimple([]common.Address{a, b, cAddr}, new(big.Int).SetUint64(amountIn))), 1_000_000, true)
		require.True(t, v.ok, "a fully bound two-hop path must quote: %s", v.err)
		require.Len(t, v.out, 32, "a multi-hop quote answers one 32-byte word")
		require.Equal(t, want, new(big.Int).SetBytes(v.out).Uint64(),
			"the answer must be hop2(hop1(in)), not hop1(in)")
		require.NotEqual(t, hop1, new(big.Int).SetBytes(v.out).Uint64(),
			"a first-hop answer would be a silently truncated route")
		require.Equal(t, uint64(1_000_000)-(GasQuoteBase+2*GasQuotePerHop), v.gas,
			"two hops are charged as two hops")
	})

	t.Run("v4 binary path over live pools", func(t *testing.T) {
		h := newSettleHarness(t) // a private trie: pools are created here, not shared
		c, pm := blueBLive()
		blueBPool(t, pm, h.state.stateDB, a, b, Fee030, TickSpacing030)
		blueBPool(t, pm, h.state.stateDB, b, cAddr, Fee030, TickSpacing030)

		const amountIn int64 = 10_000
		keys := []PathKey{
			{IntermediateCurrency: b, Fee: Fee030, TickSpacing: TickSpacing030},
			{IntermediateCurrency: cAddr, Fee: Fee030, TickSpacing: TickSpacing030},
		}
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInput,
			blueBV4(a, keys, big.NewInt(amountIn))), 1_000_000, true)
		require.True(t, v.ok, "a two-hop V4 path over live pools must quote: %s", v.err)
		require.Len(t, v.out, 32)
		require.Equal(t, int64(amountIn/4), new(big.Int).SetBytes(v.out).Int64(),
			"each hop halves, so two hops must quarter — proving both hops ran")
		require.Equal(t, uint64(1_000_000)-(GasQuoteBase+2*GasQuotePerHop), v.gas)

		// One hop for comparison: half, and a hop cheaper.
		one := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInput,
			blueBV4(a, keys[:1], big.NewInt(amountIn))), 1_000_000, true)
		require.True(t, one.ok, "%s", one.err)
		require.Equal(t, int64(amountIn/2), new(big.Int).SetBytes(one.out).Int64())
		require.Equal(t, uint64(1_000_000)-(GasQuoteBase+GasQuotePerHop), one.gas)
	})

	t.Run("a dead hop names its own index", func(t *testing.T) {
		h := newSettleHarness(t) // a private trie: only hop 0's pool exists in it
		c, pm := blueBLive()
		blueBPool(t, pm, h.state.stateDB, a, b, Fee030, TickSpacing030) // hop 0 only
		keys := []PathKey{
			{IntermediateCurrency: b, Fee: Fee030, TickSpacing: TickSpacing030},
			{IntermediateCurrency: blueBAddr(9), Fee: Fee030, TickSpacing: TickSpacing030},
		}
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInput,
			blueBV4(a, keys, big.NewInt(10_000))), 1_000_000, true)
		require.False(t, v.ok, "a path whose second hop has no pool must be refused")
		require.Contains(t, v.err, "quote hop 1 failed",
			"the failure must name hop 1 — proving hop 0 succeeded and the walk advanced")
		require.Equal(t, uint64(1_000_000)-(GasQuoteBase+2*GasQuotePerHop), v.gas,
			"a failed walk still consumes exactly the charge computed for the declared hops")
	})
}

// TestBlueBHopCountClampIsUnreachable: runQuoteExactInput clamps `numHops` up to 1
// when it computes as less than 1. That clamp can never fire, because
// DecodeExactInputParams never returns a params value with fewer than one hop —
// the simple format refuses numTokens < 2 and the V4 format refuses a zero-hop path.
//
// Rather than leave the statement as an unexplained hole, the DECODER'S
// POSTCONDITION is asserted over the whole input space that reaches it: every
// accepted input has len(Path) >= 2 or len(PathKeys) >= 1, so the clamped quantity
// is always >= 1 before the clamp is consulted.
func TestBlueBHopCountClampIsUnreachable(t *testing.T) {
	check := func(t *testing.T, in []byte, label string) {
		t.Helper()
		p, err := DecodeExactInputParams(in)
		if err != nil {
			return // refused inputs never reach the clamp
		}
		hops := len(p.Path) - 1
		if len(p.PathKeys) > 0 {
			hops = len(p.PathKeys)
		}
		require.GreaterOrEqualf(t, hops, 1,
			"%s: an ACCEPTED input yielded %d hops — the clamp would have fired", label, hops)
	}

	// Simple format across the whole count byte, with and without a full tail.
	for n := range 255 {
		toks := make([]common.Address, n)
		for i := range toks {
			toks[i] = blueBAddr(byte(i%250 + 1))
		}
		full := blueBSimple(toks, big.NewInt(1))
		check(t, full, fmt.Sprintf("simple n=%d", n))
		for _, cut := range []int{0, 1, 2, len(full) / 2, len(full) - 8, len(full) - 1} {
			if cut >= 0 && cut <= len(full) {
				check(t, full[:cut], fmt.Sprintf("simple n=%d cut=%d", n, cut))
			}
		}
	}

	// V4 format from zero hops upward, plus a hand-built zero-hop path.
	for hops := range 8 {
		keys := make([]PathKey, hops)
		for i := range keys {
			keys[i] = PathKey{IntermediateCurrency: blueBAddr(byte(i + 1)), Fee: Fee030, TickSpacing: TickSpacing030}
		}
		full := blueBV4(blueBAddr(1), keys, big.NewInt(1))
		check(t, full, fmt.Sprintf("v4 hops=%d", hops))
		for cut := range len(full) {
			check(t, full[:cut], fmt.Sprintf("v4 hops=%d cut=%d", hops, cut))
		}
	}

	// The zero-hop V4 path is refused explicitly, which is what makes the V4 branch
	// of the hop count always >= 1.
	_, err := DecodeExactInputParams(blueBV4(blueBAddr(1), nil, big.NewInt(1)))
	require.Error(t, err, "a V4 path with no hops must be refused, not clamped to one hop")

	// And the simple branch refuses both degenerate counts.
	for _, n := range []int{0, 1} {
		toks := make([]common.Address, n)
		for i := range toks {
			toks[i] = blueBAddr(byte(i + 1))
		}
		_, err := DecodeExactInputParams(blueBSimple(toks, big.NewInt(1)))
		require.Errorf(t, err, "a %d-token simple path must be refused, not clamped", n)
	}
}

// =========================================================================
// 5. What a refusal costs
// =========================================================================

// TestBlueBRefusalPricing measures what each refusal arm charges. It is a
// MEASUREMENT pinned as a table, because the arms disagree with each other:
// four of them hand back the entire budget while the decode arms charge their fee.
// The one that matters is "path too long", which returns the full budget AFTER
// decoding a path of up to 1424 hops — the only free arm that does real work first.
func TestBlueBRefusalPricing(t *testing.T) {
	h := newSettleHarness(t)
	c := RouterPrecompile
	const budget uint64 = 1_000_000

	longPath := make([]common.Address, MaxPathLength+2)
	for i := range longPath {
		longPath[i] = blueBAddr(byte(i + 1))
	}

	for _, tc := range []struct {
		name    string
		in      []byte
		wantGas uint64
		wantErr string
	}{
		{"no selector", []byte{0x0B, 0x00}, budget, "input too short"},
		{"unknown selector", blueBCall(0xDEADBEEF, make([]byte, 80)), budget, "unknown router method selector: deadbeef"},
		{"retired exactInputSingle", blueBCall(SelectorExactInputSingle, make([]byte, 200)), budget, ErrPrecompileMoved.Error()},
		{"retired exactInput", blueBCall(SelectorExactInput, make([]byte, 200)), budget, ErrPrecompileMoved.Error()},
		{"retired exactOutputSingle", blueBCall(SelectorExactOutputSingle, make([]byte, 200)), budget, ErrPrecompileMoved.Error()},
		{"retired exactOutput", blueBCall(SelectorExactOutput, make([]byte, 200)), budget, ErrPrecompileMoved.Error()},
		{"path too long", blueBCall(SelectorQuoteExactInput, blueBSimple(longPath, big.NewInt(1))), budget,
			fmt.Sprintf("path too long: %d hops exceeds maximum of %d", len(longPath)-1, MaxPathLength)},
		{"short quote body", blueBCall(SelectorQuoteExactInputSingle, make([]byte, 8)), budget - GasQuote, "input too short for quote"},
		{"short route body", blueBCall(SelectorGetBestRoute, make([]byte, 8)), budget - GasRouteLookup, "input too short for quote"},
		{"malformed multi-hop", blueBCall(SelectorQuoteExactInput, []byte{0x01}), budget - GasQuoteBase, "path must have at least 2 tokens"},
	} {
		v := blueBRun(c, h.state, tc.in, budget, true)
		require.Falsef(t, v.ok, "%s must be refused", tc.name)
		require.Equalf(t, tc.wantErr, v.err, "%s", tc.name)
		require.Equalf(t, tc.wantGas, v.gas, "%s: refusal price", tc.name)
	}

	// Four arms hand the whole budget back; two charge. That asymmetry is the point:
	// "path too long" is FREE and follows a decode of the caller's whole path.
	free := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInput, blueBSimple(longPath, big.NewInt(1))), budget, true)
	paid := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInput, []byte{0x01}), budget, true)
	require.Equal(t, budget, free.gas, "the path-length refusal returns the full budget")
	require.Less(t, paid.gas, budget, "the decode refusal does not")

	// Under-funded callers lose everything and are told only "out of gas" — the
	// malformed body they also sent is never reported.
	for _, tc := range []struct {
		name string
		sel  uint32
		body []byte
		fee  uint64
	}{
		{"quote single", SelectorQuoteExactInputSingle, make([]byte, 8), GasQuote},
		{"best route", SelectorGetBestRoute, make([]byte, 8), GasRouteLookup},
		{"multi-hop", SelectorQuoteExactInput, []byte{0x01}, GasQuoteBase},
	} {
		for _, gas := range []uint64{0, tc.fee / 2, tc.fee - 1} {
			v := blueBRun(c, h.state, blueBCall(tc.sel, tc.body), gas, true)
			require.Falsef(t, v.ok, "%s at %d gas must be refused", tc.name, gas)
			require.Equalf(t, "out of gas", v.err,
				"%s at %d gas: the shortfall is reported, masking the malformed body", tc.name, gas)
			require.Zerof(t, v.gas, "%s at %d gas: an under-funded refusal leaves nothing", tc.name, gas)
		}
		// One gas above the fee, the same body gets its real diagnosis.
		v := blueBRun(c, h.state, blueBCall(tc.sel, tc.body), tc.fee, true)
		require.False(t, v.ok)
		require.NotEqualf(t, "out of gas", v.err, "%s: funded, the caller learns why the body was refused", tc.name)
		require.Zerof(t, v.gas, "%s: exactly the fee was charged", tc.name)
	}
}

// =========================================================================
// 6. The views are views
// =========================================================================

// TestBlueBRouterViewsWriteNothingAndIgnoreStaticMode: Run never consults readOnly.
// That is only safe if no reachable arm writes state. Assert it directly — every
// selector, in both modes, over identical state: the answers must match each other
// and the storage trie must be byte-identical before and after.
//
// If a value-moving arm were ever restored to this dispatch without a readOnly
// check, this test fails: it would write in static mode, or answer differently.
func TestBlueBRouterViewsWriteNothingAndIgnoreStaticMode(t *testing.T) {
	h := newSettleHarness(t)
	withV2Configured(t)
	a, b, cAddr := blueBAddr(1), blueBAddr(2), blueBAddr(3)
	blueBBindV2(t, h.state.stateDB, a, b, 1_000_000, 2_000_000, 30)
	blueBBindV2(t, h.state.stateDB, b, cAddr, 5_000_000, 3_000_000, 30)

	c, pm := blueBLive()
	blueBPool(t, pm, h.state.stateDB, a, b, Fee030, TickSpacing030)

	inputs := map[string][]byte{
		"quoteSingle": blueBCall(SelectorQuoteExactInputSingle, blueBQuoteBody(a, b, big.NewInt(1_000), Fee030)),
		"bestRoute":   blueBCall(SelectorGetBestRoute, blueBQuoteBody(a, b, big.NewInt(1_000), Fee030)),
		"multiHop":    blueBCall(SelectorQuoteExactInput, blueBSimple([]common.Address{a, b, cAddr}, big.NewInt(1_000))),
		"v4Hop": blueBCall(SelectorQuoteExactInput, blueBV4(a,
			[]PathKey{{IntermediateCurrency: b, Fee: Fee030, TickSpacing: TickSpacing030}}, big.NewInt(1_000))),
		"retired":  blueBCall(SelectorExactInput, make([]byte, 200)),
		"unknown":  blueBCall(0xDEADBEEF, make([]byte, 80)),
		"tooShort": []byte{0x0B},
	}

	before := blueBStorage(h.state.stateDB)
	logsBefore := len(h.state.stateDB.Logs())

	for name, in := range inputs {
		ro := blueBRun(c, h.state, in, 1_000_000, true)
		rw := blueBRun(c, h.state, in, 1_000_000, false)
		require.Equalf(t, ro.ok, rw.ok, "%s: static mode must not change the verdict", name)
		require.Equalf(t, ro.err, rw.err, "%s: static mode must not change the error", name)
		require.Equalf(t, ro.out, rw.out, "%s: static mode must not change the answer", name)
		require.Equalf(t, ro.gas, rw.gas, "%s: static mode must not change the price", name)
	}

	require.Equal(t, before, blueBStorage(h.state.stateDB),
		"a router view must not write a single storage slot, in either mode")
	require.Equal(t, logsBefore, len(h.state.stateDB.Logs()),
		"a router view must not emit a log")
}

// TestBlueBQuoteGrowsProcessMemoryPerUnknownPair records a LIVENESS defect that the
// consensus-correctness design deliberately leaves open. getPool caches every pool
// it is asked about in the PoolManager's process map — including pools that do not
// exist, which it stores as a fresh empty Pool. That entry is only ever evicted by a
// later lookup of the SAME id, so a caller who never repeats a pair never triggers
// eviction.
//
// quoteV4 asks getPool once per fee tier before it checks whether the pool exists,
// so one quote over a fresh pair adds one entry per tier. The quote selectors are
// read-only views: reachable by eth_call at no cost to the caller, and by STATICCALL
// for the flat quote fee. The map is on the process singleton and lives as long as
// the node.
//
// Correctness is unaffected — every cached entry is re-validated against the state
// trie before use — so this is memory growth, not a fork. It is pinned here with the
// MEASURED growth rate so a change to either side is visible.
func TestBlueBQuoteGrowsProcessMemoryPerUnknownPair(t *testing.T) {
	h := newSettleHarness(t)
	c, pm := blueBLive()
	require.Empty(t, pm.pools, "a fresh manager caches nothing")

	const calls = 200
	for i := range calls {
		// A distinct pair per call: nothing is ever looked up twice.
		in := blueBQuoteBody(blueBAddr(byte(i%250+1)), common.BigToAddress(big.NewInt(int64(i)+1<<40)),
			big.NewInt(1_000), 0)
		v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle, in), 1_000_000, true)
		require.Falsef(t, v.ok, "call %d prices nothing — no pool exists for this pair", i)
	}

	perCall := float64(len(pm.pools)) / float64(calls)
	require.Positivef(t, len(pm.pools),
		"a read-only quote over pairs that do not exist retained %d cache entries", len(pm.pools))
	require.GreaterOrEqualf(t, perCall, 1.0,
		"measured growth: %d entries after %d free read-only quotes (%.1f per call)", len(pm.pools), calls, perCall)
	t.Logf("process-cache growth: %d entries after %d read-only quotes over fresh pairs (%.1f per call)",
		len(pm.pools), calls, perCall)

	// Repeating ONE pair does not grow the cache further — the growth is per distinct
	// pair, which is exactly what an attacker controls.
	fixed := blueBQuoteBody(blueBAddr(200), blueBAddr(201), big.NewInt(1_000), 0)
	v := blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle, fixed), 1_000_000, true)
	require.False(t, v.ok, "%s", v.err)
	settled := len(pm.pools)
	for range 50 {
		v = blueBRun(c, h.state, blueBCall(SelectorQuoteExactInputSingle, fixed), 1_000_000, true)
		require.False(t, v.ok, "%s", v.err)
	}
	require.Equal(t, settled, len(pm.pools), "repeating one pair is bounded; varying the pair is not")
}

// =========================================================================
// 7. Configuration
// =========================================================================

// TestBlueBConfigureAppliesEveryAddress: the router's four venue addresses are
// PROCESS globals assigned by Configure, each behind a non-zero guard. All four
// assignments are asserted with addresses that are REAL 40-hex-digit values —
// common.HexToAddress silently yields the ZERO address for a string that is not
// valid hex, and a zero address is exactly what the guards skip, so a test written
// with a malformed literal asserts nothing about the guarded branch.
func TestBlueBConfigureAppliesEveryAddress(t *testing.T) {
	prev3q, prev3f, prev2r, prev2f := v3QuoterAddr, v3FactoryAddr, v2RouterAddr, v2FactoryAddr
	t.Cleanup(func() {
		v3QuoterAddr, v3FactoryAddr, v2RouterAddr, v2FactoryAddr = prev3q, prev3f, prev2r, prev2f
	})

	cfgr := &routerConfigurator{}
	q := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	f3 := common.HexToAddress("0x00000000000000000000000000000000000000F3")
	r2 := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	f2 := common.HexToAddress("0x00000000000000000000000000000000000000F2")
	for _, a := range []common.Address{q, f3, r2, f2} {
		require.NotEqual(t, common.Address{}, a, "a fixture address must be non-zero or it tests the wrong branch")
	}

	// Each field applies on its OWN, so a config that sets one does not smear onto
	// the others. Start from a known zero baseline for exactly this comparison.
	v3QuoterAddr, v3FactoryAddr, v2RouterAddr, v2FactoryAddr = common.Address{}, common.Address{}, common.Address{}, common.Address{}
	for _, tc := range []struct {
		name string
		cfg  *RouterConfig
		want [4]common.Address
	}{
		{"v3 quoter only", &RouterConfig{V3QuoterAddress: q}, [4]common.Address{q, {}, {}, {}}},
		{"v3 factory only", &RouterConfig{V3FactoryAddress: f3}, [4]common.Address{q, f3, {}, {}}},
		{"v2 router only", &RouterConfig{V2RouterAddress: r2}, [4]common.Address{q, f3, r2, {}}},
		{"v2 factory only", &RouterConfig{V2FactoryAddress: f2}, [4]common.Address{q, f3, r2, f2}},
	} {
		require.NoErrorf(t, cfgr.Configure(nil, tc.cfg, nil, nil), "%s", tc.name)
		require.Equalf(t, tc.want, [4]common.Address{v3QuoterAddr, v3FactoryAddr, v2RouterAddr, v2FactoryAddr},
			"%s: each address applies independently and none is cleared", tc.name)
	}

	// The configured V2 address is what actually opens the venue: with it set, a
	// bound pair quotes; zeroed, the same pair does not. That is the assignment
	// having an observable effect rather than only a variable changing.
	h := newSettleHarness(t)
	c, _ := blueBLive()
	tin, tout := blueBAddr(1), blueBAddr(2)
	blueBBindV2(t, h.state.stateDB, tin, tout, 1_000_000, 2_000_000, 30)
	in := blueBCall(SelectorQuoteExactInputSingle, blueBQuoteBody(tin, tout, big.NewInt(1_000), 0))

	v2RouterAddr = common.Address{}
	require.False(t, blueBRun(c, h.state, in, 1_000_000, true).ok,
		"with no V2 address configured, a bound pair has no venue")

	require.NoError(t, cfgr.Configure(nil, &RouterConfig{
		V2RouterAddress: common.HexToAddress(DEXPoolManagerAddress),
	}, nil, nil))
	v := blueBRun(c, h.state, in, 1_000_000, true)
	require.True(t, v.ok, "configuring the V2 address opens the venue: %s", v.err)
	require.Equal(t, VenueV2, blueBDecodeQuotes(t, v.out)[0].venue)
}

// =========================================================================
// 8. The exported decoders (no dispatch reaches them; downstream clients do)
// =========================================================================

// blueBOutSingle compares two SwapExactOutputSingleParams field by field. Written
// out rather than reflected so a nil *big.Int is distinguished from a zero one.
func blueBOutSingle(t testing.TB, label string, got, want SwapExactOutputSingleParams) {
	t.Helper()
	require.Equalf(t, want.TokenIn, got.TokenIn, "%s tokenIn", label)
	require.Equalf(t, want.TokenOut, got.TokenOut, "%s tokenOut", label)
	require.Equalf(t, want.Fee, got.Fee, "%s fee", label)
	require.Equalf(t, want.TickSpacing, got.TickSpacing, "%s tickSpacing", label)
	require.Equalf(t, want.Hooks, got.Hooks, "%s hooks", label)
	require.Equalf(t, want.Deadline, got.Deadline, "%s deadline", label)
	require.Equalf(t, 0, got.AmountOut.Cmp(want.AmountOut), "%s amountOut: got %s want %s", label, got.AmountOut, want.AmountOut)
	require.Equalf(t, 0, got.AmountInMaximum.Cmp(want.AmountInMaximum), "%s amountInMaximum", label)
	if want.SqrtPriceLimitX96 == nil {
		require.Nilf(t, got.SqrtPriceLimitX96, "%s sqrtPriceLimit must stay unset when absent", label)
	} else {
		require.NotNilf(t, got.SqrtPriceLimitX96, "%s sqrtPriceLimit", label)
		require.Equalf(t, 0, got.SqrtPriceLimitX96.Cmp(want.SqrtPriceLimitX96), "%s sqrtPriceLimit", label)
	}
}

// TestBlueBExactOutputSingleOptionalTailMisassignsBytes sweeps the optional tail of
// DecodeExactOutputSingleParams one byte at a time and finds it POSITIONALLY
// AMBIGUOUS.
//
// Each optional field is guarded independently, and the running offset advances only
// when a field is taken. So when a field is skipped for want of room, a LATER field
// whose own guard happens to pass reads the skipped field's bytes instead of its
// own. There is no error and no way for the caller to tell.
//
// Measured, on a body carrying tickSpacing and a truncated hooks address:
//
//	118..129 bytes -> Deadline is read from input[110:118], the first eight bytes of
//	                  the HOOKS address. A hooks address of 0xdeadbeef... becomes a
//	                  deadline of 0xdeadbeefdeadbeef.
//	138..161 bytes -> Deadline is read from input[130:138], the first eight bytes of
//	                  the SQRT PRICE LIMIT.
//
// The same shape is in DecodeExactInputSingleParams, byte for byte.
//
// Two things this is NOT: it is not a read past len (the sweep runs every length
// against a 0xA5-poisoned buffer and the verdicts match exactly, so the length
// guards themselves are sound), and it is not reachable through 0x9012's dispatch
// today, because the exact-output selectors revert PRECOMPILE_MOVED before any
// decoder runs. It is an exported decoder that a downstream client calls directly,
// and it is what the retired value path would parse if it ever came back.
func TestBlueBExactOutputSingleOptionalTailMisassignsBytes(t *testing.T) {
	tokenIn := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tokenOut := common.HexToAddress("0x2222222222222222222222222222222222222222")
	hooks := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	amountOut := big.NewInt(1_000)
	amountInMax := big.NewInt(2_000)
	limit := new(big.Int).Lsh(big.NewInt(1), 160) // wider than a word's low half, so truncation would show
	const deadline uint64 = 0xFEDCBA9876543210
	// A NEGATIVE tick spacing: the sign must survive the 3-byte encoding.
	const spacing int24 = -60

	full := make([]byte, 0, 170)
	full = append(full, tokenIn.Bytes()...)
	full = append(full, tokenOut.Bytes()...)
	full = append(full, common.LeftPadBytes(amountOut.Bytes(), 32)...)
	full = append(full, common.LeftPadBytes(amountInMax.Bytes(), 32)...)
	var feeBytes [4]byte
	binary.BigEndian.PutUint32(feeBytes[:], Fee030)
	full = append(full, feeBytes[1:4]...)
	full = append(full, int24ToBytes(spacing)...)
	full = append(full, hooks.Bytes()...)
	full = append(full, common.LeftPadBytes(limit.Bytes(), 32)...)
	var dl [8]byte
	binary.BigEndian.PutUint64(dl[:], deadline)
	full = append(full, dl[:]...)
	require.Len(t, full, 170, "the full ExactOutputSingle body is 107 fixed + 63 optional")

	// The decoder's ACTUAL rule, offsets and all. Field k is taken only if the bytes
	// remaining from the CURRENT offset cover it; the offset advances only on a take.
	want := func(n int) SwapExactOutputSingleParams {
		p := SwapExactOutputSingleParams{
			TokenIn: tokenIn, TokenOut: tokenOut,
			AmountOut: amountOut, AmountInMaximum: amountInMax, Fee: Fee030,
		}
		off := 107
		if n >= off+3 {
			p.TickSpacing = spacing
			off += 3
		}
		if n >= off+20 {
			p.Hooks = hooks
			off += 20
		}
		if n >= off+32 {
			p.SqrtPriceLimitX96 = limit
			off += 32
		}
		if n >= off+8 {
			// Whatever eight bytes sit at `off` — the caller's deadline only when
			// every earlier field was taken.
			p.Deadline = binary.BigEndian.Uint64(full[off : off+8])
		}
		return p
	}

	for n := 107; n <= len(full); n++ {
		clean, err := DecodeExactOutputSingleParams(full[:n])
		require.NoErrorf(t, err, "%d bytes is at or above the 107-byte floor", n)
		blueBOutSingle(t, fmt.Sprintf("clean n=%d", n), clean, want(n))

		// The length guards themselves are sound: poisoned spare capacity behind the
		// same length decodes identically, so nothing is read past len.
		dirty, err := DecodeExactOutputSingleParams(blueBPoisoned(full[:n], 256))
		require.NoErrorf(t, err, "poisoned %d bytes", n)
		blueBOutSingle(t, fmt.Sprintf("poisoned n=%d", n), dirty, want(n))
	}

	// The misassignment, named and pinned at both windows where it occurs.
	hooksHead := binary.BigEndian.Uint64(hooks.Bytes()[:8])
	for n := 118; n < 130; n++ {
		p, err := DecodeExactOutputSingleParams(full[:n])
		require.NoErrorf(t, err, "n=%d", n)
		require.Equalf(t, common.Address{}, p.Hooks, "n=%d: hooks does not fit and is left unset", n)
		require.Equalf(t, hooksHead, p.Deadline,
			"n=%d: the deadline is the HEAD OF THE HOOKS ADDRESS, accepted without error", n)
		require.NotEqualf(t, deadline, p.Deadline, "n=%d: and it is not the caller's deadline", n)
	}
	limitHead := binary.BigEndian.Uint64(common.LeftPadBytes(limit.Bytes(), 32)[:8])
	for n := 138; n < 162; n++ {
		p, err := DecodeExactOutputSingleParams(full[:n])
		require.NoErrorf(t, err, "n=%d", n)
		require.Nilf(t, p.SqrtPriceLimitX96, "n=%d: the price limit does not fit and is left unset", n)
		require.Equalf(t, limitHead, p.Deadline,
			"n=%d: the deadline is the HEAD OF THE PRICE LIMIT", n)
	}
	// Only the full body yields the caller's own deadline.
	full170, err := DecodeExactOutputSingleParams(full)
	require.NoError(t, err)
	require.Equal(t, deadline, full170.Deadline, "a complete body decodes the deadline the caller sent")
	require.Equal(t, hooks, full170.Hooks)
	require.Equal(t, spacing, full170.TickSpacing, "a negative tick spacing must survive the 3-byte encoding")
	require.Equal(t, 0, full170.SqrtPriceLimitX96.Cmp(limit))

	// The exact-INPUT twin has the identical shape, so it carries the identical bug.
	twin, err := DecodeExactInputSingleParams(full[:118])
	require.NoError(t, err)
	require.Equal(t, common.Address{}, twin.Hooks)
	require.Equal(t, hooksHead, twin.Deadline,
		"DecodeExactInputSingleParams misassigns the same bytes at the same length")

	// Below the floor: refused at every length, clean or poisoned, never a panic.
	for n := range 107 {
		require.NotPanicsf(t, func() {
			_, err := DecodeExactOutputSingleParams(full[:n])
			require.Errorf(t, err, "%d bytes is below the floor", n)
			_, err = DecodeExactOutputSingleParams(blueBPoisoned(full[:n], 256))
			require.Errorf(t, err, "poisoned %d bytes is below the floor", n)
		}, "%d bytes must not panic", n)
	}
}

// TestBlueBExactOutputV4PathDecodes covers the V4 branch of DecodeExactOutputParams
// end to end, and pins the layout PARITY with its exact-input twin: both decoders
// read the same windows out of the same bytes, differing only in what they name the
// two amounts. A drift between them would mean one of the two reads a different
// field than the encoder wrote.
func TestBlueBExactOutputV4PathDecodes(t *testing.T) {
	currency := blueBAddr(7)
	keys := []PathKey{
		{IntermediateCurrency: blueBAddr(8), Fee: Fee030, TickSpacing: TickSpacing030,
			Hooks: common.HexToAddress("0x00000000000000000000000000000000000000AA")},
		{IntermediateCurrency: blueBAddr(9), Fee: Fee005, TickSpacing: -TickSpacing005},
	}
	amountOut := big.NewInt(123_456)
	amountInMax := new(big.Int).Lsh(big.NewInt(1), 200)
	const deadline uint64 = 0x0102030405060708

	build := func(withDeadline bool) []byte {
		path := EncodePath(currency, keys)
		out := []byte{0xFF, 0, 0}
		binary.BigEndian.PutUint16(out[1:3], uint16(len(path)))
		out = append(out, path...)
		out = append(out, common.LeftPadBytes(amountOut.Bytes(), 32)...)
		out = append(out, common.LeftPadBytes(amountInMax.Bytes(), 32)...)
		if withDeadline {
			var dl [8]byte
			binary.BigEndian.PutUint64(dl[:], deadline)
			out = append(out, dl[:]...)
		}
		return out
	}

	for _, withDeadline := range []bool{true, false} {
		in := build(withDeadline)
		wantDeadline := uint64(0)
		if withDeadline {
			wantDeadline = deadline
		}
		for _, buf := range [][]byte{in, blueBPoisoned(in, 256)} {
			p, err := DecodeExactOutputParams(buf)
			require.NoErrorf(t, err, "deadline=%v", withDeadline)
			require.Equal(t, currency, p.CurrencyOut, "the V4 branch names the path's leading address CurrencyOut")
			require.Nil(t, p.Path, "the V4 branch must not also populate the simple path")
			require.Len(t, p.PathKeys, len(keys))
			for i := range keys {
				require.Equalf(t, keys[i], p.PathKeys[i], "hop %d must survive the wire exactly", i)
			}
			require.Equal(t, 0, p.AmountOut.Cmp(amountOut))
			require.Equal(t, 0, p.AmountInMaximum.Cmp(amountInMax))
			require.Equalf(t, wantDeadline, p.Deadline,
				"an absent deadline must stay zero, never be read from beyond the end")
		}

		// Layout parity with the exact-input decoder over the SAME bytes.
		out, err := DecodeExactOutputParams(in)
		require.NoError(t, err)
		inp, err := DecodeExactInputParams(in)
		require.NoError(t, err)
		require.Equal(t, out.CurrencyOut, inp.CurrencyIn, "both decoders read the path's address from the same window")
		require.Equal(t, out.PathKeys, inp.PathKeys)
		require.Equal(t, 0, out.AmountOut.Cmp(inp.AmountIn), "the first amount word is the same window in both")
		require.Equal(t, 0, out.AmountInMaximum.Cmp(inp.AmountOutMinimum))
		require.Equal(t, out.Deadline, inp.Deadline)

		// A pathLen that overruns the buffer is refused, not read past.
		for _, claim := range []uint16{uint16(len(in)), 60_000, 0xFFFF} {
			bad := append([]byte(nil), in...)
			binary.BigEndian.PutUint16(bad[1:3], claim)
			require.NotPanicsf(t, func() {
				_, err := DecodeExactOutputParams(blueBPoisoned(bad, 4096))
				require.Errorf(t, err, "a declared path length of %d must be refused", claim)
			}, "declared path length %d must not read past the end", claim)
		}

		// A pathLen that FITS but describes no whole number of hops is a different
		// refusal, and the one worth separating: the buffer is long enough, so the
		// length guard passes and the PATH STRUCTURE is what refuses. A caller must
		// not be able to shorten the declared path and have the leftover bytes read
		// as amounts.
		for _, claim := range []uint16{0, 1, 19, 20, 21, 45, 65, 67} {
			bad := append([]byte(nil), in...)
			binary.BigEndian.PutUint16(bad[1:3], claim)
			require.GreaterOrEqual(t, len(bad), 3+int(claim)+64,
				"claim %d must FIT, so the length guard is not what refuses it", claim)
			_, err := DecodeExactOutputParams(blueBPoisoned(bad, 1024))
			require.Errorf(t, err, "a %d-byte path is not a whole number of hops", claim)
			require.Containsf(t, err.Error(), "decode V4 path",
				"claim %d must be refused by the path decoder, not by the length check", claim)

			// The exact-input twin refuses the same bytes the same way.
			_, err = DecodeExactInputParams(blueBPoisoned(bad, 1024))
			require.Errorf(t, err, "the input decoder must refuse claim %d too", claim)
			require.Containsf(t, err.Error(), "decode V4 path", "claim %d", claim)
		}
	}
}

// TestBlueBExactOutputSimplePathRejectsDegenerateCounts: the simple format's leading
// byte is a token count, and a path of fewer than two tokens is not a path. Both
// degenerate counts must be refused BY COUNT — before any length arithmetic — so a
// caller cannot get an empty or single-element Path back.
func TestBlueBExactOutputSimplePathRejectsDegenerateCounts(t *testing.T) {
	tail := make([]byte, 72) // amountOut(32) + amountInMax(32) + deadline(8)
	for _, n := range []byte{0, 1} {
		body := append([]byte{n}, make([]byte, int(n)*20)...)
		body = append(body, tail...)
		for _, buf := range [][]byte{body, blueBPoisoned(body, 512)} {
			_, err := DecodeExactOutputParams(buf)
			require.Errorf(t, err, "a %d-token path must be refused", n)
			require.Containsf(t, err.Error(), "at least 2 tokens", "a %d-token path is refused by COUNT", n)
			_, err = DecodeExactInputParams(buf)
			require.Errorf(t, err, "a %d-token path must be refused by the input decoder too", n)
		}
	}
	// Two tokens is the first accepted count, and it yields exactly two.
	body := append([]byte{2}, make([]byte, 40)...)
	body = append(body, tail...)
	p, err := DecodeExactOutputParams(body)
	require.NoError(t, err, "two tokens is the smallest real path")
	require.Len(t, p.Path, 2)
}

// =========================================================================
// 9. Deadline and slippage: what is actually enforced
// =========================================================================

// TestBlueBDeadlineWindowsAreExclusiveAndTotal sweeps checkDeadline across its
// boundary instead of sampling one point. For every non-zero deadline, exactly one
// of {allowed, expired} must hold, and the split must be at `blockNumber > deadline`
// — so a deadline EQUAL to the current height is still live. Two windows that both
// admitted the boundary would let one caller's transaction be simultaneously in time
// and out of time.
//
// It also pins the top of the uint64 domain: nothing is ever added to the deadline,
// so MaxUint64 cannot wrap into the past.
//
// And it records the two facts that matter more than the arithmetic: the comparison
// reads the BLOCK NUMBER (the only clock the state exposes here) while the field it
// compares is called a deadline and the sibling error documents it as
// block.timestamp; and NOTHING on the router calls this function.
func TestBlueBDeadlineWindowsAreExclusiveAndTotal(t *testing.T) {
	sdb := NewMockStateDB()

	// A zero deadline is "no deadline" at every height, including the extremes.
	for _, height := range []uint64{0, 1, 1 << 32, ^uint64(0)} {
		sdb.SetBlockNumber(height)
		require.NoErrorf(t, checkDeadline(sdb, 0), "height %d: a zero deadline never expires", height)
	}

	for _, height := range []uint64{0, 1, 2, 1_000, 1 << 32, ^uint64(0) - 1, ^uint64(0)} {
		sdb.SetBlockNumber(height)
		for _, delta := range []int64{-2, -1, 0, 1, 2} {
			// Skip deadlines that fall outside the domain or land on the "no deadline" value.
			if delta < 0 && height < uint64(-delta) {
				continue
			}
			if delta > 0 && height > ^uint64(0)-uint64(delta) {
				continue
			}
			deadline := height
			if delta < 0 {
				deadline = height - uint64(-delta)
			} else {
				deadline = height + uint64(delta)
			}
			if deadline == 0 {
				continue
			}
			err := checkDeadline(sdb, deadline)
			expired := err != nil
			require.Equalf(t, height > deadline, expired,
				"height=%d deadline=%d: the split must be strictly `height > deadline`", height, deadline)
			if expired {
				require.ErrorIsf(t, err, ErrDeadlineExpired, "height=%d deadline=%d", height, deadline)
			}
		}
	}

	// The boundary itself, stated once more on its own: equal is IN time, one past is out.
	sdb.SetBlockNumber(1_000)
	require.NoError(t, checkDeadline(sdb, 1_000), "a deadline equal to the current height is still live")
	require.Error(t, checkDeadline(sdb, 999), "one block earlier is expired")
	require.NoError(t, checkDeadline(sdb, 1_001), "one block later is live")

	// Top of the domain: no overflow, because nothing is added to the deadline.
	sdb.SetBlockNumber(^uint64(0))
	require.NoError(t, checkDeadline(sdb, ^uint64(0)), "MaxUint64 must not wrap into the past")
	require.Error(t, checkDeadline(sdb, ^uint64(0)-1))

	// The comparison is against the BLOCK NUMBER: the only quantity varied here is
	// the height, and the verdict follows it.
	sdb.SetBlockNumber(500)
	require.NoError(t, checkDeadline(sdb, 500))
	sdb.SetBlockNumber(501)
	require.Error(t, checkDeadline(sdb, 500), "advancing only the block NUMBER expires the deadline")
}

// TestBlueBRouterEnforcesNoSlippageOrDeadline states the surface honestly: the
// decoders parse AmountOutMinimum, AmountInMaximum and Deadline, and no reachable
// router path consults any of them. The value-moving selectors that once did are
// retired, so there is no minimum-output comparison left on 0x9012 to have a
// boundary at all.
//
// Asserted behaviourally: a quote whose declared minimum output is the largest
// number expressible, and whose deadline is long past, returns the SAME answer as
// one with both fields zeroed. If either were ever enforced here, these diverge.
func TestBlueBRouterEnforcesNoSlippageOrDeadline(t *testing.T) {
	h := newSettleHarness(t)
	withV2Configured(t)
	a, b := blueBAddr(1), blueBAddr(2)
	blueBBindV2(t, h.state.stateDB, a, b, 1_000_000, 2_000_000, 30)
	require.Equal(t, uint64(1), h.state.stateDB.GetBlockNumber(), "the harness is at height 1, so any past deadline is expired")

	// Same path, same amount; only the minimum-output and deadline words differ.
	base := blueBSimple([]common.Address{a, b}, big.NewInt(10_000))
	extreme := append([]byte(nil), base...)
	for i := len(extreme) - 40; i < len(extreme)-8; i++ {
		extreme[i] = 0xFF // amountOutMinimum = 2^256-1
	}
	// deadline = 1, i.e. the current height; and then a deadline in the past.
	past := append([]byte(nil), extreme...)
	binary.BigEndian.PutUint64(past[len(past)-8:], 0)
	expired := append([]byte(nil), extreme...)
	binary.BigEndian.PutUint64(expired[len(expired)-8:], 1)

	// The declared fields really are decoded — this is not a claim that they vanish.
	p, err := DecodeExactInputParams(extreme)
	require.NoError(t, err)
	require.Equal(t, 0, p.AmountOutMinimum.Cmp(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))),
		"the decoder does read a maximal minimum-output")

	want := blueBRun(RouterPrecompile, h.state, blueBCall(SelectorQuoteExactInput, base), 1_000_000, true)
	require.True(t, want.ok, "the bound pair must quote: %s", want.err)
	for name, in := range map[string][]byte{
		"maximal amountOutMinimum": extreme,
		"zero deadline":            past,
		"deadline at height 1":     expired,
	} {
		got := blueBRun(RouterPrecompile, h.state, blueBCall(SelectorQuoteExactInput, in), 1_000_000, true)
		require.Truef(t, got.ok, "%s: %s", name, got.err)
		require.Equalf(t, want.out, got.out, "%s: no router path consults this field", name)
		require.Equalf(t, want.gas, got.gas, "%s", name)
	}
	require.Less(t, new(big.Int).SetBytes(want.out).Cmp(p.AmountOutMinimum), 0,
		"the quoted output is far below the declared minimum, and is returned anyway")
}

// =========================================================================
// 10. The quote encoder
// =========================================================================

// TestBlueBEncodeQuoteResultsCountByteTruncates pins two silent truncations in
// EncodeQuoteResults, the exported wire format every quote answer is read from.
//
//   - The result COUNT is written into a single byte. At 256 results the byte reads
//     0 while the buffer is 18689 bytes, so a decoder that trusts the count — which
//     is the only thing telling it how many to read — sees an EMPTY answer from a
//     full one. 256 is not reachable from calldata (a chain would have to register
//     253 external venue quoters), but the encoder is exported and offers no refusal.
//   - An AmountOut wider than 32 bytes is not refused either: LeftPadBytes returns
//     an over-long slice unchanged and the copy keeps its LEADING bytes, so the wire
//     carries x>>8 for a 33-byte x — a different number, silently.
func TestBlueBEncodeQuoteResultsCountByteTruncates(t *testing.T) {
	mk := func(n int) []QuoteResult {
		rs := make([]QuoteResult, n)
		for i := range rs {
			rs[i] = QuoteResult{AmountOut: big.NewInt(int64(i + 1)), Venue: VenueV2, GasEstimate: uint64(i)}
		}
		return rs
	}

	// Below the byte's range the encoding is exact and self-describing.
	for _, n := range []int{0, 1, 2, 8, 254, 255} {
		enc := EncodeQuoteResults(mk(n))
		require.Lenf(t, enc, 1+n*73, "%d results", n)
		require.Equalf(t, byte(n), enc[0], "%d results must be declared as %d", n, n)
	}

	// At 256 the declared count and the delivered payload disagree.
	enc := EncodeQuoteResults(mk(256))
	require.Len(t, enc, 1+256*73, "the payload carries all 256 results")
	require.Equal(t, byte(0), enc[0],
		"the count byte wraps to 0: a decoder reads an empty answer out of a 18689-byte buffer")
	require.Equal(t, byte(1), EncodeQuoteResults(mk(257))[0], "and 257 declares itself as 1")

	// An amount wider than a word is truncated to its HIGH bytes, not refused.
	wide := new(big.Int).Lsh(big.NewInt(1), 256) // 33 bytes
	require.Len(t, wide.Bytes(), 33)
	one := EncodeQuoteResults([]QuoteResult{{AmountOut: wide, Venue: VenueV4Native}})
	require.Len(t, one, 74)
	got := new(big.Int).SetBytes(one[2:34]) // count(1) | venue(1) | amountOut(32)
	require.Equal(t, 0, got.Cmp(new(big.Int).Rsh(wide, 8)),
		"a 33-byte amount is encoded as amount>>8 — a different number, with no error")
	require.NotEqual(t, 0, got.Cmp(wide), "the encoded amount is not the amount")

	// Amounts that DO fit round-trip exactly, including the largest one that fits.
	maxWord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), maxWord} {
		e := EncodeQuoteResults([]QuoteResult{{AmountOut: v, Venue: VenueExternal, GasEstimate: 7}})
		require.Equal(t, 0, new(big.Int).SetBytes(e[2:34]).Cmp(v), "%s must round-trip", v)
		require.Equal(t, byte(VenueExternal), e[1], "venue is the first byte of a result")
		require.Equal(t, uint64(7), binary.BigEndian.Uint64(e[66:74]))
	}
}
