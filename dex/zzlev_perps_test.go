// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
)

// zzlev_perps_test.go covers dex/perpetuals.go — the perpetual-futures engine.
// Like margin.go it is a pure in-memory engine with no StateDB, so the mock
// StateDB doubles do not apply.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

var zzlBase = Currency{Address: common.HexToAddress("0x1000000000000000000000000000000000000001")}
var zzlQuote = Currency{Address: common.HexToAddress("0x2000000000000000000000000000000000000002")}

// zzlMM is a maintenance margin ratio expressed the way isPositionSafe reads it:
// an 18-decimal fraction of notional. zzlMM(5) is 5%.
func zzlMM(pct int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(pct), big.NewInt(1e16))
}

// zzlPerpMarket builds an engine with one market at the given price.
func zzlPerpMarket(t *testing.T, price *big.Int, maxLev uint32, mm *big.Int) (*PerpetualEngine, [32]byte) {
	t.Helper()
	pe := NewPerpetualEngine()
	id, err := pe.CreateMarket(zzlBase, zzlQuote, price, maxLev, mm)
	if err != nil {
		t.Fatalf("CreateMarket: %v", err)
	}
	return pe, id
}

// zzlAgeFunding rewinds a market's funding clock past its TWAP window so that
// UpdateFunding runs its body instead of returning early. FundingState is an
// exported struct; this drives test state, it does not modify the engine.
func zzlAgeFunding(pe *PerpetualEngine, id [32]byte) {
	st := pe.FundingStates[id]
	st.LastUpdateTime = time.Now().Unix() - int64(st.TWAPWindow) - 1
}

// zzlSafeDefn recomputes isPositionSafe from its stated definition:
// equity = margin + size*(mark-entry)/Q96, required = notional*mm/1e18.
func zzlSafeDefn(pos *PerpPosition, m *PerpMarket, margin *big.Int) (equity, required *big.Int) {
	abs := new(big.Int).Abs(pos.Size)
	notional := new(big.Int).Mul(abs, m.MarkPrice)
	notional.Div(notional, Q96)
	required = new(big.Int).Mul(notional, m.MaintenanceMargin)
	required.Div(required, big.NewInt(1e18))

	diff := new(big.Int).Sub(m.MarkPrice, pos.EntryPrice)
	pnl := new(big.Int).Mul(pos.Size, diff)
	pnl.Div(pnl, Q96)
	equity = new(big.Int).Add(margin, pnl)
	return equity, required
}

// ---------------------------------------------------------------------------
// market creation
// ---------------------------------------------------------------------------

func TestZzlPerpCreateMarketInitialState(t *testing.T) {
	pe := NewPerpetualEngine()
	price := zzlPx(100)
	id, err := pe.CreateMarket(zzlBase, zzlQuote, price, 50, zzlMM(5))
	if err != nil {
		t.Fatalf("CreateMarket: %v", err)
	}
	m := pe.Markets[id]
	if m == nil {
		t.Fatal("market not filed under its id")
	}
	if m.MarkPrice.Cmp(price) != 0 || m.IndexPrice.Cmp(price) != 0 {
		t.Fatalf("mark/index = %s/%s, want both %s", m.MarkPrice, m.IndexPrice, price)
	}
	// A brand-new market carries no open interest, no funding, and an empty fund.
	if m.OpenInterestLong.Sign() != 0 || m.OpenInterestShort.Sign() != 0 {
		t.Fatal("a new market opens with non-zero open interest")
	}
	if m.FundingRate.Sign() != 0 || m.InsuranceFund.Sign() != 0 {
		t.Fatal("a new market opens with a non-zero funding rate or insurance fund")
	}
	if m.MaxLeverage != 50 {
		t.Fatalf("MaxLeverage = %d, want 50", m.MaxLeverage)
	}
	// Prices are copied, not aliased to the caller's big.Int.
	price.Set(zzlPx(1))
	if m.MarkPrice.Cmp(zzlPx(100)) != 0 {
		t.Fatal("CreateMarket aliased its initialPrice argument")
	}
	// The funding state is created alongside the market.
	fs := pe.FundingStates[id]
	if fs == nil {
		t.Fatal("no funding state created for the market")
	}
	if fs.CumulativeFunding.Sign() != 0 || fs.PremiumEMA.Sign() != 0 {
		t.Fatal("funding state does not start at zero")
	}
	if fs.TWAPWindow != 8*3600 {
		t.Fatalf("TWAP window = %d, want 8h", fs.TWAPWindow)
	}
}

func TestZzlPerpCreateMarketClampsLeverageAndRefusesDuplicates(t *testing.T) {
	// Zero and above-ceiling leverage are both silently clamped to MaxLeverage
	// rather than refused — a market can never be created above the ceiling.
	for _, ask := range []uint32{0, MaxLeverage + 1, 1 << 20} {
		pe := NewPerpetualEngine()
		id, err := pe.CreateMarket(zzlBase, zzlQuote, zzlPx(100), ask, zzlMM(5))
		if err != nil {
			t.Fatalf("CreateMarket(%d): %v", ask, err)
		}
		if pe.Markets[id].MaxLeverage != MaxLeverage {
			t.Fatalf("asked %d, got %d, want the clamp to %d", ask, pe.Markets[id].MaxLeverage, MaxLeverage)
		}
	}
	// A value inside the ceiling is honoured exactly.
	pe := NewPerpetualEngine()
	id, err := pe.CreateMarket(zzlBase, zzlQuote, zzlPx(100), MaxLeverage, zzlMM(5))
	if err != nil {
		t.Fatalf("CreateMarket at the ceiling: %v", err)
	}
	if pe.Markets[id].MaxLeverage != MaxLeverage {
		t.Fatalf("MaxLeverage = %d, want %d", pe.Markets[id].MaxLeverage, MaxLeverage)
	}

	// The same asset pair maps to the same id, so the second create is refused
	// and the first market survives untouched.
	first := pe.Markets[id]
	dup, err := pe.CreateMarket(zzlBase, zzlQuote, zzlPx(999), 10, zzlMM(9))
	if !errors.Is(err, ErrPoolExists) {
		t.Fatalf("duplicate CreateMarket err = %v, want ErrPoolExists", err)
	}
	if dup != ([32]byte{}) {
		t.Fatalf("refused create returned id %x, want the zero id", dup)
	}
	if pe.Markets[id] != first || first.MarkPrice.Cmp(zzlPx(100)) != 0 {
		t.Fatal("a refused duplicate overwrote the existing market")
	}
	if len(pe.Markets) != 1 {
		t.Fatalf("%d markets after a refused duplicate, want 1", len(pe.Markets))
	}
}

func TestZzlPerpMarketIDIsDeterministicAndPairOrdered(t *testing.T) {
	// The id is a pure function of the pair, so it is stable across engines.
	if generateMarketID(zzlBase, zzlQuote) != generateMarketID(zzlBase, zzlQuote) {
		t.Fatal("generateMarketID is not deterministic")
	}
	// Swapping base and quote is a different market.
	if generateMarketID(zzlBase, zzlQuote) == generateMarketID(zzlQuote, zzlBase) {
		t.Fatal("base/quote order does not affect the market id")
	}
	// The id packs 20 bytes of base and only the first 12 of quote, so two quote
	// assets sharing a 12-byte prefix collide onto one market. Pinned because it
	// is what makes ErrPoolExists reachable for distinct pairs.
	q1 := Currency{Address: common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAA00000000000000001")}
	q2 := Currency{Address: common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAA00000000000000002")}
	if q1.Address == q2.Address {
		t.Fatal("fixture: the two quote assets are the same address")
	}
	if generateMarketID(zzlBase, q1) != generateMarketID(zzlBase, q2) {
		t.Fatal("quote assets differing past byte 12 no longer collide; the id widened")
	}
	id := generateMarketID(zzlBase, zzlQuote)
	if !zzlBytesEqual(id[:20], zzlBase.Address[:]) {
		t.Fatal("the first 20 bytes of the id are not the base address")
	}
}

func zzlBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// OpenPosition
// ---------------------------------------------------------------------------

func TestZzlPerpOpenPositionRefusesUnknownMarket(t *testing.T) {
	pe := NewPerpetualEngine()
	if _, err := pe.OpenPosition(zzlOwner, zzlMarket, zzlBig(1), zzlBig(1), false); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPoolNotFound", err)
	}
}

// DEFECT (reported, HIGH): OpenPosition divides the notional by the caller's
// margin with no zero check, so margin == 0 panics. A panic reachable from a
// precompile entry point halts the chain.
func TestZzlPerpZeroMarginPanics(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 50, zzlMM(5))
	panicked, rec := zzlPanics(func() {
		_, _ = pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(0), false)
	})
	if !panicked {
		t.Fatal("OpenPosition(margin=0) did not panic; a zero-margin guard was added")
	}
	if fmt.Sprint(rec) != "division by zero" {
		t.Fatalf("panic value = %v, want the big.Int division-by-zero", rec)
	}
	if len(pe.Positions) != 0 {
		t.Fatal("the panicking open left a position behind")
	}
}

func TestZzlPerpOpenPositionLeverageBoundary(t *testing.T) {
	// The engine computes leverage in hundredths: notional*100/margin, refused
	// once it exceeds MaxLeverage*100. Find the exact refusal boundary by
	// bisecting on the margin and check one unit either side of it.
	price := zzlPx(100)
	pe, id := zzlPerpMarket(t, price, 10, zzlMM(5))
	size := zzlBig(1000)
	notional := new(big.Int).Mul(size, price)
	notional.Div(notional, Q96) // 100000

	accepts := func(margin *big.Int) bool {
		delete(pe.Positions, zzlOwner)
		_, err := pe.OpenPosition(zzlOwner, id, size, margin, false)
		return err == nil
	}
	if accepts(big.NewInt(1)) {
		t.Fatal("a 1-unit margin on a 100000 notional was accepted at 10x")
	}
	if !accepts(new(big.Int).Set(notional)) {
		t.Fatal("a fully collateralised position was refused")
	}
	smallest := zzlBisect(big.NewInt(1), notional, accepts)

	// At the smallest accepted margin, leverage sits at or under the ceiling.
	lev := new(big.Int).Mul(notional, big.NewInt(100))
	lev.Div(lev, smallest)
	if lev.Cmp(big.NewInt(int64(10)*100)) > 0 {
		t.Fatalf("smallest accepted margin %s gives leverage %s hundredths, over the 1000 ceiling",
			smallest, lev)
	}
	// One unit less margin crosses it and must be refused with the right error.
	over := new(big.Int).Sub(smallest, big.NewInt(1))
	levOver := new(big.Int).Mul(notional, big.NewInt(100))
	levOver.Div(levOver, over)
	if levOver.Cmp(big.NewInt(1000)) <= 0 {
		t.Fatalf("one unit below the boundary still yields leverage %s within the ceiling", levOver)
	}
	delete(pe.Positions, zzlOwner)
	oiBefore := new(big.Int).Set(pe.Markets[id].OpenInterestLong)
	if _, err := pe.OpenPosition(zzlOwner, id, size, over, false); !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("margin %s (leverage %s hundredths): err = %v, want ErrExcessiveLeverage",
			over, levOver, err)
	}
	// A refused open leaves no position and does not touch open interest.
	if p := pe.Positions[zzlOwner]; p != nil && p[id] != nil {
		t.Fatal("a refused open created a position")
	}
	if got := pe.Markets[id].OpenInterestLong; got.Cmp(oiBefore) != 0 {
		t.Fatalf("a refused open moved open interest from %s to %s", oiBefore, got)
	}
}

// The leverage ceiling used to narrow the big.Int ratio through Uint64() before
// comparing, so a position whose leverage-in-hundredths was a multiple of 2^64
// truncated to a small number and sailed past the ceiling. The comparison is now
// made at full width; this pins the exact input that used to get through.
func TestZzlPerpLeverageCeilingHoldsAtFullWidth(t *testing.T) {
	// At a price of exactly 1 (Q96), notional == size, so leverage in hundredths
	// is size*100/margin. Choose margin = 100 and size = 2^64 to make that
	// exactly 2^64, whose low 64 bits are zero.
	pe, id := zzlPerpMarket(t, new(big.Int).Set(Q96), 10, zzlMM(5))
	margin := big.NewInt(100)
	size := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64

	honest := new(big.Int).Mul(size, big.NewInt(100))
	honest.Div(honest, margin)
	if honest.Cmp(new(big.Int).Lsh(big.NewInt(1), 64)) != 0 {
		t.Fatalf("fixture: leverage is %s, want exactly 2^64", honest)
	}
	if honest.Uint64() != 0 {
		t.Fatalf("fixture: 2^64 narrowed to %d, want 0", honest.Uint64())
	}

	// The true leverage is 2^64/100 times the market's stated 10x ceiling, and the
	// comparison now sees that rather than the zero its low word carries.
	trueLev := new(big.Int).Div(honest, big.NewInt(100))
	if trueLev.Cmp(big.NewInt(int64(pe.Markets[id].MaxLeverage))) <= 0 {
		t.Fatalf("fixture: true leverage %s did not exceed the ceiling %d", trueLev, pe.Markets[id].MaxLeverage)
	}

	pos, err := pe.OpenPosition(zzlOwner, id, size, margin, false)
	if !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("a leverage of exactly 2^64 was admitted: (%v, %v)", pos, err)
	}
	if pos != nil {
		t.Fatal("a refused open returned a position")
	}
	if p := pe.Positions[zzlOwner]; p != nil && p[id] != nil {
		t.Fatal("a refused open created a position")
	}

	// The boundary itself still opens: exactly the ceiling is admitted, one
	// hundredth past it is not. Without this half the test would pass against a
	// check that refused everything.
	pe2, id2 := zzlPerpMarket(t, new(big.Int).Set(Q96), 10, zzlMM(5))
	if _, err := pe2.OpenPosition(zzlOwner, id2, big.NewInt(1000), big.NewInt(100), false); err != nil {
		t.Fatalf("leverage exactly at the 10x ceiling was refused: %v", err)
	}
	pe3, id3 := zzlPerpMarket(t, new(big.Int).Set(Q96), 10, zzlMM(5))
	if _, err := pe3.OpenPosition(zzlOwner, id3, big.NewInt(1001), big.NewInt(100), false); !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("leverage one hundredth past the ceiling was admitted: %v", err)
	}
}

func TestZzlPerpOpenPositionRecordsBothSidesAndOpenInterest(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	m := pe.Markets[id]

	long, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(100_000), false)
	if err != nil {
		t.Fatalf("open long: %v", err)
	}
	if long.Size.Sign() <= 0 {
		t.Fatalf("long size = %s, want positive", long.Size)
	}
	if long.EntryPrice.Cmp(m.MarkPrice) != 0 {
		t.Fatalf("entry %s != mark %s", long.EntryPrice, m.MarkPrice)
	}
	if long.Owner != zzlOwner || long.Market != id {
		t.Fatal("position owner/market not recorded")
	}
	if long.LastFundingIndex.Cmp(pe.FundingStates[id].CumulativeFunding) != 0 {
		t.Fatal("a new position did not snapshot the current funding index")
	}
	if m.OpenInterestLong.Cmp(zzlBig(1000)) != 0 {
		t.Fatalf("long OI = %s, want 1000", m.OpenInterestLong)
	}
	if m.OpenInterestShort.Sign() != 0 {
		t.Fatalf("short OI = %s, want 0", m.OpenInterestShort)
	}

	// A negative size is a short and lands on the other side of the OI ledger.
	short, err := pe.OpenPosition(zzlOther, id, zzlBig(-400), zzlBig(100_000), true)
	if err != nil {
		t.Fatalf("open short: %v", err)
	}
	if short.Size.Sign() >= 0 {
		t.Fatalf("short size = %s, want negative", short.Size)
	}
	if !short.IsIsolated {
		t.Fatal("IsIsolated not recorded")
	}
	if m.OpenInterestShort.Cmp(zzlBig(400)) != 0 {
		t.Fatalf("short OI = %s, want 400 (the absolute size)", m.OpenInterestShort)
	}
	if m.OpenInterestLong.Cmp(zzlBig(1000)) != 0 {
		t.Fatal("opening a short disturbed the long open interest")
	}
	// Positions are keyed per owner, so the two do not collide.
	if pe.Positions[zzlOwner][id] == pe.Positions[zzlOther][id] {
		t.Fatal("two owners share one position object")
	}
}

func TestZzlPerpIncreasePositionBlendsEntryAndSumsMargin(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	if _, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(100_000), false); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := pe.UpdateMarkPrice(id, zzlPx(200)); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(100_000), false)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if pos.Size.Cmp(zzlBig(2000)) != 0 {
		t.Fatalf("size = %s, want 2000", pos.Size)
	}
	// (1000*100 + 1000*200) / 2000 = 150
	if pos.EntryPrice.Cmp(zzlPx(150)) != 0 {
		t.Fatalf("blended entry = %s, want %s", pos.EntryPrice, zzlPx(150))
	}
	if pos.EntryPrice.Cmp(zzlPx(100)) <= 0 || pos.EntryPrice.Cmp(zzlPx(200)) >= 0 {
		t.Fatal("blended entry escaped the interval between the two fills")
	}
	if pos.Margin.Cmp(zzlBig(200_000)) != 0 {
		t.Fatalf("margin = %s, want the sum 200000", pos.Margin)
	}
	if pe.Markets[id].OpenInterestLong.Cmp(zzlBig(2000)) != 0 {
		t.Fatalf("long OI = %s, want 2000", pe.Markets[id].OpenInterestLong)
	}
}

// DEFECT (reported): when an opposing open takes the size to exactly zero the
// engine deletes the position and returns early — BEFORE the open-interest
// update — so the closed size is never removed from the market's open interest.
func TestZzlPerpOppositeOpenToZeroLeaksOpenInterest(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	m := pe.Markets[id]
	if _, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(100_000), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	if m.OpenInterestLong.Cmp(zzlBig(1000)) != 0 {
		t.Fatalf("long OI = %s, want 1000", m.OpenInterestLong)
	}

	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(-1000), zzlBig(100_000), false)
	if err != nil {
		t.Fatalf("closing open returned err = %v, want nil", err)
	}
	if pos != nil {
		t.Fatalf("closing open returned %+v, want nil", pos)
	}
	if pe.Positions[zzlOwner][id] != nil {
		t.Fatal("the position was not deleted")
	}
	// The position is gone but the market still believes 1000 of long interest
	// is outstanding.
	if m.OpenInterestLong.Sign() == 0 {
		t.Fatal("open interest was released; the early return was fixed — update the finding")
	}
	if m.OpenInterestLong.Cmp(zzlBig(1000)) != 0 {
		t.Fatalf("stranded long OI = %s, want the original 1000", m.OpenInterestLong)
	}
	if m.OpenInterestShort.Sign() != 0 {
		t.Fatalf("short OI = %s, want 0", m.OpenInterestShort)
	}
}

// ---------------------------------------------------------------------------
// ClosePosition
// ---------------------------------------------------------------------------

func TestZzlPerpClosePositionRefusals(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))

	if _, err := pe.ClosePosition(zzlOwner, zzlMarket, zzlBig(1)); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPoolNotFound", err)
	}
	// Owner has never traded: the whole owner map is absent.
	if _, err := pe.ClosePosition(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner with no positions err = %v, want ErrPositionNotFound", err)
	}
	// Owner has traded a different market, so the map exists but the entry does not.
	other, err := pe.CreateMarket(zzlQuote, zzlBase, zzlPx(100), 100, zzlMM(5))
	if err != nil {
		t.Fatalf("CreateMarket: %v", err)
	}
	if _, err := pe.OpenPosition(zzlOwner, other, zzlBig(10), zzlBig(100_000), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pe.ClosePosition(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner without this market err = %v, want ErrPositionNotFound", err)
	}
}

func TestZzlPerpCloseIsSignCorrectForBothSidesAndClampsOverClose(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int64
		closeAt int64
		wantWin bool
	}{
		{"long into a rise", 1000, 120, true},
		{"long into a fall", 1000, 80, false},
		{"short into a fall", -1000, 80, true},
		{"short into a rise", -1000, 120, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
			if _, err := pe.OpenPosition(zzlOwner, id, zzlBig(tc.size), zzlBig(500_000), false); err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := pe.UpdateMarkPrice(id, zzlPx(tc.closeAt)); err != nil {
				t.Fatalf("UpdateMarkPrice: %v", err)
			}
			// Ask to close ten times the position: the engine must clamp to what
			// is held and pay PnL on that, never on phantom size.
			abs := new(big.Int).Abs(zzlBig(tc.size))
			pnl, err := pe.ClosePosition(zzlOwner, id, new(big.Int).Mul(abs, big.NewInt(10)))
			if err != nil {
				t.Fatalf("close: %v", err)
			}
			if tc.wantWin != (pnl.Sign() > 0) {
				t.Fatalf("PnL = %s, want positive=%v", pnl, tc.wantWin)
			}
			// The magnitude is exactly |size| * |priceDiff| / Q96 — no more.
			diff := new(big.Int).Sub(zzlPx(tc.closeAt), zzlPx(100))
			want := new(big.Int).Mul(abs, diff)
			want.Div(want, Q96)
			want.Abs(want)
			if new(big.Int).Abs(pnl).Cmp(want) != 0 {
				t.Fatalf("|PnL| = %s, want %s — the over-close was not clamped",
					new(big.Int).Abs(pnl), want)
			}
			if pe.Positions[zzlOwner][id] != nil {
				t.Fatal("an over-close did not fully close the position")
			}
		})
	}
}

func TestZzlPerpPartialCloseShrinksSizeTowardZeroAndReleasesMargin(t *testing.T) {
	for _, size := range []int64{1000, -1000} {
		name := "long"
		if size < 0 {
			name = "short"
		}
		t.Run(name, func(t *testing.T) {
			pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
			pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(size), zzlBig(500_000), false)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			m0 := new(big.Int).Set(pos.Margin)

			if _, err := pe.ClosePosition(zzlOwner, id, zzlBig(250)); err != nil {
				t.Fatalf("partial close: %v", err)
			}
			// A partial close moves the size toward zero, never past it, and
			// never flips the side.
			if new(big.Int).Abs(pos.Size).Cmp(zzlBig(750)) != 0 {
				t.Fatalf("|size| = %s, want 750", new(big.Int).Abs(pos.Size))
			}
			if pos.Size.Sign() != int(big.NewInt(size).Sign()) {
				t.Fatalf("a partial close flipped the side: %s", pos.Size)
			}
			// A quarter of the margin was released, and never more than posted.
			released := new(big.Int).Sub(m0, pos.Margin)
			if released.Sign() <= 0 {
				t.Fatalf("no margin released (%s -> %s)", m0, pos.Margin)
			}
			if released.Cmp(m0) > 0 {
				t.Fatalf("released %s of a %s margin", released, m0)
			}
			want := new(big.Int).Div(m0, big.NewInt(4))
			if new(big.Int).Sub(released, want).CmpAbs(big.NewInt(1)) > 0 {
				t.Fatalf("released %s for a 25%% close, want ~%s", released, want)
			}
			if pe.Positions[zzlOwner][id] == nil {
				t.Fatal("a partial close removed the position")
			}
		})
	}
}

// DEFECT (reported, HIGH): ClosePosition never rejects a negative size. The
// clamp only catches sizeToClose ABOVE the position size, so a negative value
// runs the partial-close arithmetic backwards: it GROWS the position and ADDS
// margin that was never posted.
func TestZzlPerpNegativeCloseSizeGrowsThePositionAndMintsMargin(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(500_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	size0 := new(big.Int).Set(pos.Size)
	margin0 := new(big.Int).Set(pos.Margin)

	if _, err := pe.ClosePosition(zzlOwner, id, zzlBig(-500)); err != nil {
		t.Fatalf("negative close returned err = %v, want it to be refused or to no-op", err)
	}
	if pos.Size.Cmp(size0) <= 0 {
		t.Fatalf("size went %s -> %s; a negative-size guard was added — update the finding",
			size0, pos.Size)
	}
	if pos.Size.Cmp(zzlBig(1500)) != 0 {
		t.Fatalf("size = %s, want 1500 (the close ran backwards)", pos.Size)
	}
	if pos.Margin.Cmp(margin0) <= 0 {
		t.Fatalf("margin went %s -> %s, expected it to grow out of nothing", margin0, pos.Margin)
	}
}

// ---------------------------------------------------------------------------
// margin adjustment
// ---------------------------------------------------------------------------

func TestZzlPerpAddAndRemoveMarginRefusals(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))

	if err := pe.AddMargin(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("AddMargin with no positions err = %v, want ErrPositionNotFound", err)
	}
	if err := pe.RemoveMargin(zzlOwner, zzlMarket, zzlBig(1)); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("RemoveMargin unknown market err = %v, want ErrPoolNotFound", err)
	}
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("RemoveMargin with no positions err = %v, want ErrPositionNotFound", err)
	}

	// Owner holds a position in another market: the owner map exists, the entry
	// does not.
	other, err := pe.CreateMarket(zzlQuote, zzlBase, zzlPx(100), 100, zzlMM(5))
	if err != nil {
		t.Fatalf("CreateMarket: %v", err)
	}
	if _, err := pe.OpenPosition(zzlOwner, other, zzlBig(10), zzlBig(100_000), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := pe.AddMargin(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("AddMargin unknown market err = %v, want ErrPositionNotFound", err)
	}
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("RemoveMargin unknown market err = %v, want ErrPositionNotFound", err)
	}
}

func TestZzlPerpMarginMovesHealthInTheRightDirection(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	m := pe.Markets[id]
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Move the mark against the position but leave it inside the maintenance
	// requirement, so a symmetric add-then-remove is legitimate at both ends.
	if err := pe.UpdateMarkPrice(id, zzlPx(97)); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	if !pe.isPositionSafe(pos, m, pos.Margin) {
		t.Fatal("fixture: the position is already unsafe before any margin is moved")
	}

	if err := pe.AddMargin(zzlOwner, id, zzlBig(1_000_000)); err != nil {
		t.Fatalf("AddMargin: %v", err)
	}
	if pos.Margin.Cmp(zzlBig(1_010_000)) != 0 {
		t.Fatalf("margin = %s, want 1010000", pos.Margin)
	}
	if !pe.isPositionSafe(pos, m, pos.Margin) {
		t.Fatal("adding a million units of margin left the position unsafe")
	}
	// Removing it again restores the previous verdict exactly.
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(1_000_000)); err != nil {
		t.Fatalf("RemoveMargin: %v", err)
	}
	if pos.Margin.Cmp(zzlBig(10_000)) != 0 {
		t.Fatalf("margin = %s, want the original 10000", pos.Margin)
	}
	if !pe.isPositionSafe(pos, m, pos.Margin) {
		t.Fatal("add-then-remove did not restore the original safety verdict")
	}

	// Once the mark moves far enough that the base margin no longer covers
	// maintenance, removing anything at all is refused.
	if err := pe.UpdateMarkPrice(id, zzlPx(94)); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	if pe.isPositionSafe(pos, m, pos.Margin) {
		t.Fatal("fixture: the position is still safe at 94")
	}
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("removing 1 unit from an unsafe position: err = %v, want ErrInsufficientMargin", err)
	}
	if pos.Margin.Cmp(zzlBig(10_000)) != 0 {
		t.Fatal("a safety-refused removal moved the margin")
	}
	if err := pe.UpdateMarkPrice(id, zzlPx(97)); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}

	// Taking the margin to exactly zero is refused, and the balance is untouched.
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(10_000)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("removing the whole margin: err = %v, want ErrInsufficientMargin", err)
	}
	if pos.Margin.Cmp(zzlBig(10_000)) != 0 {
		t.Fatal("a refused removal moved the margin")
	}
	// Removing an amount that leaves a positive but unsafe margin is also refused.
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(9_999)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("removing down to 1 unit: err = %v, want ErrInsufficientMargin", err)
	}
	if pos.Margin.Cmp(zzlBig(10_000)) != 0 {
		t.Fatal("a safety-refused removal moved the margin")
	}
}

func TestZzlPerpMarginMayNeverBeTakenToZeroEvenWhenSolvent(t *testing.T) {
	// The zero-margin floor is a SEPARATE guard from the solvency check, and it
	// has to be, because a position can be nominally solvent at zero margin: on
	// a market with no maintenance requirement, equity of 0 clears a requirement
	// of 0. An unmargined position is still an unbacked position and must be
	// refused on the floor alone.
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, big.NewInt(0))
	m := pe.Markets[id]
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Confirm the solvency check alone would wave this through.
	if !pe.isPositionSafe(pos, m, big.NewInt(0)) {
		t.Fatal("fixture: a zero margin is not solvent here, so the floor is not isolated")
	}
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(10_000)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("removing the entire margin from a nominally solvent position: err = %v, "+
			"want ErrInsufficientMargin", err)
	}
	if pos.Margin.Cmp(zzlBig(10_000)) != 0 {
		t.Fatalf("margin = %s, want it untouched at 10000", pos.Margin)
	}
	// One unit short of the whole balance is allowed, so the floor sits exactly
	// at zero and not one unit above it.
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(9_999)); err != nil {
		t.Fatalf("leaving one unit of margin: %v", err)
	}
	if pos.Margin.Cmp(zzlBig(1)) != 0 {
		t.Fatalf("margin = %s, want 1", pos.Margin)
	}
	// And removing that last unit is refused too.
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(1)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("removing the last unit: err = %v, want ErrInsufficientMargin", err)
	}
	if pos.Margin.Cmp(zzlBig(1)) != 0 {
		t.Fatal("a refused removal moved the margin")
	}
}

// DEFECT (reported, HIGH): AddMargin performs no validation whatsoever. A
// negative amount is a margin REMOVAL that bypasses RemoveMargin's zero check
// and its solvency check entirely, driving the margin negative.
func TestZzlPerpAddMarginWithNegativeAmountBypassesEveryCheck(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// The same move through RemoveMargin is correctly refused.
	if err := pe.RemoveMargin(zzlOwner, id, zzlBig(20_000)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("RemoveMargin(20000) err = %v, want ErrInsufficientMargin", err)
	}
	if pos.Margin.Cmp(zzlBig(10_000)) != 0 {
		t.Fatal("the refused removal moved the margin")
	}
	// Through AddMargin it goes straight through.
	if err := pe.AddMargin(zzlOwner, id, zzlBig(-20_000)); err != nil {
		t.Fatalf("AddMargin(-20000) err = %v, want nil (this test pins the missing validation)", err)
	}
	if pos.Margin.Sign() >= 0 {
		t.Fatalf("margin = %s, want negative; a validation was added — update the finding", pos.Margin)
	}
	if pos.Margin.Cmp(zzlBig(-10_000)) != 0 {
		t.Fatalf("margin = %s, want -10000", pos.Margin)
	}
	if pe.isPositionSafe(pos, pe.Markets[id], pos.Margin) {
		t.Fatal("a position with negative margin reports safe")
	}
}

// ---------------------------------------------------------------------------
// isPositionSafe: exact boundary
// ---------------------------------------------------------------------------

func TestZzlPerpSafetyBoundaryIsEquityAtLeastMaintenance(t *testing.T) {
	for _, size := range []int64{1000, -1000} {
		name := "long"
		if size < 0 {
			name = "short"
		}
		t.Run(name, func(t *testing.T) {
			pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
			m := pe.Markets[id]
			pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(size), zzlBig(500_000), false)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			// Bisect on the margin: safety is monotone increasing in margin.
			safe := func(margin *big.Int) bool { return pe.isPositionSafe(pos, m, margin) }
			if safe(big.NewInt(0)) {
				t.Fatal("a zero-margin position reports safe at its entry price")
			}
			hi := zzlBig(10_000_000)
			if !safe(hi) {
				t.Fatal("even a huge margin reports unsafe")
			}
			edge := zzlBisect(big.NewInt(0), hi, safe)

			// At the edge the position is safe and equity >= required; one unit
			// below it is unsafe and equity < required. That pins `>=`, not `>`.
			for _, tc := range []struct {
				label  string
				margin *big.Int
				want   bool
			}{
				{"the smallest safe margin", edge, true},
				{"one unit below it", new(big.Int).Sub(edge, big.NewInt(1)), false},
				{"one unit above it", new(big.Int).Add(edge, big.NewInt(1)), true},
			} {
				if got := safe(tc.margin); got != tc.want {
					t.Fatalf("%s (%s): isPositionSafe = %v, want %v", tc.label, tc.margin, got, tc.want)
				}
				eq, req := zzlSafeDefn(pos, m, tc.margin)
				if (eq.Cmp(req) >= 0) != tc.want {
					t.Fatalf("%s: definition says equity %s vs required %s, engine says %v",
						tc.label, eq, req, tc.want)
				}
			}
			// Exactly on the requirement is SAFE — liquidation triggers at the
			// threshold and never before it.
			eq, req := zzlSafeDefn(pos, m, edge)
			if eq.Cmp(req) < 0 {
				t.Fatalf("the smallest safe margin has equity %s below required %s", eq, req)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// liquidation
// ---------------------------------------------------------------------------

func TestZzlPerpLiquidateRefusals(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))

	if _, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPoolNotFound", err)
	}
	if _, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner with no positions err = %v, want ErrPositionNotFound", err)
	}
	other, err := pe.CreateMarket(zzlQuote, zzlBase, zzlPx(100), 100, zzlMM(5))
	if err != nil {
		t.Fatalf("CreateMarket: %v", err)
	}
	if _, err := pe.OpenPosition(zzlOwner, other, zzlBig(10), zzlBig(100_000), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner without this market err = %v, want ErrPositionNotFound", err)
	}

	// A healthy position may not be liquidated, and the attempt leaves it intact.
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(500_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id); !errors.Is(err, ErrPositionNotLiquidatable) {
		t.Fatalf("healthy position err = %v, want ErrPositionNotLiquidatable", err)
	}
	if pe.Positions[zzlOwner][id] != pos {
		t.Fatal("a refused liquidation removed the position")
	}
}

func TestZzlPerpLiquidationTriggersExactlyAtTheMaintenanceThreshold(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	m := pe.Markets[id]
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Bisect on the mark price for the highest price at which the long is still
	// unsafe: safety is monotone increasing in price for a long.
	liquidatable := func(price *big.Int) bool {
		m.MarkPrice = new(big.Int).Set(price)
		return !pe.isPositionSafe(pos, m, pos.Margin)
	}
	// Search on the "how far did price fall" axis so the predicate is monotone.
	drop := zzlBisect(big.NewInt(0), zzlPx(100), func(k *big.Int) bool {
		return liquidatable(new(big.Int).Sub(zzlPx(100), k))
	})
	pKill := new(big.Int).Sub(zzlPx(100), drop)
	pSafe := new(big.Int).Sub(zzlPx(100), new(big.Int).Sub(drop, big.NewInt(1)))

	// One wei on the safe side: refused.
	m.MarkPrice = new(big.Int).Set(pSafe)
	if _, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id); !errors.Is(err, ErrPositionNotLiquidatable) {
		t.Fatalf("one wei inside the threshold: err = %v, want ErrPositionNotLiquidatable", err)
	}
	if pe.Positions[zzlOwner][id] == nil {
		t.Fatal("a refused liquidation removed the position")
	}
	// One wei past it: allowed. The threshold is exact.
	m.MarkPrice = new(big.Int).Set(pKill)
	reward, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id)
	if err != nil {
		t.Fatalf("one wei past the threshold: %v", err)
	}
	if reward == nil {
		t.Fatal("liquidation returned a nil reward")
	}
	if pe.Positions[zzlOwner][id] != nil {
		t.Fatal("a successful liquidation left the position open")
	}
	// The closed size left the open-interest ledger.
	if m.OpenInterestLong.Sign() != 0 {
		t.Fatalf("long OI = %s after liquidating the only position, want 0", m.OpenInterestLong)
	}
}

func TestZzlPerpLiquidationRewardIsCappedAndTheFundAbsorbsTheRest(t *testing.T) {
	// Case: the fund can cover the shortfall, so the liquidator is paid in full
	// and the fund shrinks by exactly the deficit.
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	m := pe.Markets[id]
	m.InsuranceFund = big.NewInt(10_000_000)
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m.MarkPrice = zzlPx(50)
	if pe.isPositionSafe(pos, m, pos.Margin) {
		t.Fatal("fixture: the position is still safe at half price")
	}
	notional := new(big.Int).Mul(zzlBig(1000), m.MarkPrice)
	notional.Div(notional, Q96)
	wantReward := new(big.Int).Div(notional, big.NewInt(20)) // the engine's 5%
	pnl := new(big.Int).Mul(zzlBig(1000), new(big.Int).Sub(m.MarkPrice, pos.EntryPrice))
	pnl.Div(pnl, Q96)
	remaining := new(big.Int).Add(pos.Margin, pnl)
	deficit := new(big.Int).Sub(wantReward, remaining)
	fundBefore := new(big.Int).Set(m.InsuranceFund)

	got, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id)
	if err != nil {
		t.Fatalf("liquidate: %v", err)
	}
	if got.Cmp(wantReward) != 0 {
		t.Fatalf("reward = %s, want notional/20 = %s", got, wantReward)
	}
	if moved := new(big.Int).Sub(fundBefore, m.InsuranceFund); moved.Cmp(deficit) != 0 {
		t.Fatalf("fund moved by %s, want the deficit %s", moved, deficit)
	}

	// Case: the fund cannot cover it, so the reward is capped at what the
	// position actually holds and the fund is left alone.
	pe2, id2 := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	m2 := pe2.Markets[id2]
	m2.InsuranceFund = big.NewInt(1)
	pos2, err := pe2.OpenPosition(zzlOwner, id2, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m2.MarkPrice = zzlPx(50)
	pnl2 := new(big.Int).Mul(zzlBig(1000), new(big.Int).Sub(m2.MarkPrice, pos2.EntryPrice))
	pnl2.Div(pnl2, Q96)
	remaining2 := new(big.Int).Add(pos2.Margin, pnl2)

	got2, err := pe2.LiquidatePosition(zzlLiquidator, zzlOwner, id2)
	if err != nil {
		t.Fatalf("liquidate: %v", err)
	}
	if got2.Cmp(remaining2) != 0 {
		t.Fatalf("capped reward = %s, want the remaining equity %s", got2, remaining2)
	}
	if m2.InsuranceFund.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("fund = %s, want it untouched at 1", m2.InsuranceFund)
	}
}

// DEFECT (reported): when the position is insolvent and the fund cannot cover
// the shortfall, the reward is set to the remaining equity — which is NEGATIVE.
// The engine hands the liquidator a negative payout instead of clamping to zero.
func TestZzlPerpInsolventLiquidationReturnsNegativeReward(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	m := pe.Markets[id]
	m.InsuranceFund = big.NewInt(0)
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Below entry - margin/size the position owes more than it holds.
	m.MarkPrice = zzlPx(1)
	pnl := new(big.Int).Mul(zzlBig(1000), new(big.Int).Sub(m.MarkPrice, pos.EntryPrice))
	pnl.Div(pnl, Q96)
	remaining := new(big.Int).Add(pos.Margin, pnl)
	if remaining.Sign() >= 0 {
		t.Fatalf("fixture: the position is still solvent (%s)", remaining)
	}

	reward, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id)
	if err != nil {
		t.Fatalf("liquidate: %v", err)
	}
	if reward.Sign() >= 0 {
		t.Fatalf("reward = %s, want negative; a clamp to zero was added — update the finding", reward)
	}
	if reward.Cmp(remaining) != 0 {
		t.Fatalf("reward = %s, want the negative remaining equity %s", reward, remaining)
	}
	if m.InsuranceFund.Sign() != 0 {
		t.Fatalf("fund = %s, want it untouched at 0", m.InsuranceFund)
	}
}

func TestZzlPerpLiquidatingAShortReleasesShortOpenInterest(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	m := pe.Markets[id]
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(-1000), zzlBig(10_000), false)
	if err != nil {
		t.Fatalf("open short: %v", err)
	}
	if m.OpenInterestShort.Cmp(zzlBig(1000)) != 0 {
		t.Fatalf("short OI = %s, want 1000", m.OpenInterestShort)
	}
	// A short is killed by a price RISE.
	m.MarkPrice = zzlPx(200)
	if pe.isPositionSafe(pos, m, pos.Margin) {
		t.Fatal("fixture: the short is still safe at double price")
	}
	if _, err := pe.LiquidatePosition(zzlLiquidator, zzlOwner, id); err != nil {
		t.Fatalf("liquidate short: %v", err)
	}
	if m.OpenInterestShort.Sign() != 0 {
		t.Fatalf("short OI = %s after liquidation, want 0", m.OpenInterestShort)
	}
	if m.OpenInterestLong.Sign() != 0 {
		t.Fatalf("liquidating a short moved long OI to %s", m.OpenInterestLong)
	}
}

// ---------------------------------------------------------------------------
// funding
// ---------------------------------------------------------------------------

func TestZzlPerpUpdateFundingRefusalAndTimeGate(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))

	if err := pe.UpdateFunding(zzlMarket); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPoolNotFound", err)
	}
	// Inside the TWAP window the call is a no-op: nothing moves.
	fs := pe.FundingStates[id]
	before := new(big.Int).Set(fs.CumulativeFunding)
	last := fs.LastUpdateTime
	if err := pe.UpdateIndexPrice(id, zzlPx(50)); err != nil {
		t.Fatalf("UpdateIndexPrice: %v", err)
	}
	if err := pe.UpdateFunding(id); err != nil {
		t.Fatalf("UpdateFunding inside the window: %v", err)
	}
	if fs.CumulativeFunding.Cmp(before) != 0 || fs.LastUpdateTime != last {
		t.Fatal("UpdateFunding ran its body inside the TWAP window")
	}
	if pe.Markets[id].FundingRate.Sign() != 0 {
		t.Fatal("the funding rate moved inside the TWAP window")
	}
}

// DEFECT (reported, HIGH): UpdateFunding divides by the index price with no
// zero check. A market created at price zero, or one whose index is set to
// zero, panics on the next funding update.
func TestZzlPerpZeroIndexPricePanicsOnFunding(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	if err := pe.UpdateIndexPrice(id, big.NewInt(0)); err != nil {
		t.Fatalf("UpdateIndexPrice(0) was refused (%v); a guard was added there instead", err)
	}
	zzlAgeFunding(pe, id)
	panicked, rec := zzlPanics(func() { _ = pe.UpdateFunding(id) })
	if !panicked {
		t.Fatal("UpdateFunding with a zero index did not panic; a guard was added")
	}
	if fmt.Sprint(rec) != "division by zero" {
		t.Fatalf("panic value = %v, want the big.Int division-by-zero", rec)
	}
}

func TestZzlPerpFundingRateIsClampedBothWays(t *testing.T) {
	// The rate is clamped to +-7500. A mark above the index drives it to the
	// positive cap, below to the negative cap, and the cap is symmetric.
	for _, tc := range []struct {
		name string
		mark int64
		want int64
	}{
		{"mark above index", 200, 7500},
		{"mark below index", 50, -7500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
			m := pe.Markets[id]
			if err := pe.UpdateMarkPrice(id, zzlPx(tc.mark)); err != nil {
				t.Fatalf("UpdateMarkPrice: %v", err)
			}
			zzlAgeFunding(pe, id)
			if err := pe.UpdateFunding(id); err != nil {
				t.Fatalf("UpdateFunding: %v", err)
			}
			if m.FundingRate.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("funding rate = %s, want the clamp at %d", m.FundingRate, tc.want)
			}
			// The clamped rate is carried into the cumulative index, signed the
			// same way, and the clock advances.
			fs := pe.FundingStates[id]
			wantCum := new(big.Int).Mul(m.FundingRate, m.MarkPrice)
			wantCum.Div(wantCum, big.NewInt(1e6))
			if fs.CumulativeFunding.Cmp(wantCum) != 0 {
				t.Fatalf("cumulative funding = %s, want rate*mark/1e6 = %s", fs.CumulativeFunding, wantCum)
			}
			if fs.CumulativeFunding.Sign() != int(big.NewInt(tc.want).Sign()) {
				t.Fatal("the cumulative index does not carry the rate's sign")
			}
			if m.LastFundingTime != fs.LastUpdateTime {
				t.Fatal("the market and funding state clocks disagree after an update")
			}
			// A second call inside the fresh window is a no-op.
			cum := new(big.Int).Set(fs.CumulativeFunding)
			if err := pe.UpdateFunding(id); err != nil {
				t.Fatalf("second UpdateFunding: %v", err)
			}
			if fs.CumulativeFunding.Cmp(cum) != 0 {
				t.Fatal("a second funding update inside the window moved the index")
			}
		})
	}
}

// DEFECT (reported): the premium is scaled by 1e18 while the interest-rate term
// and the +-7500 clamp are stated in 1e6. The premium term therefore dominates
// by twelve orders of magnitude, so any mark/index divergence above roughly one
// part in 1e13 saturates the clamp. The unclamped path needs a divergence far
// too small to occur at realistic prices.
func TestZzlPerpFundingUnclampedPathNeedsAnAbsurdlySmallDivergence(t *testing.T) {
	// A one-wei divergence on a 1e18-scale index is small enough to stay inside
	// the clamp; the same one-wei divergence at a normal Q96 price is not.
	pe, id := zzlPerpMarket(t, big.NewInt(1e18), 100, zzlMM(5))
	m := pe.Markets[id]
	if err := pe.UpdateMarkPrice(id, new(big.Int).Add(big.NewInt(1e18), big.NewInt(5))); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	zzlAgeFunding(pe, id)
	if err := pe.UpdateFunding(id); err != nil {
		t.Fatalf("UpdateFunding: %v", err)
	}
	if m.FundingRate.CmpAbs(big.NewInt(7500)) >= 0 {
		t.Fatalf("a 5-wei divergence on a 1e18 index still saturated the clamp (%s); the "+
			"scaling was fixed — update the reported finding", m.FundingRate)
	}
	// The unclamped rate is the premium EMA plus the 1e6-scaled interest term.
	fs := pe.FundingStates[id]
	want := new(big.Int).Add(fs.PremiumEMA, big.NewInt(100))
	if m.FundingRate.Cmp(want) != 0 {
		t.Fatalf("unclamped rate = %s, want premiumEMA + interest = %s", m.FundingRate, want)
	}

	// The same relative divergence at a Q96 price saturates immediately: one
	// part in 1e13 of the index is enough.
	pe2, id2 := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	tiny := new(big.Int).Div(zzlPx(100), big.NewInt(1e13))
	if err := pe2.UpdateMarkPrice(id2, new(big.Int).Add(zzlPx(100), tiny)); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	zzlAgeFunding(pe2, id2)
	if err := pe2.UpdateFunding(id2); err != nil {
		t.Fatalf("UpdateFunding: %v", err)
	}
	if pe2.Markets[id2].FundingRate.Cmp(big.NewInt(7500)) != 0 {
		t.Fatalf("a one-part-in-1e13 divergence gave rate %s, want the saturated 7500",
			pe2.Markets[id2].FundingRate)
	}
}

func TestZzlPerpFundingRateAtParityIsTheInterestTermAlone(t *testing.T) {
	// With mark == index the premium is zero, so the rate is exactly the
	// interest-rate component and the sign is positive (longs pay shorts).
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	zzlAgeFunding(pe, id)
	if err := pe.UpdateFunding(id); err != nil {
		t.Fatalf("UpdateFunding: %v", err)
	}
	if pe.Markets[id].FundingRate.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("rate at parity = %s, want the interest term 100", pe.Markets[id].FundingRate)
	}
	if pe.FundingStates[id].PremiumEMA.Sign() != 0 {
		t.Fatalf("premium EMA at parity = %s, want 0", pe.FundingStates[id].PremiumEMA)
	}
}

func TestZzlPerpGetFundingRateReturnsACopy(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	if _, err := pe.GetFundingRate(zzlMarket); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPoolNotFound", err)
	}
	got, err := pe.GetFundingRate(id)
	if err != nil {
		t.Fatalf("GetFundingRate: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("initial funding rate = %s, want 0", got)
	}
	// Mutating the returned value must not reach into the market.
	got.SetInt64(999)
	if pe.Markets[id].FundingRate.Sign() != 0 {
		t.Fatal("GetFundingRate returned a live reference to the market's rate")
	}
}

// DEFECT (reported): settleFundingForPosition floors the division and then
// negates. Because a long and a short carry opposite-signed sizes, the two
// numerators floor in opposite directions, so a matched pair does not net to
// zero — one unit of value appears per settlement that crosses a Q96 boundary.
func TestZzlPerpFundingSettlementIsNotZeroSum(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	fs := pe.FundingStates[id]

	long, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(500_000), false)
	if err != nil {
		t.Fatalf("open long: %v", err)
	}
	short, err := pe.OpenPosition(zzlOther, id, zzlBig(-1000), zzlBig(500_000), false)
	if err != nil {
		t.Fatalf("open short: %v", err)
	}

	// A funding index that does not divide evenly by Q96 once multiplied by the
	// position size is the case that leaks.
	fs.CumulativeFunding = big.NewInt(1)
	payLong := pe.settleFundingForPosition(long, fs)
	payShort := pe.settleFundingForPosition(short, fs)

	sum := new(big.Int).Add(payLong, payShort)
	if sum.Sign() == 0 {
		t.Fatalf("matched funding netted to zero (long %s, short %s); the floor-then-negate "+
			"asymmetry was fixed — update the reported finding", payLong, payShort)
	}
	if sum.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("matched funding summed to %s, want the known +1", sum)
	}
	// Direction: with a positive cumulative index the long pays and the short
	// receives — the stated convention.
	if payLong.Sign() > 0 {
		t.Fatalf("long funding payment = %s, want <= 0 with a positive index", payLong)
	}
	if payShort.Sign() < 0 {
		t.Fatalf("short funding payment = %s, want >= 0 with a positive index", payShort)
	}
	// Settlement is idempotent: the index snapshot advances so an immediate
	// re-settle pays nothing.
	if long.LastFundingIndex.Cmp(fs.CumulativeFunding) != 0 {
		t.Fatal("the position's funding index was not advanced")
	}
	if again := pe.settleFundingForPosition(long, fs); again.Sign() != 0 {
		t.Fatalf("re-settling with no index movement paid %s, want 0", again)
	}
}

func TestZzlPerpFundingSettlesOnCloseAndFlowsIntoRealizedPnL(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	if _, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(500_000), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	// Move the funding index far enough that the payment dominates the (zero)
	// price PnL, then close: the returned PnL must carry the funding.
	pe.FundingStates[id].CumulativeFunding = new(big.Int).Mul(Q96, big.NewInt(7))
	pnl, err := pe.ClosePosition(zzlOwner, id, zzlBig(1000))
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	// Price has not moved, so the entire PnL is funding: -size*index/Q96.
	want := new(big.Int).Mul(zzlBig(1000), big.NewInt(7))
	want.Neg(want)
	if pnl.Cmp(want) != 0 {
		t.Fatalf("PnL on close = %s, want the funding payment %s", pnl, want)
	}
	if pnl.Sign() >= 0 {
		t.Fatal("a long paid nothing under positive funding")
	}
}

// DEFECT (reported): the increase path of OpenPosition calls
// settleFundingForPosition and DISCARDS its return value. The accrued funding
// is silently dropped instead of being booked, and the position's funding index
// advances so it can never be recovered.
func TestZzlPerpIncreasePathDropsAccruedFunding(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))
	pos, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(500_000), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pe.FundingStates[id].CumulativeFunding = new(big.Int).Mul(Q96, big.NewInt(7))
	owed := new(big.Int).Mul(zzlBig(1000), big.NewInt(7)) // 7000 owed by the long
	marginBefore := new(big.Int).Set(pos.Margin)

	if _, err := pe.OpenPosition(zzlOwner, id, zzlBig(1), zzlBig(1000), false); err != nil {
		t.Fatalf("increase: %v", err)
	}
	// The margin grew by exactly the newly posted amount: the 7000 of accrued
	// funding was neither charged nor credited anywhere.
	if got := new(big.Int).Sub(pos.Margin, marginBefore); got.Cmp(zzlBig(1000)) != 0 {
		t.Fatalf("margin moved by %s, want exactly the posted 1000 — funding is now being "+
			"booked, update the reported finding", got)
	}
	// And the index advanced, so closing now pays nothing for that period.
	if pos.LastFundingIndex.Cmp(pe.FundingStates[id].CumulativeFunding) != 0 {
		t.Fatal("the funding index was not advanced by the increase")
	}
	pnl, err := pe.ClosePosition(zzlOwner, id, new(big.Int).Abs(pos.Size))
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if pnl.Sign() != 0 {
		t.Fatalf("close paid %s; the dropped %s of funding reappeared", pnl, owed)
	}
}

// ---------------------------------------------------------------------------
// views
// ---------------------------------------------------------------------------

func TestZzlPerpGetPositionReturnsADetachedCopy(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))

	if _, err := pe.GetPosition(zzlOwner, id); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner with no positions err = %v, want ErrPositionNotFound", err)
	}
	live, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(100_000), true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pe.GetPosition(zzlOwner, zzlMarket); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPositionNotFound", err)
	}

	got, err := pe.GetPosition(zzlOwner, id)
	if err != nil {
		t.Fatalf("GetPosition: %v", err)
	}
	if got == live {
		t.Fatal("GetPosition returned the live position object")
	}
	if got.Owner != live.Owner || got.Market != live.Market || got.IsIsolated != live.IsIsolated {
		t.Fatal("the copy does not carry the scalar fields")
	}
	// Every big.Int is copied, so mutating the view cannot reach the book.
	got.Size.SetInt64(1)
	got.EntryPrice.SetInt64(1)
	got.Margin.SetInt64(1)
	got.LastFundingIndex.SetInt64(1)
	if live.Size.Cmp(zzlBig(1000)) != 0 || live.Margin.Cmp(zzlBig(100_000)) != 0 {
		t.Fatal("mutating the returned copy changed the live position")
	}
	if live.EntryPrice.Cmp(zzlPx(100)) != 0 {
		t.Fatal("mutating the copy's entry price changed the live position")
	}
}

func TestZzlPerpUnrealizedPnLTracksTheMarkAndBothSides(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 1000, zzlMM(5))

	if _, err := pe.GetUnrealizedPnL(zzlOwner, zzlMarket); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPoolNotFound", err)
	}
	if _, err := pe.GetUnrealizedPnL(zzlOwner, id); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner with no positions err = %v, want ErrPositionNotFound", err)
	}
	if _, err := pe.OpenPosition(zzlOwner, id, zzlBig(1000), zzlBig(500_000), false); err != nil {
		t.Fatalf("open long: %v", err)
	}
	second, err := pe.CreateMarket(zzlQuote, zzlBase, zzlPx(100), 1000, zzlMM(5))
	if err != nil {
		t.Fatalf("CreateMarket: %v", err)
	}
	if _, err := pe.GetUnrealizedPnL(zzlOwner, second); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("owner without this market err = %v, want ErrPositionNotFound", err)
	}
	if _, err := pe.OpenPosition(zzlOther, id, zzlBig(-1000), zzlBig(500_000), false); err != nil {
		t.Fatalf("open short: %v", err)
	}

	// At the entry price both sides show zero.
	for _, who := range []common.Address{zzlOwner, zzlOther} {
		got, err := pe.GetUnrealizedPnL(who, id)
		if err != nil {
			t.Fatalf("GetUnrealizedPnL: %v", err)
		}
		if got.Sign() != 0 {
			t.Fatalf("PnL at entry = %s, want 0", got)
		}
	}
	// A price rise pays the long and costs the short, equally and oppositely.
	if err := pe.UpdateMarkPrice(id, zzlPx(150)); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	l, _ := pe.GetUnrealizedPnL(zzlOwner, id)
	s, _ := pe.GetUnrealizedPnL(zzlOther, id)
	if l.Sign() <= 0 {
		t.Fatalf("long PnL on a rise = %s, want > 0", l)
	}
	if s.Sign() >= 0 {
		t.Fatalf("short PnL on a rise = %s, want < 0", s)
	}
	if new(big.Int).Add(l, s).Sign() != 0 {
		t.Fatalf("long %s and short %s do not net to zero", l, s)
	}
	// And it is exactly size * (mark - entry) / Q96.
	want := new(big.Int).Mul(zzlBig(1000), new(big.Int).Sub(zzlPx(150), zzlPx(100)))
	want.Div(want, Q96)
	if l.Cmp(want) != 0 {
		t.Fatalf("long PnL = %s, want %s", l, want)
	}
}

func TestZzlPerpPriceUpdatesAreCopiedAndScoped(t *testing.T) {
	pe, id := zzlPerpMarket(t, zzlPx(100), 100, zzlMM(5))
	m := pe.Markets[id]

	if err := pe.UpdateMarkPrice(zzlMarket, zzlPx(1)); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("UpdateMarkPrice unknown market err = %v, want ErrPoolNotFound", err)
	}
	if err := pe.UpdateIndexPrice(zzlMarket, zzlPx(1)); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("UpdateIndexPrice unknown market err = %v, want ErrPoolNotFound", err)
	}

	mark := zzlPx(150)
	if err := pe.UpdateMarkPrice(id, mark); err != nil {
		t.Fatalf("UpdateMarkPrice: %v", err)
	}
	if m.MarkPrice.Cmp(zzlPx(150)) != 0 {
		t.Fatalf("mark = %s, want %s", m.MarkPrice, zzlPx(150))
	}
	// Setting the mark leaves the index alone, and vice versa.
	if m.IndexPrice.Cmp(zzlPx(100)) != 0 {
		t.Fatalf("index = %s, want it untouched at %s", m.IndexPrice, zzlPx(100))
	}
	index := zzlPx(160)
	if err := pe.UpdateIndexPrice(id, index); err != nil {
		t.Fatalf("UpdateIndexPrice: %v", err)
	}
	if m.IndexPrice.Cmp(zzlPx(160)) != 0 || m.MarkPrice.Cmp(zzlPx(150)) != 0 {
		t.Fatalf("after setting the index: mark=%s index=%s", m.MarkPrice, m.IndexPrice)
	}
	// Neither aliases the caller's big.Int.
	mark.Set(zzlPx(1))
	index.Set(zzlPx(2))
	if m.MarkPrice.Cmp(zzlPx(150)) != 0 || m.IndexPrice.Cmp(zzlPx(160)) != 0 {
		t.Fatal("a price update aliased its caller's argument")
	}
}
