// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// zzmop_settle9999_test.go covers settle9999.go — THE 0x9999 two-phase money path and
// its pure helpers. The properties under test:
//
//   - EVERY value-path entry refuses malformed input rather than settling something.
//   - A plain swap ALWAYS carries a FINITE reclaim horizon (the fund-lock fix), and the
//     horizon SATURATES rather than wrapping to an already-past deadline.
//   - The V4 price limit converts to the CLOB grid by EXACT integer arithmetic with a
//     pinned rounding DIRECTION (round-to-nearest), never a float.
//   - The analytics keys are deterministic pure functions (no map iteration).

// ---------------------------------------------------------------------------
// SettleSwap — entry refusals
// ---------------------------------------------------------------------------

func TestZzmpSettleSwapRefusesReadOnlyMalformedAndUnwiredHosts(t *testing.T) {
	h := newSettleHarness(t)
	good := h.intentCalldata()

	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorSwap, good, 5_000_000, true); err == nil {
		t.Fatal("read-only swap must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("read-only refusal must charge no gas, got %d", gasLeft)
	}

	// EVERY truncation of a well-formed swap calldata must refuse and never panic.
	for n := 0; n < len(good); n++ {
		n := n
		zzmpNoPanic(t, "swap truncated calldata", func() {
			if _, _, err := zzmpRun(h, h.caller, SelectorSwap, good[:n], 5_000_000, false); err == nil {
				t.Errorf("swap accepted a %d-byte body (needs >= 256)", n)
			}
		})
	}

	// A host with NO cross-chain atomic capability cannot settle: value crosses only as
	// an atomic object, so the seam stays closed rather than crediting locally.
	if _, _, err := h.c.Run(zzmpPlain(h), h.caller, poolManagerAddr9999, prependSelector(SelectorSwap, good), 5_000_000, false); !errors.Is(err, ErrSettleNoAtomicState) {
		t.Fatalf("swap with no AtomicState: want ErrSettleNoAtomicState, got %v", err)
	}
	// An AtomicState whose memory is nil is the same closed seam.
	savedSM := h.state.sm
	h.state.sm = nil
	if _, _, err := zzmpRun(h, h.caller, SelectorSwap, good, 5_000_000, false); !errors.Is(err, ErrSettleNoAtomicState) {
		t.Fatalf("swap with nil atomic memory: want ErrSettleNoAtomicState, got %v", err)
	}
	h.state.sm = savedSM

	// A DELEGATECALL (self != 0x9999) is rejected before any state is touched.
	if _, _, err := h.c.Run(h.state, h.caller, common.HexToAddress("0x000000000000000000000000000000000000dead"),
		prependSelector(SelectorSwap, good), 5_000_000, false); !errors.Is(err, ErrSettleWrongContext) {
		t.Fatalf("delegatecall entry: want ErrSettleWrongContext, got %v", err)
	}
	// An unknown selector is refused.
	if _, _, err := zzmpRun(h, h.caller, 0xDEADBEEF, make([]byte, 64), 5_000_000, false); err == nil {
		t.Fatal("an unknown 0x9999 selector must be refused")
	}
}

func TestZzmpSettleSwapRefusesOutOfGasInBothPhases(t *testing.T) {
	h := newSettleHarness(t)

	// PHASE A floor.
	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorSwap, h.intentCalldata(), GasNativeIntent-1, false); err == nil {
		t.Fatal("phase-A swap under GasNativeIntent must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	// PHASE B floor (the DS01-tagged form).
	settle := h.settlementCalldata(ids.ID{0x01}, 10)
	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorSwap, settle, GasNativeSettlement-1, false); err == nil {
		t.Fatal("phase-B swap under GasNativeSettlement must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
}

// TestZzmpSettleSwapRefusesEveryHaltScopeInBothPhases pins that BOTH phases run the
// ordered halt gate: global, then market, then either asset side.
func TestZzmpSettleSwapRefusesEveryHaltScopeInBothPhases(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(1_000_000)
	poolID := h.key.ID()

	setMarketHalt := func(on bool) {
		t.Helper()
		data := make([]byte, 64)
		copy(data[0:32], poolID[:])
		if on {
			data[63] = 1
		}
		if _, _, err := zzmpRun(h, h.operator(), SelectorSetHaltMarket, data, 5_000_000, false); err != nil {
			t.Fatalf("setHaltMarket: %v", err)
		}
	}

	phases := map[string][]byte{
		"intent":     h.intentCalldata(),
		"settlement": h.settlementCalldata(ids.ID{0x77}, 10),
	}

	for _, sc := range []struct {
		name string
		on   func()
		off  func()
		want error
	}{
		{"global", func() { zzmpSetHaltGlobal(t, h, true) }, func() { zzmpSetHaltGlobal(t, h, false) }, ErrDEXHalted},
		{"market", func() { setMarketHalt(true) }, func() { setMarketHalt(false) }, ErrMarketHalted},
		{"assetIn", func() { zzmpSetHaltAsset(t, h, h.inAssetID(), true) }, func() { zzmpSetHaltAsset(t, h, h.inAssetID(), false) }, ErrAssetHalted},
		{"assetOut", func() { zzmpSetHaltAsset(t, h, h.outAssetID(), true) }, func() { zzmpSetHaltAsset(t, h, h.outAssetID(), false) }, ErrAssetHalted},
	} {
		sc.on()
		for phase, data := range phases {
			if _, _, err := zzmpRun(h, h.caller, SelectorSwap, data, 5_000_000, false); !errors.Is(err, sc.want) {
				t.Fatalf("%s halt in the %s phase: want %v, got %v", sc.name, phase, sc.want, err)
			}
		}
		sc.off()
	}
	// With every halt cleared, a Phase-A intent lands again.
	if _, _, err := zzmpRun(h, h.caller, SelectorSwap, h.intentCalldata(), 5_000_000, false); err != nil {
		t.Fatalf("swap after clearing every halt: %v", err)
	}
}

func TestZzmpSettleSwapRefusesMalformedPhaseBodies(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(1_000_000)

	// A DI01 intent body of an unsupported width is malformed — the swap reverts rather
	// than silently dropping a deadline (which would strand funds with no horizon).
	for _, width := range []int{1, 31, 33, 63, 65, 96} {
		hookData := append(append([]byte{}, intentPhaseTag[:]...), make([]byte, width)...)
		if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, h.params, hookData), 5_000_000, false); !errors.Is(err, ErrIntentBodyMalformed) {
			t.Fatalf("DI01 body of %d bytes: want ErrIntentBodyMalformed, got %v", width, err)
		}
	}
	// A deadline that does not fit uint64 is refused.
	body := make([]byte, 32)
	body[0] = 0xFF
	hookData := append(append([]byte{}, intentPhaseTag[:]...), body...)
	if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, h.params, hookData), 5_000_000, false); !errors.Is(err, ErrIntentBadDeadline) {
		t.Fatalf("out-of-uint64 deadline: want ErrIntentBadDeadline, got %v", err)
	}

	// A DS01 settlement body of ANY width but the fixed one is malformed.
	for _, width := range []int{0, 1, 31, 64, 95, 97, 128} {
		hookData := append(append([]byte{}, settlementPhaseTag[:]...), make([]byte, width)...)
		if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, h.params, hookData), 5_000_000, false); !errors.Is(err, ErrSettleBodyMalformed) {
			t.Fatalf("DS01 body of %d bytes: want ErrSettleBodyMalformed, got %v", width, err)
		}
	}
	// A zero / out-of-uint64 claimed amount is refused before any object is read.
	zero := make([]byte, settlementBodyLen)
	if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, h.params, append(append([]byte{}, settlementPhaseTag[:]...), zero...)), 5_000_000, false); !errors.Is(err, ErrSettleBadAmount) {
		t.Fatalf("zero-amount settlement claim: want ErrSettleBadAmount, got %v", err)
	}
	big68 := make([]byte, settlementBodyLen)
	big68[32] = 0x01 // amount >= 2^248, far past uint64
	if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, h.params, append(append([]byte{}, settlementPhaseTag[:]...), big68...)), 5_000_000, false); !errors.Is(err, ErrSettleBadAmount) {
		t.Fatalf("out-of-uint64 settlement claim: want ErrSettleBadAmount, got %v", err)
	}
}

// TestZzmpSettleSwapRefusesAZeroSizedIntent pins buildIntentRequest's amount gate: a
// swap that names no input locks nothing and creates no intent.
func TestZzmpSettleSwapRefusesAZeroSizedIntent(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(1_000)

	for _, amount := range []*big.Int{nil, big.NewInt(0)} {
		params := h.params
		params.AmountSpecified = amount
		if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, params, EncodeIntentHookData(0, 0)), 5_000_000, false); !errors.Is(err, ErrInvalidAmount) {
			t.Fatalf("zero-sized intent (%v): want ErrInvalidAmount, got %v", amount, err)
		}
	}

	// An exact-input magnitude past uint64 cannot be locked as an integer unit count.
	params := h.params
	params.AmountSpecified = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 70))
	if _, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, params, EncodeIntentHookData(0, 0)), 5_000_000, false); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("out-of-uint64 intent magnitude: want ErrInvalidAmount, got %v", err)
	}
	if got := loadSeamReserve(zzmpDB(h), h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("a refused intent locked %s into the seam reserve", got)
	}
	// buildIntentRequest itself, at the unit level, over the same domain.
	for _, amount := range []*big.Int{nil, big.NewInt(0), new(big.Int).Lsh(big.NewInt(1), 64)} {
		p := h.params
		p.AmountSpecified = amount
		if _, err := buildIntentRequest(h.key, p, h.caller, 0, 0); !errors.Is(err, ErrInvalidAmount) {
			t.Fatalf("buildIntentRequest(%v): want ErrInvalidAmount, got %v", amount, err)
		}
	}
}

// TestZzmpBuildIntentRequestBindsTheSwapDirection proves the request the C->D object is
// derived from carries the taker, the INPUT side of the swap, the exact magnitude and
// the pool — and that reversing the direction reverses the locked asset.
func TestZzmpBuildIntentRequestBindsTheSwapDirection(t *testing.T) {
	h := newSettleHarness(t)

	fwd := h.params
	fwd.AmountSpecified = big.NewInt(-4242)
	req, err := buildIntentRequest(h.key, fwd, h.caller, 999, 7)
	if err != nil {
		t.Fatalf("buildIntentRequest: %v", err)
	}
	if req.Account != h.caller || req.Recipient != h.caller {
		t.Fatalf("intent must bind the caller as both taker and recipient, got %s/%s", req.Account.Hex(), req.Recipient.Hex())
	}
	if req.AssetIn != h.inAssetID() {
		t.Fatal("zeroForOne must lock currency0")
	}
	if req.AssetInAddr != h.key.Currency0.Address {
		t.Fatalf("AssetInAddr must be the input token, got %s", req.AssetInAddr.Hex())
	}
	if req.AmountIn != 4242 {
		t.Fatalf("AmountIn: want the exact-input magnitude 4242, got %d", req.AmountIn)
	}
	if req.MarketID != h.key.ID() || req.Deadline != 999 || req.Nonce != 7 {
		t.Fatalf("intent routing fields not bound: %+v", req)
	}
	if req.MinAmountOut.Sign() != 0 {
		t.Fatalf("exact-input names no output floor, got %s", req.MinAmountOut)
	}

	rev := h.params
	rev.ZeroForOne = false
	rev.AmountSpecified = big.NewInt(-4242)
	rrev, err := buildIntentRequest(h.key, rev, h.caller, 0, 0)
	if err != nil {
		t.Fatalf("buildIntentRequest (reverse): %v", err)
	}
	if rrev.AssetIn != h.outAssetID() {
		t.Fatal("!zeroForOne must lock currency1")
	}
	if rrev.AssetIn == req.AssetIn {
		t.Fatal("the two swap directions must lock DIFFERENT assets")
	}

	// Exact-OUTPUT (a positive amountSpecified) names the slippage floor.
	exactOut := h.params
	exactOut.AmountSpecified = big.NewInt(555)
	req3, err := buildIntentRequest(h.key, exactOut, h.caller, 0, 0)
	if err != nil {
		t.Fatalf("buildIntentRequest (exact output): %v", err)
	}
	if req3.MinAmountOut.Int64() != 555 {
		t.Fatalf("exact-output MinAmountOut: want 555, got %s", req3.MinAmountOut)
	}
	if req3.AmountIn != 555 {
		t.Fatalf("exact-output locks the named magnitude, got %d", req3.AmountIn)
	}
	// minAmountOut is a COPY, never an alias into the caller's params.
	req3.MinAmountOut.SetInt64(1)
	if exactOut.AmountSpecified.Int64() != 555 {
		t.Fatal("minAmountOut aliased the caller's AmountSpecified")
	}
}

// ---------------------------------------------------------------------------
// defaultedReclaimDeadline — the fund-lock fix
// ---------------------------------------------------------------------------

// TestZzmpDefaultedReclaimDeadlineIsFiniteAndSaturates pins the horizon: it is always
// STRICTLY in the future of the block time, and near the uint64 ceiling it SATURATES
// rather than wrapping to a small (already-past) value.
func TestZzmpDefaultedReclaimDeadlineIsFiniteAndSaturates(t *testing.T) {
	for _, now := range []uint64{0, 1, harnessBlockTime, math.MaxUint64 - maxIntentTTL} {
		got := defaultedReclaimDeadline(now)
		if got != now+maxIntentTTL {
			t.Fatalf("defaultedReclaimDeadline(%d) = %d, want %d", now, got, now+maxIntentTTL)
		}
		if got <= now {
			t.Fatalf("defaultedReclaimDeadline(%d) = %d is not in the future", now, got)
		}
	}
	for _, now := range []uint64{math.MaxUint64 - maxIntentTTL + 1, math.MaxUint64 - 1, math.MaxUint64} {
		got := defaultedReclaimDeadline(now)
		if got != math.MaxUint64 {
			t.Fatalf("defaultedReclaimDeadline(%d) = %d — it must SATURATE at MaxUint64, never wrap", now, got)
		}
		if got < now {
			t.Fatalf("defaultedReclaimDeadline(%d) wrapped to %d (an already-past deadline)", now, got)
		}
	}
}

// TestZzmpPlainSwapAlwaysCarriesAFiniteReclaimHorizon is the fund-lock invariant end to
// end: a plain (untagged) swap and a DI01 body with deadline 0 BOTH persist a finite,
// future deadline, so the principal can always be reclaimed. An explicit deadline is
// honoured as-is.
func TestZzmpPlainSwapAlwaysCarriesAFiniteReclaimHorizon(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hookData []byte
		want     uint64
	}{
		{"plain untagged swap", nil, defaultedReclaimDeadline(harnessBlockTime)},
		{"opaque hook bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}, defaultedReclaimDeadline(harnessBlockTime)},
		{"DI01 with deadline 0", EncodeIntentHookData(0, 0), defaultedReclaimDeadline(harnessBlockTime)},
		{"DI01 with an explicit deadline", EncodeIntentHookData(harnessBlockTime+60, 0), harnessBlockTime + 60},
	} {
		h := newSettleHarness(t)
		h.fundCallerNative(500)
		params := h.params
		params.AmountSpecified = big.NewInt(-500)
		out, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, params, tc.hookData), 5_000_000, false)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var id ids.ID
		copy(id[:], out)
		rec := loadSwapIntentRecord(zzmpDB(h), id)
		if rec.Status != swapIntentOpen {
			t.Fatalf("%s: intent not open", tc.name)
		}
		if rec.Deadline != tc.want {
			t.Fatalf("%s: deadline = %d, want %d", tc.name, rec.Deadline, tc.want)
		}
		if rec.Deadline == 0 {
			t.Fatalf("%s: a zero deadline permanently strands the principal", tc.name)
		}
		if rec.Remaining != 500 || rec.Owner != h.caller {
			t.Fatalf("%s: escrow record not bound: %+v", tc.name, rec)
		}
	}
}

// ---------------------------------------------------------------------------
// priceLimitToCLOB — exact integers, pinned rounding direction
// ---------------------------------------------------------------------------

// TestZzmpPriceLimitToCLOBRoundsToNearestExactly pins the conversion AND its rounding
// direction against an independent big.Int reference. Round-to-NEAREST (not floor) is
// load-bearing: the client's sqrtPriceLimitX96 is a floored sqrt, so flooring the grid
// value would quantize a "50" limit to 49.99999999 and fail to cross a maker resting AT
// 50.
func TestZzmpPriceLimitToCLOBRoundsToNearestExactly(t *testing.T) {
	// reference = round(s^2 * priceScale / 2^192), computed independently.
	reference := func(s *big.Int) *big.Int {
		num := new(big.Int).Mul(s, s)
		num.Mul(num, big.NewInt(priceScale))
		den := new(big.Int).Lsh(big.NewInt(1), 192)
		q, r := new(big.Int).QuoRem(num, den, new(big.Int))
		if new(big.Int).Lsh(r, 1).Cmp(den) >= 0 {
			q.Add(q, big.NewInt(1))
		}
		return q
	}

	for _, mult := range []int64{1, 2, 3, 7, 10, 1000} {
		s := new(big.Int).Mul(Q96, big.NewInt(mult)) // price = mult^2
		units, isUpper := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: s})
		want := reference(s)
		if !want.IsUint64() {
			continue
		}
		if units != want.Uint64() {
			t.Fatalf("priceLimitToCLOB(s=%s) = %d, want the exact grid value %s", s, units, want)
		}
		if isUpper {
			t.Fatal("zeroForOne (a SELL) bounds a price FLOOR, so limitIsUpper must be false")
		}
		// price = mult^2 exactly, so the grid value is mult^2 * priceScale.
		if want.Uint64() != uint64(mult*mult)*priceScale {
			t.Fatalf("grid value for price %d: got %s", mult*mult, want)
		}
	}

	// A FLOORED sqrt must still quantize UP to the intended grid price — the whole point
	// of round-to-nearest. Take the exact sqrt for price 50 and floor it.
	fifty := new(big.Int).Mul(big.NewInt(50), new(big.Int).Lsh(big.NewInt(1), 192))
	sFloor := new(big.Int).Sqrt(fifty) // floor(sqrt(50) * 2^96)
	units, _ := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: sFloor})
	if units != 50*priceScale {
		t.Fatalf("a floored sqrt of price 50 quantized to %d, want %d — flooring here misses a maker resting AT 50", units, uint64(50)*priceScale)
	}

	// Direction: !zeroForOne (a BUY) bounds a CEILING.
	if _, isUpper := priceLimitToCLOB(SwapParams{ZeroForOne: false, SqrtPriceLimitX96: new(big.Int).Mul(Q96, big.NewInt(2))}); !isUpper {
		t.Fatal("!zeroForOne (a BUY) bounds a price CEILING, so limitIsUpper must be true")
	}
}

// TestZzmpPriceLimitToCLOBTreatsSentinelsAsUnbounded pins the "no limit" cases: unset,
// zero/negative, the two V4 sentinels, and a value whose grid projection is degenerate
// or out of uint64 range all yield 0 (unbounded), with the side flag still correct.
func TestZzmpPriceLimitToCLOBTreatsSentinelsAsUnbounded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		zeroForOne bool
		s          *big.Int
	}{
		{"unset", true, nil},
		{"zero", true, big.NewInt(0)},
		{"negative", true, big.NewInt(-1)},
		{"sell at MinSqrtRatio", true, new(big.Int).Set(MinSqrtRatio)},
		{"sell below MinSqrtRatio", true, big.NewInt(1)},
		{"buy at MaxSqrtRatio", false, new(big.Int).Set(MaxSqrtRatio)},
		{"buy above MaxSqrtRatio", false, new(big.Int).Add(MaxSqrtRatio, big.NewInt(1))},
		{"sell so small the grid rounds to 0", true, big.NewInt(4295128740)},
		{"sell so large the grid leaves uint64", true, new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1))},
	} {
		units, isUpper := priceLimitToCLOB(SwapParams{ZeroForOne: tc.zeroForOne, SqrtPriceLimitX96: tc.s})
		if units != 0 {
			t.Fatalf("%s: want 0 (unbounded), got %d", tc.name, units)
		}
		if isUpper == tc.zeroForOne {
			t.Fatalf("%s: limitIsUpper must be !zeroForOne even when unbounded", tc.name)
		}
	}
	// A limit just INSIDE the sell sentinel is honoured, so the sentinel is a boundary,
	// not a blanket disable.
	inside := new(big.Int).Mul(Q96, big.NewInt(3))
	if units, _ := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: inside}); units == 0 {
		t.Fatal("a real in-range sell limit must NOT be treated as unbounded")
	}
}

// TestZzmpPriceLimitToCLOBIsDeterministic runs the conversion many times over the same
// input and demands byte-identical output — the value is consensus-critical.
func TestZzmpPriceLimitToCLOBIsDeterministic(t *testing.T) {
	s := new(big.Int).Mul(Q96, big.NewInt(1234))
	first, firstUpper := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: s})
	for i := 0; i < 256; i++ {
		got, upper := priceLimitToCLOB(SwapParams{ZeroForOne: true, SqrtPriceLimitX96: new(big.Int).Set(s)})
		if got != first || upper != firstUpper {
			t.Fatalf("priceLimitToCLOB is not deterministic: %d/%v then %d/%v", first, firstUpper, got, upper)
		}
	}
}

// ---------------------------------------------------------------------------
// pure helpers: balanceDeltaForOutput / minAmountOut / swapAssetDirection / isWord
// ---------------------------------------------------------------------------

func TestZzmpBalanceDeltaForOutputSignsTheOutputSide(t *testing.T) {
	amt := big.NewInt(1_000)

	fwd := balanceDeltaForOutput(SwapParams{ZeroForOne: true}, amt)
	if fwd.Amount0.Sign() != 0 || fwd.Amount1.Cmp(big.NewInt(-1_000)) != 0 {
		t.Fatalf("zeroForOne credits token1: got (%s, %s)", fwd.Amount0, fwd.Amount1)
	}
	rev := balanceDeltaForOutput(SwapParams{ZeroForOne: false}, amt)
	if rev.Amount1.Sign() != 0 || rev.Amount0.Cmp(big.NewInt(-1_000)) != 0 {
		t.Fatalf("!zeroForOne credits token0: got (%s, %s)", rev.Amount0, rev.Amount1)
	}
	// The two directions are mirror images and the input amount is never mutated.
	if amt.Int64() != 1_000 {
		t.Fatal("balanceDeltaForOutput mutated its input")
	}
	if fwd.Amount1.Cmp(rev.Amount0) != 0 || fwd.Amount0.Cmp(rev.Amount1) != 0 {
		t.Fatal("the two directions are not mirror images")
	}
	// A zero credit is a zero delta on both sides (never a phantom sign).
	z := balanceDeltaForOutput(SwapParams{ZeroForOne: true}, big.NewInt(0))
	if z.Amount0.Sign() != 0 || z.Amount1.Sign() != 0 {
		t.Fatalf("zero credit produced (%s, %s)", z.Amount0, z.Amount1)
	}
}

func TestZzmpMinAmountOutOnlyHonoursExactOutput(t *testing.T) {
	if got := minAmountOut(SwapParams{AmountSpecified: nil}); got.Sign() != 0 {
		t.Fatalf("nil amountSpecified: want 0, got %s", got)
	}
	if got := minAmountOut(SwapParams{AmountSpecified: big.NewInt(0)}); got.Sign() != 0 {
		t.Fatalf("zero amountSpecified: want 0, got %s", got)
	}
	if got := minAmountOut(SwapParams{AmountSpecified: big.NewInt(-500)}); got.Sign() != 0 {
		t.Fatalf("exact-INPUT names no floor: want 0, got %s", got)
	}
	src := big.NewInt(750)
	got := minAmountOut(SwapParams{AmountSpecified: src})
	if got.Int64() != 750 {
		t.Fatalf("exact-OUTPUT floor: want 750, got %s", got)
	}
	got.SetInt64(1)
	if src.Int64() != 750 {
		t.Fatal("minAmountOut returned an alias into the caller's params")
	}
}

func TestZzmpSwapAssetDirectionAndAssetAddressAreInverse(t *testing.T) {
	h := newSettleHarness(t)

	in, out := swapAssetDirection(h.key, SwapParams{ZeroForOne: true})
	if in != assetID(h.key.Currency0) || out != assetID(h.key.Currency1) {
		t.Fatal("zeroForOne: in must be currency0 and out currency1")
	}
	rin, rout := swapAssetDirection(h.key, SwapParams{ZeroForOne: false})
	if rin != out || rout != in {
		t.Fatal("reversing the direction must swap the two asset ids")
	}

	// assetAddress is the injective inverse of assetID over the EVM address domain —
	// this is what makes the FIX-5 credit-token derivation sound.
	for _, addr := range []common.Address{
		{},
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		h.key.Currency1.Address,
		common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
	} {
		id := assetID(Currency{Address: addr})
		if got := assetAddress(id); got != addr {
			t.Fatalf("assetAddress(assetID(%s)) = %s", addr.Hex(), got.Hex())
		}
		if isNativeAsset(id) != (addr == common.Address{}) {
			t.Fatalf("isNativeAsset misclassified %s", addr.Hex())
		}
	}
}

func TestZzmpIsWordBoundsTheUint256Domain(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), max} {
		if !isWord(v) {
			t.Fatalf("isWord(%s) must be true", v)
		}
	}
	for _, v := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Add(max, big.NewInt(1))} {
		if isWord(v) {
			t.Fatalf("isWord(%v) must be false", v)
		}
	}
}

// TestZzmpStateDBERC20ResolvesTheVaultCapability covers both arms: the production
// adapter IS a complete vault, and a StateDB with no vault capability is refused.
func TestZzmpStateDBERC20ResolvesTheVaultCapability(t *testing.T) {
	h := newSettleHarness(t)
	if v, ok := stateDBERC20(zzmpDB(h)); !ok || v == nil {
		t.Fatal("the poolStateAdapter must resolve as a complete erc20Vault")
	}
	if v, ok := stateDBERC20(NewMockStateDB()); ok || v != nil {
		t.Fatal("a StateDB with no vault capability must NOT resolve")
	}
	// A StateDB that implements erc20Vault DIRECTLY resolves through the non-adapter arm.
	if v, ok := stateDBERC20(zzmpNewVaultDB()); !ok || v == nil {
		t.Fatal("a StateDB that directly implements erc20Vault must resolve")
	}
}

// ---------------------------------------------------------------------------
// sharded analytics keys — deterministic, no map iteration
// ---------------------------------------------------------------------------

// TestZzmpAnalyticsBucketKeysAreDeterministicAndSharded pins that the fee/volume keys
// are pure functions of (id, epoch) — a key that depended on Go map order would fork
// consensus — and that they shard by epoch modulo the shard count.
func TestZzmpAnalyticsBucketKeysAreDeterministicAndSharded(t *testing.T) {
	assetA := [32]byte{0x01}
	assetB := [32]byte{0x02}

	for i := 0; i < 64; i++ {
		if got := feeBucketKey(assetA, 5); got != feeBucketKey(assetA, 5) {
			t.Fatal("feeBucketKey is not deterministic")
		}
		if got := volBucketKey(assetA, 5); got != volBucketKey(assetA, 5) {
			t.Fatal("volBucketKey is not deterministic")
		}
	}
	// Distinct assets, distinct keys; and the two namespaces never collide.
	if feeBucketKey(assetA, 1) == feeBucketKey(assetB, 1) {
		t.Fatal("feeBucketKey collides across assets")
	}
	if feeBucketKey(assetA, 1) == volBucketKey(assetA, 1) {
		t.Fatal("the fee and volume namespaces collide")
	}
	// Epoch shards wrap modulo the shard count, so epoch and epoch+shards share a slot
	// while adjacent epochs do not.
	if feeBucketKey(assetA, 3) != feeBucketKey(assetA, 3+feeShards) {
		t.Fatal("feeBucketKey does not shard modulo feeShards")
	}
	if feeBucketKey(assetA, 3) == feeBucketKey(assetA, 4) {
		t.Fatal("adjacent epochs must land in different fee shards")
	}
	if volBucketKey(assetA, 3) != volBucketKey(assetA, 3+volShards) {
		t.Fatal("volBucketKey does not shard modulo volShards")
	}
}

// TestZzmpAccrueVolumeAccumulatesAndIgnoresNonPositive pins the analytics accumulator:
// it sums into its shard and treats a nil / zero / negative amount as nothing to record
// (never a negative slot).
func TestZzmpAccrueVolumeAccumulatesAndIgnoresNonPositive(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	poolID := h.key.ID()

	read := func(epoch uint64) *big.Int {
		return new(big.Int).SetBytes(db.GetState(poolManagerAddr9999, volBucketKey(poolID, epoch)).Bytes())
	}

	for _, skip := range []*big.Int{nil, big.NewInt(0), big.NewInt(-5)} {
		accrueVolume(db, poolID, skip, 1)
		if read(1).Sign() != 0 {
			t.Fatalf("accrueVolume recorded a non-positive amount %v", skip)
		}
	}
	accrueVolume(db, poolID, big.NewInt(100), 1)
	accrueVolume(db, poolID, big.NewInt(250), 1)
	if got := read(1); got.Int64() != 350 {
		t.Fatalf("accrueVolume must accumulate: want 350, got %s", got)
	}
	// A different epoch lands in a different shard and does not disturb this one.
	accrueVolume(db, poolID, big.NewInt(7), 2)
	if got := read(1); got.Int64() != 350 {
		t.Fatalf("a neighbouring epoch disturbed the shard: %s", got)
	}
	if got := read(2); got.Int64() != 7 {
		t.Fatalf("epoch 2 shard: want 7, got %s", got)
	}
}

func TestZzmpPutU64IsBigEndianAndTotal(t *testing.T) {
	for _, v := range []uint64{0, 1, 255, 256, 1 << 32, math.MaxUint64} {
		var b [8]byte
		putU64(b[:], v)
		if got := new(big.Int).SetBytes(b[:]).Uint64(); got != v {
			t.Fatalf("putU64(%d) round-tripped to %d", v, got)
		}
	}
	var b [8]byte
	putU64(b[:], 0x0102030405060708)
	if b[0] != 0x01 || b[7] != 0x08 {
		t.Fatalf("putU64 is not big-endian: %x", b)
	}
	// Writing again fully overwrites — no residue from the previous value.
	putU64(b[:], 0)
	for i, x := range b {
		if x != 0 {
			t.Fatalf("putU64 left residue at byte %d: %x", i, b)
		}
	}
}

// ---------------------------------------------------------------------------
// reclaimIntent entry
// ---------------------------------------------------------------------------

func TestZzmpReclaimIntentEntryRefusals(t *testing.T) {
	h := newSettleHarness(t)
	id := ids.ID{0x2A}

	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, true); err == nil {
		t.Fatal("read-only reclaimIntent must be refused")
	} else if gasLeft != 5_000_000 {
		t.Fatalf("read-only refusal must charge no gas, got %d", gasLeft)
	}
	if _, gasLeft, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), GasNativeSettlement-1, false); err == nil {
		t.Fatal("reclaimIntent under GasNativeSettlement must be refused")
	} else if gasLeft != 0 {
		t.Fatalf("out-of-gas refusal must consume the supply, got %d", gasLeft)
	}
	for n := 0; n < 32; n++ {
		n := n
		zzmpNoPanic(t, "reclaimIntent truncated body", func() {
			if _, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, make([]byte, n), 5_000_000, false); !errors.Is(err, ErrReclaimBadInput) {
				t.Errorf("reclaimIntent with a %d-byte body: want ErrReclaimBadInput, got %v", n, err)
			}
		})
	}
	// No AtomicState => the seam is closed, so there is nothing to reclaim through.
	if _, _, err := h.c.Run(zzmpPlain(h), h.caller, poolManagerAddr9999, prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(id)), 5_000_000, false); !errors.Is(err, ErrSettleNoAtomicState) {
		t.Fatalf("reclaimIntent with no AtomicState: want ErrSettleNoAtomicState, got %v", err)
	}
	savedSM := h.state.sm
	h.state.sm = nil
	if _, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, false); !errors.Is(err, ErrSettleNoAtomicState) {
		t.Fatalf("reclaimIntent with nil atomic memory: want ErrSettleNoAtomicState, got %v", err)
	}
	h.state.sm = savedSM

	// Reentrancy is refused on this entrypoint too (the refund moves value).
	zzmpDB(h).SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{31: 1})
	if _, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, false); !errors.Is(err, ErrCustodyReentrant) {
		t.Fatalf("re-entered reclaimIntent: want ErrCustodyReentrant, got %v", err)
	}
	// EncodeReclaimIntentInput is exactly one word and round-trips the id.
	enc := EncodeReclaimIntentInput(id)
	if len(enc) != 32 || ids.ID(enc[:32]) != id {
		t.Fatalf("EncodeReclaimIntentInput does not round-trip: %x", enc)
	}
}

// TestZzmpReclaimIntentRefundsExactlyOnce drives the whole liveness path end to end: a
// stranded intent's principal comes back to the LOCKER after the deadline, exactly once,
// and a second reclaim is refused — reclaim and a late settlement can never both pay out.
func TestZzmpReclaimIntentRefundsExactlyOnce(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(1_000)

	params := h.params
	params.AmountSpecified = big.NewInt(-1_000)
	out, _, err := zzmpRun(h, h.caller, SelectorSwap, buildSwapCalldata(h.key, params, EncodeIntentHookData(harnessBlockTime+10, 0)), 5_000_000, false)
	if err != nil {
		t.Fatalf("phase-A intent: %v", err)
	}
	var id ids.ID
	copy(id[:], out)

	db := zzmpDB(h)
	if got := loadSeamReserve(db, h.inAssetID()); got.Int64() != 1_000 {
		t.Fatalf("the lock must credit seamReserve: want 1000, got %s", got)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != 0 {
		t.Fatalf("the taker's principal must have LEFT their balance, got %d", got)
	}

	// Before the deadline the principal stays locked (a settlement may still land).
	if _, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, false); !errors.Is(err, ErrReclaimBeforeDeadline) {
		t.Fatalf("reclaim before the deadline: want ErrReclaimBeforeDeadline, got %v", err)
	}
	// A stranger can never reclaim someone else's principal.
	h.state.blockTimestamp = harnessBlockTime + 11
	if _, _, err := zzmpRun(h, common.HexToAddress("0x00000000000000000000000000000000000000AA"), SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, false); !errors.Is(err, ErrReclaimNotOwner) {
		t.Fatalf("reclaim by a stranger: want ErrReclaimNotOwner, got %v", err)
	}
	// An intent id that names nothing at all refuses too.
	if _, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(ids.ID{0xFE}), 5_000_000, false); !errors.Is(err, ErrReclaimNoIntent) {
		t.Fatalf("reclaim of an unknown intent: want ErrReclaimNoIntent, got %v", err)
	}

	refunded, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, false)
	if err != nil {
		t.Fatalf("reclaim after the deadline: %v", err)
	}
	if got := new(big.Int).SetBytes(refunded).Int64(); got != 1_000 {
		t.Fatalf("reclaim refunded %d, want the full 1000", got)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != 1_000 {
		t.Fatalf("the locker's balance after reclaim: want 1000, got %d", got)
	}
	if got := loadSeamReserve(db, h.inAssetID()); got.Sign() != 0 {
		t.Fatalf("seamReserve after reclaim: want 0, got %s", got)
	}

	// EXACTLY ONCE: a second reclaim pays nothing.
	if _, _, err := zzmpRun(h, h.caller, SelectorReclaimIntent, EncodeReclaimIntentInput(id), 5_000_000, false); !errors.Is(err, ErrReclaimNoIntent) {
		t.Fatalf("second reclaim: want ErrReclaimNoIntent, got %v", err)
	}
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != 1_000 {
		t.Fatalf("a second reclaim paid out again: %d", got)
	}
}
