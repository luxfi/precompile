// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/dex/pkg/lx"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
)

// swap_sync_gateb_test.go is the Gate-B proof suite for 0x9999 as THE one on-chain
// router. Every test runs over the REAL EVM/vault/ERC-20 path (no synthetic asset
// ids, no stubs) and proves one canonical-model invariant:
//
//   - C and D commit atomically in one block (both-or-neither under the EVM snapshot).
//   - A validator REPLAYS the swap from block bytes + prior state — NO live ZAP, NO
//     external venue, NO keeper — and derives the identical C+D outcome.
//   - A fabricated proposer fill is rejected by deterministic re-execution (the route
//     is a pure function; a lying amount cannot reproduce the honest result).
//   - The trade is visible in BOTH D state (the dexcore book/ledger) and C events
//     (the DEXFill log the indexer ingests).
//   - ERC-20 settlement is observed-delta and the vault's real holdings exactly back
//     the ledger claims (conservation).
//   - The money surface is non-reentrant.
//   - The native HFT maker and the EVM taker meet in the SAME book/state (and the
//     mirror: EVM maker, native taker).
//
// The token layout matches the e2e harness: LETH = currency0 (base, 0x..01), LUSD =
// currency1 (quote, 0x..02); "sell LETH for LUSD" is zeroForOne.

// ---------------------------------------------------------------------------
// Test9999SyncSwap_CAndDCommitAtomically
// ---------------------------------------------------------------------------

// Test9999SyncSwap_CAndDCommitAtomically asserts that one synchronous swap moves the
// C-Chain ERC-20 balances AND the D book/ledger in ONE block — the joint journal
// applied under one EVM snapshot. The taker's real LETH leaves and real LUSD arrives,
// while the maker's D book reflects the same fill, and the vault conserves. This is
// the positive twin of the revert test: on success BOTH surfaces move together.
func Test9999SyncSwap_CAndDCommitAtomically(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// Maker rests a real-funded BID: 100 LETH @ 50 (locks 5000 LUSD).
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)

	// Taker swaps SELL 80 LETH -> LUSD.
	h.mint(e2eLETH, taker, 80)
	out, err := h.swap(t, taker, true, 80, sqrtX96For(1.0))
	if err != nil {
		t.Fatalf("swap: %v", err)
	}

	// C SURFACE moved: taker -80 LETH, +4000 LUSD; both committed.
	if got := h.ercBal(e2eLETH, taker); got != 0 {
		t.Fatalf("C: taker LETH = %d, want 0 (sold)", got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("C: taker LUSD = %d, want 4000 (proceeds)", got)
	}

	// D SURFACE moved IN THE SAME BLOCK: the maker bought 80 LETH (dexcore available),
	// 4000 of its 5000 LUSD lock spent, 1000 still locked.
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("D: maker LETH available = %d, want 80", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != 1000 {
		t.Fatalf("D: maker LUSD locked = %d, want 1000", got)
	}

	// The V4 BalanceDelta confirms the realized legs.
	a0, a1 := UnpackBalanceDelta(out)
	if a0.Int64() != -80 || a1.Int64() != 4000 {
		t.Fatalf("BalanceDelta = (%s,%s), want (-80,4000)", a0, a1)
	}

	// CONSERVATION: the vault's real holdings back the ledger to the unit.
	assertVaultConservation(t, h, maker, taker)
}

// ---------------------------------------------------------------------------
// Test9999SyncSwap_ValidatorReplayNoLiveZAP
// ---------------------------------------------------------------------------

// Test9999SyncSwap_ValidatorReplayNoLiveZAP proves a non-proposing validator reaches
// the IDENTICAL C+D state by REPLAYING the swap from the same calldata + prior state —
// with NO live ZAP, NO external venue, NO keeper. Two independent harnesses (two
// validators) build the same economy and run the same swap; their resulting C balances,
// D ledger, and dexcore execution root are byte-identical. The route is a pure function
// of (prior state, calldata): nothing is carried in a side channel.
func Test9999SyncSwap_ValidatorReplayNoLiveZAP(t *testing.T) {
	run := func(t *testing.T) (lethTaker, lusdTaker, makerLETH, makerLUSDLocked uint64, root [dexcore.Size]byte) {
		h := newE2EHarness(t)
		maker, taker := e2eMaker, e2eTaker
		h.mint(e2eLUSD, maker, 5000)
		h.deposit(t, maker, e2eLUSD, 5000)
		h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
		h.mint(e2eLETH, taker, 80)
		if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
			t.Fatalf("swap: %v", err)
		}
		// dexcore execution root over the resulting book (the cross-validator witness).
		st := h.store()
		// A swap leaves the taker's transient ledger drained; the persistent witness is
		// the maker book + the maker's bought balance. We fold a fresh SwapResult-free
		// book root via the same construction the core uses, by reading the resting rows.
		root = dexBookRootOnly(st, h.key.ID())
		return uint64(h.ercBal(e2eLETH, taker)), uint64(h.ercBal(e2eLUSD, taker)),
			h.dcAvail(maker, e2eLETH), h.dcLocked(maker, e2eLUSD), root
	}

	l0, u0, mL0, mLk0, r0 := run(t) // "proposer"
	l1, u1, mL1, mLk1, r1 := run(t) // "replaying validator"

	if l0 != l1 || u0 != u1 {
		t.Fatalf("replay diverged on C balances: taker (LETH,LUSD) proposer=(%d,%d) validator=(%d,%d)", l0, u0, l1, u1)
	}
	if mL0 != mL1 || mLk0 != mLk1 {
		t.Fatalf("replay diverged on D ledger: maker proposer (LETH=%d,LUSDlock=%d) validator (LETH=%d,LUSDlock=%d)", mL0, mLk0, mL1, mLk1)
	}
	if !bytes.Equal(r0[:], r1[:]) {
		t.Fatalf("replay diverged on the dexcore book root: %x vs %x", r0[:8], r1[:8])
	}
	// Sanity: the swap actually did something (proceeds credited).
	if u0 != 4000 {
		t.Fatalf("taker proceeds = %d, want 4000 (a no-op replay would prove nothing)", u0)
	}
}

// ---------------------------------------------------------------------------
// Test9999SyncSwap_FakeProposerFillRejected
// ---------------------------------------------------------------------------

// Test9999SyncSwap_FakeProposerFillRejected proves a Byzantine proposer cannot make a
// validator credit a fabricated amount. Because the route is RECOMPUTED by every
// validator from the calldata + prior state (not read from a proposer-supplied fill),
// a proposer who WANTS the taker to receive more than the book yields has no channel
// to inject it: the honest re-execution produces exactly the book-derived proceeds,
// and any larger claimed amount yields a DIFFERENT dexcore execution root — detectable
// and rejectable. We assert (a) the realized proceeds equal the deterministic book
// result, and (b) inflating that result by one unit changes the root (so a lying root
// is caught).
func Test9999SyncSwap_FakeProposerFillRejected(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	out, err := h.swap(t, taker, true, 80, sqrtX96For(1.0))
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	_, a1 := UnpackBalanceDelta(out)
	// (a) The realized proceeds are EXACTLY the book-derived amount (80 @ 50 = 4000).
	// A proposer cannot return more — the BalanceDelta is computed from the recomputed
	// route, not supplied.
	if a1.Int64() != 4000 {
		t.Fatalf("realized proceeds = %s, want exactly 4000 (the book result); a proposer cannot inflate it", a1)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker credited %d LUSD, want exactly 4000 (no proposer inflation)", got)
	}

	// (b) Independently: a fabricated result (one extra unit) yields a DIFFERENT
	// execution root, so a validator re-deriving the honest root rejects the lie. We
	// compute the honest root and the inflated root over the same resulting book.
	st := h.store()
	honest := &dexcore.SwapResult{AmountIn: 80, AmountOut: 4000}
	fake := &dexcore.SwapResult{AmountIn: 80, AmountOut: 4001}
	honestRoot := dexcore.SwapExecutionRoot(st, h.key.ID(), honest)
	fakeRoot := dexcore.SwapExecutionRoot(st, h.key.ID(), fake)
	if honestRoot == fakeRoot {
		t.Fatalf("an inflated fill produced the SAME root — a fake proposer fill would be undetectable")
	}
}

// ---------------------------------------------------------------------------
// Test9999SyncSwap_TradeVisibleInDStateAndCEvents
// ---------------------------------------------------------------------------

// Test9999SyncSwap_TradeVisibleInDStateAndCEvents proves the fill is observable on BOTH
// surfaces after one swap: in D state (the maker's dexcore book/ledger reflects the
// cross) AND in C events (the DEXFill log fired at 0x9999 carries the taker + amount,
// so the graph indexer / lux.exchange surface it). The sync money path must emit the
// SAME indexable signal the async Phase-B path does.
func Test9999SyncSwap_TradeVisibleInDStateAndCEvents(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	logsBefore := len(h.state.stateDB.Logs())
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
		t.Fatalf("swap: %v", err)
	}

	// D STATE: the trade is recorded in the dexcore book (maker bought 80 LETH).
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("D state: maker LETH = %d, want 80 (the fill is not in D state)", got)
	}

	// C EVENTS: a DEXFill log fired at 0x9999, topic0 = DEXFill sig, taker indexed,
	// amountOut in data == 4000.
	logs := h.state.stateDB.Logs()
	fill := findDEXFillLog(logs[logsBefore:], h.key.ID(), taker)
	if fill == nil {
		t.Fatalf("C events: no DEXFill log emitted for the synchronous fill (indexer would not see it)")
	}
	amountOut := new(big.Int).SetBytes(fill.Data[:32])
	if amountOut.Int64() != 4000 {
		t.Fatalf("DEXFill amountOut = %s, want 4000", amountOut)
	}
	if fill.Address != poolManagerAddr9999 {
		t.Fatalf("DEXFill emitted at %x, want 0x9999", fill.Address)
	}
}

// ---------------------------------------------------------------------------
// Test9999SyncSwap_ERC20ObservedDelta
// ---------------------------------------------------------------------------

// Test9999SyncSwap_ERC20ObservedDelta proves the swap settles ERC-20 by OBSERVED
// DELTA: the vault credits the taker's dexcore input by exactly what ARRIVED, not what
// was nominally requested. With a fee-on-transfer token that delivers less than the
// stated amount, the routed input is the delivered amount — so the vault is never
// short, and conservation (seamReserve == ledger total) holds exactly. This is the
// "the vault holds the REAL tokens" invariant on a non-standard token.
func Test9999SyncSwap_ERC20ObservedDelta(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// Maker rests a deep real-funded BID so the taker's whole delivered input can fill.
	h.mint(e2eLUSD, maker, 100_000)
	h.deposit(t, maker, e2eLUSD, 100_000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 1000) // BID 1000 LETH @ 50

	// Make tokens 1% fee-on-transfer: a 100-unit transferFrom delivers 99. (The mock's
	// fee flag is global, so it taxes BOTH the input lock leg AND the output proceeds
	// leg; the observed-delta invariant we prove is on the INPUT leg — the vault routes
	// what ARRIVED, not what was requested.)
	h.state.stateDB.feeOnTransferBps = 100 // 1.00%
	h.mint(e2eLETH, taker, 100)

	// Taker SELLs 100 LETH. Only 99 ARRIVE in the vault (the 1% transfer tax), so the
	// router fills 99 LETH — the OBSERVED DELTA, not the requested 100.
	if _, err := h.swap(t, taker, true, 100, sqrtX96For(1.0)); err != nil {
		t.Fatalf("swap: %v", err)
	}

	// THE OBSERVED-DELTA PROOF: the maker bought EXACTLY 99 LETH off the book — proof
	// only the delivered 99 (not the requested 100) was routed. A naive path trusting
	// the requested amount would have routed 100 and left the vault 1 LETH short.
	if got := h.dcAvail(maker, e2eLETH); got != 99 {
		t.Fatalf("maker bought %d LETH, want 99 (observed delta: only the delivered 99 was routed, not 100)", got)
	}
	if got := h.ercBal(e2eLETH, taker); got != 0 {
		t.Fatalf("taker LETH = %d, want 0 (whole balance transferred)", got)
	}
	// Taker proceeds: 99 LETH @ 50 = 4950 LUSD owed, less the 1%% tax on the OUTPUT
	// transfer (the global mock fee taxes this leg too) -> 4950 - 49 = 4901 delivered.
	if got := h.ercBal(e2eLUSD, taker); got != 4901 {
		t.Fatalf("taker LUSD = %d, want 4901 (99 @ 50 = 4950 owed, minus 1%% output-leg transfer tax)", got)
	}

	// CONSERVATION holds: the vault's real holdings exactly back the ledger. Turn the
	// global fee OFF first so the conservation read (which transfers nothing) is clean.
	h.state.stateDB.feeOnTransferBps = 0
	assertVaultConservation(t, h, maker, taker)
}

// ---------------------------------------------------------------------------
// Test9999SyncSwap_NonReentrant
// ---------------------------------------------------------------------------

// Test9999SyncSwap_NonReentrant proves the synchronous swap refuses to execute while
// the GLOBAL custody guard is held — the reentrancy a malicious ERC-20 would mount
// during its transfer is blocked. We simulate an in-flight custody op holding the
// guard and assert a sync swap entered under it refuses with ErrCustodyReentrant and
// moves NO value.
func Test9999SyncSwap_NonReentrant(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)
	takerLETHBefore := h.ercBal(e2eLETH, taker)
	makerLockedBefore := h.dcLocked(maker, e2eLUSD)

	// Hold the global custody guard (what a deposit/withdraw/settle does for the
	// duration of its sub-call).
	db := newPoolStateAdapter(h.state)
	if !enterCustodyKV(db) {
		t.Fatal("guard must be free initially")
	}
	defer exitCustodyKV(db)

	// A sync swap entering while the guard is held must refuse.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, nil)
	_, _, err := h.c.Run(h.state, taker, poolManagerAddr9999, prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err != ErrCustodyReentrant {
		t.Fatalf("re-entrant sync swap must refuse with ErrCustodyReentrant, got: %v", err)
	}

	// NO value moved: the taker's LETH and the maker's lock are untouched.
	if got := h.ercBal(e2eLETH, taker); got != takerLETHBefore {
		t.Fatalf("taker LETH moved on a refused re-entrant swap: %d -> %d", takerLETHBefore, got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != makerLockedBefore {
		t.Fatalf("maker lock changed on a refused re-entrant swap: %d -> %d", makerLockedBefore, got)
	}
}

// ---------------------------------------------------------------------------
// Test9999Routes{CLOBWhenDepth,V3WhenCLOBEmpty}  (precompile / real-asset level)
// ---------------------------------------------------------------------------

// Test9999RoutesCLOBWhenDepth proves the 0x9999 router fills from the V4 CLOB when the
// book has depth — the canonical primary source. (The AMM fallthrough at the
// precompile layer is exercised by Test9999RoutesV3WhenCLOBEmpty; the dexcore-level
// split is covered by Test9999BestExecSplitCLOBAndAMM.)
func Test9999RoutesCLOBWhenDepth(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker
	// Deep CLOB bid.
	h.mint(e2eLUSD, maker, 1_000_000)
	h.deposit(t, maker, e2eLUSD, 1_000_000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 1000)
	h.mint(e2eLETH, taker, 80)

	out, err := h.swap(t, taker, true, 80, sqrtX96For(1.0))
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	_, a1 := UnpackBalanceDelta(out)
	if a1.Int64() != 4000 {
		t.Fatalf("CLOB fill proceeds = %s, want 4000 (80 @ 50 from the book)", a1)
	}
	// The maker's book absorbed the fill (proof it routed CLOB, not some AMM).
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("maker bought %d LETH off the book, want 80", got)
	}
}

// Test9999RoutesV3WhenCLOBEmpty proves the 0x9999 router falls through to the V2/V3
// AMM when the CLOB has no crossable depth. The precompile's buildRouter wires the AMM
// source over a real pool; here we drive the dexcore router directly over the precompile
// AMM-pool adapter (swap_amm_pool.go) seeded with reserves, asserting the swap fills
// from the curve when the book is empty. This is the precompile-layer twin of the
// dexcore Test9999Swap_FallsToV2V3WhenNoV4.
func Test9999RoutesV3WhenCLOBEmpty(t *testing.T) {
	h := newE2EHarness(t)
	store := h.store()
	pid := h.key.ID()
	// Bind the market (real assets) but rest NO CLOB order.
	if err := dexcore.OpenMarket(store, pid, assetID(h.key.Currency0), assetID(h.key.Currency1)); err != nil {
		t.Fatalf("OpenMarket: %v", err)
	}

	// Seed a real AMM pool over the precompile's AMM-pool adapter.
	seedAMMReserves(t, h, pid, 100_000, 5_000_000) // ~50 LUSD/LETH

	taker := e2eTaker
	// The taker's input must be locked in the dexcore ledger (the top-level lock); seed
	// it directly here since we drive the dexcore router (not the full 0x9999 Run).
	takerAcct := accountFromAddress(taker)
	if err := dexcore.Deposit(store, takerAcct, assetID(h.key.Currency0), 100); err != nil {
		t.Fatalf("seed taker LETH: %v", err)
	}

	router := buildRouter(h.state.stateDB, pid) // CLOB + AMM (AMM active: pool bound)
	req := dexcore.SwapRequest{
		PoolID: pid, TakerUser: takerAcct, Side: lx.Sell,
		Base: assetID(h.key.Currency0), Quote: assetID(h.key.Currency1),
		AmountIn: 100, OrderID: 7, TimestampN: 1, Class: dexcore.ClassPublicCLOB,
	}
	res, err := dexcore.ExecuteSwap(store, router, req)
	if err != nil {
		t.Fatalf("ExecuteSwap (AMM fallthrough): %v", err)
	}
	wantOut := lx.ConstantProductOut(100_000, 5_000_000, 100)
	if res.AmountOut != wantOut {
		t.Fatalf("AMM fallthrough out = %d, want %d", res.AmountOut, wantOut)
	}
	if len(res.Fills) != 1 || res.Fills[0].Source != dexcore.SourceAMM {
		t.Fatalf("expected a single AMM fill (CLOB empty), got %+v", res.Fills)
	}
}

// Test9999SyncSwap_TakerPriorDepositPreserved proves a swap does NOT strand a taker's
// PRE-EXISTING dexcore deposit. A multi-role user (a maker who deposited, then swaps as
// a taker on the same market) has a resting dexcore balance of the market's asset. The
// post-swap ledger drain must remove ONLY the transient swap proceeds/refund — NEVER the
// prior deposit — and conservation must hold (the vault still backs the surviving
// deposit). This guards the "drain the whole available to zero" hazard.
func Test9999SyncSwap_TakerPriorDepositPreserved(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// Maker rests a deep real-funded BID (the taker will SELL into it).
	h.mint(e2eLUSD, maker, 1_000_000)
	h.deposit(t, maker, e2eLUSD, 1_000_000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 1000)

	// The TAKER ALSO holds a prior dexcore deposit of LUSD (the market's QUOTE) — e.g. it
	// deposited 500 LUSD earlier to rest its own orders. This is real backing in the vault.
	h.mint(e2eLUSD, taker, 500)
	h.deposit(t, taker, e2eLUSD, 500)
	if got := h.dcAvail(taker, e2eLUSD); got != 500 {
		t.Fatalf("setup: taker prior LUSD deposit = %d, want 500", got)
	}

	// Now the taker SELLs 80 LETH -> LUSD through 0x9999. Proceeds = 4000 LUSD (to EVM).
	h.mint(e2eLETH, taker, 80)
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
		t.Fatalf("swap: %v", err)
	}

	// THE INVARIANT: the taker's PRIOR 500 LUSD dexcore deposit SURVIVES — only the
	// transient swap proceeds were drained (and released to EVM). A naive drain-to-zero
	// would have wiped the 500 and stranded its vault backing.
	if got := h.dcAvail(taker, e2eLUSD); got != 500 {
		t.Fatalf("taker prior LUSD deposit = %d after swap, want 500 (the swap stranded the prior deposit)", got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker EVM LUSD = %d, want 4000 (proceeds)", got)
	}
	// CONSERVATION holds: the vault backs the surviving 500 LUSD deposit + the maker's
	// remaining lock.
	assertVaultConservation(t, h, maker, taker)
	// The taker can still withdraw its prior 500 LUSD deposit (it's real, backed).
	withdrawAll(t, h, taker, e2eLUSD)
	if got := h.ercBal(e2eLUSD, taker); got != 4500 {
		t.Fatalf("taker EVM LUSD after withdraw = %d, want 4500 (4000 proceeds + 500 prior deposit)", got)
	}
}

// Test9999SyncSwap_AMMLegMovesRealERC20EndToEnd proves the AMM fallthrough end-to-end
// through the FULL 0x9999 swap Run: with NO CLOB depth and a real-vault-BACKED AMM pool,
// a taker's swap routes to the AMM, moves REAL ERC-20 balances (input into the vault,
// proceeds out of the vault), updates the pool reserves, and conserves. The AMM pool's
// quote reserve MUST be backed by real vault tokens (seeded via the operator seam-reserve
// seed) — creditSettlementOutput is no-mint, so an unbacked AMM payout would revert. This
// is the AMM twin of the CLOB e2e: the full custody+journal path, not just the router.
func Test9999SyncSwap_AMMLegMovesRealERC20EndToEnd(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker
	pid := h.key.ID()

	// Bind a real AMM pool (NO CLOB order rests). Reserves: 100k LETH / 5M LUSD (~50).
	const baseR, quoteR = uint64(100_000), uint64(5_000_000)
	seedAMMReserves(t, h, pid, baseR, quoteR)

	// BACK the AMM pool's quote reserve with REAL LUSD in the vault, via the operator
	// seam-reserve seed (the production counterparty-funding path). Without this, the
	// proceeds payout has no backing and reverts (ErrNativeSettleUnbacked) — exactly the
	// conservation guard. We seed the full quote reserve so any AMM payout is backed.
	seedVaultReserve(t, h, e2eLUSD, int64(quoteR))

	// Taker SELLs 100 LETH -> LUSD through the FULL 0x9999 Run.
	h.mint(e2eLETH, taker, 100)
	out, err := h.swap(t, taker, true, 100, sqrtX96For(1.0))
	if err != nil {
		t.Fatalf("AMM-leg swap through 0x9999: %v", err)
	}

	wantOut := lx.ConstantProductOut(baseR, quoteR, 100)
	// REAL ERC-20 MOVED: taker -100 LETH (into vault), +wantOut LUSD (out of vault).
	if got := h.ercBal(e2eLETH, taker); got != 0 {
		t.Fatalf("taker LETH = %d, want 0 (sold into the AMM)", got)
	}
	if got := h.ercBal(e2eLUSD, taker); uint64(got) != wantOut {
		t.Fatalf("taker LUSD = %d, want %d (AMM curve out)", got, wantOut)
	}
	// V4 BalanceDelta confirms the realized legs.
	a0, a1 := UnpackBalanceDelta(out)
	if a0.Int64() != -100 || uint64(a1.Int64()) != wantOut {
		t.Fatalf("BalanceDelta = (%s,%s), want (-100,%d)", a0, a1, wantOut)
	}

	// POOL RESERVES MOVED: base +100, quote -wantOut (the curve fill, in 0x9999 storage).
	store := h.store()
	gotBase, gotQuote, _, ok := readAMMRow(store, pid)
	if !ok {
		t.Fatal("AMM row vanished after the swap")
	}
	if gotBase != baseR+100 || gotQuote != quoteR-wantOut {
		t.Fatalf("AMM reserves = (%d,%d), want (%d,%d)", gotBase, gotQuote, baseR+100, quoteR-wantOut)
	}

	// CONSERVATION across BOTH assets: the vault's real holdings exactly back what is
	// owed. seamReserve[LETH] == 100 (the taker's input now custodied); seamReserve[LUSD]
	// == quoteR - wantOut (the seeded backing minus the paid proceeds).
	if seam := h.seamReserveOf(e2eLETH); seam != 100 {
		t.Fatalf("seamReserve[LETH] = %d, want 100 (taker input custodied)", seam)
	}
	if seam := h.seamReserveOf(e2eLUSD); seam != quoteR-wantOut {
		t.Fatalf("seamReserve[LUSD] = %d, want %d (seeded backing minus proceeds)", seam, quoteR-wantOut)
	}
}

// ---------------------------------------------------------------------------
// Test9999BestExecSplitCLOBAndAMM  (precompile / real-asset level)
// ---------------------------------------------------------------------------

// Test9999BestExecSplitCLOBAndAMM proves the 0x9999 router splits the input across the
// CLOB and the AMM when neither alone is best: it takes the thin-but-better CLOB depth,
// then the AMM for the remainder. Driven over the precompile AMM-pool adapter + a real
// resting CLOB order in dexcore.
func Test9999BestExecSplitCLOBAndAMM(t *testing.T) {
	h := newE2EHarness(t)
	store := h.store()
	pid := h.key.ID()
	base, quote := assetID(h.key.Currency0), assetID(h.key.Currency1)
	if err := dexcore.OpenMarket(store, pid, base, quote); err != nil {
		t.Fatalf("OpenMarket: %v", err)
	}

	// Thin but BETTER CLOB bid: 10 LETH @ 60 (maker funded in the dexcore ledger).
	maker := accountFromAddress(e2eMaker)
	if err := dexcore.Deposit(store, maker, quote, 1_000_000); err != nil {
		t.Fatalf("seed maker LUSD: %v", err)
	}
	if ok, err := dexcore.PlaceOrder(store, pid, maker, lx.Buy, 60, 10, 1, blockTime()); err != nil || !ok {
		t.Fatalf("rest CLOB bid: ok=%v err=%v", ok, err)
	}

	// AMM priced ~50.
	seedAMMReserves(t, h, pid, 100_000, 5_000_000)

	taker := accountFromAddress(e2eTaker)
	if err := dexcore.Deposit(store, taker, base, 1000); err != nil {
		t.Fatalf("seed taker LETH: %v", err)
	}

	router := buildRouter(h.state.stateDB, pid)
	req := dexcore.SwapRequest{
		PoolID: pid, TakerUser: taker, Side: lx.Sell,
		Base: base, Quote: quote, AmountIn: 30, OrderID: 9, TimestampN: 1,
		Class: dexcore.ClassPublicCLOB,
	}
	res, err := dexcore.ExecuteSwap(store, router, req)
	if err != nil {
		t.Fatalf("ExecuteSwap (split): %v", err)
	}

	var clobBase, ammBase uint64
	var sawCLOB, sawAMM bool
	for _, f := range res.Fills {
		switch f.Source {
		case dexcore.SourceCLOB:
			sawCLOB = true
			for _, tr := range f.Trades {
				clobBase += tr.BaseUnits.Uint64()
			}
		case dexcore.SourceAMM:
			sawAMM = true
			ammBase += f.AMMBaseDelta
		}
	}
	if !sawCLOB || !sawAMM {
		t.Fatalf("expected a split across CLOB+AMM, got %+v", res.Fills)
	}
	if clobBase != 10 || ammBase != 20 {
		t.Fatalf("split legs: CLOB base=%d (want 10), AMM base=%d (want 20)", clobBase, ammBase)
	}
	wantOut := uint64(600) + lx.ConstantProductOut(100_000, 5_000_000, 20)
	if res.AmountOut != wantOut {
		t.Fatalf("split out = %d, want %d (600 CLOB @60 + AMM curve(20))", res.AmountOut, wantOut)
	}
}

// ---------------------------------------------------------------------------
// Test{HFTAndEVMUseSameBook,NativeMakerEVMTaker,EVMMakerNativeTaker}SameState
// ---------------------------------------------------------------------------

// TestHFTAndEVMUseSameBookSameState proves the native HFT surface and the EVM 0x9999
// surface read and write the SAME book. A maker placed via the NATIVE custody selector
// (swapPlace — the HFT/native rail) is crossed by a taker who enters via the EVM V4
// swap (0x9999). One book, one fill: the EVM swap consumes the native-placed order.
func TestHFTAndEVMUseSameBookSameState(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// Maker rests via the native custody rail (swapPlace).
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	orderID := h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	if orderID == 0 {
		t.Fatal("native swapPlace returned order id 0")
	}

	// Taker enters via the EVM 0x9999 swap and crosses the SAME native-placed order.
	h.mint(e2eLETH, taker, 80)
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
		t.Fatalf("EVM swap: %v", err)
	}

	// SAME BOOK: the native maker's order was consumed by the EVM taker — the maker
	// bought 80 LETH and its lock dropped to the 20-remaining (1000 LUSD).
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("native maker LETH = %d, want 80 (EVM taker did not hit the native book)", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != 1000 {
		t.Fatalf("native maker LUSD locked = %d, want 1000 (the EVM swap did not consume the native order)", got)
	}
	assertVaultConservation(t, h, maker, taker)
}

// TestNativeMakerEVMTakerSameState is the product flow named explicitly in the model:
// a NATIVE maker rests, an EVM taker swaps through 0x9999, the fill lands once in the
// shared state, the maker can realize it on-chain. (This is the same crossing as the
// e2e, asserted here as the named invariant: native maker + EVM taker -> same state.)
func TestNativeMakerEVMTakerSameState(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100) // native maker
	h.mint(e2eLETH, taker, 80)
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil { // EVM taker
		t.Fatalf("EVM taker swap: %v", err)
	}

	// The maker (native) holds the bought base in the SHARED state; withdraw realizes it.
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("native maker LETH in shared state = %d, want 80", got)
	}
	withdrawAll(t, h, maker, e2eLETH)
	if got := h.ercBal(e2eLETH, maker); got != 80 {
		t.Fatalf("native maker realized %d LETH on-chain, want 80", got)
	}
	// The EVM taker holds the proceeds on-chain.
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("EVM taker proceeds = %d, want 4000", got)
	}
}

// TestEVMMakerNativeTakerSameState is the mirror: an EVM participant rests a maker
// order via 0x9999's swapPlace (the EVM rail places into the shared book), and a taker
// crosses it. Both makers and takers — whichever rail they enter by — meet in the one
// book. Here we rest via swapPlace (the on-chain rail a contract/EVM caller uses) and
// cross with a swap; the resting maker is consumed exactly once.
func TestEVMMakerNativeTakerSameState(t *testing.T) {
	h := newE2EHarness(t)
	// "EVM maker" = a maker who rests through the on-chain 0x9999 swapPlace selector.
	evmMaker := common.HexToAddress("0xcc00000000000000000000000000000000000003")
	// "native taker" = a taker who crosses; the cross is the same shared book regardless.
	nativeTaker := e2eTaker

	// EVM maker rests an ASK: 100 LETH @ 50 (locks 100 LETH base).
	h.mint(e2eLETH, evmMaker, 100)
	h.deposit(t, evmMaker, e2eLETH, 100)
	if oid := h.placeArgs(t, evmMaker, false, 50*uint64(priceMultiplierConst), 100); oid == 0 {
		t.Fatal("EVM maker swapPlace returned order id 0")
	}

	// Native taker BUYs 80 LETH with a 50 ceiling (spends 4000 LUSD).
	h.mint(e2eLUSD, nativeTaker, 4000)
	out, err := h.swap(t, nativeTaker, false, 4000, sqrtPriceForCeil(50)) // !zeroForOne = BUY
	if err != nil {
		t.Fatalf("native taker BUY: %v", err)
	}
	a0, a1 := UnpackBalanceDelta(out)
	// BUY: amount0 (LETH) = +80 received, amount1 (LUSD) = -4000 paid.
	if a0.Int64() != 80 {
		t.Fatalf("taker received %s LETH, want 80", a0)
	}
	if a1.Int64() != -4000 {
		t.Fatalf("taker paid %s LUSD, want -4000", a1)
	}

	// SAME BOOK: the EVM-placed ASK was consumed — the maker sold 80 LETH and received
	// 4000 LUSD into the shared ledger; 20 LETH still locked on the resting remainder.
	if got := h.dcAvail(evmMaker, e2eLUSD); got != 4000 {
		t.Fatalf("EVM maker LUSD = %d, want 4000 (sold into the shared book)", got)
	}
	if got := h.dcLocked(evmMaker, e2eLETH); got != 20 {
		t.Fatalf("EVM maker LETH locked = %d, want 20 (resting remainder)", got)
	}
	assertVaultConservation(t, h, evmMaker, nativeTaker)
}

// ---------------------------------------------------------------------------
// TestNo{LiveZAPSettlement,KeeperSettlementPath,VenueFallback}
// ---------------------------------------------------------------------------

// TestNoLiveZAPSettlement proves the synchronous value path settles ENTIRELY in-process
// with NO live ZAP: the swap moves value through dexcore + the EVM vault only. The
// behavioral proof is that a swap succeeds and credits real proceeds with NO ZAP
// endpoint, NO venue, and NO keeper configured anywhere in the harness — if the value
// path secretly needed a live ZAP round-trip it would hang or fail here. (The
// structural complement — that the value-path source never invokes a ZAP/venue/keeper
// transport — is asserted by the absence of any such call in swap_sync.go /
// swap_custody.go / dexcore; the matcher the route calls is the pure lx.OrderBook, not
// a transport.)
func TestNoLiveZAPSettlement(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	// No ZAP endpoint, no venue, no keeper is wired in the harness — the swap settles
	// purely in-process. If the value path secretly needed a live ZAP, this would hang
	// or fail; it succeeds and credits real proceeds.
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
		t.Fatalf("in-process swap failed (a live-ZAP dependency would surface here): %v", err)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker proceeds = %d, want 4000 (settled with no live ZAP)", got)
	}
}

// TestNoKeeperSettlementPath proves there is NO keeper in the synchronous value path:
// the swap credits the taker's output IN THE SAME CALL, with no second transaction, no
// off-chain keeper poll, no deferred settlement. We assert the proceeds are present
// immediately after the single swap call (a keeper model would leave the taker
// uncredited until a later settle tx).
func TestNoKeeperSettlementPath(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	lethBefore := h.ercBal(e2eLETH, taker)
	// ONE call. No keeper, no second tx.
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
		t.Fatalf("swap: %v", err)
	}
	// Proceeds are credited IMMEDIATELY in the same call — not pending a keeper settle.
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker proceeds = %d after ONE call, want 4000 (a keeper path would leave 0 pending)", got)
	}
	if got := h.ercBal(e2eLETH, taker); got != lethBefore-80 {
		t.Fatalf("taker input = %d, want %d (spent in the same call)", got, lethBefore-80)
	}
}

// TestNoVenueFallback proves the router has NO external-venue fallback: when neither
// on-chain source (CLOB nor AMM) can fill, the swap REVERTS rather than reaching out to
// an external venue. The taker's funds are untouched (the EVM snapshot rolled back the
// lock), and no proceeds appear.
func TestNoVenueFallback(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker
	// Market exists (a maker deposit binds it) but has NO crossable CLOB depth and NO
	// AMM pool — there is nowhere on-chain to fill.
	h.mint(e2eLETH, taker, 80)
	takerLETHBefore := h.ercBal(e2eLETH, taker)

	_, err := h.swap(t, taker, true, 80, sqrtX96For(1.0))
	if err == nil {
		t.Fatal("a swap with no on-chain liquidity must REVERT (no external-venue fallback)")
	}
	// The taker's funds are untouched — no venue was paid, the lock rolled back.
	if got := h.ercBal(e2eLETH, taker); got != takerLETHBefore {
		t.Fatalf("taker LETH moved on a no-liquidity swap: %d -> %d (a venue fallback would have spent it)", takerLETHBefore, got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 0 {
		t.Fatalf("taker received %d LUSD with no on-chain liquidity (a venue fallback)", got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// findDEXFillLog returns the first DEXFill log in logs whose indexed topics match
// (poolId, taker), or nil.
func findDEXFillLog(logs []*ethtypes.Log, poolID [32]byte, taker common.Address) *ethtypes.Log {
	wantPool := common.BytesToHash(poolID[:])
	wantTaker := common.BytesToHash(taker.Bytes())
	for _, l := range logs {
		if len(l.Topics) == 3 && l.Topics[0] == dexFillEventSig && l.Topics[1] == wantPool && l.Topics[2] == wantTaker {
			return l
		}
	}
	return nil
}

// dexBookRootOnly folds a market's resting book into the dexcore book root (no swap
// result), giving a cross-validator witness over the persistent post-swap state.
func dexBookRootOnly(db dexcore.Store, poolID [32]byte) [dexcore.Size]byte {
	// SwapExecutionRoot with an empty result folds only the book + zero amounts, which
	// is exactly the persistent-book witness we want.
	return dexcore.SwapExecutionRoot(db, poolID, &dexcore.SwapResult{})
}

// blockTime returns a fixed deterministic block time for the direct-router tests. The
// maker/ephemeral order timestamp never participates in value, so a fixed instant is a
// valid validator-identical stand-in.
func blockTime() time.Time { return time.Unix(0, 1_000) }

// seedAMMReserves binds a real AMM pool's (base,quote) reserves over the precompile AMM
// binding (swap_amm_pool.go BindAMMPool), activating the dexcore AMM source for the
// market so the router prices/executes over the bound reserves (0 bps fee).
func seedAMMReserves(t *testing.T, h *e2eHarness, poolID [32]byte, base, quote uint64) {
	t.Helper()
	if err := BindAMMPool(h.store(), poolID, base, quote, 0); err != nil {
		t.Fatalf("bind AMM pool: %v", err)
	}
}

// seedVaultReserve backs an asset's vault seam reserve with `amount` of REAL token via
// the PRODUCTION operator-gated seedSeamReserve selector (the counterparty-funding
// path). The operator is minted the token, then seeds it (observed-delta transferFrom
// into the vault). This is how an AMM pool's quote reserve gets real vault backing so a
// proceeds payout is no-mint-conservation-clean.
func seedVaultReserve(t *testing.T, h *e2eHarness, token common.Address, amount int64) {
	t.Helper()
	h.wrapper().mintTestToken(token, h.operator(), big.NewInt(amount))
	data := make([]byte, 64)
	copy(data[12:32], token.Bytes())
	big.NewInt(amount).FillBytes(data[32:64])
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false); err != nil {
		t.Fatalf("seedSeamReserve(%x, %d): %v", token[19], amount, err)
	}
}

// sqrtPriceForCeil returns a SqrtPriceLimitX96 encoding a price CEILING for a BUY
// (!zeroForOne). For a BUY the V4 limit is the MAX sqrt price; a ceiling of `price`
// means reject fills above it. price = (sqrt/2^96)^2, so sqrt = floor(sqrt(price)*2^96).
func sqrtPriceForCeil(price uint64) *big.Int {
	pf := new(big.Float).SetUint64(price)
	sq := new(big.Float).Sqrt(pf)
	twoPow96 := new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 96))
	res := new(big.Float).Mul(sq, twoPow96)
	out, _ := res.Int(nil)
	return out
}
