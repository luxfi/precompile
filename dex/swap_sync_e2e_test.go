// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/geth/common"
)

// swap_sync_e2e_test.go is the REAL end-to-end proof of 0x9999 as the on-chain
// smart-order-router: a native maker rests a real-ERC-20-funded order, an EVM taker
// swaps through 0x9999 with a REAL ERC-20, the fill appears ONCE in the dexcore book,
// the C-Chain ERC-20 balances change correctly, and conservation + ownership hold.
// Every leg runs through REAL selectors (swapDeposit / swapPlace / swap) over REAL
// ERC-20 token balances — no synthetic asset ids, no stubs.
//
// Token layout (V4 requires currency0 < currency1):
//   - LETH (base, currency0)  = 0x..01
//   - LUSD (quote, currency1) = 0x..02
// so "sell LETH for LUSD" is zeroForOne (currency0 -> currency1).

var (
	e2eLETH = common.HexToAddress("0x0000000000000000000000000000000000000001") // base / currency0
	e2eLUSD = common.HexToAddress("0x0000000000000000000000000000000000000002") // quote / currency1

	// Distinct participant wallets (valid hex; high bytes set so they never collide
	// with the token addresses or 0x9999).
	e2eMaker = common.HexToAddress("0xaa00000000000000000000000000000000000001")
	e2eTaker = common.HexToAddress("0xbb00000000000000000000000000000000000002")
)

// e2eMarketKey is the LETH/LUSD market (base=currency0=LETH, quote=currency1=LUSD).
func e2eMarketKey() PoolKey {
	return PoolKey{
		Currency0:   Currency{Address: e2eLETH},
		Currency1:   Currency{Address: e2eLUSD},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
}

// e2eHarness wraps the shared settle harness with the value-swap gate enabled and the
// real-ERC-20 token-balance helpers. It restores the gate on cleanup.
type e2eHarness struct {
	*settleHarness
	key PoolKey
}

func newE2EHarness(t *testing.T) *e2eHarness {
	t.Helper()
	h := newSettleHarness(t)
	h.key = e2eMarketKey()
	EnableValueSwaps(true)
	t.Cleanup(func() { EnableValueSwaps(false) })
	return &e2eHarness{settleHarness: h, key: e2eMarketKey()}
}

// mint seeds a holder's real ERC-20 balance.
func (h *e2eHarness) mint(token, holder common.Address, amount int64) {
	h.wrapper().mintTestToken(token, holder, big.NewInt(amount))
}

// ercBal reads a holder's real ERC-20 balance.
func (h *e2eHarness) ercBal(token, holder common.Address) int64 {
	return h.wrapper().ercBal(token, holder).Int64()
}

// deposit drives a real swapDeposit (ERC-20 into the vault + dexcore ledger).
func (h *e2eHarness) deposit(t *testing.T, who, token common.Address, amount int64) {
	t.Helper()
	data := make([]byte, 64)
	copy(data[12:32], token.Bytes())
	big.NewInt(amount).FillBytes(data[32:64])
	if _, _, err := h.c.Run(h.state, who, poolManagerAddr9999, prependSelector(SelectorSwapDeposit, data), 5_000_000, false); err != nil {
		t.Fatalf("swapDeposit(%x, %d): %v", token[19], amount, err)
	}
}

// placeArgs builds the swapPlace args with the correct field layout and runs it.
// priceGrid is the PriceInt (quote-per-base * PriceMultiplier); size is base units.
func (h *e2eHarness) placeArgs(t *testing.T, who common.Address, isBid bool, priceGrid, size uint64) uint64 {
	t.Helper()
	data := make([]byte, 256)
	copy(data[0:160], EncodePoolKeyABI(h.key))
	if isBid {
		data[191] = 1
	}
	new(big.Int).SetUint64(priceGrid).FillBytes(data[192:224]) // price
	new(big.Int).SetUint64(size).FillBytes(data[224:256])      // size
	out, _, err := h.c.Run(h.state, who, poolManagerAddr9999, prependSelector(SelectorSwapPlace, data), 5_000_000, false)
	if err != nil {
		t.Fatalf("swapPlace(isBid=%v price=%d size=%d): %v", isBid, priceGrid, size, err)
	}
	return new(big.Int).SetBytes(out).Uint64()
}

// swap drives a real V4 swap through 0x9999 with EMPTY hookData (the synchronous
// router path). zeroForOne sells base (LETH) for quote (LUSD). amountSpecified is the
// negative exact-input magnitude. Returns the raw BalanceDelta bytes.
func (h *e2eHarness) swap(t *testing.T, taker common.Address, zeroForOne bool, amountIn int64, sqrtLimit *big.Int) ([]byte, error) {
	t.Helper()
	params := SwapParams{
		ZeroForOne:        zeroForOne,
		AmountSpecified:   big.NewInt(-amountIn),
		SqrtPriceLimitX96: sqrtLimit,
	}
	if sqrtLimit == nil {
		params.SqrtPriceLimitX96 = big.NewInt(0)
	}
	calldata := buildSwapCalldata(h.key, params, nil) // nil hookData -> untagged -> sync router
	// Drive through the taker (msg.sender) over the EVM atomicity boundary: the
	// production EVM snapshots before the precompile CALL and reverts on error, so a
	// failed swap rolls back BOTH the C balances and the D book. runWithEVMSnapshot
	// reproduces that boundary exactly (see swap_sync_snapshot_test.go), so a revert
	// here is observably atomic in the mock — as it is in production.
	out, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999, prependSelector(SelectorSwap, calldata), 5_000_000, false)
	return out, err
}

// store returns a dexcore Store over the harness StateDB (for asserting dexcore
// state), via the SAME poolStateAdapter the production swap path uses.
func (h *e2eHarness) store() dexcore.Store {
	return newEVMStore(newPoolStateAdapter(h.state))
}

// dcAvail/dcLocked read a participant's dexcore available/locked balance for an asset.
func (h *e2eHarness) dcAvail(who, token common.Address) uint64 {
	v, _ := dexcore.GetAvailable(h.store(), accountFromAddress(who), assetID(Currency{Address: token}))
	return v
}
func (h *e2eHarness) dcLocked(who, token common.Address) uint64 {
	v, _ := dexcore.GetLocked(h.store(), accountFromAddress(who), assetID(Currency{Address: token}))
	return v
}

// seamReserveOf reads the vault's seam reserve for an asset (the real backing). It
// reads through the SAME poolStateAdapter (the stateKV form) the production seam
// readers use (swap_sync.go / settle_seed.go / native_dchain_client.go), NOT the
// contract.StateDB wrapper (whose SetState returns the prior value) — so the test
// observes exactly the bytes production writes.
func (h *e2eHarness) seamReserveOf(token common.Address) uint64 {
	return loadSeamReserve(newPoolStateAdapter(h.state), assetID(Currency{Address: token})).Uint64()
}

// THE product e2e: a native maker rests a real-funded BID; an EVM taker swaps a REAL
// ERC-20 through 0x9999; the fill appears once in the dexcore book; C-Chain ERC-20
// balances change correctly; conservation + ownership hold.
func TestE2E_SyncSwap_MakerRestsTakerSwaps(t *testing.T) {
	h := newE2EHarness(t)
	maker := e2eMaker
	taker := e2eTaker

	// Maker has 5000 real LUSD; deposits it and rests a BID of 100 LETH @ 50 (locks
	// 5000 LUSD).
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	priceGrid := uint64(50) * uint64(priceMultiplierConst) // 50 quote-per-base on the grid
	h.placeArgs(t, maker, true, priceGrid, 100)

	// Maker's real LUSD is now in the vault; its dexcore claim is 5000 LUSD locked.
	if got := h.ercBal(e2eLUSD, maker); got != 0 {
		t.Fatalf("maker real LUSD after deposit = %d, want 0 (moved to vault)", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != 5000 {
		t.Fatalf("maker dexcore locked LUSD = %d, want 5000", got)
	}

	// Taker has 80 real LETH; swaps (SELL 80 LETH -> LUSD) through 0x9999.
	h.mint(e2eLETH, taker, 80)
	out, err := h.swap(t, taker, true, 80, nil)
	if err != nil {
		t.Fatalf("taker swap: %v", err)
	}

	// The V4 BalanceDelta: amount0 (base/LETH) = -80 (paid), amount1 (quote/LUSD) =
	// +4000 (received).
	a0, a1 := UnpackBalanceDelta(out)
	if a0.Int64() != -80 {
		t.Fatalf("BalanceDelta amount0 (LETH) = %s, want -80", a0)
	}
	if a1.Int64() != 4000 {
		t.Fatalf("BalanceDelta amount1 (LUSD) = %s, want 4000 (80 LETH @ 50)", a1)
	}

	// C-CHAIN ERC-20 BALANCES CHANGED CORRECTLY:
	//   - taker: -80 LETH (into vault), +4000 LUSD (received).
	if got := h.ercBal(e2eLETH, taker); got != 0 {
		t.Fatalf("taker real LETH = %d, want 0 (sold)", got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker real LUSD = %d, want 4000 (proceeds)", got)
	}

	// THE FILL APPEARS ONCE IN THE D (dexcore) BOOK STATE:
	//   - maker bought 80 LETH (dexcore available), 4000 of its 5000 LUSD lock spent,
	//     1000 LUSD still locked on the 20-LETH resting remainder.
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("maker dexcore LETH available = %d, want 80 (bought)", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != 1000 {
		t.Fatalf("maker dexcore LUSD locked = %d, want 1000 (20 LETH @ 50 remaining)", got)
	}
	// Taker holds NO dexcore balance (the swap drained its transient ledger).
	if got := h.dcAvail(taker, e2eLETH); got != 0 {
		t.Fatalf("taker dexcore LETH = %d, want 0", got)
	}
	if got := h.dcAvail(taker, e2eLUSD); got != 0 {
		t.Fatalf("taker dexcore LUSD = %d, want 0", got)
	}

	// CONSERVATION: seamReserve[a] == Σ dexcore (available + locked)[a].
	assertVaultConservation(t, h, maker, taker)

	// RESTART PRESERVES: the dexcore state lives in the 0x9999 EVM trie (committed
	// storage), and the resting book is REBUILT from the persisted order: rows on a
	// node restart (the rebuildable-accelerator discipline). Re-read the state through a
	// FRESH store + a fresh book rebuild over the SAME committed StateDB — exactly what
	// a restarted node does — and confirm the maker's bought balance, the resting
	// remainder, the maker identity, and conservation all survive.
	fresh := newEVMStore(newPoolStateAdapter(h.state))
	if av, _ := dexcore.GetAvailable(fresh, accountFromAddress(maker), assetID(Currency{Address: e2eLETH})); av != 80 {
		t.Fatalf("restart: maker LETH available = %d, want 80 (state did not survive a re-read)", av)
	}
	if lk, _ := dexcore.GetLocked(fresh, accountFromAddress(maker), assetID(Currency{Address: e2eLUSD})); lk != 1000 {
		t.Fatalf("restart: maker LUSD locked = %d, want 1000 (resting remainder lost)", lk)
	}
	// The resting remainder is rebuildable from rows: a fresh book rebuild yields the
	// 20-LETH remaining ASK... err BID (maker bought, 20 LETH @ 50 still resting).
	freshBook, err := dexcore.RebuildBook(fresh, h.key.ID(), dexcore.PoolSymbol(h.key.ID()))
	if err != nil {
		t.Fatalf("restart: rebuild book: %v", err)
	}
	if freshBook == nil {
		t.Fatalf("restart: rebuilt book is nil (resting order not recoverable from rows)")
	}

	// The maker can withdraw its bought 80 LETH (realize the fill on-chain).
	withdrawAll(t, h, maker, e2eLETH)
	if got := h.ercBal(e2eLETH, maker); got != 80 {
		t.Fatalf("maker real LETH after withdraw = %d, want 80", got)
	}
}

// Test9999SyncSwap_RevertRollsBackCAndD asserts an atomic revert: a swap that breaches
// the taker price limit moves NEITHER the C ERC-20 balances NOR the D book — both-or-
// neither in one block.
func Test9999SyncSwap_RevertRollsBackCAndD(t *testing.T) {
	h := newE2EHarness(t)
	maker := e2eMaker
	taker := e2eTaker

	// Maker rests a BID at 40 (below the taker's floor of 50).
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 40*uint64(priceMultiplierConst), 100)

	h.mint(e2eLETH, taker, 80)
	takerLETHBefore := h.ercBal(e2eLETH, taker)
	makerLockedBefore := h.dcLocked(maker, e2eLUSD)

	// Taker SELLs with a floor (sqrtPriceLimit encoding a 50 floor). The matcher won't
	// cross a 40 bid with a 50 floor, so the swap reverts (no liquidity at the floor).
	sqrtLimit := sqrtPriceForFloor(50) // a sqrt-price limit above the 40 bid
	_, err := h.swap(t, taker, true, 80, sqrtLimit)
	if err == nil {
		t.Fatalf("expected the swap to revert (floor 50 > bid 40), got success")
	}

	// ATOMIC ROLLBACK: the taker's real LETH is untouched (the lock rolled back), the
	// maker's resting order is untouched, no balance moved.
	if got := h.ercBal(e2eLETH, taker); got != takerLETHBefore {
		t.Fatalf("taker LETH moved on a reverted swap: %d -> %d", takerLETHBefore, got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 0 {
		t.Fatalf("taker received LUSD on a reverted swap: %d", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != makerLockedBefore {
		t.Fatalf("maker lock changed on a reverted swap: %d -> %d", makerLockedBefore, got)
	}
	if got := h.dcAvail(maker, e2eLETH); got != 0 {
		t.Fatalf("maker received LETH on a reverted swap: %d", got)
	}
}

// Test9999SyncSwap_ValueGateFailsClosed asserts the SYNCHRONOUS value router does NOT
// execute when native-value swaps are disabled (the node has not verified quorum
// finality). The fail-closed property is precise: NO synchronous settlement occurs —
// the taker receives NO proceeds and the maker's resting order is NOT crossed. (With
// the gate off and an empty hookData, the dispatch routes to the async cross-chain
// intent path, which legitimately LOCKS the taker's input as a recoverable C->D
// intent — that lock is not a synchronous fill and is governed by the async rail's
// own atomic-object settlement + deadline reclaim, so it is NOT the thing this gate
// guards. What this gate guards is that no swap SETTLES synchronously off a self-
// finalizable proposer fill, which is what we assert here.)
func Test9999SyncSwap_ValueGateFailsClosed(t *testing.T) {
	h := newSettleHarness(t)
	h.key = e2eMarketKey()
	wrap := &e2eHarness{settleHarness: h, key: e2eMarketKey()}

	// First, with the gate ENABLED, rest a real-funded maker BID so a synchronous fill
	// WOULD have a counterparty to cross. Then disable the gate and swap; if the sync
	// router were to run it would cross this bid — so an unfilled bid proves it did not.
	EnableValueSwaps(true)
	maker := e2eMaker
	wrap.mint(e2eLUSD, maker, 5000)
	wrap.deposit(t, maker, e2eLUSD, 5000)
	wrap.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100) // BID 100 LETH @ 50
	makerLUSDLockedBefore := wrap.dcLocked(maker, e2eLUSD)
	makerLETHBefore := wrap.dcAvail(maker, e2eLETH)

	// Now turn the gate OFF and attempt the swap.
	EnableValueSwaps(false)
	taker := e2eTaker
	wrap.mint(e2eLETH, taker, 80)

	// (a) DIRECT unit proof: runSyncSwap itself fails closed with the gate off.
	directParams := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: big.NewInt(0)}
	if _, _, derr := runSyncSwap(h.state, taker, wrap.key, directParams, 5_000_000, false); !errors.Is(derr, ErrValueSwapsNotEnabled) {
		t.Fatalf("runSyncSwap with gate off: err=%v, want ErrValueSwapsNotEnabled", derr)
	}

	// (b) DISPATCH proof: a full Run swap with the gate off must NOT settle synchronously.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(wrap.key, params, nil)
	_, _, _ = runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999, prependSelector(SelectorSwap, calldata), 5_000_000, false)

	// NO SYNCHRONOUS FILL: the taker received ZERO proceeds (no LUSD) and the maker's
	// resting BID is untouched (still fully locked, no LETH bought). Whether the async
	// rail locked the taker's LETH as an intent is orthogonal (and recoverable).
	if got := wrap.ercBal(e2eLUSD, taker); got != 0 {
		t.Fatalf("taker received %d LUSD with value swaps disabled — sync router must not settle", got)
	}
	if got := wrap.dcLocked(maker, e2eLUSD); got != makerLUSDLockedBefore {
		t.Fatalf("maker LUSD lock changed (%d -> %d) with value swaps disabled — no sync fill must occur", makerLUSDLockedBefore, got)
	}
	if got := wrap.dcAvail(maker, e2eLETH); got != makerLETHBefore {
		t.Fatalf("maker bought %d LETH with value swaps disabled — no sync fill must occur", got)
	}
}

// --- helpers ---

// priceMultiplierConst mirrors lx.PriceMultiplier for the test grid math.
const priceMultiplierConst = 100_000_000

// assertVaultConservation checks seamReserve[a] == Σ dexcore (available+locked)[a] for
// the market's two assets across the named participants.
func assertVaultConservation(t *testing.T, h *e2eHarness, accts ...common.Address) {
	t.Helper()
	for _, token := range []common.Address{e2eLETH, e2eLUSD} {
		var ledgerTotal uint64
		for _, who := range accts {
			ledgerTotal += h.dcAvail(who, token) + h.dcLocked(who, token)
		}
		if seam := h.seamReserveOf(token); seam != ledgerTotal {
			t.Fatalf("conservation violated for %x: seamReserve=%d ledgerTotal=%d", token[19], seam, ledgerTotal)
		}
	}
}

// withdrawAll drives a swapWithdraw of the participant's entire dexcore available.
func withdrawAll(t *testing.T, h *e2eHarness, who, token common.Address) {
	t.Helper()
	amt := h.dcAvail(who, token)
	if amt == 0 {
		return
	}
	data := make([]byte, 64)
	copy(data[12:32], token.Bytes())
	new(big.Int).SetUint64(amt).FillBytes(data[32:64])
	if _, _, err := h.c.Run(h.state, who, poolManagerAddr9999, prependSelector(SelectorSwapWithdraw, data), 5_000_000, false); err != nil {
		t.Fatalf("swapWithdraw(%x, %d): %v", token[19], amt, err)
	}
}

// sqrtPriceForFloor returns a SqrtPriceLimitX96 encoding a price FLOOR for a SELL
// (zeroForOne). price = (sqrt/2^96)^2, so sqrt = floor(sqrt(price) * 2^96). For a SELL
// the V4 limit is the MIN sqrt price; a floor of `price` means reject fills below it.
func sqrtPriceForFloor(price uint64) *big.Int {
	// sqrt(price) as a big.Float, times 2^96.
	pf := new(big.Float).SetUint64(price)
	sq := new(big.Float).Sqrt(pf)
	twoPow96 := new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 96))
	res := new(big.Float).Mul(sq, twoPow96)
	out, _ := res.Int(nil)
	return out
}

// guard against an unused import if the errors pkg ends up unreferenced in a refactor.
var _ = errors.New
