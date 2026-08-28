// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Custody: the money path. Every unit the precompile pays out must first have
// been observed inbound, and the per-asset `reserve` ledger must equal deposits
// minus withdrawals at every instant. These tests cover BOTH asset kinds — the
// ERC-20 vault AND the native-LUX path — to the same depth.
package v3

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/dex"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The conservation anchor, for any asset: reserve[asset] == real holdings.
// ---------------------------------------------------------------------------

// assertAnchor asserts the ledger equals the real balance for an ERC-20 or, for
// the zero address, the precompile's real native balance.
func assertAnchor(t *testing.T, m *mockState, asset common.Address) {
	t.Helper()
	if asset == native {
		eqBig(t, m.nativeBal(v3Addr), loadReserve(m, native))
		return
	}
	eqBig(t, m.bal(asset, v3Addr), loadReserve(m, asset))
}

// ---------------------------------------------------------------------------
// Native path — pullExactNative / pushOutNative through the real entry points.
// ---------------------------------------------------------------------------

// TestNative_MintPullsExactDeliveredValue drives the ENTIRE native inbound path:
// the EVM has already moved msg.value into v3Addr before Run, so the precompile
// must credit the OBSERVED surplus over its accounted reserve — never the
// requested amount — and must refuse when the two disagree in either direction.
func TestNative_MintPullsExactDeliveredValue(t *testing.T) {
	L := oneE18
	want0, want1 := mintAmounts(dex.Q96, -600, 600, L)
	require.True(t, want0.Sign() > 0 && want1.Sign() > 0, "the fixture must move both legs")

	// --- under-delivered: one wei short of what the position costs ---
	e := newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err := e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
	e.db().fundNative(v3Addr, new(big.Int).Sub(want0, big.NewInt(1)))
	_, _, err = e.mint(trader, nativePool, -600, 600, L, false)
	require.ErrorIs(t, err, ErrDeltaMismatch, "a short msg.value must be refused, not credited")
	eqBig(t, big.NewInt(0), loadReserve(e.db(), native))

	// --- over-delivered: one wei too much is ALSO refused (never silently kept) ---
	e = newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err = e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
	e.db().fundNative(v3Addr, new(big.Int).Add(want0, big.NewInt(1)))
	_, _, err = e.mint(trader, nativePool, -600, 600, L, false)
	require.ErrorIs(t, err, ErrDeltaMismatch, "an over-delivering msg.value must be refused")

	// --- exact: the only accepted delivery ---
	e = newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err = e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
	e.db().fundNative(v3Addr, want0)
	got0, got1, err := e.mint(trader, nativePool, -600, 600, L, false)
	require.NoError(t, err)
	eqBig(t, want0, got0)
	eqBig(t, want1, got1)

	// The reserve now equals the delivered value exactly, on BOTH legs.
	assertAnchor(t, e.db(), native)
	assertAnchor(t, e.db(), tokenB)
	eqBig(t, want0, loadReserve(e.db(), native))
}

// TestNative_SecondMintMeasuresAgainstReserve proves the delta is taken against
// the ACCOUNTED reserve, not against zero: with value already custodied from an
// earlier mint, a second mint must demand exactly its own cost and no more.
func TestNative_SecondMintMeasuresAgainstReserve(t *testing.T) {
	L := oneE18
	first0, _ := mintAmounts(dex.Q96, -600, 600, L)
	second0, _ := mintAmounts(dex.Q96, -1200, 1200, L)

	e := newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err := e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)

	e.db().fundNative(v3Addr, first0)
	_, _, err = e.mint(trader, nativePool, -600, 600, L, false)
	require.NoError(t, err)

	// Deliver nothing: the surplus over the reserve is 0, so the mint is refused
	// even though v3Addr's raw balance is large.
	_, _, err = e.mint(trader, nativePool, -1200, 1200, L, false)
	require.ErrorIs(t, err, ErrDeltaMismatch, "already-custodied value must not pay for a new mint")

	e.db().fundNative(v3Addr, second0)
	_, _, err = e.mint(trader, nativePool, -1200, 1200, L, false)
	require.NoError(t, err)
	eqBig(t, new(big.Int).Add(first0, second0), loadReserve(e.db(), native))
	assertAnchor(t, e.db(), native)
}

// TestNative_SwapPaysOutNative drives the native OUTBOUND path end to end: a
// oneForZero swap pays the trader in native LUX via SubBalance/AddBalance. The
// pool's native balance must fall by exactly the payout, the trader's must rise
// by exactly the same, and the ledger must track it — no mint, no loss.
func TestNative_SwapPaysOutNative(t *testing.T) {
	L := oneE18
	want0, _ := mintAmounts(dex.Q96, -600, 600, L)

	e := newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err := e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
	e.db().fundNative(v3Addr, want0)
	_, _, err = e.mint(trader, nativePool, -600, 600, L, false)
	require.NoError(t, err)

	poolNativeBefore := e.db().nativeBal(v3Addr)
	traderNativeBefore := e.db().nativeBal(trader)
	totalNativeBefore := new(big.Int).Add(poolNativeBefore, traderNativeBefore)

	// oneForZero exact input: pay tokenB in, receive native out.
	amt := new(big.Int).Neg(mustBig("1000000000000000")) // 1e15
	limit := new(big.Int).Sub(dex.MaxSqrtRatio, big.NewInt(1))
	a0, a1, err := e.swap(trader, nativePool, false, amt, limit)
	require.NoError(t, err)
	require.True(t, a0.Sign() < 0, "native leg is the payout, so amount0 must be negative")
	require.True(t, a1.Sign() > 0)
	paid := new(big.Int).Neg(a0)
	require.True(t, paid.Sign() > 0)

	// Exact movement, both sides, and nothing created or destroyed.
	eqBig(t, new(big.Int).Sub(poolNativeBefore, paid), e.db().nativeBal(v3Addr))
	eqBig(t, new(big.Int).Add(traderNativeBefore, paid), e.db().nativeBal(trader))
	eqBig(t, totalNativeBefore, new(big.Int).Add(e.db().nativeBal(v3Addr), e.db().nativeBal(trader)))
	assertAnchor(t, e.db(), native)
	assertAnchor(t, e.db(), tokenB)
}

// TestNative_SwapPullsNativeIn is the mirror: a zeroForOne swap on a native pool
// takes native IN. The amount is not knowable ahead of the call, so it is read
// off an identically-configured ERC-20 pool — proving, as a side effect, that
// settlement size is a function of the pool parameters and not of the addresses.
func TestNative_SwapPullsNativeIn(t *testing.T) {
	L := oneE18
	amt := new(big.Int).Neg(mustBig("1000000000000000")) // 1e15 exact input
	limit := new(big.Int).Add(dex.MinSqrtRatio, big.NewInt(1))

	// Mirror pool: same fee, spacing, price, liquidity — only the addresses differ.
	mirror := fundedEnv(e18x1000)
	_, _, err := mirror.mint(trader, stdPool, -600, 600, L, false)
	require.NoError(t, err)
	mIn, _, err := mirror.swap(trader, stdPool, true, amt, limit)
	require.NoError(t, err)
	require.True(t, mIn.Sign() > 0)

	want0, _ := mintAmounts(dex.Q96, -600, 600, L)
	e := newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err = e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
	e.db().fundNative(v3Addr, want0)
	_, _, err = e.mint(trader, nativePool, -600, 600, L, false)
	require.NoError(t, err)

	// Deliver exactly the mirror's settlement: the native pool must accept it and
	// credit the reserve by exactly that.
	reserveBefore := loadReserve(e.db(), native)
	e.db().fundNative(v3Addr, mIn)
	a0, a1, err := e.swap(trader, nativePool, true, amt, limit)
	require.NoError(t, err)
	eqBig(t, mIn, a0)
	require.True(t, a1.Sign() < 0)
	eqBig(t, new(big.Int).Add(reserveBefore, mIn), loadReserve(e.db(), native))
	assertAnchor(t, e.db(), native)
	assertAnchor(t, e.db(), tokenB)
}

// TestNative_CollectPaysOutNative walks the burn→collect payout on the native leg
// and asserts the trader ends up with exactly what the pool released.
func TestNative_CollectPaysOutNative(t *testing.T) {
	L := oneE18
	want0, _ := mintAmounts(dex.Q96, -600, 600, L)

	e := newEnv()
	e.db().fund(tokenB, trader, e18x1000)
	_, err := e.initialize(nativePool, dex.Q96, false)
	require.NoError(t, err)
	e.db().fundNative(v3Addr, want0)
	_, _, err = e.mint(trader, nativePool, -600, 600, L, false)
	require.NoError(t, err)

	burn0, burn1, err := e.burn(trader, nativePool, -600, 600, L)
	require.NoError(t, err)
	// Burn credits owed; it must not have moved a single wei yet.
	eqBig(t, want0, e.db().nativeBal(v3Addr))
	eqBig(t, big.NewInt(0), e.db().nativeBal(trader))

	maxU := new(big.Int).Set(maxUint128)
	got0, got1, err := e.collect(trader, nativePool, -600, 600, maxU, maxU)
	require.NoError(t, err)
	eqBig(t, burn0, got0)
	eqBig(t, burn1, got1)
	eqBig(t, got0, e.db().nativeBal(trader))
	// Round-down on both legs means the pool never pays out more than it took in.
	require.Truef(t, got0.Cmp(want0) <= 0, "native payout %s must not exceed the %s taken in", got0, want0)
	assertAnchor(t, e.db(), native)
	assertAnchor(t, e.db(), tokenB)
}

// TestPushOutNative_RefusesBeyondRealBalance is the last line of native defence:
// even with the ledger claiming coverage, a payout larger than the precompile's
// REAL native balance must abort loudly rather than wrap v3Addr's modular
// balance into a huge number.
func TestPushOutNative_RefusesBeyondRealBalance(t *testing.T) {
	m := newMockState()
	m.fundNative(v3Addr, big.NewInt(100))

	require.NoError(t, pushOutNative(m, trader, big.NewInt(100)))
	eqBig(t, big.NewInt(0), m.nativeBal(v3Addr))
	eqBig(t, big.NewInt(100), m.nativeBal(trader))

	// One wei beyond holdings: refused, and nothing moved.
	m.fundNative(v3Addr, big.NewInt(50))
	require.ErrorIs(t, pushOutNative(m, trader, big.NewInt(51)), ErrReserveUnderflow)
	eqBig(t, big.NewInt(50), m.nativeBal(v3Addr))
	eqBig(t, big.NewInt(100), m.nativeBal(trader))

	// A value beyond uint256 cannot even be expressed as a balance: refused too.
	tooBig := new(big.Int).Lsh(big.NewInt(1), 256)
	require.ErrorIs(t, pushOutNative(m, trader, tooBig), ErrTransferFailed)
	eqBig(t, big.NewInt(50), m.nativeBal(v3Addr))
}

// TestPullExactNative_Direct pins the surplus arithmetic itself, including the
// case the entry points cannot produce: a reserve ABOVE the real balance makes
// the delivered surplus negative, which must never compare equal to a positive
// request.
func TestPullExactNative_Direct(t *testing.T) {
	m := newMockState()
	m.fundNative(v3Addr, big.NewInt(1000))

	require.NoError(t, pullExactNative(m, big.NewInt(400), big.NewInt(600)))
	require.ErrorIs(t, pullExactNative(m, big.NewInt(400), big.NewInt(599)), ErrDeltaMismatch)
	require.ErrorIs(t, pullExactNative(m, big.NewInt(400), big.NewInt(601)), ErrDeltaMismatch)

	// Reserve exceeds holdings: surplus is negative, so no positive request matches.
	require.ErrorIs(t, pullExactNative(m, big.NewInt(1500), big.NewInt(1)), ErrDeltaMismatch)
}

// ---------------------------------------------------------------------------
// ERC-20 path — the vault capability, the observed delta, and its refusals.
// ---------------------------------------------------------------------------

// TestVaultUnavailable proves a host StateDB that does not implement the ERC-20
// vault refuses custody cleanly on BOTH directions rather than faking a credit.
func TestVaultUnavailable(t *testing.T) {
	db := newNonVaultState()
	r := newRig(db)
	gas := uint64(50_000_000)

	_, _, err := r.call(trader, inInitialize(stdPool, dex.Q96), gas, false)
	require.NoError(t, err)

	// mint -> pullAsset -> no vault.
	_, _, err = r.call(trader, inMint(stdPool, -600, 600, oneE18), gas, false)
	require.ErrorIs(t, err, ErrVaultUnavailable)

	// payAsset -> no vault. Reach it by crediting owed directly, so the pay-out leg
	// is the first thing that needs the capability.
	poolId := poolIdOf(stdPool)
	posKey := dex.PositionKey(trader, -600, 600, salt)
	pos := loadPosition(db, poolId, posKey)
	pos.TokensOwed0 = big.NewInt(500)
	storePosition(db, poolId, posKey, pos)
	storeReserve(db, tokenA, big.NewInt(500))

	_, _, err = r.call(trader, inCollect(stdPool, -600, 600, big.NewInt(500), big.NewInt(0)), gas, false)
	require.ErrorIs(t, err, ErrVaultUnavailable)
}

// TestDeltaMismatch_FeeOnTransferToken proves the OpenZeppelin-style observed
// delta is what gets credited: a deflationary token that delivers less than the
// pool asked for is REFUSED, never credited at face value. Crediting the request
// instead of the delivery is exactly how a pool becomes insolvent.
func TestDeltaMismatch_FeeOnTransferToken(t *testing.T) {
	db := &shortTransferState{mockState: newMockState(), shortfall: big.NewInt(1)}
	db.fund(tokenA, trader, e18x1000)
	db.fund(tokenB, trader, e18x1000)
	r := newRig(db)
	gas := uint64(50_000_000)

	_, _, err := r.call(trader, inInitialize(stdPool, dex.Q96), gas, false)
	require.NoError(t, err)
	_, _, err = r.call(trader, inMint(stdPool, -600, 600, oneE18), gas, false)
	require.ErrorIs(t, err, ErrDeltaMismatch)

	// Nothing was credited on the leg that under-delivered.
	eqBig(t, big.NewInt(0), loadReserve(db, tokenA))
}

// TestTransferFailed_InsufficientCallerBalance proves a reverting transferFrom
// (the caller simply does not have the tokens) surfaces as ErrTransferFailed and
// credits nothing.
func TestTransferFailed_InsufficientCallerBalance(t *testing.T) {
	e := newEnv()
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)

	// token0 funded, token1 not: the SECOND leg must revert the call.
	want0, _ := mintAmounts(dex.Q96, -600, 600, oneE18)
	e.db().fund(tokenA, trader, want0)

	_, _, err = e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.ErrorIs(t, err, ErrTransferFailed)
	eqBig(t, big.NewInt(0), e.reserve(tokenB))
}

// TestPushOut_TransferReverts proves a failing outbound ERC-20 transfer surfaces
// as ErrTransferFailed. It is reached by corrupting the ledger UPWARD, which is
// the shape of the bug the check exists for: the reserve claims coverage the
// real balance does not have.
func TestPushOut_TransferReverts(t *testing.T) {
	e := fundedEnv(e18x1000)
	_, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)

	poolId := poolIdOf(stdPool)
	posKey := dex.PositionKey(trader, -600, 600, salt)
	pos := loadPosition(e.db(), poolId, posKey)
	inflated := new(big.Int).Add(e.reserve(tokenA), oneE18)
	pos.TokensOwed0 = inflated
	storePosition(e.db(), poolId, posKey, pos)
	storeReserve(e.db(), tokenA, inflated) // ledger now lies about holdings

	_, _, err = e.collect(trader, stdPool, -600, 600, inflated, big.NewInt(0))
	require.ErrorIs(t, err, ErrTransferFailed, "the token itself must stop an unbacked payout")
}

// TestPullExact_Direct pins the observed-delta helper on its own, including the
// over-delivering token (an inflationary rebase mid-transfer), which the entry
// points cannot produce but which must be refused all the same.
func TestPullExact_Direct(t *testing.T) {
	m := newMockState()
	m.fund(tokenA, trader, big.NewInt(1000))

	got, err := pullExact(m, tokenA, trader, v3Addr, big.NewInt(400))
	require.NoError(t, err)
	eqBig(t, big.NewInt(400), got)
	eqBig(t, big.NewInt(400), m.bal(tokenA, v3Addr))

	// Caller cannot cover it.
	_, err = pullExact(m, tokenA, trader, v3Addr, big.NewInt(10_000))
	require.ErrorIs(t, err, ErrTransferFailed)

	// Over-delivery is refused as firmly as under-delivery.
	over := &overTransferState{mockState: m, surplus: big.NewInt(3)}
	_, err = pullExact(over, tokenA, trader, v3Addr, big.NewInt(100))
	require.ErrorIs(t, err, ErrDeltaMismatch)
}

// overTransferState is an inflationary token: transferFrom delivers MORE than
// requested. Only used by TestPullExact_Direct.
type overTransferState struct {
	*mockState
	surplus *big.Int
}

func (o *overTransferState) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if err := o.mockState.TransferTokenFrom(token, from, to, amount); err != nil {
		return err
	}
	o.setBal(token, to, new(big.Int).Add(o.bal(token, to), o.surplus))
	return nil
}

// TestPushOut_Direct pins the outbound ERC-20 helper's success and failure.
func TestPushOut_Direct(t *testing.T) {
	m := newMockState()
	m.fund(tokenA, v3Addr, big.NewInt(500))

	require.NoError(t, pushOut(m, tokenA, trader, big.NewInt(200)))
	eqBig(t, big.NewInt(300), m.bal(tokenA, v3Addr))
	eqBig(t, big.NewInt(200), m.bal(tokenA, trader))

	require.ErrorIs(t, pushOut(m, tokenA, trader, big.NewInt(301)), ErrTransferFailed)
	eqBig(t, big.NewInt(300), m.bal(tokenA, v3Addr))
}

// ---------------------------------------------------------------------------
// The reserve ledger itself.
// ---------------------------------------------------------------------------

// TestSubReserve_UnderflowAborts proves the conservation backstop refuses rather
// than wrapping. A modular subtraction here would turn a 1-wei overdraw into a
// ~2^256 reserve — the classic underflow that lets a pool be drained.
func TestSubReserve_UnderflowAborts(t *testing.T) {
	m := newMockState()
	storeReserve(m, tokenA, big.NewInt(100))

	require.False(t, subReserve(m, tokenA, big.NewInt(101)), "overdraw must be refused")
	require.Zerof(t, big.NewInt(100).Cmp(loadReserve(m, tokenA)),
		"a refused debit must leave the ledger untouched, got %s", loadReserve(m, tokenA))

	require.True(t, subReserve(m, tokenA, big.NewInt(100)), "an exact debit is allowed")
	eqBig(t, big.NewInt(0), loadReserve(m, tokenA))

	// At zero, any positive debit is refused and the ledger stays at zero — never
	// wraps to 2^256-1.
	require.False(t, subReserve(m, tokenA, big.NewInt(1)))
	eqBig(t, big.NewInt(0), loadReserve(m, tokenA))
	require.True(t, loadReserve(m, tokenA).Sign() >= 0)
}

// TestPayAsset_ReserveUnderflowRefused proves the ledger check fires BEFORE any
// value moves: an unbacked payout must abort with the reserve and both balances
// exactly as they were.
func TestPayAsset_ReserveUnderflowRefused(t *testing.T) {
	// ERC-20 leg: the vault could physically pay (v3Addr holds the tokens) but the
	// ledger says they are not this pool's to give.
	m := newMockState()
	m.fund(tokenA, v3Addr, big.NewInt(1000))
	storeReserve(m, tokenA, big.NewInt(10))

	require.ErrorIs(t, payAsset(m, tokenA, trader, big.NewInt(11)), ErrReserveUnderflow)
	eqBig(t, big.NewInt(10), loadReserve(m, tokenA))
	eqBig(t, big.NewInt(1000), m.bal(tokenA, v3Addr))
	eqBig(t, big.NewInt(0), m.bal(tokenA, trader))

	// Native leg: same refusal.
	m.fundNative(v3Addr, big.NewInt(1000))
	storeReserve(m, native, big.NewInt(10))
	require.ErrorIs(t, payAsset(m, native, trader, big.NewInt(11)), ErrReserveUnderflow)
	eqBig(t, big.NewInt(1000), m.nativeBal(v3Addr))
	eqBig(t, big.NewInt(0), m.nativeBal(trader))
}

// TestZeroAmountIsANoOp proves both money paths short-circuit on zero without
// touching the ledger, the vault, or the native balance — so a zero-value leg of
// a single-sided position never needs a vault capability at all.
func TestZeroAmountIsANoOp(t *testing.T) {
	db := newNonVaultState() // no vault: any real move would fail here
	require.NoError(t, pullAsset(db, tokenA, trader, big.NewInt(0)))
	require.NoError(t, payAsset(db, tokenA, trader, big.NewInt(0)))
	require.NoError(t, pullAsset(db, native, trader, big.NewInt(0)))
	require.NoError(t, payAsset(db, native, trader, big.NewInt(0)))
	eqBig(t, big.NewInt(0), loadReserve(db, tokenA))
	eqBig(t, big.NewInt(0), loadReserve(db, native))
}

// TestSingleSidedPositionMovesOneLegOnly proves the zero short-circuit on a real
// call: a position entirely above the current price is funded in token1 only, so
// the token0 reserve must stay at zero and the caller must need no token0.
func TestSingleSidedPositionMovesOneLegOnly(t *testing.T) {
	e := newEnv()
	e.db().fund(tokenB, trader, e18x1000) // deliberately NO tokenA
	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)

	// [-1200, -600] is entirely BELOW the price, so it costs token1 only.
	a0, a1, err := e.mint(trader, stdPool, -1200, -600, oneE18, false)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), a0)
	require.True(t, a1.Sign() > 0)
	eqBig(t, big.NewInt(0), e.reserve(tokenA))
	assertCustodyConsistent(t, e)

	// [600, 1200] is entirely ABOVE the price, so it costs token0 only — and the
	// trader has none, which is what makes the leg observable.
	_, _, err = e.mint(trader, stdPool, 600, 1200, oneE18, false)
	require.ErrorIs(t, err, ErrTransferFailed)
}

// TestReserveIsGlobalAcrossPools proves the reserve is keyed by ASSET, not by
// pool: it shadows the precompile's real balance of that asset, which is shared.
// Two pools over the same token must sum into one ledger entry, or the anchor
// (reserve == balanceOf) cannot hold.
func TestReserveIsGlobalAcrossPools(t *testing.T) {
	e := newEnv()
	e.db().fund(tokenA, trader, e18x1000)
	e.db().fund(tokenB, trader, e18x1000)
	e.db().fund(tokenC, trader, e18x1000)
	other := poolCfg{c0: tokenA, c1: tokenC, fee: uint32(dex.Fee030), tickSpacing: int32(dex.TickSpacing030)}

	_, err := e.initialize(stdPool, dex.Q96, false)
	require.NoError(t, err)
	_, err = e.initialize(other, dex.Q96, false)
	require.NoError(t, err)

	a0, _, err := e.mint(trader, stdPool, -600, 600, oneE18, false)
	require.NoError(t, err)
	b0, _, err := e.mint(trader, other, -600, 600, oneE18, false)
	require.NoError(t, err)

	eqBig(t, new(big.Int).Add(a0, b0), e.reserve(tokenA))
	eqBig(t, e.db().bal(tokenA, v3Addr), e.reserve(tokenA))
}

// TestNativeBalanceCodecRoundTrip guards the uint256 boundary the native path
// crosses on every call: the balance the precompile reads must be the value the
// host holds, at the very top of the range.
func TestNativeBalanceCodecRoundTrip(t *testing.T) {
	m := newMockState()
	maxU256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	m.setNative(v3Addr, maxU256)
	eqBig(t, maxU256, m.GetBalance(v3Addr).ToBig())

	// And the subtract path leaves exactly the remainder.
	m.SubBalance(v3Addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	eqBig(t, new(big.Int).Sub(maxU256, big.NewInt(1)), m.nativeBal(v3Addr))
}

// TestSingleSidedPositionBurnsAndCollectsItsPrincipal proves a position funded
// on ONE leg gets that leg back. A position entirely outside the current price
// costs exactly one token, so the other leg's principal is legitimately zero —
// and a credit rule that demanded BOTH legs be non-zero would silently strand
// the LP's whole deposit in the pool with no way to withdraw it.
func TestSingleSidedPositionBurnsAndCollectsItsPrincipal(t *testing.T) {
	maxU := new(big.Int).Set(maxUint128)

	// --- entirely BELOW the price: funded in token1 only ---
	e := fundedEnv(e18x1000)
	before1 := e.db().bal(tokenB, trader)
	a0, a1, err := e.mint(trader, stdPool, -1200, -600, oneE18, false)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), a0)
	require.True(t, a1.Sign() > 0)

	b0, b1, err := e.burn(trader, stdPool, -1200, -600, oneE18)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), b0)
	eqBig(t, a1, b1)

	// The credit landed: owed must hold the freed principal, not zero.
	_, owed0, owed1 := e.positionOf(trader, stdPool, -1200, -600)
	eqBig(t, big.NewInt(0), owed0)
	eqBig(t, a1, owed1)

	c0, c1, err := e.collect(trader, stdPool, -1200, -600, maxU, maxU)
	require.NoError(t, err)
	eqBig(t, big.NewInt(0), c0)
	eqBig(t, a1, c1)
	eqBig(t, before1, e.db().bal(tokenB, trader))
	assertCustodyConsistent(t, e)

	// --- entirely ABOVE the price: funded in token0 only ---
	e2 := fundedEnv(e18x1000)
	before0 := e2.db().bal(tokenA, trader)
	a0, a1, err = e2.mint(trader, stdPool, 600, 1200, oneE18, false)
	require.NoError(t, err)
	require.True(t, a0.Sign() > 0)
	eqBig(t, big.NewInt(0), a1)

	b0, b1, err = e2.burn(trader, stdPool, 600, 1200, oneE18)
	require.NoError(t, err)
	eqBig(t, a0, b0)
	eqBig(t, big.NewInt(0), b1)

	c0, c1, err = e2.collect(trader, stdPool, 600, 1200, maxU, maxU)
	require.NoError(t, err)
	eqBig(t, a0, c0)
	eqBig(t, big.NewInt(0), c1)
	eqBig(t, before0, e2.db().bal(tokenA, trader))
	assertCustodyConsistent(t, e2)
}
