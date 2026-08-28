// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// zzmop_transmuter_test.go covers transmuter.go — the liquid-token exit: stakers put
// liquid in, underlying flows into the buffer, and the accrued share converts pro rata.
//
// The properties under test are VALUE CONSERVATION and ROUNDING DIRECTION:
//   - a claim never exceeds the buffer that backs it (no mint);
//   - an unstake never returns more than was staked;
//   - both divisions (the exchange-rate bump and the pro-rata accrual) FLOOR, i.e. they
//     round toward the protocol — the staker is never credited a fractional unit the
//     buffer does not hold.

var (
	zzmpLiquid     = common.HexToAddress("0x0000000000000000000000000000000000004C51")
	zzmpUnderlying = Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000055D0")}
	zzmpStaker     = common.HexToAddress("0x0000000000000000000000000000000000005747")
)

// zzmpTransmuter returns a Transmuter with zzmpLiquid initialized and the staker funded.
func zzmpTransmuter(t *testing.T, fund int64) (*Transmuter, *MockStateDB) {
	t.Helper()
	tr := NewTransmuter(nil)
	db := NewMockStateDB()
	if err := tr.InitializeTransmuter(db, zzmpLiquid, zzmpUnderlying); err != nil {
		t.Fatalf("InitializeTransmuter: %v", err)
	}
	if fund > 0 {
		db.AddBalance(zzmpStaker, uint256.NewInt(uint64(fund)))
	}
	return tr, db
}

// ---------------------------------------------------------------------------
// registration
// ---------------------------------------------------------------------------

// TestZzmpTransmuterRegistrationIsOnceAndGatesEveryOperation pins the registry: a second
// InitializeTransmuter for the same liquid token is refused, and EVERY operation against
// an unregistered token fails closed rather than acting on a zero state.
func TestZzmpTransmuterRegistrationIsOnceAndGatesEveryOperation(t *testing.T) {
	tr := NewTransmuter(nil)
	db := NewMockStateDB()
	other := common.HexToAddress("0x00000000000000000000000000000000000000FF")

	// Unregistered: every mutating op refuses, every view returns the neutral value.
	if err := tr.Stake(db, zzmpStaker, other, big.NewInt(1)); !errors.Is(err, ErrLiquidTokenNotRegistered) {
		t.Fatalf("Stake on an unregistered token: want ErrLiquidTokenNotRegistered, got %v", err)
	}
	if err := tr.Unstake(db, zzmpStaker, other, big.NewInt(1)); !errors.Is(err, ErrLiquidTokenNotRegistered) {
		t.Fatalf("Unstake on an unregistered token: want ErrLiquidTokenNotRegistered, got %v", err)
	}
	if _, err := tr.Claim(db, zzmpStaker, other); !errors.Is(err, ErrLiquidTokenNotRegistered) {
		t.Fatalf("Claim on an unregistered token: want ErrLiquidTokenNotRegistered, got %v", err)
	}
	if err := tr.Deposit(db, other, big.NewInt(1)); !errors.Is(err, ErrLiquidTokenNotRegistered) {
		t.Fatalf("Deposit on an unregistered token: want ErrLiquidTokenNotRegistered, got %v", err)
	}
	if got := tr.GetClaimable(db, zzmpStaker, other); got.Sign() != 0 {
		t.Fatalf("GetClaimable on an unregistered token: want 0, got %s", got)
	}
	if got := tr.GetExchangeRate(other); got.Cmp(Q96) != 0 {
		t.Fatalf("GetExchangeRate on an unregistered token: want the 1:1 rate Q96, got %s", got)
	}
	if got := tr.GetLiquidFXState(other); got != nil {
		t.Fatalf("GetLiquidFXState on an unregistered token: want nil, got %+v", got)
	}

	// Registration initializes the state at a 1:1 rate with empty pots.
	if err := tr.InitializeTransmuter(db, zzmpLiquid, zzmpUnderlying); err != nil {
		t.Fatalf("InitializeTransmuter: %v", err)
	}
	st := tr.GetLiquidFXState(zzmpLiquid)
	if st == nil || st.ExchangeRate.Cmp(Q96) != 0 || st.ExchangeBuffer.Sign() != 0 || st.TotalStaked.Sign() != 0 {
		t.Fatalf("fresh transmuter state: %+v", st)
	}
	if st.UnderlyingAsset != zzmpUnderlying || st.LiquidToken != zzmpLiquid {
		t.Fatalf("transmuter state identity: %+v", st)
	}
	if got := tr.GetExchangeRate(zzmpLiquid); got.Cmp(Q96) != 0 {
		t.Fatalf("initial exchange rate: want Q96, got %s", got)
	}
	// The returned rate is a COPY — a caller cannot move the protocol's rate.
	tr.GetExchangeRate(zzmpLiquid).SetInt64(1)
	if got := tr.GetExchangeRate(zzmpLiquid); got.Cmp(Q96) != 0 {
		t.Fatalf("GetExchangeRate returned an alias into the live state: %s", got)
	}

	// A second registration is refused and does NOT reset the live state.
	st.ExchangeBuffer = big.NewInt(999)
	if err := tr.InitializeTransmuter(db, zzmpLiquid, zzmpUnderlying); !errors.Is(err, ErrLiquidTokenNotRegistered) {
		t.Fatalf("re-registration: want ErrLiquidTokenNotRegistered, got %v", err)
	}
	if got := tr.GetLiquidFXState(zzmpLiquid).ExchangeBuffer; got.Int64() != 999 {
		t.Fatalf("a refused re-registration reset the live buffer to %s", got)
	}
}

// ---------------------------------------------------------------------------
// stake / unstake
// ---------------------------------------------------------------------------

func TestZzmpStakeRefusesNonPositiveAndMovesRealValue(t *testing.T) {
	tr, db := zzmpTransmuter(t, 1_000)

	for _, amount := range []*big.Int{big.NewInt(0), big.NewInt(-1)} {
		if err := tr.Stake(db, zzmpStaker, zzmpLiquid, amount); !errors.Is(err, ErrInvalidPositionSize) {
			t.Fatalf("Stake(%s): want ErrInvalidPositionSize, got %v", amount, err)
		}
	}
	if got := tr.GetLiquidFXState(zzmpLiquid).TotalStaked; got.Sign() != 0 {
		t.Fatalf("a refused stake moved totalStaked to %s", got)
	}

	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(400)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// The liquid token really leaves the staker and lands with the transmuter.
	if got := db.GetBalance(zzmpStaker).Uint64(); got != 600 {
		t.Fatalf("staker balance after staking 400 of 1000: want 600, got %d", got)
	}
	if got := db.GetBalance(transmuterAddr).Uint64(); got != 400 {
		t.Fatalf("transmuter balance: want 400, got %d", got)
	}
	stake := tr.GetStake(db, zzmpStaker, zzmpLiquid)
	if stake == nil || stake.StakedAmount.Int64() != 400 || stake.UnclaimedAmount.Sign() != 0 {
		t.Fatalf("stake record: %+v", stake)
	}
	if stake.Owner != zzmpStaker || stake.LiquidToken != zzmpLiquid {
		t.Fatalf("stake identity: %+v", stake)
	}
	if got := tr.GetLiquidFXState(zzmpLiquid).TotalStaked.Int64(); got != 400 {
		t.Fatalf("totalStaked: want 400, got %d", got)
	}

	// A second stake accumulates onto the SAME record.
	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(600)); err != nil {
		t.Fatalf("second Stake: %v", err)
	}
	if got := tr.GetStake(db, zzmpStaker, zzmpLiquid).StakedAmount.Int64(); got != 1_000 {
		t.Fatalf("accumulated stake: want 1000, got %d", got)
	}
	if got := tr.GetLiquidFXState(zzmpLiquid).TotalStaked.Int64(); got != 1_000 {
		t.Fatalf("totalStaked after both: want 1000, got %d", got)
	}
}

// TestZzmpUnstakeClampsToTheStakeAndConservesValue pins the exit bound: an over-ask
// returns exactly what was staked and never more, and the liquid really comes back.
func TestZzmpUnstakeClampsToTheStakeAndConservesValue(t *testing.T) {
	tr, db := zzmpTransmuter(t, 1_000)

	// Nothing staked yet -> nothing to unstake.
	if err := tr.Unstake(db, zzmpStaker, zzmpLiquid, big.NewInt(1)); !errors.Is(err, ErrInvalidPositionSize) {
		t.Fatalf("Unstake with no stake: want ErrInvalidPositionSize, got %v", err)
	}

	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(1_000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// An over-ask is clamped to the stake — a staker cannot pull other stakers' liquid.
	if err := tr.Unstake(db, zzmpStaker, zzmpLiquid, big.NewInt(10_000)); err != nil {
		t.Fatalf("Unstake: %v", err)
	}
	if got := db.GetBalance(zzmpStaker).Uint64(); got != 1_000 {
		t.Fatalf("staker got %d back — the clamp must return exactly the 1000 staked", got)
	}
	if got := db.GetBalance(transmuterAddr).Uint64(); got != 0 {
		t.Fatalf("transmuter still holds %d after a full unstake", got)
	}
	if got := tr.GetStake(db, zzmpStaker, zzmpLiquid).StakedAmount.Sign(); got != 0 {
		t.Fatalf("stake after a full unstake: want 0, got %d", got)
	}
	if got := tr.GetLiquidFXState(zzmpLiquid).TotalStaked.Sign(); got != 0 {
		t.Fatalf("totalStaked after a full unstake: want 0, got %d", got)
	}
	// A drained stake refuses again (nothing left to exit).
	if err := tr.Unstake(db, zzmpStaker, zzmpLiquid, big.NewInt(1)); !errors.Is(err, ErrInvalidPositionSize) {
		t.Fatalf("Unstake of a drained stake: want ErrInvalidPositionSize, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// deposit / accrual — rounding direction
// ---------------------------------------------------------------------------

// TestZzmpDepositIgnoresNonPositiveAndOnlyMovesTheRateWithStakers pins both guards on
// the yield inflow: a non-positive deposit is a no-op, and with NO stakers the buffer
// still grows but the rate cannot (dividing by a zero stake is undefined).
func TestZzmpDepositIgnoresNonPositiveAndOnlyMovesTheRateWithStakers(t *testing.T) {
	tr, db := zzmpTransmuter(t, 1_000)

	for _, amount := range []*big.Int{big.NewInt(0), big.NewInt(-7)} {
		if err := tr.Deposit(db, zzmpLiquid, amount); err != nil {
			t.Fatalf("Deposit(%s) must be a silent no-op, got %v", amount, err)
		}
	}
	st := tr.GetLiquidFXState(zzmpLiquid)
	if st.ExchangeBuffer.Sign() != 0 || st.ExchangeRate.Cmp(Q96) != 0 {
		t.Fatalf("a non-positive deposit moved the state: %+v", st)
	}

	// With no stakers the buffer grows but the rate does not (nothing to divide over).
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(500)); err != nil {
		t.Fatalf("Deposit with no stakers: %v", err)
	}
	if got := tr.GetLiquidFXState(zzmpLiquid).ExchangeBuffer.Int64(); got != 500 {
		t.Fatalf("buffer after a staker-less deposit: want 500, got %d", got)
	}
	if got := tr.GetExchangeRate(zzmpLiquid); got.Cmp(Q96) != 0 {
		t.Fatalf("the rate moved with no stakers: %s", got)
	}

	// With stakers the rate rises by exactly floor(amount * Q96 / totalStaked).
	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(1_000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	before := tr.GetExchangeRate(zzmpLiquid)
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(300)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	want := new(big.Int).Add(before, new(big.Int).Div(new(big.Int).Mul(big.NewInt(300), Q96), big.NewInt(1_000)))
	if got := tr.GetExchangeRate(zzmpLiquid); got.Cmp(want) != 0 {
		t.Fatalf("exchange rate after a deposit: want %s, got %s", want, got)
	}
}

// TestZzmpExchangeRateBumpFloorsTowardTheProtocol pins the rounding DIRECTION of the
// rate bump: floor(amount * Q96 / totalStaked). Rounding up would credit stakers value
// the buffer does not hold, so the remainder must stay with the protocol.
func TestZzmpExchangeRateBumpFloorsTowardTheProtocol(t *testing.T) {
	// totalStaked = 3 does not divide Q96 evenly, so 1 unit of underlying leaves a
	// remainder the protocol must keep.
	tr, db := zzmpTransmuter(t, 3)
	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(3)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(1)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	exact := new(big.Int).Mul(big.NewInt(1), Q96)
	floorInc, rem := new(big.Int).QuoRem(exact, big.NewInt(3), new(big.Int))
	if rem.Sign() == 0 {
		t.Fatal("precondition: the division must have a remainder to test the direction")
	}
	wantFloor := new(big.Int).Add(Q96, floorInc)
	wantCeil := new(big.Int).Add(wantFloor, big.NewInt(1))
	got := tr.GetExchangeRate(zzmpLiquid)
	if got.Cmp(wantFloor) != 0 {
		t.Fatalf("rate bump = %s; it must FLOOR to %s (ceiling %s would over-credit stakers)", got, wantFloor, wantCeil)
	}

	// The accrual back out of the rate floors too: floor(staked * rateDiff / Q96).
	claimable := tr.GetClaimable(db, zzmpStaker, zzmpLiquid)
	wantAccrual := new(big.Int).Div(new(big.Int).Mul(big.NewInt(3), floorInc), Q96)
	if claimable.Cmp(wantAccrual) != 0 {
		t.Fatalf("claimable = %s, want the floored accrual %s", claimable, wantAccrual)
	}
	// Round-trip conservation: the staker can never accrue more than was deposited.
	if claimable.Cmp(big.NewInt(1)) > 0 {
		t.Fatalf("a 1-unit deposit produced %s of claimable value (a mint)", claimable)
	}
}

// TestZzmpClaimNeverExceedsTheBuffer is the no-mint invariant on the exit leg: the
// claim is capped at the underlying the transmuter actually holds.
func TestZzmpClaimNeverExceedsTheBuffer(t *testing.T) {
	tr, db := zzmpTransmuter(t, 1_000)

	// A staker with no record at all cannot claim.
	if _, err := tr.Claim(db, zzmpStaker, zzmpLiquid); !errors.Is(err, ErrTransmuterEmpty) {
		t.Fatalf("Claim with no stake: want ErrTransmuterEmpty, got %v", err)
	}

	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(1_000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// A staker with nothing accrued claims zero, with no error and no value moved.
	got, err := tr.Claim(db, zzmpStaker, zzmpLiquid)
	if err != nil || got.Sign() != 0 {
		t.Fatalf("Claim with nothing accrued: want 0/nil, got %s/%v", got, err)
	}

	// Accrue 400 of underlying, then drain the buffer behind the staker's back: the
	// claim must clamp to what is really there rather than mint the difference.
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(400)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	// The accrual runs through TWO floors — the rate bump floor(deposit*Q96/staked) and
	// the pro-rata floor(staked*rateDiff/Q96) — so the staker accrues at most the
	// deposit and the residue stays with the protocol. Assert the DIRECTION (never more
	// than was deposited) and the exact double-floor value, not a round figure.
	rateInc := new(big.Int).Div(new(big.Int).Mul(big.NewInt(400), Q96), big.NewInt(1_000))
	accrued := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1_000), rateInc), Q96)
	if accrued.Cmp(big.NewInt(400)) > 0 {
		t.Fatalf("the reference accrual %s exceeds the 400 deposited — rounding must favour the protocol", accrued)
	}
	claimable := tr.GetClaimable(db, zzmpStaker, zzmpLiquid)
	if claimable.Cmp(accrued) != 0 {
		t.Fatalf("claimable = %s, want the double-floored %s", claimable, accrued)
	}
	if claimable.Cmp(big.NewInt(400)) > 0 {
		t.Fatalf("claimable %s exceeds the 400 deposited (a mint)", claimable)
	}
	if claimable.Sign() <= 0 {
		t.Fatalf("claimable collapsed to %s", claimable)
	}
	tr.GetLiquidFXState(zzmpLiquid).ExchangeBuffer = big.NewInt(150)
	if claimable := tr.GetClaimable(db, zzmpStaker, zzmpLiquid); claimable.Int64() != 150 {
		t.Fatalf("GetClaimable must cap at the buffer: want 150, got %s", claimable)
	}

	db.AddBalance(transmuterAddr, uint256.NewInt(150)) // the underlying the buffer stands for
	before := db.GetBalance(zzmpStaker).Uint64()
	claimed, err := tr.Claim(db, zzmpStaker, zzmpLiquid)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.Int64() != 150 {
		t.Fatalf("Claim returned %s — it must clamp to the 150 the buffer holds", claimed)
	}
	if got := db.GetBalance(zzmpStaker).Uint64(); got != before+150 {
		t.Fatalf("staker balance after the claim: want %d, got %d", before+150, got)
	}
	st := tr.GetLiquidFXState(zzmpLiquid)
	if st.ExchangeBuffer.Sign() != 0 {
		t.Fatalf("buffer after the clamped claim: want 0, got %s", st.ExchangeBuffer)
	}
	// The unclaimed remainder stays owed to the staker; it is not silently dropped.
	wantOwed := new(big.Int).Sub(accrued, big.NewInt(150))
	if got := tr.GetStake(db, zzmpStaker, zzmpLiquid).UnclaimedAmount; got.Cmp(wantOwed) != 0 {
		t.Fatalf("unclaimed remainder: want %s still owed, got %s", wantOwed, got)
	}
	// With an empty buffer a second claim moves nothing.
	if got, err := tr.Claim(db, zzmpStaker, zzmpLiquid); err != nil || got.Sign() != 0 {
		t.Fatalf("Claim against an empty buffer: want 0/nil, got %s/%v", got, err)
	}
	if got := db.GetBalance(zzmpStaker).Uint64(); got != before+150 {
		t.Fatalf("a buffer-less claim paid out again: %d", got)
	}
}

// TestZzmpFullConversionBurnsTheWholeStake pins the terminal accrual case: when the
// accrued underlying reaches (or passes) the staked amount, the whole stake converts and
// the record's staked balance goes to exactly zero — never negative.
func TestZzmpFullConversionBurnsTheWholeStake(t *testing.T) {
	tr, db := zzmpTransmuter(t, 100)
	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// Deposit far more underlying than the stake: the conversion saturates.
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(1_000)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	db.AddBalance(transmuterAddr, uint256.NewInt(1_000))

	claimed, err := tr.Claim(db, zzmpStaker, zzmpLiquid)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.Int64() != 1_000 {
		t.Fatalf("claimed %s, want the full 1000 accrued", claimed)
	}
	stake := tr.GetStake(db, zzmpStaker, zzmpLiquid)
	if stake.StakedAmount.Sign() != 0 {
		t.Fatalf("a fully converted stake must burn to 0, got %s", stake.StakedAmount)
	}
	if stake.StakedAmount.Sign() < 0 {
		t.Fatalf("the staked amount went NEGATIVE: %s", stake.StakedAmount)
	}
	if stake.UnclaimedAmount.Sign() != 0 {
		t.Fatalf("unclaimed after a full claim: want 0, got %s", stake.UnclaimedAmount)
	}
	// A converted staker accrues nothing more from later deposits.
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(500)); err != nil {
		t.Fatalf("later Deposit: %v", err)
	}
	if got := tr.GetClaimable(db, zzmpStaker, zzmpLiquid); got.Sign() != 0 {
		t.Fatalf("a fully converted stake still accrued %s", got)
	}
}

// TestZzmpUpdateStakeUnclaimedIsAMonotoneNoOpWithoutRateGrowth pins the accrual guard
// directly: a zero stake or a non-increasing rate accrues nothing, so replaying the
// update can never inflate the unclaimed balance.
func TestZzmpUpdateStakeUnclaimedIsAMonotoneNoOpWithoutRateGrowth(t *testing.T) {
	tr := NewTransmuter(nil)
	state := &LiquidFXState{ExchangeRate: new(big.Int).Set(Q96), ExchangeBuffer: big.NewInt(0), TotalStaked: big.NewInt(0)}

	// A zero stake accrues nothing (and does not touch LastUpdateIndex).
	zero := &TransmuterStake{StakedAmount: big.NewInt(0), UnclaimedAmount: big.NewInt(0), LastUpdateIndex: big.NewInt(0)}
	tr.updateStakeUnclaimed(zero, state)
	if zero.UnclaimedAmount.Sign() != 0 || zero.LastUpdateIndex.Sign() != 0 {
		t.Fatalf("a zero stake accrued: %+v", zero)
	}

	// A rate that has NOT moved (or has moved backwards) accrues nothing.
	for _, last := range []*big.Int{new(big.Int).Set(Q96), new(big.Int).Add(Q96, big.NewInt(1))} {
		s := &TransmuterStake{StakedAmount: big.NewInt(100), UnclaimedAmount: big.NewInt(0), LastUpdateIndex: last}
		tr.updateStakeUnclaimed(s, state)
		if s.UnclaimedAmount.Sign() != 0 {
			t.Fatalf("a non-increasing rate accrued %s", s.UnclaimedAmount)
		}
		if s.StakedAmount.Int64() != 100 {
			t.Fatalf("a non-increasing rate burned stake down to %s", s.StakedAmount)
		}
	}

	// A rate that DID move accrues exactly once: replaying is idempotent because the
	// index advances with the accrual.
	state.ExchangeRate = new(big.Int).Add(Q96, new(big.Int).Div(Q96, big.NewInt(2))) // +0.5
	s := &TransmuterStake{StakedAmount: big.NewInt(100), UnclaimedAmount: big.NewInt(0), LastUpdateIndex: new(big.Int).Set(Q96)}
	tr.updateStakeUnclaimed(s, state)
	if s.UnclaimedAmount.Int64() != 50 {
		t.Fatalf("accrual: want 50, got %s", s.UnclaimedAmount)
	}
	if s.StakedAmount.Int64() != 50 {
		t.Fatalf("converted stake: want 50 left, got %s", s.StakedAmount)
	}
	tr.updateStakeUnclaimed(s, state)
	if s.UnclaimedAmount.Int64() != 50 {
		t.Fatalf("replaying the accrual inflated unclaimed to %s", s.UnclaimedAmount)
	}
}

// TestZzmpGetClaimableMatchesTheRealizedClaim pins the view against the mutator: what
// GetClaimable reports is exactly what Claim pays out, for a buffer that covers it.
func TestZzmpGetClaimableMatchesTheRealizedClaim(t *testing.T) {
	tr, db := zzmpTransmuter(t, 1_000)
	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(777)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	if err := tr.Deposit(db, zzmpLiquid, big.NewInt(333)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	db.AddBalance(transmuterAddr, uint256.NewInt(333))

	predicted := tr.GetClaimable(db, zzmpStaker, zzmpLiquid)
	claimed, err := tr.Claim(db, zzmpStaker, zzmpLiquid)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.Cmp(predicted) != 0 {
		t.Fatalf("GetClaimable predicted %s but Claim paid %s", predicted, claimed)
	}
	// After the claim the view reports nothing left.
	if got := tr.GetClaimable(db, zzmpStaker, zzmpLiquid); got.Sign() != 0 {
		t.Fatalf("claimable after a full claim: want 0, got %s", got)
	}
	// A staker who never staked has nothing claimable (a nil record, not a panic).
	if got := tr.GetClaimable(db, common.HexToAddress("0x00000000000000000000000000000000000000AA"), zzmpLiquid); got.Sign() != 0 {
		t.Fatalf("claimable for a non-staker: want 0, got %s", got)
	}
}

// TestZzmpStakeKeyIsInjectiveAndDeterministic pins the record key: the same (liquid,
// owner) pair always derives the same slot, and distinct pairs never collide — including
// the swapped pair, which a naive concatenation would alias.
func TestZzmpStakeKeyIsInjectiveAndDeterministic(t *testing.T) {
	a := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	b := common.HexToAddress("0x00000000000000000000000000000000000000B2")

	first := stakeKey(a, b)
	for i := 0; i < 256; i++ {
		if got := stakeKey(a, b); got != first {
			t.Fatalf("stakeKey is not deterministic on iteration %d", i)
		}
	}
	if stakeKey(a, b) == stakeKey(b, a) {
		t.Fatal("stakeKey aliases the (liquid, owner) pair with its reverse")
	}
	seen := map[[32]byte]bool{}
	for _, liquid := range []common.Address{a, b, {}} {
		for _, owner := range []common.Address{a, b, {}} {
			k := stakeKey(liquid, owner)
			if seen[k] {
				t.Fatalf("stakeKey collided for (%s, %s)", liquid.Hex(), owner.Hex())
			}
			seen[k] = true
		}
	}
	// Two stakers of the same token keep independent records.
	tr, db := zzmpTransmuter(t, 0)
	db.AddBalance(a, uint256.NewInt(100))
	db.AddBalance(b, uint256.NewInt(200))
	if err := tr.Stake(db, a, zzmpLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake a: %v", err)
	}
	if err := tr.Stake(db, b, zzmpLiquid, big.NewInt(200)); err != nil {
		t.Fatalf("Stake b: %v", err)
	}
	if got := tr.GetStake(db, a, zzmpLiquid).StakedAmount.Int64(); got != 100 {
		t.Fatalf("staker a's record: want 100, got %d", got)
	}
	if got := tr.GetStake(db, b, zzmpLiquid).StakedAmount.Int64(); got != 200 {
		t.Fatalf("staker b's record: want 200, got %d", got)
	}
}

// TestZzmpColdStakeReadIsNotValuePreserving is a DEFECT WITNESS, not an endorsement.
// saveStake left-aligns the minimal big-endian bytes into data[:16] / data[16:], while
// getStake reads each half as a full 16-byte big-endian integer, so a stake persisted by
// one process and read back by a FRESH Transmuter (empty in-memory cache) is scaled by
// 2^(8*(16-len(bytes))). The test pins the exact current decode so a fix to the encoding
// visibly flips it.
func TestZzmpColdStakeReadIsNotValuePreserving(t *testing.T) {
	tr, db := zzmpTransmuter(t, 1_000)
	if err := tr.Stake(db, zzmpStaker, zzmpLiquid, big.NewInt(5)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	if got := tr.GetStake(db, zzmpStaker, zzmpLiquid).StakedAmount.Int64(); got != 5 {
		t.Fatalf("the in-process record must read back exactly: want 5, got %d", got)
	}

	// A FRESH manager over the SAME state reads the persisted bytes.
	cold := NewTransmuter(nil)
	got := cold.GetStake(db, zzmpStaker, zzmpLiquid)
	if got == nil {
		t.Fatal("a cold read found no persisted stake at all")
	}
	// 5 encodes as the single byte 0x05 left-aligned in a 16-byte half, i.e. 5 << 120.
	scaled := new(big.Int).Lsh(big.NewInt(5), 120)
	if got.StakedAmount.Cmp(scaled) != 0 {
		t.Fatalf("cold-read staked amount = %s; the persisted encoding currently decodes to %s "+
			"(saveStake left-aligns minimal bytes, getStake reads a full 16-byte integer). "+
			"If the encoding has been fixed, this witness must be updated to assert 5.",
			got.StakedAmount, scaled)
	}
	// A cold read also restores the neutral 1:1 index rather than the live rate.
	if got.LastUpdateIndex.Cmp(Q96) != 0 {
		t.Fatalf("cold-read LastUpdateIndex: want Q96, got %s", got.LastUpdateIndex)
	}
	// An unwritten slot reads as absent (nil), not as a zero-valued stake.
	if cold.GetStake(db, common.HexToAddress("0x00000000000000000000000000000000000000EE"), zzmpLiquid) != nil {
		t.Fatal("a cold read invented a stake for an account that never staked")
	}
}
