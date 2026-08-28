// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// Fixtures for the credit subsystem (lending.go, interest_rate.go, liquidation.go,
// liquid.go). Addresses are disjoint from the ones in lending_test.go and
// liquid_test.go so the two sets cannot alias each other's positions.
var (
	zzcrAsset    = common.HexToAddress("0x00000000000000000000000000000000c0de0001")
	zzcrAssetB   = common.HexToAddress("0x00000000000000000000000000000000c0de0002")
	zzcrBorrower = common.HexToAddress("0x00000000000000000000000000000000b0110001")
	zzcrKeeper   = common.HexToAddress("0x000000000000000000000000000000000c1ea001")
	zzcrLender   = common.HexToAddress("0x00000000000000000000000000000000defa0001")
	zzcrThird    = common.HexToAddress("0x000000000000000000000000000000000a1ce001")
	zzcrYieldTok = common.HexToAddress("0x00000000000000000000000000000000c011a001")
	zzcrSynthTok = common.HexToAddress("0x0000000000000000000000000000000005d0c001")
	zzcrUnder    = Currency{Address: common.HexToAddress("0x00000000000000000000000000000000ba5e0001")}
)

// zzcrFrac is num/den expressed in the protocol's fixed point (RAY == 1e18).
// Rates are always derived from RAY here rather than written as literals, so a
// change to the scale surfaces as a behaviour change instead of a stale constant.
func zzcrFrac(num, den int64) *big.Int {
	x := new(big.Int).Mul(big.NewInt(num), RAY)
	return x.Div(x, big.NewInt(den))
}

// zzcrHuge is a balance large enough that no fixture ever underflows a transfer.
// transferAsset subtracts without checking the sender, so an unfunded fixture
// wraps silently instead of failing (see the report on lending.go:739).
func zzcrHuge() *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(40), nil)
}

// zzcrMarket is one lending market plus the liquidation engine bound to it.
type zzcrMarket struct {
	db    *MockStateDB
	lp    *LendingPool
	liq   *Liquidator
	asset common.Address
}

// zzcrNewMarket builds a market at the given collateral factor and liquidation
// bonus (both RAY-scaled). The block number stays at 1 unless a test advances it,
// so accrueInterest is inert and every figure below is exact.
func zzcrNewMarket(t *testing.T, collateralFactor, liquidationBonus *big.Int) *zzcrMarket {
	t.Helper()
	m := &zzcrMarket{db: NewMockStateDB(), asset: zzcrAsset}
	m.lp = NewLendingPool(NewPoolManager())
	m.liq = NewLiquidator(m.lp)
	if err := m.lp.InitializeReserve(m.db, m.asset, collateralFactor, liquidationBonus, DefaultInterestRateModel()); err != nil {
		t.Fatalf("InitializeReserve: %v", err)
	}
	for _, a := range []common.Address{zzcrBorrower, zzcrKeeper, zzcrLender, zzcrThird, lendingPoolAddr} {
		setBalance(m.db, a, zzcrHuge())
	}
	return m
}

func (m *zzcrMarket) reserve(t *testing.T) *Reserve {
	t.Helper()
	r := m.lp.GetReserve(m.asset)
	if r == nil {
		t.Fatal("reserve missing")
	}
	return r
}

func (m *zzcrMarket) supply(t *testing.T, user common.Address, amount int64) *big.Int {
	t.Helper()
	shares, err := m.lp.Supply(m.db, user, m.asset, big.NewInt(amount))
	if err != nil {
		t.Fatalf("Supply(%s, %d): %v", user.Hex(), amount, err)
	}
	return shares
}

func (m *zzcrMarket) borrow(t *testing.T, user common.Address, amount int64) {
	t.Helper()
	if err := m.lp.Borrow(m.db, user, m.asset, big.NewInt(amount)); err != nil {
		t.Fatalf("Borrow(%s, %d): %v", user.Hex(), amount, err)
	}
}

func (m *zzcrMarket) position(t *testing.T, user common.Address) *LendingPosition {
	t.Helper()
	p := m.lp.GetPosition(m.db, user, m.asset)
	if p == nil {
		t.Fatalf("no position for %s", user.Hex())
	}
	return p
}

func (m *zzcrMarket) health(user common.Address) *big.Int {
	return m.lp.GetHealthFactor(m.db, user, m.asset)
}

// bal reads a balance out of the mock as a signed big.Int. Balances are stored as
// uint256, so an underflowed balance reads back near 2^256 rather than negative;
// tests that care about that compare against zzcrTwo256 instead of zero.
func (m *zzcrMarket) bal(addr common.Address) *big.Int {
	return m.db.GetBalance(addr).ToBig()
}

// zzcrTwo256 is 2^256, the modulus the mock's uint256 balances wrap at.
func zzcrTwo256() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), 256)
}

// zzcrPushDebt forces the borrower's outstanding debt to exactly `debt`, keeping
// the reserve's TotalBorrows consistent so the liquidation arithmetic downstream
// still balances. Used to sit a position one unit either side of a boundary that
// the Borrow guard will not let a caller reach directly.
func (m *zzcrMarket) zzcrPushDebt(t *testing.T, user common.Address, debt int64) {
	t.Helper()
	p := m.position(t, user)
	r := m.reserve(t)
	delta := new(big.Int).Sub(big.NewInt(debt), p.BorrowAmount)
	p.BorrowAmount = big.NewInt(debt)
	r.TotalBorrows = new(big.Int).Add(r.TotalBorrows, delta)
}

// zzcrVault is one Liquid (self-repaying loan) vault with a yield token and a
// synthetic registered.
type zzcrVault struct {
	db *MockStateDB
	v  *Liquid
}

func zzcrNewVault(t *testing.T, yieldPerBlock, debtCeiling *big.Int) *zzcrVault {
	t.Helper()
	q := &zzcrVault{db: NewMockStateDB(), v: NewLiquid(NewPoolManager())}
	if err := q.v.AddYieldToken(q.db, zzcrYieldTok, zzcrUnder, yieldPerBlock); err != nil {
		t.Fatalf("AddYieldToken: %v", err)
	}
	if err := q.v.AddLiquidToken(q.db, zzcrSynthTok, zzcrUnder, debtCeiling); err != nil {
		t.Fatalf("AddLiquidToken: %v", err)
	}
	for _, a := range []common.Address{zzcrBorrower, zzcrKeeper, zzcrThird, liquidAddr} {
		setBalance(q.db, a, zzcrHuge())
	}
	return q
}

// zzcrSetLiquidBlock writes the counter Liquid.getCurrentBlock reads. Liquid does
// not use MockStateDB.blockNumber; it keeps its own value in contract storage.
func zzcrSetLiquidBlock(db *MockStateDB, n uint64) {
	key := makeStorageKey(liquidGlobalPrefix, []byte("block"))
	db.SetState(liquidAddr, key, common.BigToHash(new(big.Int).SetUint64(n)))
}

func (q *zzcrVault) account(t *testing.T, owner common.Address) *LiquidAccount {
	t.Helper()
	a := q.v.GetAccount(q.db, owner, zzcrYieldTok)
	if a == nil {
		t.Fatalf("no liquid account for %s", owner.Hex())
	}
	return a
}

func (q *zzcrVault) bal(addr common.Address) *big.Int {
	return q.db.GetBalance(addr).ToBig()
}

// zzcrEq fails unless got == want.
func zzcrEq(t *testing.T, what string, got, want *big.Int) {
	t.Helper()
	if got.Cmp(want) != 0 {
		t.Fatalf("%s: got %s, want %s", what, got, want)
	}
}

// zzcrAtMost fails unless got <= limit.
func zzcrAtMost(t *testing.T, what string, got, limit *big.Int) {
	t.Helper()
	if got.Cmp(limit) > 0 {
		t.Fatalf("%s: %s exceeds limit %s", what, got, limit)
	}
}

// zzcrAtLeast fails unless got >= floor.
func zzcrAtLeast(t *testing.T, what string, got, floor *big.Int) {
	t.Helper()
	if got.Cmp(floor) < 0 {
		t.Fatalf("%s: %s below floor %s", what, got, floor)
	}
}
