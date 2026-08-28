// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzlev_vaults_test.go covers dex/vaults.go — the share-based yield vaults and
// the three bundled strategies. The properties that matter for a vault are the
// ones an ERC-4626 auditor asks about: shares must round toward the vault on
// both sides, a round trip must never return more than it took in, the share
// price must not divide by zero at an empty supply, and a donation must not let
// one depositor take another's principal.

// ---------------------------------------------------------------------------
// a controllable strategy
// ---------------------------------------------------------------------------

// zzlStrategy is a VaultStrategy whose every hook is steerable, so the vault's
// error and rollback paths can be driven without pretending a real yield source
// exists. Its name is deliberately at least 10 bytes — see
// TestZzlVaultCreateWithAShortStrategyNamePanics for why that matters.
type zzlStrategy struct {
	name        string
	deployed    *big.Int
	depositErr  error
	withdrawErr error
	harvestErr  error
	profit      *big.Int
	apy         *big.Int
	// returnOnWithdraw, when non-nil, is handed back instead of the requested
	// amount — modelling a strategy that settles for more or less than asked.
	returnOnWithdraw *big.Int
}

func zzlNewStrategy(name string) *zzlStrategy {
	return &zzlStrategy{
		name:     name,
		deployed: big.NewInt(0),
		profit:   big.NewInt(0),
		apy:      big.NewInt(1234),
	}
}

func (s *zzlStrategy) Name() string { return s.name }

func (s *zzlStrategy) Deposit(amount *big.Int) error {
	if s.depositErr != nil {
		return s.depositErr
	}
	s.deployed.Add(s.deployed, amount)
	return nil
}

func (s *zzlStrategy) Withdraw(amount *big.Int) (*big.Int, error) {
	if s.withdrawErr != nil {
		return nil, s.withdrawErr
	}
	if s.returnOnWithdraw != nil {
		return new(big.Int).Set(s.returnOnWithdraw), nil
	}
	s.deployed.Sub(s.deployed, amount)
	return new(big.Int).Set(amount), nil
}

func (s *zzlStrategy) Harvest() (*big.Int, error) {
	if s.harvestErr != nil {
		return nil, s.harvestErr
	}
	return new(big.Int).Set(s.profit), nil
}

func (s *zzlStrategy) EstimatedAPY() *big.Int { return new(big.Int).Set(s.apy) }
func (s *zzlStrategy) TotalDeployed() *big.Int {
	return new(big.Int).Set(s.deployed)
}

var _ VaultStrategy = (*zzlStrategy)(nil)

var zzlVaultAsset = Currency{Address: common.HexToAddress("0x6666666666666666666666666666666666666666")}
var zzlVaultAsset2 = Currency{Address: common.HexToAddress("0x8888888888888888888888888888888888888888")}

var zzlErrStrategy = errors.New("zzl strategy refused")

// zzlVault builds a manager with one vault over a controllable strategy.
func zzlVault(t *testing.T) (*VaultManager, common.Address, *zzlStrategy) {
	t.Helper()
	vm := NewVaultManager()
	s := zzlNewStrategy("ZZLSTRATEGY")
	addr, err := vm.CreateVault(zzlVaultAsset, s, 1000, 100, big.NewInt(0), zzlOwner)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	return vm, addr, s
}

// ---------------------------------------------------------------------------
// vault creation
// ---------------------------------------------------------------------------

func TestZzlVaultCreateInitialState(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]
	if v == nil {
		t.Fatal("vault not filed under its address")
	}
	if v.Address != addr || v.Asset != zzlVaultAsset || v.Strategist != zzlOwner {
		t.Fatal("the vault does not carry its creation parameters")
	}
	if v.Strategy != s {
		t.Fatal("the vault does not hold the strategy it was given")
	}
	if v.TotalAssets.Sign() != 0 || v.TotalShares.Sign() != 0 {
		t.Fatal("a new vault opens with assets or shares")
	}
	// A vault opens usable in both directions.
	if !v.DepositEnabled || !v.WithdrawEnabled {
		t.Fatal("a new vault opens with deposits or withdrawals disabled")
	}
	if v.PerformanceFee != 1000 || v.ManagementFee != 100 {
		t.Fatalf("fees = %d/%d, want 1000/100", v.PerformanceFee, v.ManagementFee)
	}
	if v.LastHarvest != 0 {
		t.Fatalf("LastHarvest = %d, want 0", v.LastHarvest)
	}
}

func TestZzlVaultFeeCeilingsAreInclusive(t *testing.T) {
	// The performance fee caps at 5000bps and the management fee at 500bps.
	// Exactly the cap is accepted; one basis point more is refused. A refused
	// create must leave no vault behind.
	for _, tc := range []struct {
		name       string
		perf, mgmt uint32
		wantErr    bool
	}{
		{"both at the cap", 5000, 500, false},
		{"performance one over", 5001, 500, true},
		{"management one over", 5000, 501, true},
		{"both over", 60000, 60000, true},
		{"both zero", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := NewVaultManager()
			addr, err := vm.CreateVault(zzlVaultAsset, zzlNewStrategy("ZZLSTRATEGY"),
				tc.perf, tc.mgmt, big.NewInt(0), zzlOwner)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidFee) {
					t.Fatalf("perf=%d mgmt=%d: err = %v, want ErrInvalidFee", tc.perf, tc.mgmt, err)
				}
				if addr != (common.Address{}) {
					t.Fatalf("a refused create returned address %s", addr)
				}
				if len(vm.Vaults) != 0 {
					t.Fatal("a refused create left a vault behind")
				}
				return
			}
			if err != nil {
				t.Fatalf("perf=%d mgmt=%d: %v", tc.perf, tc.mgmt, err)
			}
			if vm.Vaults[addr].PerformanceFee != tc.perf {
				t.Fatalf("performance fee = %d, want %d", vm.Vaults[addr].PerformanceFee, tc.perf)
			}
		})
	}
}

func TestZzlVaultAddressCollidesOnTenBytePrefixes(t *testing.T) {
	// The vault address is the asset's first 10 bytes followed by the strategy
	// name's first 10. Two assets that agree on that prefix therefore land on
	// one address, and the second create is refused rather than overwriting.
	vm := NewVaultManager()
	a := Currency{Address: common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAA00000000000000000001")}
	b := Currency{Address: common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAA00000000000000000002")}
	if a.Address == b.Address {
		t.Fatal("fixture: the two assets are the same address")
	}
	first, err := vm.CreateVault(a, zzlNewStrategy("ZZLSTRATEGY"), 0, 0, big.NewInt(0), zzlOwner)
	if err != nil {
		t.Fatalf("first CreateVault: %v", err)
	}
	if generateVaultAddress(a, "ZZLSTRATEGY") != generateVaultAddress(b, "ZZLSTRATEGY") {
		t.Fatal("assets differing past byte 10 no longer collide; the derivation widened")
	}
	dup, err := vm.CreateVault(b, zzlNewStrategy("ZZLSTRATEGY"), 0, 0, big.NewInt(0), zzlOwner)
	if !errors.Is(err, ErrVaultExists) {
		t.Fatalf("colliding create err = %v, want ErrVaultExists", err)
	}
	if dup != (common.Address{}) {
		t.Fatalf("a refused create returned %s", dup)
	}
	if len(vm.Vaults) != 1 || vm.Vaults[first].Asset != a {
		t.Fatal("the colliding create overwrote the original vault")
	}
	// A different strategy name over the same asset is a distinct vault.
	other, err := vm.CreateVault(a, zzlNewStrategy("OTHERSTRATEGY"), 0, 0, big.NewInt(0), zzlOwner)
	if err != nil {
		t.Fatalf("second strategy over the same asset: %v", err)
	}
	if other == first {
		t.Fatal("two strategies over one asset share a vault address")
	}
}

// DEFECT (reported, HIGH): generateVaultAddress slices the strategy name to a
// fixed 10 bytes without checking its length, so any strategy whose name is
// shorter panics. LPYieldStrategy is named "LP_YIELD" — 8 bytes — so creating a
// vault over the engine's own LP strategy is an unconditional panic.
func TestZzlVaultCreateWithAShortStrategyNamePanics(t *testing.T) {
	lp := NewLPYieldStrategy(nil, [32]byte{})
	if len(lp.Name()) >= 10 {
		t.Fatalf("LPYieldStrategy is now named %q (%d bytes); the panic is gone — "+
			"update the reported finding", lp.Name(), len(lp.Name()))
	}
	vm := NewVaultManager()
	panicked, rec := zzlPanics(func() {
		_, _ = vm.CreateVault(zzlVaultAsset, lp, 0, 0, big.NewInt(0), zzlOwner)
	})
	if !panicked {
		t.Fatal("CreateVault over LPYieldStrategy did not panic; a length guard was added")
	}
	if !zzlContains(fmt.Sprint(rec), "out of range") {
		t.Fatalf("panic value = %v, want a slice-bounds panic", rec)
	}
	if len(vm.Vaults) != 0 {
		t.Fatal("the panicking create left a vault behind")
	}

	// A name of exactly 10 bytes is the shortest that works.
	if _, err := vm.CreateVault(zzlVaultAsset, zzlNewStrategy("TENBYTESXX"), 0, 0,
		big.NewInt(0), zzlOwner); err != nil {
		t.Fatalf("a 10-byte strategy name was refused: %v", err)
	}
	// Nine bytes still panics — the boundary is exact.
	panicked, _ = zzlPanics(func() {
		_, _ = vm.CreateVault(zzlVaultAsset2, zzlNewStrategy("NINEBYTES"), 0, 0,
			big.NewInt(0), zzlOwner)
	})
	if !panicked {
		t.Fatal("a 9-byte strategy name did not panic")
	}
	// The other two bundled strategies are long enough to be safe.
	for _, s := range []VaultStrategy{
		NewLendingYieldStrategy(nil, common.Address{}),
		NewDeltaNeutralStrategy(nil, nil, [32]byte{}),
	} {
		if len(s.Name()) < 10 {
			t.Fatalf("bundled strategy %q is only %d bytes and would panic", s.Name(), len(s.Name()))
		}
	}
}

func zzlContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// deposit
// ---------------------------------------------------------------------------

func TestZzlVaultDepositRefusals(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]

	if _, err := vm.Deposit(zzlOwner, common.Address{0x99}, big.NewInt(1)); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("unknown vault err = %v, want ErrVaultNotFound", err)
	}
	// Deposits disabled.
	v.DepositEnabled = false
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(100)); !errors.Is(err, ErrDepositsDisabled) {
		t.Fatalf("disabled deposits err = %v, want ErrDepositsDisabled", err)
	}
	if v.TotalAssets.Sign() != 0 {
		t.Fatal("a refused deposit moved the vault total")
	}
	v.DepositEnabled = true

	// A zero deposit would mint zero shares and is refused.
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(0)); !errors.Is(err, ErrZeroShares) {
		t.Fatalf("zero deposit err = %v, want ErrZeroShares", err)
	}

	// A strategy that refuses the deployment rolls the vault back completely.
	s.depositErr = zzlErrStrategy
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(100)); !errors.Is(err, zzlErrStrategy) {
		t.Fatalf("strategy error err = %v, want it surfaced", err)
	}
	if v.TotalAssets.Sign() != 0 || v.TotalShares.Sign() != 0 {
		t.Fatalf("a failed strategy deposit left assets=%s shares=%s, want 0/0",
			v.TotalAssets, v.TotalShares)
	}
	if vm.getPosition(zzlOwner, addr) != nil {
		t.Fatal("a failed strategy deposit created a position")
	}
	s.depositErr = nil
}

func TestZzlVaultDepositLimitIsInclusiveAndZeroMeansUnlimited(t *testing.T) {
	// A limit of zero disables the check entirely.
	vm, addr, _ := zzlVault(t)
	if vm.Vaults[addr].DepositLimit.Sign() != 0 {
		t.Fatal("fixture: the vault has a non-zero limit")
	}
	big1 := new(big.Int).Lsh(big.NewInt(1), 100)
	if _, err := vm.Deposit(zzlOwner, addr, big1); err != nil {
		t.Fatalf("a huge deposit against a zero limit was refused: %v", err)
	}

	// With a real limit, exactly the limit is accepted and one over is refused.
	vm2 := NewVaultManager()
	a2, err := vm2.CreateVault(zzlVaultAsset, zzlNewStrategy("ZZLSTRATEGY"), 0, 0,
		big.NewInt(1000), zzlOwner)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	v2 := vm2.Vaults[a2]
	if _, err := vm2.Deposit(zzlOwner, a2, big.NewInt(1000)); err != nil {
		t.Fatalf("depositing exactly the limit: %v", err)
	}
	if _, err := vm2.Deposit(zzlOther, a2, big.NewInt(1)); !errors.Is(err, ErrDepositLimitExceeded) {
		t.Fatalf("one over the limit err = %v, want ErrDepositLimitExceeded", err)
	}
	if v2.TotalAssets.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("total = %s after a refused deposit, want 1000", v2.TotalAssets)
	}
	// The limit is on the TOTAL, so a fresh vault refuses an over-limit first
	// deposit too.
	vm3 := NewVaultManager()
	a3, err := vm3.CreateVault(zzlVaultAsset, zzlNewStrategy("ZZLSTRATEGY"), 0, 0,
		big.NewInt(1000), zzlOwner)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if _, err := vm3.Deposit(zzlOwner, a3, big.NewInt(1001)); !errors.Is(err, ErrDepositLimitExceeded) {
		t.Fatalf("over-limit first deposit err = %v, want ErrDepositLimitExceeded", err)
	}
}

func TestZzlVaultFirstDepositIsOneToOneAndLaterOnesAreProRata(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]

	shares, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000))
	if err != nil {
		t.Fatalf("first deposit: %v", err)
	}
	if shares.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("first-deposit shares = %s, want 1:1 with 1000", shares)
	}
	if v.TotalAssets.Cmp(big.NewInt(1000)) != 0 || v.TotalShares.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("vault totals = %s/%s, want 1000/1000", v.TotalAssets, v.TotalShares)
	}
	if s.deployed.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("strategy holds %s, want the whole 1000", s.deployed)
	}
	if pos := vm.getPosition(zzlOwner, addr); pos == nil || pos.Shares.Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("the depositor's position does not hold the minted shares")
	}

	// A second depositor at an unchanged share price gets the same ratio.
	shares2, err := vm.Deposit(zzlOther, addr, big.NewInt(500))
	if err != nil {
		t.Fatalf("second deposit: %v", err)
	}
	if shares2.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("second-deposit shares = %s, want 500", shares2)
	}
	// Positions are per user and do not merge.
	if vm.getPosition(zzlOwner, addr).Shares.Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("the second deposit disturbed the first depositor's position")
	}
	// Depositing again adds to the same position rather than replacing it.
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(250)); err != nil {
		t.Fatalf("top-up deposit: %v", err)
	}
	if got := vm.getPosition(zzlOwner, addr).Shares; got.Cmp(big.NewInt(1250)) != 0 {
		t.Fatalf("position shares = %s, want 1250", got)
	}
	// Conservation: total shares equals the sum of every position.
	sum := new(big.Int).Add(vm.getPosition(zzlOwner, addr).Shares, vm.getPosition(zzlOther, addr).Shares)
	if sum.Cmp(v.TotalShares) != 0 {
		t.Fatalf("positions sum to %s but TotalShares is %s", sum, v.TotalShares)
	}
}

func TestZzlVaultDepositRoundsSharesTowardTheVault(t *testing.T) {
	// After a harvest the vault holds more assets than shares, so a deposit that
	// does not divide evenly must mint the FLOOR of the pro-rata share count.
	// Rounding the other way would hand the depositor value belonging to
	// everyone else.
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	s.profit = big.NewInt(500) // performance fee is 1000bps, so 450 net
	if _, err := vm.Harvest(addr); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	ta := new(big.Int).Set(v.TotalAssets)
	ts := new(big.Int).Set(v.TotalShares)
	if ta.Cmp(ts) <= 0 {
		t.Fatalf("fixture: assets %s are not above shares %s", ta, ts)
	}

	dep := big.NewInt(777)
	want := new(big.Int).Mul(dep, ts)
	want.Div(want, ta) // the floor
	exact := new(big.Int).Mul(dep, ts)
	if new(big.Int).Mul(want, ta).Cmp(exact) == 0 {
		t.Fatal("fixture: the deposit divides evenly, so rounding is not exercised")
	}
	got, err := vm.Deposit(zzlOther, addr, dep)
	if err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("minted %s shares, want the floor %s", got, want)
	}
	// Strictly fewer than the exact fractional entitlement: the remainder stays
	// with the vault.
	scaled := new(big.Int).Mul(got, ta)
	if scaled.Cmp(exact) >= 0 {
		t.Fatalf("minted %s shares which is worth at least the exact entitlement; the "+
			"rounding favours the depositor", got)
	}
}

func TestZzlVaultDepositTooSmallToMintAShareIsRefused(t *testing.T) {
	// Once the share price exceeds one asset unit, a deposit of one unit is
	// worth less than a share. The vault refuses rather than taking the assets
	// and minting nothing.
	vm, addr, s := zzlVault(t)
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.profit = big.NewInt(100_000)
	if _, err := vm.Harvest(addr); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	v := vm.Vaults[addr]
	assetsBefore := new(big.Int).Set(v.TotalAssets)
	sharesBefore := new(big.Int).Set(v.TotalShares)

	if _, err := vm.Deposit(zzlOther, addr, big.NewInt(1)); !errors.Is(err, ErrZeroShares) {
		t.Fatalf("dust deposit err = %v, want ErrZeroShares", err)
	}
	// Crucially, the refusal did not keep the assets.
	if v.TotalAssets.Cmp(assetsBefore) != 0 || v.TotalShares.Cmp(sharesBefore) != 0 {
		t.Fatalf("a refused dust deposit moved the totals to %s/%s", v.TotalAssets, v.TotalShares)
	}
	if vm.getPosition(zzlOther, addr) != nil {
		t.Fatal("a refused dust deposit created a position")
	}
}

// DEFECT (reported, HIGH): Deposit divides by TotalAssets whenever TotalShares
// is non-zero, with no zero check. A strategy that returns MORE than the vault
// asked for on withdrawal drives TotalAssets to zero while shares remain
// outstanding, and the next deposit panics.
func TestZzlVaultDepositPanicsWhenAssetsHitZeroWithSharesOutstanding(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(100)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Withdraw 10 shares but have the strategy settle the whole 100.
	s.returnOnWithdraw = big.NewInt(100)
	if _, err := vm.Withdraw(zzlOwner, addr, big.NewInt(10)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	s.returnOnWithdraw = nil
	if v.TotalAssets.Sign() != 0 {
		t.Fatalf("TotalAssets = %s, want 0", v.TotalAssets)
	}
	if v.TotalShares.Sign() == 0 {
		t.Fatal("TotalShares hit zero too; the fixture no longer reproduces the state")
	}

	panicked, rec := zzlPanics(func() { _, _ = vm.Deposit(zzlOther, addr, big.NewInt(50)) })
	if !panicked {
		t.Fatal("a deposit into a zero-asset vault did not panic; a guard was added")
	}
	if fmt.Sprint(rec) != "division by zero" {
		t.Fatalf("panic value = %v, want the big.Int division-by-zero", rec)
	}
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------

func TestZzlVaultWithdrawRefusals(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]

	if _, err := vm.Withdraw(zzlOwner, common.Address{0x99}, big.NewInt(1)); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("unknown vault err = %v, want ErrVaultNotFound", err)
	}
	v.WithdrawEnabled = false
	if _, err := vm.Withdraw(zzlOwner, addr, big.NewInt(1)); !errors.Is(err, ErrWithdrawalsDisabled) {
		t.Fatalf("disabled withdrawals err = %v, want ErrWithdrawalsDisabled", err)
	}
	v.WithdrawEnabled = true

	// A user with no position at all cannot withdraw.
	if _, err := vm.Withdraw(zzlOwner, addr, big.NewInt(1)); !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("no position err = %v, want ErrInsufficientShares", err)
	}
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// One share more than held is refused; exactly what is held is not.
	if _, err := vm.Withdraw(zzlOwner, addr, big.NewInt(1001)); !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("over-withdraw err = %v, want ErrInsufficientShares", err)
	}
	if vm.getPosition(zzlOwner, addr).Shares.Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("a refused withdrawal moved the position")
	}
	// A different user's shares are not spendable.
	if _, err := vm.Withdraw(zzlOther, addr, big.NewInt(1)); !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("withdrawing another user's shares err = %v, want ErrInsufficientShares", err)
	}

	// A strategy that refuses leaves the vault and the position untouched.
	s.withdrawErr = zzlErrStrategy
	if _, err := vm.Withdraw(zzlOwner, addr, big.NewInt(100)); !errors.Is(err, zzlErrStrategy) {
		t.Fatalf("strategy error err = %v, want it surfaced", err)
	}
	if v.TotalShares.Cmp(big.NewInt(1000)) != 0 || v.TotalAssets.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("a failed strategy withdrawal moved the totals to %s/%s", v.TotalAssets, v.TotalShares)
	}
	if vm.getPosition(zzlOwner, addr).Shares.Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("a failed strategy withdrawal moved the position")
	}
	s.withdrawErr = nil
}

func TestZzlVaultFullWithdrawClosesThePosition(t *testing.T) {
	vm, addr, _ := zzlVault(t)
	v := vm.Vaults[addr]
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := vm.Withdraw(zzlOwner, addr, big.NewInt(1000))
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("returned %s, want 1000", got)
	}
	if v.TotalAssets.Sign() != 0 || v.TotalShares.Sign() != 0 {
		t.Fatalf("vault totals = %s/%s after the only depositor left, want 0/0",
			v.TotalAssets, v.TotalShares)
	}
	// A zeroed position is deleted rather than left as a husk.
	if vm.getPosition(zzlOwner, addr) != nil {
		t.Fatal("a fully withdrawn position was not deleted")
	}
	if len(vm.Positions[zzlOwner]) != 0 {
		t.Fatalf("%d positions remain for the user", len(vm.Positions[zzlOwner]))
	}
	// And the share price falls back to its empty-vault value.
	price, err := vm.GetSharePrice(addr)
	if err != nil {
		t.Fatalf("GetSharePrice: %v", err)
	}
	if price.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("share price = %s on an emptied vault, want 1e18", price)
	}
}

func TestZzlVaultWithdrawRoundsAssetsTowardTheVault(t *testing.T) {
	// assets = shares * totalAssets / totalShares must floor, so a partial exit
	// leaves the remainder with the remaining shareholders.
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(3)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// 1001 leaves a remainder against 3 shares; 1000 would divide evenly.
	s.profit = big.NewInt(1001)
	if _, err := vm.Harvest(addr); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	ta := new(big.Int).Set(v.TotalAssets)
	ts := new(big.Int).Set(v.TotalShares)

	want := new(big.Int).Mul(big.NewInt(1), ta)
	want.Div(want, ts)
	exact := new(big.Int).Mul(big.NewInt(1), ta)
	if new(big.Int).Mul(want, ts).Cmp(exact) == 0 {
		t.Fatal("fixture: one share divides evenly, so rounding is not exercised")
	}
	got, err := vm.Withdraw(zzlOwner, addr, big.NewInt(1))
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("returned %s, want the floor %s", got, want)
	}
	if new(big.Int).Mul(got, ts).Cmp(exact) >= 0 {
		t.Fatalf("returned %s which is at least the exact entitlement; the rounding "+
			"favours the withdrawer", got)
	}
}

func TestZzlVaultRoundTripNeverReturnsMoreThanWasDeposited(t *testing.T) {
	// The core solvency property: with no yield in between, depositing and
	// immediately withdrawing must never return more than went in, for any
	// amount and against any pre-existing vault state.
	for _, seed := range []int64{0, 1, 7, 1000, 999_983} {
		for _, amount := range []int64{1, 3, 17, 1000, 123_457} {
			vm, addr, _ := zzlVault(t)
			if seed > 0 {
				if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(seed)); err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
			}
			shares, err := vm.Deposit(zzlOther, addr, big.NewInt(amount))
			if err != nil {
				if errors.Is(err, ErrZeroShares) {
					continue
				}
				t.Fatalf("seed=%d amount=%d deposit: %v", seed, amount, err)
			}
			back, err := vm.Withdraw(zzlOther, addr, shares)
			if err != nil {
				t.Fatalf("seed=%d amount=%d withdraw: %v", seed, amount, err)
			}
			if back.Cmp(big.NewInt(amount)) > 0 {
				t.Fatalf("seed=%d: deposited %d and withdrew %s — the vault paid out more "+
					"than it took in", seed, amount, back)
			}
			// The first depositor's stake must survive the round trip intact.
			if seed > 0 {
				assets, err := vm.GetUserAssets(zzlOwner, addr)
				if err != nil {
					t.Fatalf("GetUserAssets: %v", err)
				}
				if assets.Cmp(big.NewInt(seed)) < 0 {
					t.Fatalf("seed=%d amount=%d: the seeder was left with %s, less than "+
						"the %d they deposited", seed, amount, assets, seed)
				}
			}
		}
	}
}

// DEFECT (reported): a harvest adds assets without minting shares, which is a
// donation to existing holders. On a vault holding a single wei-sized share
// that donation inflates the share price so far that the next depositor's
// rounding loss is nearly their whole principal — the ERC-4626 first-depositor
// attack. The vault's only defence is ErrZeroShares, which refuses the very
// smallest victims but not the ones just above the threshold.
func TestZzlVaultDonationInflatesSharePriceAgainstTheNextDepositor(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]

	// The attacker seeds one wei of shares.
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1)); err != nil {
		t.Fatalf("attacker seed: %v", err)
	}
	if v.TotalShares.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("TotalShares = %s, want 1", v.TotalShares)
	}
	// Then donates through the harvest path, minting no shares.
	s.profit = big.NewInt(10_000)
	netProfit, err := vm.Harvest(addr)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	if v.TotalShares.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("the harvest minted shares; it is no longer a donation")
	}
	price, err := vm.GetSharePrice(addr)
	if err != nil {
		t.Fatalf("GetSharePrice: %v", err)
	}
	if price.Cmp(big.NewInt(1e18)) <= 0 {
		t.Fatalf("share price = %s after a %s donation, want it inflated", price, netProfit)
	}

	// A victim below the share price is refused outright — the one protection
	// that does work.
	if _, err := vm.Deposit(zzlOther, addr, big.NewInt(100)); !errors.Is(err, ErrZeroShares) {
		t.Fatalf("a sub-share victim deposit err = %v, want ErrZeroShares", err)
	}
	// A victim just above it is not: they mint one share and immediately lose a
	// large fraction of their principal to the attacker's share.
	victim := big.NewInt(15_000)
	shares, err := vm.Deposit(zzlOther, addr, victim)
	if err != nil {
		t.Fatalf("victim deposit: %v", err)
	}
	if shares.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("victim minted %s shares, want 1", shares)
	}
	back, err := vm.Withdraw(zzlOther, addr, shares)
	if err != nil {
		t.Fatalf("victim withdraw: %v", err)
	}
	if back.Cmp(victim) >= 0 {
		t.Fatalf("victim recovered %s of %s; the inflation defence now holds — update the "+
			"reported finding", back, victim)
	}
	loss := new(big.Int).Sub(victim, back)
	// The loss is a material fraction of principal, not a rounding wei. (The
	// worst case for this shape is 25%, at a deposit just under two shares.)
	if new(big.Int).Mul(loss, big.NewInt(10)).Cmp(victim) < 0 {
		t.Fatalf("victim lost only %s of %s; the fixture is not demonstrating the attack",
			loss, victim)
	}
	// And the attacker's single share is now worth more than they put in.
	attacker, err := vm.GetUserAssets(zzlOwner, addr)
	if err != nil {
		t.Fatalf("GetUserAssets: %v", err)
	}
	if attacker.Cmp(big.NewInt(1)) <= 0 {
		t.Fatalf("attacker holds %s after seeding 1 wei, want a gain", attacker)
	}
}

// ---------------------------------------------------------------------------
// harvest
// ---------------------------------------------------------------------------

func TestZzlVaultHarvest(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]

	if _, err := vm.Harvest(common.Address{0x99}); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("unknown vault err = %v, want ErrVaultNotFound", err)
	}
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(10_000)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A strategy error is surfaced and nothing is compounded.
	s.harvestErr = zzlErrStrategy
	if _, err := vm.Harvest(addr); !errors.Is(err, zzlErrStrategy) {
		t.Fatalf("strategy error err = %v, want it surfaced", err)
	}
	if v.TotalAssets.Cmp(big.NewInt(10_000)) != 0 {
		t.Fatal("a failed harvest moved the vault total")
	}
	s.harvestErr = nil

	// Zero and negative profit are no-ops that report zero.
	for _, p := range []int64{0, -500} {
		s.profit = big.NewInt(p)
		got, err := vm.Harvest(addr)
		if err != nil {
			t.Fatalf("harvest of %d: %v", p, err)
		}
		if got.Sign() != 0 {
			t.Fatalf("harvest of %d returned %s, want 0", p, got)
		}
		if v.TotalAssets.Cmp(big.NewInt(10_000)) != 0 {
			t.Fatalf("harvest of %d moved the total to %s", p, v.TotalAssets)
		}
	}

	// A real profit is compounded net of the performance fee, and no shares are
	// minted, so every existing holder gains.
	s.profit = big.NewInt(1000)
	fee := new(big.Int).Mul(big.NewInt(1000), big.NewInt(int64(v.PerformanceFee)))
	fee.Div(fee, big.NewInt(10000))
	wantNet := new(big.Int).Sub(big.NewInt(1000), fee)
	sharesBefore := new(big.Int).Set(v.TotalShares)

	net, err := vm.Harvest(addr)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	if net.Cmp(wantNet) != 0 {
		t.Fatalf("net profit = %s, want profit - fee = %s", net, wantNet)
	}
	if v.TotalAssets.Cmp(new(big.Int).Add(big.NewInt(10_000), wantNet)) != 0 {
		t.Fatalf("total assets = %s, want 10000 + %s", v.TotalAssets, wantNet)
	}
	if v.TotalShares.Cmp(sharesBefore) != 0 {
		t.Fatal("a harvest minted shares")
	}
	// The performance fee rounds down, so the vault never over-charges.
	scaled := new(big.Int).Mul(fee, big.NewInt(10000))
	if scaled.Cmp(new(big.Int).Mul(big.NewInt(1000), big.NewInt(int64(v.PerformanceFee)))) > 0 {
		t.Fatal("the performance fee rounds up")
	}
}

// DEFECT (reported): the performance fee is computed and subtracted from the
// profit, but it is never credited to the strategist or anywhere else. It is
// simply not added to TotalAssets — the value evaporates. The ManagementFee is
// likewise stored at creation and never charged at all.
func TestZzlVaultPerformanceFeeIsBurnedAndManagementFeeIsNeverCharged(t *testing.T) {
	vm, addr, s := zzlVault(t)
	v := vm.Vaults[addr]
	// Deposit as someone OTHER than the strategist, so the strategist's holding
	// is a clean read of whether any fee was ever paid to them.
	if _, err := vm.Deposit(zzlOther, addr, big.NewInt(10_000)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if v.Strategist == zzlOther {
		t.Fatal("fixture: the depositor is the strategist")
	}
	assetsBefore := new(big.Int).Set(v.TotalAssets)

	s.profit = big.NewInt(1000)
	net, err := vm.Harvest(addr)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	fee := new(big.Int).Sub(big.NewInt(1000), net)
	if fee.Sign() <= 0 {
		t.Fatal("fixture: no performance fee was taken")
	}
	// The vault grew by the NET only: the gross profit is not fully accounted
	// for anywhere in the manager's state.
	grew := new(big.Int).Sub(v.TotalAssets, assetsBefore)
	if grew.Cmp(net) != 0 {
		t.Fatalf("assets grew by %s, want the net %s", grew, net)
	}
	// The strategist holds no position, so the fee did not go to them.
	if pos := vm.getPosition(v.Strategist, addr); pos != nil {
		t.Fatalf("the strategist holds %s shares; a fee payout was added — update the finding",
			pos.Shares)
	}
	// Management fee: charging it would reduce assets over time, but repeated
	// harvests at zero profit never move the total.
	s.profit = big.NewInt(0)
	stable := new(big.Int).Set(v.TotalAssets)
	for i := 0; i < 10; i++ {
		if _, err := vm.Harvest(addr); err != nil {
			t.Fatalf("harvest %d: %v", i, err)
		}
	}
	if v.TotalAssets.Cmp(stable) != 0 {
		t.Fatalf("assets moved to %s over ten zero-profit harvests; a management fee is now "+
			"charged — update the reported finding", v.TotalAssets)
	}
	if v.ManagementFee == 0 {
		t.Fatal("fixture: the vault has no management fee configured")
	}
}

// ---------------------------------------------------------------------------
// views
// ---------------------------------------------------------------------------

func TestZzlVaultSharePriceHandlesTheEmptyVault(t *testing.T) {
	vm, addr, _ := zzlVault(t)

	if _, err := vm.GetSharePrice(common.Address{0x99}); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("unknown vault err = %v, want ErrVaultNotFound", err)
	}
	// Zero supply must not divide by zero; it reports the 1:1 price.
	price, err := vm.GetSharePrice(addr)
	if err != nil {
		t.Fatalf("GetSharePrice: %v", err)
	}
	if price.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("empty-vault share price = %s, want 1e18", price)
	}
	// After a 1:1 deposit the price is unchanged.
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	price, err = vm.GetSharePrice(addr)
	if err != nil {
		t.Fatalf("GetSharePrice: %v", err)
	}
	if price.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("share price after a 1:1 deposit = %s, want 1e18", price)
	}
	// It is exactly totalAssets * 1e18 / totalShares.
	v := vm.Vaults[addr]
	v.TotalAssets = big.NewInt(3000)
	want := new(big.Int).Mul(v.TotalAssets, big.NewInt(1e18))
	want.Div(want, v.TotalShares)
	price, _ = vm.GetSharePrice(addr)
	if price.Cmp(want) != 0 {
		t.Fatalf("share price = %s, want %s", price, want)
	}
}

// A direct donation into TotalAssets moves the share price, which is the
// manipulation vector a vault is supposed to resist. Pinned so the exposure is
// explicit rather than assumed.
func TestZzlVaultSharePriceMovesOnADonation(t *testing.T) {
	vm, addr, s := zzlVault(t)
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	before, err := vm.GetSharePrice(addr)
	if err != nil {
		t.Fatalf("GetSharePrice: %v", err)
	}
	s.profit = big.NewInt(1000)
	if _, err := vm.Harvest(addr); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	after, err := vm.GetSharePrice(addr)
	if err != nil {
		t.Fatalf("GetSharePrice: %v", err)
	}
	if after.Cmp(before) <= 0 {
		t.Fatalf("share price did not move on a donation: %s -> %s", before, after)
	}
	// Every holder's claim rose in step, since no shares were minted.
	assets, err := vm.GetUserAssets(zzlOwner, addr)
	if err != nil {
		t.Fatalf("GetUserAssets: %v", err)
	}
	if assets.Cmp(big.NewInt(1000)) <= 0 {
		t.Fatalf("the sole holder's claim is %s, want it above the 1000 deposited", assets)
	}
}

func TestZzlVaultUserAssets(t *testing.T) {
	vm, addr, _ := zzlVault(t)

	if _, err := vm.GetUserAssets(zzlOwner, common.Address{0x99}); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("unknown vault err = %v, want ErrVaultNotFound", err)
	}
	// No position at all reports zero rather than erroring.
	got, err := vm.GetUserAssets(zzlOwner, addr)
	if err != nil {
		t.Fatalf("GetUserAssets: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("a user with no position holds %s, want 0", got)
	}

	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if _, err := vm.Deposit(zzlOther, addr, big.NewInt(3000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	a, _ := vm.GetUserAssets(zzlOwner, addr)
	b, _ := vm.GetUserAssets(zzlOther, addr)
	if a.Cmp(big.NewInt(1000)) != 0 || b.Cmp(big.NewInt(3000)) != 0 {
		t.Fatalf("claims = %s / %s, want 1000 / 3000", a, b)
	}
	// Conservation: the claims never sum to more than the vault holds.
	if new(big.Int).Add(a, b).Cmp(vm.Vaults[addr].TotalAssets) > 0 {
		t.Fatalf("claims %s + %s exceed the vault's %s", a, b, vm.Vaults[addr].TotalAssets)
	}

	// A vault holding shares-but-no-assets is guarded against dividing by zero
	// on the read path as well.
	v := vm.Vaults[addr]
	shares := new(big.Int).Set(v.TotalShares)
	v.TotalShares = big.NewInt(0)
	got, err = vm.GetUserAssets(zzlOwner, addr)
	if err != nil {
		t.Fatalf("GetUserAssets with zero supply: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("claim against a zero supply = %s, want 0", got)
	}
	v.TotalShares = shares
}

func TestZzlVaultAPYComesFromTheStrategy(t *testing.T) {
	vm, addr, s := zzlVault(t)
	if _, err := vm.GetVaultAPY(common.Address{0x99}); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("unknown vault err = %v, want ErrVaultNotFound", err)
	}
	got, err := vm.GetVaultAPY(addr)
	if err != nil {
		t.Fatalf("GetVaultAPY: %v", err)
	}
	if got.Cmp(s.apy) != 0 {
		t.Fatalf("APY = %s, want the strategy's %s", got, s.apy)
	}
	// It tracks the strategy rather than being snapshotted at creation.
	s.apy = big.NewInt(4321)
	got, _ = vm.GetVaultAPY(addr)
	if got.Cmp(big.NewInt(4321)) != 0 {
		t.Fatalf("APY = %s after the strategy changed, want 4321", got)
	}
}

// DEFECT (reported): currentTimestamp is hardcoded to 0, so DepositTime is set
// to 0 and the "first deposit" branch in updatePosition re-runs on every
// deposit. Any lockup or fee-decay keyed to DepositTime would never elapse.
func TestZzlVaultDepositTimeIsNeverRecorded(t *testing.T) {
	if got := currentTimestamp(); got != 0 {
		t.Fatalf("currentTimestamp = %d, want 0; a real clock was wired in — update the finding", got)
	}
	vm, addr, _ := zzlVault(t)
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	pos := vm.getPosition(zzlOwner, addr)
	if pos.DepositTime != 0 {
		t.Fatalf("DepositTime = %d, want 0", pos.DepositTime)
	}
	if pos.LastAction != 0 {
		t.Fatalf("LastAction = %d, want 0 (it is never written)", pos.LastAction)
	}
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(1000)); err != nil {
		t.Fatalf("second deposit: %v", err)
	}
	if pos.DepositTime != 0 {
		t.Fatalf("DepositTime = %d after a second deposit, want 0", pos.DepositTime)
	}
	// The position still carries its identity fields correctly.
	if pos.Owner != zzlOwner || pos.Vault != addr {
		t.Fatal("the position does not carry its owner and vault")
	}
}

// ---------------------------------------------------------------------------
// bundled strategies
// ---------------------------------------------------------------------------

func TestZzlVaultBundledStrategiesRoundTripAndRefuseOverWithdrawal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy VaultStrategy
		wantName string
		wantAPY  int64
		// harvestDivisor is the fraction of deployed capital the strategy
		// reports as profit.
		harvestDivisor int64
	}{
		{"LP", NewLPYieldStrategy(nil, [32]byte{1}), "LP_YIELD", 1000, 100},
		{"lending", NewLendingYieldStrategy(nil, zzlAssetA), "LENDING_YIELD", 500, 200},
		{"delta neutral", NewDeltaNeutralStrategy(nil, nil, [32]byte{2}), "DELTA_NEUTRAL", 2000, 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.strategy
			if s.Name() != tc.wantName {
				t.Fatalf("Name = %q, want %q", s.Name(), tc.wantName)
			}
			if got := s.EstimatedAPY(); got.Cmp(big.NewInt(tc.wantAPY)) != 0 {
				t.Fatalf("EstimatedAPY = %s, want %d", got, tc.wantAPY)
			}
			// A fresh strategy holds nothing.
			if got := s.TotalDeployed(); got.Sign() != 0 {
				t.Fatalf("TotalDeployed = %s on a fresh strategy, want 0", got)
			}
			// Deposits accumulate.
			if err := s.Deposit(big.NewInt(1000)); err != nil {
				t.Fatalf("Deposit: %v", err)
			}
			if err := s.Deposit(big.NewInt(500)); err != nil {
				t.Fatalf("Deposit: %v", err)
			}
			if got := s.TotalDeployed(); got.Cmp(big.NewInt(1500)) != 0 {
				t.Fatalf("TotalDeployed = %s, want 1500", got)
			}
			// TotalDeployed and EstimatedAPY return copies, not live state.
			s.TotalDeployed().SetInt64(0)
			s.EstimatedAPY().SetInt64(0)
			if got := s.TotalDeployed(); got.Cmp(big.NewInt(1500)) != 0 {
				t.Fatalf("TotalDeployed leaked a live reference: %s", got)
			}
			if got := s.EstimatedAPY(); got.Cmp(big.NewInt(tc.wantAPY)) != 0 {
				t.Fatalf("EstimatedAPY leaked a live reference: %s", got)
			}
			// Harvest reports the documented fraction of deployed capital.
			profit, err := s.Harvest()
			if err != nil {
				t.Fatalf("Harvest: %v", err)
			}
			want := new(big.Int).Div(big.NewInt(1500), big.NewInt(tc.harvestDivisor))
			if profit.Cmp(want) != 0 {
				t.Fatalf("Harvest = %s, want deployed/%d = %s", profit, tc.harvestDivisor, want)
			}
			// Withdrawing more than is deployed is refused, and nothing moves.
			if _, err := s.Withdraw(big.NewInt(1501)); !errors.Is(err, ErrInsufficientLiquidity) {
				t.Fatalf("over-withdraw err = %v, want ErrInsufficientLiquidity", err)
			}
			if got := s.TotalDeployed(); got.Cmp(big.NewInt(1500)) != 0 {
				t.Fatalf("a refused withdrawal moved the deployed total to %s", got)
			}
			// Exactly what is deployed comes back in full.
			got, err := s.Withdraw(big.NewInt(1500))
			if err != nil {
				t.Fatalf("Withdraw: %v", err)
			}
			if got.Cmp(big.NewInt(1500)) != 0 {
				t.Fatalf("Withdraw returned %s, want 1500", got)
			}
			if left := s.TotalDeployed(); left.Sign() != 0 {
				t.Fatalf("TotalDeployed = %s after a full withdrawal, want 0", left)
			}
			// An emptied strategy harvests nothing.
			profit, err = s.Harvest()
			if err != nil {
				t.Fatalf("Harvest on an empty strategy: %v", err)
			}
			if profit.Sign() != 0 {
				t.Fatalf("an empty strategy harvested %s, want 0", profit)
			}
		})
	}
}

func TestZzlVaultBundledStrategyConstructorsCarryTheirWiring(t *testing.T) {
	// The constructors record the collaborators the strategy will act through.
	pm := NewPoolManager()
	poolID := [32]byte{0xAB}
	lp := NewLPYieldStrategy(pm, poolID)
	if lp.PoolManager != pm || lp.PoolID != poolID {
		t.Fatal("NewLPYieldStrategy did not record its pool")
	}
	if lp.APY.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("LP default APY = %s, want 1000", lp.APY)
	}

	lend := NewLendingYieldStrategy(nil, zzlAssetB)
	if lend.Asset != zzlAssetB {
		t.Fatal("NewLendingYieldStrategy did not record its asset")
	}

	pe := NewPerpetualEngine()
	marketID := [32]byte{0xCD}
	dn := NewDeltaNeutralStrategy(pe, pm, marketID)
	if dn.PerpEngine != pe || dn.SpotDEX != pm || dn.MarketID != marketID {
		t.Fatal("NewDeltaNeutralStrategy did not record its collaborators")
	}
}

func TestZzlVaultDrivesTheStrategyThroughDepositAndWithdraw(t *testing.T) {
	// End to end over a bundled strategy with a long enough name to survive
	// CreateVault: the vault's assets and the strategy's deployed capital move
	// together, in both directions.
	vm := NewVaultManager()
	s := NewLendingYieldStrategy(nil, zzlAssetA)
	addr, err := vm.CreateVault(zzlVaultAsset, s, 1000, 0, big.NewInt(0), zzlOwner)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if _, err := vm.Deposit(zzlOwner, addr, big.NewInt(10_000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if got := s.TotalDeployed(); got.Cmp(big.NewInt(10_000)) != 0 {
		t.Fatalf("strategy holds %s, want the deposited 10000", got)
	}
	if vm.Vaults[addr].TotalAssets.Cmp(s.TotalDeployed()) != 0 {
		t.Fatal("the vault's assets and the strategy's deployed capital disagree")
	}
	if _, err := vm.Withdraw(zzlOwner, addr, big.NewInt(4_000)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if got := s.TotalDeployed(); got.Cmp(big.NewInt(6_000)) != 0 {
		t.Fatalf("strategy holds %s after a 4000 withdrawal, want 6000", got)
	}
	if vm.Vaults[addr].TotalAssets.Cmp(s.TotalDeployed()) != 0 {
		t.Fatal("the vault and the strategy diverged after a withdrawal")
	}
	// Harvesting through the vault compounds the strategy's reported yield.
	before := new(big.Int).Set(vm.Vaults[addr].TotalAssets)
	net, err := vm.Harvest(addr)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	if net.Sign() <= 0 {
		t.Fatalf("net profit = %s, want positive", net)
	}
	if vm.Vaults[addr].TotalAssets.Cmp(new(big.Int).Add(before, net)) != 0 {
		t.Fatal("the harvested profit was not compounded into the vault")
	}
}
