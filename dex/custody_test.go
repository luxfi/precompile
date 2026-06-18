// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/holiman/uint256"
)

// custody_test.go exercises the CLOB CUSTODY MODEL at the precompile ingress
// boundary: native LUX DEPOSITS lock value in the 0x9010 vault and MINT a D-Chain
// available balance; orders LOCK/SETTLE that balance inside the D-Chain;
// WITHDRAWS burn the D-Chain balance and RELEASE the vault. The hard invariant
// these tests prove is that 0x9010 is a PASSIVE LOCK VAULT, never a trade
// counterparty / reserve, and that value is conserved across the rail.
//
// These run against the in-memory fakeCLOB double (which carries a minimal
// balance ledger) so they pin the precompile's adapter wire contract + the vault
// accounting. The LIVE e2e (cmd/dvenue-custody + the EVM driver) proves the same
// against the REAL D-Chain ledger.

// custodyPM builds a PoolManager wired to a fresh fakeCLOB + a tx-identified
// MockStateDB (so the deposit/withdraw idempotency bindings engage), and funds the
// caller with `seed` native LUX on C-Chain. Returns the manager, the fake book,
// the stateDB, and the caller address.
func custodyPM(t *testing.T, seed uint64) (*PoolManager, *fakeCLOB, *txStateDB, common.Address) {
	t.Helper()
	f := newFakeCLOB()
	withFakeCLOB(t, f)
	zap := NewZAPEngine("fake:0", 2*time.Second)
	t.Cleanup(func() { _ = zap.Close() })
	pm := NewPoolManager(zap)
	sdb := &txStateDB{MockStateDB: NewMockStateDB()}
	sdb.txHash = common.HexToHash("0xdead00000000000000000000000000000000000000000000000000000000beef")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	// Fund the caller on C-Chain (their wallet balance, pre-deposit).
	sdb.balances[caller] = uint256.NewInt(seed)
	return pm, f, sdb, caller
}

// simulateDepositValueTransfer models the EVM's pre-dispatch value transfer: when
// a tx sends msg.value to 0x9010, geth moves it caller->0x9010 BEFORE the
// precompile runs (core/vm/evm.go Transfer precedes precompile dispatch). The
// precompile then sees the value already in the vault. We replicate that here so
// the test exercises lockNativeIntoVault's real precondition.
func simulateDepositValueTransfer(sdb *txStateDB, caller common.Address, amount uint64) {
	amt := uint256.NewInt(amount)
	sdb.SubBalance(caller, amt)
	sdb.AddBalance(poolManagerAddr, amt)
}

// vaultBal / availBal / ledgerAvail read the three accounting surfaces.
func vaultBal(sdb *txStateDB) uint64 { return sdb.GetBalance(poolManagerAddr).Uint64() }
func walletBal(sdb *txStateDB, a common.Address) uint64 {
	return sdb.GetBalance(a).Uint64()
}
func fakeAvail(f *fakeCLOB, a common.Address, asset Currency) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ledger[ledgerKey(a.Bytes()[:16], assetHandle(asset))]
}

// --- HARD GATE: DEPOSIT ---
//
// C/EVM asset balance decreases AND D-Chain available increases by the EXACT
// amount; the native LUX lives in the 0x9010 vault (lock leg), NOT as a reserve
// the book draws from. Revert/replay cannot double-credit.
func TestCustody_Deposit_LocksVaultAndMintsLedger(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)

	const dep = uint64(250)
	// EVM moves msg.value into the vault before the precompile runs.
	simulateDepositValueTransfer(sdb, caller, dep)

	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// C-Chain wallet decreased by exactly dep.
	if got := walletBal(sdb, caller); got != 1000-dep {
		t.Fatalf("caller wallet = %d, want %d", got, 1000-dep)
	}
	// D-Chain available increased by exactly dep.
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("D-Chain available = %d, want %d", got, dep)
	}
	// The native LUX is held in the 0x9010 vault as the lock backing.
	if got := vaultBal(sdb); got != dep {
		t.Fatalf("vault (0x9010) balance = %d, want %d", got, dep)
	}
}

// A deposit not funded by msg.value (vault does not hold it) must be refused —
// never mint an unbacked D-Chain credit.
func TestCustody_Deposit_RefusesUnfunded(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	// Do NOT simulate the value transfer: the vault holds nothing.
	err := pm.Deposit(sdb, caller, NativeCurrency, big.NewInt(100))
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("unfunded deposit err = %v, want ErrInsufficientBalance", err)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != 0 {
		t.Fatalf("D-Chain available = %d after refused deposit, want 0 (no mint)", got)
	}
}

// Replaying the SAME deposit tx (the EVM executes one tx ~5x) must credit the
// ledger exactly ONCE — the StateDB idempotency binding maps the re-exec to the
// prior result without a second mint.
func TestCustody_Deposit_ReplayDoesNotDoubleCredit(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	const dep = uint64(300)
	simulateDepositValueTransfer(sdb, caller, dep)

	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit#1: %v", err)
	}
	// Replay the identical tx. The EVM does NOT re-transfer msg.value on a re-exec
	// of the same tx, but even if the vault were re-funded the binding must dedup.
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit#2 (replay): %v", err)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("D-Chain available after replay = %d, want %d (credited once)", got, dep)
	}
}

// --- HARD GATE: WITHDRAW ---
//
// D-Chain available decreases; the realized amount is released from the vault to
// the caller; replay withdraw FAILS (returns the same realized once, no second
// release); a withdraw exceeding available is clamped (no mint).
func TestCustody_Withdraw_BurnsLedgerAndReleasesVault(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	const dep = uint64(400)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// Withdraw 150 < available 400.
	sdb.txHash = common.HexToHash("0x01") // a distinct tx
	realized, err := pm.Withdraw(sdb, caller, NativeCurrency, big.NewInt(150))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if realized.Uint64() != 150 {
		t.Fatalf("realized = %d, want 150", realized.Uint64())
	}
	// Ledger burned by 150.
	if got := fakeAvail(f, caller, NativeCurrency); got != dep-150 {
		t.Fatalf("D-Chain available = %d, want %d", got, dep-150)
	}
	// Vault released 150; still holds the remaining 250 backing.
	if got := vaultBal(sdb); got != dep-150 {
		t.Fatalf("vault = %d, want %d", got, dep-150)
	}
	// Caller wallet got the 150 back (started 1000, deposited 400, withdrew 150).
	if got := walletBal(sdb, caller); got != 1000-dep+150 {
		t.Fatalf("caller wallet = %d, want %d", got, 1000-dep+150)
	}
}

// A replayed withdraw tx returns the SAME realized amount and does NOT release a
// second time (the binding dedups the burn+release).
func TestCustody_Withdraw_ReplayReleasesOnce(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	const dep = uint64(400)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	sdb.txHash = common.HexToHash("0x02")
	r1, err := pm.Withdraw(sdb, caller, NativeCurrency, big.NewInt(200))
	if err != nil {
		t.Fatalf("Withdraw#1: %v", err)
	}
	// Replay identical withdraw tx.
	r2, err := pm.Withdraw(sdb, caller, NativeCurrency, big.NewInt(200))
	if err != nil {
		t.Fatalf("Withdraw#2 (replay): %v", err)
	}
	if r1.Uint64() != 200 || r2.Uint64() != 200 {
		t.Fatalf("realized r1=%d r2=%d, want 200/200", r1.Uint64(), r2.Uint64())
	}
	// Released exactly once: vault = 400-200, ledger = 400-200.
	if got := vaultBal(sdb); got != dep-200 {
		t.Fatalf("vault = %d after replay, want %d (released once)", got, dep-200)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep-200 {
		t.Fatalf("D-Chain available = %d after replay, want %d (burned once)", got, dep-200)
	}
}

// A withdraw exceeding available is CLAMPED to availability; the vault never
// releases more than the ledger burned (no mint, failed-export-style safety).
func TestCustody_Withdraw_ClampsToAvailableNoMint(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	const dep = uint64(100)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	sdb.txHash = common.HexToHash("0x03")
	realized, err := pm.Withdraw(sdb, caller, NativeCurrency, big.NewInt(999)) // > available
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if realized.Uint64() != dep {
		t.Fatalf("realized = %d, want %d (clamped to available)", realized.Uint64(), dep)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != 0 {
		t.Fatalf("D-Chain available = %d, want 0 (drained)", got)
	}
	if got := vaultBal(sdb); got != 0 {
		t.Fatalf("vault = %d, want 0 (released exactly the realized burn, no mint)", got)
	}
}

// --- RELEASE GATE: the conservation invariant across deposit -> withdraw ---
//
// sum(vault) == sum(D-Chain available) at all times for a single asset; across a
// full deposit/withdraw cycle, C-Chain value out == C-Chain value in.
func TestCustody_ConservationInvariant_DepositWithdrawCycle(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	const dep = uint64(750)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// INVARIANT after deposit: vault == Σ available.
	if vaultBal(sdb) != fakeAvail(f, caller, NativeCurrency) {
		t.Fatalf("invariant breach: vault %d != Σ available %d", vaultBal(sdb), fakeAvail(f, caller, NativeCurrency))
	}

	// Withdraw everything.
	sdb.txHash = common.HexToHash("0x04")
	realized, err := pm.Withdraw(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if realized.Uint64() != dep {
		t.Fatalf("realized = %d, want %d", realized.Uint64(), dep)
	}

	// INVARIANT after withdraw: vault == Σ available == 0.
	if vaultBal(sdb) != 0 || fakeAvail(f, caller, NativeCurrency) != 0 {
		t.Fatalf("invariant breach: vault %d, Σ available %d, want 0/0", vaultBal(sdb), fakeAvail(f, caller, NativeCurrency))
	}
	// C-Chain value conserved: caller wallet back to the initial seed.
	if got := walletBal(sdb, caller); got != 1000 {
		t.Fatalf("caller wallet = %d, want 1000 (C-Chain value conserved across the cycle)", got)
	}
}

// --- NO-RESERVE GATE: a swap/place must NOT move native LUX caller<->0x9010 ---
//
// The OLD bug (settleNativeLegs) left native LUX sitting in 0x9010 "backing
// resting asks". This proves a place no longer touches the C-Chain vault: the
// only thing that changes the vault is an explicit deposit/withdraw.
func TestCustody_PlaceDoesNotTouchVault(t *testing.T) {
	pm, _, sdb, caller := custodyPM(t, 1000)
	// Deposit first so the maker has a ledger balance to lock.
	const dep = uint64(500)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	vaultAfterDeposit := vaultBal(sdb)

	// Initialize a native/quote market and place a resting native-LUX ask.
	key := conservationPoolKey() // currency0 = native LUX
	if _, err := pm.Initialize(sdb, key, new(big.Int).Set(Q96), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	var salt [32]byte
	salt[31] = 7
	params := ModifyLiquidityParams{
		TickLower: -60, TickUpper: 60, LiquidityDelta: big.NewInt(10), Salt: salt,
	}
	if _, _, err := pm.ModifyLiquidity(sdb, caller, key, params, nil); err != nil {
		t.Fatalf("ModifyLiquidity place: %v", err)
	}

	// THE GATE: the vault balance is UNCHANGED by the place. The resting order's
	// funds live in the D-Chain ledger's locked[], not in 0x9010.
	if got := vaultBal(sdb); got != vaultAfterDeposit {
		t.Fatalf("vault changed by place: %d -> %d (NO native reserve must back a resting order)", vaultAfterDeposit, got)
	}
}

// --- ERC-20 DISABLED-WITH-HONEST-FLAG (this pass) ---
//
// A non-native deposit/withdraw is REFUSED explicitly (no fake reserve). It does
// NOT mint a D-Chain credit and does NOT touch any C-Chain balance.
func TestCustody_ERC20Deposit_RefusedNotFaked(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	erc20 := Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000A0")}

	err := pm.Deposit(sdb, caller, erc20, big.NewInt(100))
	if !errors.Is(err, ErrERC20DepositUnsupported) {
		t.Fatalf("ERC-20 deposit err = %v, want ErrERC20DepositUnsupported", err)
	}
	if got := fakeAvail(f, caller, erc20); got != 0 {
		t.Fatalf("ERC-20 D-Chain available = %d, want 0 (no mint)", got)
	}

	_, werr := pm.Withdraw(sdb, caller, erc20, big.NewInt(100))
	if !errors.Is(werr, ErrERC20DepositUnsupported) {
		t.Fatalf("ERC-20 withdraw err = %v, want ErrERC20DepositUnsupported", werr)
	}
}

// An inert backend (no venue) refuses deposit/withdraw cleanly — never moves
// value, never mints.
func TestCustody_InertBackend_RefusesDeposit(t *testing.T) {
	pm := NewPoolManager(newInertEngine())
	sdb := &txStateDB{MockStateDB: NewMockStateDB()}
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sdb.balances[caller] = uint256.NewInt(1000)
	simulateDepositValueTransfer(sdb, caller, 100)

	err := pm.Deposit(sdb, caller, NativeCurrency, big.NewInt(100))
	if !errors.Is(err, ErrDEXBackendNotConfigured) {
		t.Fatalf("inert deposit err = %v, want ErrDEXBackendNotConfigured", err)
	}
}
