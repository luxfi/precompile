// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// zzpool_custody_test.go covers Deposit / Withdraw / BalanceOf and the two native
// vault legs (lockNativeIntoVault / releaseNativeFromVault), plus the global
// non-reentrant guard (enterCustody / exitCustody).
//
// The invariant under test is CUSTODY CONSERVATION: the vault's native balance
// equals the sum of the D-Chain claims minted against it. Every deposit must add
// the same amount to both sides; every withdraw must subtract the same amount
// from both sides; and no sequence of calls may move one without the other.
// Everything else here (refusals, replay, reentrancy) exists to protect that one
// equation.

// zzpConservedNative fails unless the 0x9010 vault's native balance equals the
// total of the D-Chain available balances minted against it.
func zzpConservedNative(t *testing.T, db StateDB, l *zzpLedger, when string) {
	t.Helper()
	vault := db.GetBalance(poolManagerAddr).ToBig()
	claims := l.zzpTotal(NativeCurrency)
	if vault.Cmp(claims) != 0 {
		t.Fatalf("%s: CONSERVATION BROKEN — vault holds %s native, D-Chain claims total %s", when, vault, claims)
	}
}

// zzpConservedToken fails unless the precompile's per-token vault ledger, the
// vault's REAL token balance, and the D-Chain claims all agree.
func zzpConservedToken(t *testing.T, db *zzpVaultDB, l *zzpLedger, token common.Address, when string) {
	t.Helper()
	recorded := loadVaultLedger(db, token)
	actual := db.TokenBalanceOf(token, poolManagerAddr)
	claims := l.zzpTotal(Currency{Address: token})
	if recorded.Cmp(actual) != 0 {
		t.Fatalf("%s: vault ledger says %s of %x but the vault really holds %s", when, recorded, token, actual)
	}
	if recorded.Cmp(claims) != 0 {
		t.Fatalf("%s: vault ledger says %s but D-Chain claims total %s", when, recorded, claims)
	}
}

// zzpFundVault models the EVM value transfer that precedes a native deposit: the
// caller's msg.value is already sitting in 0x9010 when the precompile runs.
func zzpFundVault(db StateDB, amount int64) {
	db.AddBalance(poolManagerAddr, uint256.NewInt(uint64(amount)))
}

// =========================================================================
// enterCustody / exitCustody — the global non-reentrant guard
// =========================================================================

func TestZzpCustodyGuardRefusesSecondEntryAndReleasesOnExit(t *testing.T) {
	db := NewMockStateDB()

	if !enterCustody(db) {
		t.Fatal("the first entry into a clean custody guard was refused")
	}
	if enterCustody(db) {
		t.Fatal("a SECOND entry was admitted while the guard was held — a malicious token can re-enter Deposit/Withdraw")
	}
	exitCustody(db)
	if !enterCustody(db) {
		t.Fatal("the guard stayed latched after exit — custody would be permanently bricked")
	}
	exitCustody(db)

	// Exit on a guard that was never entered must be safe (it is deferred on
	// every path, including ones that never set it in a prior execution).
	exitCustody(db)
	if !enterCustody(db) {
		t.Fatal("a redundant exit broke the guard")
	}
}

func TestZzpCustodyGuardIsGlobalNotPerArgument(t *testing.T) {
	// The documented attack is a reentrant call with DIFFERENT arguments, which a
	// per-(caller,asset,amount) flag would miss. One held guard must refuse every
	// custody entry regardless of who is calling with what.
	db := zzpNewVaultDB(zzpTx1)
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)

	if !enterCustody(db) {
		t.Fatal("could not take the guard")
	}
	zzpFundVault(db, 1_000)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); !errors.Is(err, ErrCustodyReentrant) {
		t.Errorf("Deposit under a held guard: got %v, want ErrCustodyReentrant", err)
	}
	if _, err := pm.Withdraw(db, zzpBob, zzpToken, big.NewInt(5)); !errors.Is(err, ErrCustodyReentrant) {
		t.Errorf("Withdraw (different caller, different asset, different amount) under a held guard: got %v, want ErrCustodyReentrant", err)
	}
	if ledger.deposits != 0 || ledger.withdraws != 0 {
		t.Errorf("a refused reentrant call still reached the D-Chain backend (deposits=%d withdraws=%d)", ledger.deposits, ledger.withdraws)
	}
}

func TestZzpDepositReentryDuringTokenTransferIsRefused(t *testing.T) {
	// The real shape: a malicious ERC-20 re-enters Deposit from inside its own
	// transferFrom, i.e. INSIDE the observed-delta window. Without the guard both
	// calls mint and the ledger claims exceed the vault.
	db := zzpNewVaultDB(zzpTx1)
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db.zzpMint(zzpTokenAddr, zzpAlice, 10_000)

	var nested error
	db.onTransferFrom = func() {
		if nested == nil {
			nested = pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(1_000))
		}
	}
	if err := pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(1_000)); err != nil {
		t.Fatalf("outer deposit: %v", err)
	}
	if !errors.Is(nested, ErrCustodyReentrant) {
		t.Fatalf("reentrant deposit from inside transferFrom: got %v, want ErrCustodyReentrant", nested)
	}
	if ledger.deposits != 1 {
		t.Errorf("the reentrant deposit reached the backend: %d credits for one deposit", ledger.deposits)
	}
	zzpConservedToken(t, db, ledger, zzpTokenAddr, "after a refused reentrant deposit")
}

func TestZzpWithdrawReentryDuringTokenTransferIsRefused(t *testing.T) {
	db := zzpNewVaultDB(zzpTx1)
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db.zzpMint(zzpTokenAddr, zzpAlice, 10_000)

	if err := pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(4_000)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	// A distinct tx, so the withdraw is not served from the deposit's binding.
	db.tx = zzpTx2

	var nested error
	db.onTransferTo = func() {
		if nested == nil {
			_, nested = pm.Withdraw(db, zzpAlice, zzpToken, big.NewInt(4_000))
		}
	}
	got, err := pm.Withdraw(db, zzpAlice, zzpToken, big.NewInt(4_000))
	if err != nil {
		t.Fatalf("outer withdraw: %v", err)
	}
	if got.Cmp(big.NewInt(4_000)) != 0 {
		t.Errorf("realized: got %s, want 4000", got)
	}
	if !errors.Is(nested, ErrCustodyReentrant) {
		t.Fatalf("reentrant withdraw from inside transfer: got %v, want ErrCustodyReentrant", nested)
	}
	if ledger.withdraws != 1 {
		t.Errorf("the reentrant withdraw reached the backend: %d burns for one withdraw", ledger.withdraws)
	}
	zzpConservedToken(t, db, ledger, zzpTokenAddr, "after a refused reentrant withdraw")
}

func TestZzpCustodyGuardIsReleasedOnEveryErrorPath(t *testing.T) {
	// A guard left latched by a failing deposit would brick custody for the rest
	// of the execution. Drive several distinct failures, then prove the next
	// genuine deposit still works.
	db := zzpNewVaultDB(zzpTx1)
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)

	ledger.depositErr = errors.New("backend down")
	zzpFundVault(db, 1_000)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err == nil {
		t.Fatal("a failing backend deposit returned nil")
	}
	ledger.depositErr = nil

	// Unfunded native deposit (the vault does not hold msg.value).
	empty := zzpNewVaultDB(zzpTx1)
	if err := pm.Deposit(empty, zzpAlice, NativeCurrency, big.NewInt(1)); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("unfunded native deposit: got %v, want ErrInsufficientBalance", err)
	}

	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err != nil {
		t.Fatalf("a genuine deposit after failures: %v — the guard was not released", err)
	}
	zzpConservedNative(t, db, ledger, "after the failure sequence")
}

// =========================================================================
// lockNativeIntoVault / releaseNativeFromVault
// =========================================================================

func TestZzpLockNativeVerifiesTheVaultIsFunded(t *testing.T) {
	pm := NewPoolManager(zzpNewLedger())
	db := NewMockStateDB()

	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if err := pm.lockNativeIntoVault(db, bad); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("lockNativeIntoVault(%v): got %v, want ErrInvalidAmount", bad, err)
		}
	}
	// Unfunded: 0x9010 does not hold the amount, so the mint would be unbacked.
	if err := pm.lockNativeIntoVault(db, big.NewInt(100)); !errors.Is(err, ErrInsufficientBalance) {
		t.Errorf("unfunded lock: got %v, want ErrInsufficientBalance", err)
	}
	// Exactly funded is the boundary and must be ACCEPTED (a > vs >= slip here
	// would reject every honest deposit).
	zzpFundVault(db, 100)
	if err := pm.lockNativeIntoVault(db, big.NewInt(100)); err != nil {
		t.Errorf("exactly-funded lock: %v", err)
	}
	// One wei short is the other side of the same boundary and must be REFUSED.
	if err := pm.lockNativeIntoVault(db, big.NewInt(101)); !errors.Is(err, ErrInsufficientBalance) {
		t.Errorf("one wei short: got %v, want ErrInsufficientBalance", err)
	}
	// The lock MOVES NOTHING — it only verifies. The vault balance is untouched.
	if got := db.GetBalance(poolManagerAddr); got.Uint64() != 100 {
		t.Errorf("lockNativeIntoVault moved value: vault holds %s, want 100", got)
	}
	// Beyond uint256 the amount cannot be represented at all: refuse, never wrap.
	huge := new(big.Int).Lsh(big.NewInt(1), 256)
	if err := pm.lockNativeIntoVault(db, huge); !errors.Is(err, ErrInvalidAmount) {
		t.Errorf("2^256 lock: got %v, want ErrInvalidAmount", err)
	}
}

func TestZzpReleaseNativeNeverExceedsTheVault(t *testing.T) {
	pm := NewPoolManager(zzpNewLedger())
	db := NewMockStateDB()
	zzpFundVault(db, 1_000)

	// Non-positive is a no-op, not an error: the withdraw leg calls it with the
	// realized amount, and a realized zero must simply release nothing.
	for _, zero := range []*big.Int{nil, big.NewInt(0), big.NewInt(-5)} {
		if err := pm.releaseNativeFromVault(db, zzpAlice, zero); err != nil {
			t.Errorf("release(%v): got %v, want nil", zero, err)
		}
	}
	if db.GetBalance(zzpAlice).Sign() != 0 {
		t.Fatal("a non-positive release paid the caller")
	}

	// Over the vault: refuse. Releasing more than the vault holds is a mint.
	if err := pm.releaseNativeFromVault(db, zzpAlice, big.NewInt(1_001)); !errors.Is(err, ErrInsufficientBalance) {
		t.Errorf("over-release: got %v, want ErrInsufficientBalance", err)
	}
	if db.GetBalance(zzpAlice).Sign() != 0 || db.GetBalance(poolManagerAddr).Uint64() != 1_000 {
		t.Fatal("a refused release still moved value")
	}

	// Exactly the vault: allowed, and CONSERVING — every wei that leaves 0x9010
	// arrives at the caller.
	if err := pm.releaseNativeFromVault(db, zzpAlice, big.NewInt(1_000)); err != nil {
		t.Fatalf("exact release: %v", err)
	}
	if got := db.GetBalance(zzpAlice).Uint64(); got != 1_000 {
		t.Errorf("caller received %d, want 1000", got)
	}
	if got := db.GetBalance(poolManagerAddr).Uint64(); got != 0 {
		t.Errorf("vault retained %d after an exact release, want 0", got)
	}

	huge := new(big.Int).Lsh(big.NewInt(1), 256)
	if err := pm.releaseNativeFromVault(db, zzpAlice, huge); !errors.Is(err, ErrInvalidAmount) {
		t.Errorf("2^256 release: got %v, want ErrInvalidAmount", err)
	}
}

// =========================================================================
// Deposit — refusals
// =========================================================================

func TestZzpDepositRefusesNonPositiveAndOversizeAmounts(t *testing.T) {
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 1_000_000)

	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if err := pm.Deposit(db, zzpAlice, NativeCurrency, bad); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("Deposit(%v): got %v, want ErrInvalidAmount", bad, err)
		}
	}
	// The D-Chain ledger keys balances in uint64. uint64 max is the LAST accepted
	// value and uint64max+1 the FIRST refused one — drive both sides.
	overflow := new(big.Int).Add(new(big.Int).SetUint64(^uint64(0)), big.NewInt(1))
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, overflow); !errors.Is(err, ErrInvalidAmount) {
		t.Errorf("Deposit(2^64): got %v, want ErrInvalidAmount", err)
	}
	// The amount is judged BEFORE any capability is resolved, so an invalid
	// amount reads as invalid whatever backend or StateDB is behind it. If the
	// amount check moved after the capability checks, a zero-amount call would
	// report "no backend" and hide the caller's actual mistake.
	noBackend := NewPoolManager(&mockEngine{})
	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if err := noBackend.Deposit(db, zzpAlice, NativeCurrency, bad); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("Deposit(%v) with no custody backend: got %v, want ErrInvalidAmount", bad, err)
		}
		if err := pm.Deposit(zzpNewTxDB(zzpTx1), zzpAlice, zzpToken, bad); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("ERC-20 Deposit(%v) with no vault capability: got %v, want ErrInvalidAmount", bad, err)
		}
		if err := pm.Deposit(NewMockStateDB(), zzpAlice, NativeCurrency, bad); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("Deposit(%v) with no tx identity: got %v, want ErrInvalidAmount", bad, err)
		}
	}

	// The guard must not have latched on any of those early returns.
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(10)); err != nil {
		t.Errorf("a valid deposit after the refusals: %v", err)
	}
}

func TestZzpDepositRefusesWithoutBackendVaultOrTxIdentity(t *testing.T) {
	// No custody backend: refuse, never fabricate a credit.
	plain := NewPoolManager(&mockEngine{})
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 1_000)
	if err := plain.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); !errors.Is(err, ErrDChainUnavailable) {
		t.Errorf("deposit with a non-custody backend: got %v, want ErrDChainUnavailable", err)
	}

	// No tx identity: refuse rather than lock+mint against the zero ref, which
	// would collide on the D-Chain dedup key.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	noTx := NewMockStateDB()
	zzpFundVault(noTx, 1_000)
	if err := pm.Deposit(noTx, zzpAlice, NativeCurrency, big.NewInt(1_000)); !errors.Is(err, ErrCustodyUnbound) {
		t.Errorf("deposit with no tx identity: got %v, want ErrCustodyUnbound", err)
	}
	zeroTx := zzpNewTxDB(common.Hash{})
	zzpFundVault(zeroTx, 1_000)
	if err := pm.Deposit(zeroTx, zzpAlice, NativeCurrency, big.NewInt(1_000)); !errors.Is(err, ErrCustodyUnbound) {
		t.Errorf("deposit with a zero txHash: got %v, want ErrCustodyUnbound", err)
	}
	if ledger.deposits != 0 {
		t.Errorf("a refused deposit still credited the D-Chain (%d calls)", ledger.deposits)
	}

	// ERC-20 against a StateDB with no vault capability: refuse BEFORE minting.
	noVault := zzpNewTxDB(zzpTx1)
	if err := pm.Deposit(noVault, zzpAlice, zzpToken, big.NewInt(1_000)); !errors.Is(err, ErrERC20VaultUnavailable) {
		t.Errorf("ERC-20 deposit without a vault-capable StateDB: got %v, want ErrERC20VaultUnavailable", err)
	}
	if ledger.deposits != 0 {
		t.Errorf("the vault-less ERC-20 deposit still credited the D-Chain (%d calls)", ledger.deposits)
	}
}

func TestZzpDepositUnfundedNativeMintsNothing(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 99) // the caller sent 99 but asks to mint 100

	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(100)); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("under-funded deposit: got %v, want ErrInsufficientBalance", err)
	}
	if ledger.deposits != 0 {
		t.Fatal("an under-funded deposit reached the D-Chain mint — an unbacked claim")
	}
	if got := ledger.zzpAvail(zzpAlice, NativeCurrency); got != 0 {
		t.Fatalf("an under-funded deposit credited %d", got)
	}
}

func TestZzpDepositBackendFailureLeavesNoBinding(t *testing.T) {
	ledger := zzpNewLedger()
	ledger.depositErr = errors.New("clob down")
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 500)

	err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(500))
	if !errors.Is(err, ErrSettlementFailed) {
		t.Fatalf("backend failure: got %v, want ErrSettlementFailed", err)
	}
	key, _ := depositBindKey(db, zzpAlice, NativeCurrency, big.NewInt(500))
	if loadCustodyBinding(db, key) {
		t.Fatal("a FAILED deposit recorded an idempotency binding — the retry would be short-circuited and the funds stranded")
	}
	// The retry, once the backend recovers, must go through.
	ledger.depositErr = nil
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(500)); err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	zzpConservedNative(t, db, ledger, "after a failed-then-successful deposit")
}

// =========================================================================
// Deposit / Withdraw — replay idempotency
// =========================================================================

func TestZzpDepositIsExactlyOncePerTx(t *testing.T) {
	// The EVM runs one tx ~5x; a clob_deposit is an irreversible credit. Every
	// re-execution after the first must mint NOTHING.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 1_000)

	for i := 0; i < 5; i++ {
		if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err != nil {
			t.Fatalf("execution %d: %v", i, err)
		}
	}
	if ledger.deposits != 1 {
		t.Fatalf("5 executions of one deposit tx produced %d D-Chain credits, want 1", ledger.deposits)
	}
	if got := ledger.zzpAvail(zzpAlice, NativeCurrency); got != 1_000 {
		t.Fatalf("available after 5 executions: %d, want 1000", got)
	}
	zzpConservedNative(t, db, ledger, "after 5 executions of one deposit")

	// A GENUINELY distinct deposit (new tx) must NOT be short-circuited.
	db.tx = zzpTx2
	zzpFundVault(db, 1_000)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err != nil {
		t.Fatalf("second genuine deposit: %v", err)
	}
	if ledger.deposits != 2 {
		t.Fatalf("a distinct deposit tx was swallowed by the first one's binding (%d credits)", ledger.deposits)
	}
	zzpConservedNative(t, db, ledger, "after a second genuine deposit")
}

func TestZzpWithdrawIsExactlyOncePerTx(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 1_000)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}

	db.tx = zzpTx2
	var first *big.Int
	for i := 0; i < 5; i++ {
		got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(600))
		if err != nil {
			t.Fatalf("execution %d: %v", i, err)
		}
		if first == nil {
			first = got
		} else if got.Cmp(first) != 0 {
			t.Fatalf("execution %d returned %s, first returned %s — a replay must return the SAME realized amount", i, got, first)
		}
	}
	if ledger.withdraws != 1 {
		t.Fatalf("5 executions of one withdraw tx produced %d D-Chain burns, want 1", ledger.withdraws)
	}
	if got := db.GetBalance(zzpAlice).Uint64(); got != 600 {
		t.Fatalf("caller received %d across 5 executions, want 600 — the vault paid more than it burned", got)
	}
	zzpConservedNative(t, db, ledger, "after 5 executions of one withdraw")
}

func TestZzpSecondGenuineWithdrawReclampsToCurrentBalance(t *testing.T) {
	// The vault-drain fix: a second, GENUINELY distinct withdraw of the same shape
	// must re-clamp to the CURRENT available (zero after the first), not replay the
	// first realized amount against an already-paid vault.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 1_000)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}

	db.tx = zzpTx2
	got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(1_000))
	if err != nil || got.Cmp(big.NewInt(1_000)) != 0 {
		t.Fatalf("first withdraw: got %s err %v", got, err)
	}
	db.tx = common.HexToHash("0x33")
	got, err = pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(1_000))
	if err != nil {
		t.Fatalf("second withdraw: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("a second withdraw against a drained balance realized %s — the vault paid twice for one burn", got)
	}
	if paid := db.GetBalance(zzpAlice).Uint64(); paid != 1_000 {
		t.Fatalf("caller was paid %d in total against a 1000 deposit", paid)
	}
	zzpConservedNative(t, db, ledger, "after a drained second withdraw")
}

// =========================================================================
// Withdraw — refusals and the vault-underflow guard
// =========================================================================

func TestZzpWithdrawRefusesNonPositiveOversizeAndUnbacked(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)

	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, bad)
		if !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("Withdraw(%v): got %v, want ErrInvalidAmount", bad, err)
		}
		if got.Sign() != 0 {
			t.Errorf("a refused withdraw reported a realized amount of %s", got)
		}
	}
	overflow := new(big.Int).Add(new(big.Int).SetUint64(^uint64(0)), big.NewInt(1))
	if _, err := pm.Withdraw(db, zzpAlice, NativeCurrency, overflow); !errors.Is(err, ErrInvalidAmount) {
		t.Errorf("Withdraw(2^64): got %v, want ErrInvalidAmount", err)
	}

	// No backend / no tx identity / no vault capability, exactly as for Deposit.
	plain := NewPoolManager(&mockEngine{})
	if _, err := plain.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(1)); !errors.Is(err, ErrDChainUnavailable) {
		t.Errorf("withdraw with a non-custody backend: got %v, want ErrDChainUnavailable", err)
	}
	if _, err := pm.Withdraw(NewMockStateDB(), zzpAlice, NativeCurrency, big.NewInt(1)); !errors.Is(err, ErrCustodyUnbound) {
		t.Errorf("withdraw with no tx identity: got %v, want ErrCustodyUnbound", err)
	}
	if _, err := pm.Withdraw(zzpNewTxDB(zzpTx1), zzpAlice, zzpToken, big.NewInt(1)); !errors.Is(err, ErrERC20VaultUnavailable) {
		t.Errorf("ERC-20 withdraw without a vault-capable StateDB: got %v, want ErrERC20VaultUnavailable", err)
	}
	if ledger.withdraws != 0 {
		t.Fatalf("a refused withdraw still burned the D-Chain ledger (%d calls) — the claim would be stranded", ledger.withdraws)
	}
}

func TestZzpWithdrawNeverExceedsTheDepositedBalance(t *testing.T) {
	// Asking for more than was deposited must realize exactly what is there.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 400)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(400)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}

	db.tx = zzpTx2
	got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(10_000))
	if err != nil {
		t.Fatalf("over-ask withdraw: %v", err)
	}
	if got.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("realized %s against a 400 deposit — a withdrawal exceeded the balance", got)
	}
	zzpConservedNative(t, db, ledger, "after an over-ask withdraw")
}

func TestZzpWithdrawWithNothingDepositedPaysNothing(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	// Someone ELSE'S money is in the vault; Alice has no claim on it.
	zzpFundVault(db, 5_000)
	ledger.zzpSet(zzpBob, NativeCurrency, 5_000)

	got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(5_000))
	if err != nil {
		t.Fatalf("withdraw with no balance: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("realized %s with nothing deposited — another account's backing was paid out", got)
	}
	if db.GetBalance(zzpAlice).Sign() != 0 {
		t.Fatal("the caller was paid despite realizing zero")
	}
	zzpConservedNative(t, db, ledger, "after a zero-balance withdraw")
}

func TestZzpWithdrawVaultUnderflowRefusesAnOverReportingBackend(t *testing.T) {
	// The vault-underflow guard is the LAST line between a backend that reports a
	// realized amount larger than it burned and a vault that mints value. Under
	// the maintained invariant it never fires; it must fire when the invariant is
	// violated rather than pay out.
	ledger := zzpNewLedger()
	ledger.overpay = 1
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 100)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(100)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}

	db.tx = zzpTx2
	got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(100))
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("over-reported withdraw: got realized %s err %v, want ErrInsufficientBalance", got, err)
	}
	if db.GetBalance(zzpAlice).Sign() != 0 {
		t.Fatal("the refused over-release still paid the caller")
	}
	if db.GetBalance(poolManagerAddr).Uint64() != 100 {
		t.Fatal("the refused over-release still debited the vault")
	}
}

func TestZzpWithdrawPassesTheRequestedAmountThroughUnchanged(t *testing.T) {
	// The PoolManager forwards `want` to the backend verbatim and uses the
	// returned realized value verbatim: it applies no clamp of its own. That makes
	// the ledger's clamp and the vault-underflow guard the ONLY two things
	// standing between a backend and the vault, which is worth pinning explicitly.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 700)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(700)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	var seenWant uint64
	ledger.onWithdraw = func() { seenWant = 250 }
	db.tx = zzpTx2
	got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(250))
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if seenWant != 250 || got.Cmp(big.NewInt(250)) != 0 {
		t.Errorf("want/realized pass-through: backend saw %d, caller got %s", seenWant, got)
	}
	if got := db.GetBalance(zzpAlice).Uint64(); got != 250 {
		t.Errorf("released %d for a realized 250", got)
	}
	zzpConservedNative(t, db, ledger, "after a partial withdraw")
}

func TestZzpWithdrawBackendFailureLeavesNoBindingAndReleasesNothing(t *testing.T) {
	ledger := zzpNewLedger()
	ledger.withdrawErr = errors.New("clob down")
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 300)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(300)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}

	db.tx = zzpTx2
	got, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(300))
	if !errors.Is(err, ErrSettlementFailed) {
		t.Fatalf("failing burn: got %v, want ErrSettlementFailed", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("a failed burn reported realized %s", got)
	}
	if db.GetBalance(zzpAlice).Sign() != 0 {
		t.Fatal("a failed burn still released from the vault")
	}
	key, _ := withdrawBindKey(db, zzpAlice, NativeCurrency, big.NewInt(300))
	if _, settled := loadWithdrawBinding(db, key); settled {
		t.Fatal("a FAILED withdraw recorded a settled binding — the retry would return a phantom realized amount")
	}
	zzpConservedNative(t, db, ledger, "after a failed withdraw")
}

func TestZzpCustodyThreadsTheTxHashAsTheDedupRef(t *testing.T) {
	// The EVM-side replay key and the D-Chain-side dedup key must be ONE identity.
	// A zero (or constant) ref would make every content-identical custody op
	// collide on the ledger's dedup index — the replay that let one burn be paid
	// twice. So the ref must be the tx hash, non-zero, and distinct per tx.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	zzpFundVault(db, 1_000)

	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(1_000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	db.tx = zzpTx2
	if _, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(400)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	tx3 := common.HexToHash("0x33")
	db.tx = tx3
	zzpFundVault(db, 500)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(500)); err != nil {
		t.Fatalf("second deposit: %v", err)
	}

	want := [][32]byte{zzpTx1, zzpTx2, tx3}
	if len(ledger.refs) != len(want) {
		t.Fatalf("the backend saw %d refs for 3 custody ops", len(ledger.refs))
	}
	for i, w := range want {
		if ledger.refs[i] != w {
			t.Errorf("op %d threaded ref %x, want the tx hash %x", i, ledger.refs[i], w)
		}
		if ledger.refs[i] == ([32]byte{}) {
			t.Errorf("op %d threaded the ZERO ref — every such op collides on the ledger dedup key", i)
		}
	}
}

// =========================================================================
// BalanceOf
// =========================================================================

func TestZzpBalanceOfReadsThroughToTheLedger(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)

	got, err := pm.BalanceOf(zzpAlice, NativeCurrency)
	if err != nil || got.Sign() != 0 {
		t.Fatalf("balance before any deposit: got %s err %v", got, err)
	}

	zzpFundVault(db, 900)
	if err := pm.Deposit(db, zzpAlice, NativeCurrency, big.NewInt(900)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	// BalanceOf == credits - debits, for the RIGHT account and the RIGHT asset.
	if got, _ := pm.BalanceOf(zzpAlice, NativeCurrency); got.Cmp(big.NewInt(900)) != 0 {
		t.Errorf("after deposit: got %s, want 900", got)
	}
	if got, _ := pm.BalanceOf(zzpBob, NativeCurrency); got.Sign() != 0 {
		t.Errorf("another account reads %s of Alice's deposit", got)
	}
	if got, _ := pm.BalanceOf(zzpAlice, zzpToken); got.Sign() != 0 {
		t.Errorf("another asset reads %s of the native deposit", got)
	}

	db.tx = zzpTx2
	if _, err := pm.Withdraw(db, zzpAlice, NativeCurrency, big.NewInt(400)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if got, _ := pm.BalanceOf(zzpAlice, NativeCurrency); got.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("after a 400 debit against a 900 credit: got %s, want 500", got)
	}

	// A backend read failure surfaces, it does not silently read as zero.
	ledger.balanceErr = errors.New("clob down")
	if _, err := pm.BalanceOf(zzpAlice, NativeCurrency); err == nil {
		t.Error("a failing balance read returned nil error — a stale zero would look like an empty account")
	}

	// A non-custody backend has nothing deposited, so zero with no error.
	got, err = NewPoolManager(&mockEngine{}).BalanceOf(zzpAlice, NativeCurrency)
	if err != nil || got.Sign() != 0 {
		t.Errorf("non-custody backend: got %s err %v, want 0 nil", got, err)
	}
}

// =========================================================================
// Conservation sweep
// =========================================================================

// TestZzpCustodyConservationSweep drives a long randomized deposit/withdraw
// sequence for two accounts and asserts, after EVERY operation, that the vault's
// native balance equals the total D-Chain claims and that no account was ever
// paid more than it deposited. Seed 0x9010 is fixed so the exact sequence is
// reproducible from this file alone.
func TestZzpCustodyConservationSweep(t *testing.T) {
	rng := rand.New(rand.NewSource(0x9010))
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)

	accounts := []common.Address{zzpAlice, zzpBob}
	deposited := map[common.Address]int64{}
	released := map[common.Address]int64{}

	for i := 0; i < 600; i++ {
		// A fresh tx per iteration: each op is a genuinely distinct EVM tx, so the
		// replay bindings never mask a real second op.
		var tx common.Hash
		tx[0] = byte(i)
		tx[1] = byte(i >> 8)
		tx[31] = 1 // never the zero hash
		db.tx = tx

		who := accounts[rng.Intn(len(accounts))]
		amount := int64(rng.Intn(5_000) + 1)

		if rng.Intn(2) == 0 {
			zzpFundVault(db, amount) // the EVM moved msg.value in before dispatch
			if err := pm.Deposit(db, who, NativeCurrency, big.NewInt(amount)); err != nil {
				t.Fatalf("iteration %d deposit: %v", i, err)
			}
			deposited[who] += amount
		} else {
			before := db.GetBalance(who).ToBig()
			realized, err := pm.Withdraw(db, who, NativeCurrency, big.NewInt(amount))
			if err != nil {
				t.Fatalf("iteration %d withdraw: %v", i, err)
			}
			if realized.Cmp(big.NewInt(amount)) > 0 {
				t.Fatalf("iteration %d: realized %s exceeds the %d requested", i, realized, amount)
			}
			after := db.GetBalance(who).ToBig()
			paid := new(big.Int).Sub(after, before)
			if paid.Cmp(realized) != 0 {
				t.Fatalf("iteration %d: the vault paid %s for a realized %s — value was created or destroyed", i, paid, realized)
			}
			released[who] += realized.Int64()
		}
		zzpConservedNative(t, db, ledger, "sweep iteration")
		for _, a := range accounts {
			if released[a] > deposited[a] {
				t.Fatalf("iteration %d: %x was paid %d against %d deposited", i, a, released[a], deposited[a])
			}
		}
	}

	// Close the books: every account withdraws everything, and the vault must end
	// EXACTLY empty — value in equals value out, no dust either way.
	for n, a := range accounts {
		var tx common.Hash
		tx[0] = 0xFF
		tx[1] = byte(n)
		db.tx = tx
		realized, err := pm.Withdraw(db, a, NativeCurrency, new(big.Int).SetUint64(ledger.zzpAvail(a, NativeCurrency)+1))
		if err != nil {
			t.Fatalf("final withdraw for %x: %v", a, err)
		}
		released[a] += realized.Int64()
	}
	if got := db.GetBalance(poolManagerAddr).Uint64(); got != 0 {
		t.Fatalf("the vault retained %d after every claim was withdrawn", got)
	}
	for _, a := range accounts {
		if released[a] != deposited[a] {
			t.Fatalf("%x deposited %d and was paid %d — value in must equal value out", a, deposited[a], released[a])
		}
	}
	zzpConservedNative(t, db, ledger, "after closing the books")
}
