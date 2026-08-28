// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzpool_vault_test.go covers erc20_vault.go: the token analog of the native
// lock/release legs. The invariant is the same one the native rail keeps, stated
// per token:
//
//	vaultLedger[token] == balanceOf(token, 0x9010) == Σ D-Chain claims[*][token]
//
// The sharp edge is that the credited amount is the OBSERVED delta, never the
// requested amount: a fee-on-transfer token delivers less than asked, and
// crediting the request would mint an unbacked claim. Every test below is about
// keeping those three numbers equal.

// =========================================================================
// vault ledger word
// =========================================================================

func TestZzpVaultLedgerRoundTripsAndIsPerToken(t *testing.T) {
	db := NewMockStateDB()
	other := common.HexToAddress("0x00000000000000000000000000000000000000D0")

	if got := loadVaultLedger(db, zzpTokenAddr); got.Sign() != 0 {
		t.Fatalf("an untouched ledger reads %s, want 0", got)
	}
	storeVaultLedger(db, zzpTokenAddr, big.NewInt(1_234))
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big.NewInt(1_234)) != 0 {
		t.Errorf("ledger round-trip: got %s, want 1234", got)
	}
	if got := loadVaultLedger(db, other); got.Sign() != 0 {
		t.Errorf("one token's holdings are visible under another token's key: %s", got)
	}
	// Zero, nil and NEGATIVE all clear the word. A negative must never wrap into a
	// huge unsigned holding, which would let the underflow guard pass anything.
	for _, v := range []*big.Int{big.NewInt(0), nil, big.NewInt(-1)} {
		storeVaultLedger(db, zzpTokenAddr, v)
		if got := loadVaultLedger(db, zzpTokenAddr); got.Sign() != 0 {
			t.Errorf("storeVaultLedger(%v) left %s in the ledger, want 0", v, got)
		}
	}
	// Full-width holdings round-trip (the word is a uint256).
	big256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	storeVaultLedger(db, zzpTokenAddr, big256)
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big256) != 0 {
		t.Errorf("uint256-max ledger round-trip: got %s", got)
	}
}

// =========================================================================
// safeTransferTokenFrom / safeTransferTokenTo
// =========================================================================

func TestZzpSafeTransferFromReturnsTheObservedDelta(t *testing.T) {
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 10_000)

	got, err := safeTransferTokenFrom(db, zzpTokenAddr, zzpAlice, poolManagerAddr, big.NewInt(1_000))
	if err != nil {
		t.Fatalf("honest transfer: %v", err)
	}
	if got.Cmp(big.NewInt(1_000)) != 0 {
		t.Errorf("observed delta: got %s, want 1000", got)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, poolManagerAddr); bal.Cmp(big.NewInt(1_000)) != 0 {
		t.Errorf("vault holds %s after the pull, want 1000", bal)
	}

	// A fee-on-transfer token delivers less. The RETURNED value must be what
	// arrived, not what was asked — crediting the request mints the difference.
	db.shortBps = 250 // 2.5%
	got, err = safeTransferTokenFrom(db, zzpTokenAddr, zzpAlice, poolManagerAddr, big.NewInt(1_000))
	if err != nil {
		t.Fatalf("fee-on-transfer pull: %v", err)
	}
	if got.Cmp(big.NewInt(975)) != 0 {
		t.Fatalf("observed delta on a 2.5%% fee token: got %s, want 975 (the amount that ARRIVED)", got)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, poolManagerAddr); bal.Cmp(big.NewInt(1_975)) != 0 {
		t.Errorf("vault holds %s, want 1975 — the observed delta must match the real balance move", bal)
	}
	db.shortBps = 0

	// A reverting token is a FAILED transfer, never a silent success.
	db.failFrom = true
	if _, err := safeTransferTokenFrom(db, zzpTokenAddr, zzpAlice, poolManagerAddr, big.NewInt(1)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Errorf("reverting transferFrom: got %v, want ErrERC20TransferFailed", err)
	}
	db.failFrom = false

	// A token whose transfer is a silent no-op delivers nothing. Only the observed
	// delta catches it; the call "succeeded".
	db.swallow = true
	if _, err := safeTransferTokenFrom(db, zzpTokenAddr, zzpAlice, poolManagerAddr, big.NewInt(100)); !errors.Is(err, ErrERC20ZeroDelta) {
		t.Errorf("no-op transferFrom: got %v, want ErrERC20ZeroDelta", err)
	}
	db.swallow = false

	// An insufficient balance is a failure, not a partial fill.
	if _, err := safeTransferTokenFrom(db, zzpTokenAddr, zzpBob, poolManagerAddr, big.NewInt(1)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Errorf("transferFrom with no balance: got %v, want ErrERC20TransferFailed", err)
	}
}

func TestZzpSafeTransferToSurfacesFailure(t *testing.T) {
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, poolManagerAddr, 500)

	if err := safeTransferTokenTo(db, zzpTokenAddr, zzpAlice, big.NewInt(200)); err != nil {
		t.Fatalf("honest push: %v", err)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, zzpAlice); bal.Cmp(big.NewInt(200)) != 0 {
		t.Errorf("recipient holds %s, want 200", bal)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, poolManagerAddr); bal.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("vault holds %s after paying 200 of 500, want 300", bal)
	}

	db.failTo = true
	if err := safeTransferTokenTo(db, zzpTokenAddr, zzpAlice, big.NewInt(1)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Errorf("reverting transfer: got %v, want ErrERC20TransferFailed", err)
	}
}

// =========================================================================
// lockTokenIntoVault
// =========================================================================

func TestZzpLockTokenRefusesNonPositiveAndCreditsObservedDelta(t *testing.T) {
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 10_000)

	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, bad); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("lockTokenIntoVault(%v): got %v, want ErrInvalidAmount", bad, err)
		}
	}

	delta, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(3_000))
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if delta.Cmp(big.NewInt(3_000)) != 0 {
		t.Errorf("lock delta: got %s, want 3000", delta)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big.NewInt(3_000)) != 0 {
		t.Errorf("vault ledger after the lock: got %s, want 3000", got)
	}

	// A fee-on-transfer token: the ledger must record what ARRIVED, so the ledger
	// and the real token balance stay equal.
	db.shortBps = 1_000 // 10%
	delta, err = pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(1_000))
	if err != nil {
		t.Fatalf("fee-on-transfer lock: %v", err)
	}
	if delta.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("fee-on-transfer lock credited %s, want 900 — crediting the request would mint 100 unbacked", delta)
	}
	if recorded, actual := loadVaultLedger(db, zzpTokenAddr), db.TokenBalanceOf(zzpTokenAddr, poolManagerAddr); recorded.Cmp(actual) != 0 {
		t.Fatalf("ledger %s != real vault balance %s", recorded, actual)
	}
	db.shortBps = 0

	// The ledger ACCUMULATES: two locks add, they do not overwrite.
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big.NewInt(3_900)) != 0 {
		t.Errorf("ledger after two locks: got %s, want 3900", got)
	}
}

func TestZzpLockTokenRefusesADeltaBeyondTheLedgerRange(t *testing.T) {
	// The D-Chain keys balances by uint64. An observed delta beyond that cannot be
	// credited 1:1, and TRUNCATING would strand the remainder in the vault with no
	// claim against it. Refuse instead.
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	over := new(big.Int).Add(new(big.Int).SetUint64(^uint64(0)), big.NewInt(1))
	db.bal[zzpTokenAddr] = map[common.Address]*big.Int{zzpAlice: new(big.Int).Set(over)}

	if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, over); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("a 2^64 observed delta: got %v, want ErrInvalidAmount", err)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Sign() != 0 {
		t.Errorf("the refused lock still credited the vault ledger with %s", got)
	}
	// uint64 max is the last ACCEPTED value — drive the other side of the boundary.
	fresh := zzpNewVaultDB(zzpTx1)
	max := new(big.Int).SetUint64(^uint64(0))
	fresh.bal[zzpTokenAddr] = map[common.Address]*big.Int{zzpAlice: new(big.Int).Set(max)}
	if _, err := pm.lockTokenIntoVault(fresh, fresh, zzpAlice, zzpTokenAddr, max); err != nil {
		t.Fatalf("a uint64-max observed delta must be accepted: %v", err)
	}
}

func TestZzpLockTokenFailureCreditsNothing(t *testing.T) {
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 1_000)

	db.failFrom = true
	if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(500)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("reverting pull: got %v, want ErrERC20TransferFailed", err)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Sign() != 0 {
		t.Fatalf("a failed pull credited the vault ledger with %s", got)
	}
	db.failFrom = false

	db.swallow = true
	if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(500)); !errors.Is(err, ErrERC20ZeroDelta) {
		t.Fatalf("no-op pull: got %v, want ErrERC20ZeroDelta", err)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Sign() != 0 {
		t.Fatalf("a no-op pull credited the vault ledger with %s", got)
	}
}

// =========================================================================
// releaseTokenFromVault
// =========================================================================

func TestZzpReleaseTokenNeverExceedsRecordedHoldings(t *testing.T) {
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 1_000)
	if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(1_000)); err != nil {
		t.Fatalf("seed lock: %v", err)
	}

	// Non-positive is a no-op (a realized-zero withdraw releases nothing).
	for _, zero := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if err := pm.releaseTokenFromVault(db, db, zzpAlice, zzpTokenAddr, zero); err != nil {
			t.Errorf("release(%v): got %v, want nil", zero, err)
		}
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big.NewInt(1_000)) != 0 {
		t.Fatalf("a non-positive release moved the ledger to %s", got)
	}

	// One over the recorded holdings: refuse. Paying it would take another
	// account's backing for this token.
	if err := pm.releaseTokenFromVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(1_001)); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("over-release: got %v, want ErrInsufficientBalance", err)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big.NewInt(1_000)) != 0 {
		t.Fatalf("a refused release still debited the ledger to %s", got)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, zzpAlice); bal.Sign() != 0 {
		t.Fatalf("a refused release still paid %s to the recipient", bal)
	}

	// Exactly the holdings: allowed, ledger and real balance both go to zero.
	if err := pm.releaseTokenFromVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(1_000)); err != nil {
		t.Fatalf("exact release: %v", err)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Sign() != 0 {
		t.Errorf("ledger after an exact release: %s, want 0", got)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, poolManagerAddr); bal.Sign() != 0 {
		t.Errorf("vault token balance after an exact release: %s, want 0", bal)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, zzpAlice); bal.Cmp(big.NewInt(1_000)) != 0 {
		t.Errorf("recipient received %s, want 1000", bal)
	}
}

func TestZzpReleaseTokenIsPerTokenIsolated(t *testing.T) {
	// Holdings of token A must not back a release of token B. Otherwise one
	// market's deposits fund another's withdrawals.
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	tokenB := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	db.zzpMint(zzpTokenAddr, zzpAlice, 5_000)
	if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(5_000)); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	if err := pm.releaseTokenFromVault(db, db, zzpBob, tokenB, big.NewInt(1)); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("release of an unheld token: got %v, want ErrInsufficientBalance", err)
	}
	if got := loadVaultLedger(db, zzpTokenAddr); got.Cmp(big.NewInt(5_000)) != 0 {
		t.Errorf("the cross-token release disturbed token A's ledger: %s", got)
	}
}

func TestZzpReleaseTokenFailureIsReported(t *testing.T) {
	// A token that reverts the outbound transfer (a blocklisted recipient is the
	// live example) must surface the failure, not report a silent success.
	pm := NewPoolManager(zzpNewLedger())
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 1_000)
	if _, err := pm.lockTokenIntoVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(1_000)); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	db.failTo = true
	if err := pm.releaseTokenFromVault(db, db, zzpAlice, zzpTokenAddr, big.NewInt(400)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("reverting outbound transfer: got %v, want ErrERC20TransferFailed", err)
	}
}

// =========================================================================
// end-to-end ERC-20 custody through Deposit / Withdraw
// =========================================================================

func TestZzpTokenDepositWithdrawConserves(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 10_000)

	if err := pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(4_000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	zzpConservedToken(t, db, ledger, zzpTokenAddr, "after a token deposit")
	if got := ledger.zzpAvail(zzpAlice, zzpToken); got != 4_000 {
		t.Fatalf("credited %d, want 4000", got)
	}

	db.tx = zzpTx2
	realized, err := pm.Withdraw(db, zzpAlice, zzpToken, big.NewInt(1_500))
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if realized.Cmp(big.NewInt(1_500)) != 0 {
		t.Fatalf("realized %s, want 1500", realized)
	}
	zzpConservedToken(t, db, ledger, zzpTokenAddr, "after a token withdraw")
	if bal := db.TokenBalanceOf(zzpTokenAddr, zzpAlice); bal.Cmp(big.NewInt(7_500)) != 0 {
		t.Fatalf("holder balance %s, want 7500 (10000 - 4000 + 1500)", bal)
	}
}

func TestZzpFeeOnTransferTokenCreditsWhatArrived(t *testing.T) {
	// The unbacked-claim edge end to end: a 5% fee token deposited for 1000 must
	// credit 950, and a withdraw of the credited amount must be fully backed.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	db.shortBps = 500
	db.zzpMint(zzpTokenAddr, zzpAlice, 10_000)

	if err := pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(1_000)); err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if got := ledger.zzpAvail(zzpAlice, zzpToken); got != 950 {
		t.Fatalf("credited %d for a 1000 deposit of a 5%% fee token, want 950 — the difference would be unbacked", got)
	}
	zzpConservedToken(t, db, ledger, zzpTokenAddr, "after a fee-on-transfer deposit")

	db.tx = zzpTx2
	realized, err := pm.Withdraw(db, zzpAlice, zzpToken, big.NewInt(950))
	if err != nil {
		t.Fatalf("withdraw of the full credit: %v", err)
	}
	if realized.Cmp(big.NewInt(950)) != 0 {
		t.Fatalf("realized %s, want 950", realized)
	}
	zzpConservedToken(t, db, ledger, zzpTokenAddr, "after withdrawing the full fee-token credit")
}

func TestZzpTokenDepositThatDeliversNothingIsRefused(t *testing.T) {
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	db.swallow = true
	db.zzpMint(zzpTokenAddr, zzpAlice, 1_000)

	if err := pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(1_000)); !errors.Is(err, ErrERC20ZeroDelta) {
		t.Fatalf("deposit of a no-op token: got %v, want ErrERC20ZeroDelta", err)
	}
	if ledger.deposits != 0 {
		t.Fatal("a deposit that funded nothing still credited the D-Chain")
	}
	key, _ := depositBindKey(db, zzpAlice, zzpToken, big.NewInt(1_000))
	if loadCustodyBinding(db, key) {
		t.Fatal("a refused deposit recorded an idempotency binding")
	}
}

func TestZzpTokenWithdrawWhoseReleaseRevertsPaysNothingAndBindsNothing(t *testing.T) {
	// A token that reverts the outbound transfer (a recipient the token refuses to
	// pay is the live example) must not leave a settled binding behind: a binding
	// would make the retry return a realized amount against a release that never
	// happened.
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)
	db.zzpMint(zzpTokenAddr, zzpAlice, 2_000)
	if err := pm.Deposit(db, zzpAlice, zzpToken, big.NewInt(2_000)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}

	db.tx = zzpTx2
	db.failTo = true
	realized, err := pm.Withdraw(db, zzpAlice, zzpToken, big.NewInt(2_000))
	if !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("withdraw whose release reverts: got %v, want ErrERC20TransferFailed", err)
	}
	if realized.Sign() != 0 {
		t.Errorf("a failed release reported realized %s", realized)
	}
	if bal := db.TokenBalanceOf(zzpTokenAddr, zzpAlice); bal.Sign() != 0 {
		t.Errorf("a failed release still paid %s to the recipient", bal)
	}
	key, _ := withdrawBindKey(db, zzpAlice, zzpToken, big.NewInt(2_000))
	if _, settled := loadWithdrawBinding(db, key); settled {
		t.Fatal("a failed release recorded a settled withdraw binding — the retry would report a phantom payout")
	}
}

// TestZzpTokenCustodyConservationSweep is the ERC-20 twin of the native sweep.
// Seed 0xC0C matches the test token address digits — an arbitrary but documented
// constant, fixed so the sequence is reproducible from this file alone.
func TestZzpTokenCustodyConservationSweep(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0C))
	ledger := zzpNewLedger()
	pm := NewPoolManager(ledger)
	db := zzpNewVaultDB(zzpTx1)

	accounts := []common.Address{zzpAlice, zzpBob}
	for _, a := range accounts {
		db.zzpMint(zzpTokenAddr, a, 5_000_000)
	}
	held := map[common.Address]int64{zzpAlice: 5_000_000, zzpBob: 5_000_000}

	for i := 0; i < 500; i++ {
		var tx common.Hash
		tx[0] = byte(i)
		tx[1] = byte(i >> 8)
		tx[31] = 2
		db.tx = tx

		who := accounts[rng.Intn(len(accounts))]
		amount := int64(rng.Intn(4_000) + 1)

		if rng.Intn(2) == 0 {
			if err := pm.Deposit(db, who, zzpToken, big.NewInt(amount)); err != nil {
				t.Fatalf("iteration %d deposit: %v", i, err)
			}
			held[who] -= amount
		} else {
			realized, err := pm.Withdraw(db, who, zzpToken, big.NewInt(amount))
			if err != nil {
				t.Fatalf("iteration %d withdraw: %v", i, err)
			}
			if realized.Cmp(big.NewInt(amount)) > 0 {
				t.Fatalf("iteration %d realized %s for a %d request", i, realized, amount)
			}
			held[who] += realized.Int64()
		}
		zzpConservedToken(t, db, ledger, zzpTokenAddr, "sweep iteration")
		for _, a := range accounts {
			if got := db.TokenBalanceOf(zzpTokenAddr, a); got.Cmp(big.NewInt(held[a])) != 0 {
				t.Fatalf("iteration %d: %x holds %s, expected %d", i, a, got, held[a])
			}
		}
	}

	// Total supply is invariant: the vault plus the two holders must still be the
	// 10,000,000 minted at the start. Custody moves tokens, it never creates them.
	total := new(big.Int).Set(db.TokenBalanceOf(zzpTokenAddr, poolManagerAddr))
	for _, a := range accounts {
		total.Add(total, db.TokenBalanceOf(zzpTokenAddr, a))
	}
	if total.Cmp(big.NewInt(10_000_000)) != 0 {
		t.Fatalf("token supply drifted to %s from 10000000", total)
	}
}
