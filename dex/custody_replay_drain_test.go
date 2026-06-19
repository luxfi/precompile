// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/holiman/uint256"
)

// custody_replay_drain_test.go is the REGRESSION PROOF for the vault-drain theft
// bug (CRITICAL #2) and its deposit-strand mirror (HIGH #1).
//
// THE BUG (red-team PoC, confirmed on the real VM): the EVM precompile keyed
// custody replay-idempotency on the EVM txHash (withdrawBindKey = blake3(txHash‖
// caller‖asset‖want)) while the D-Chain keyed its dedup on CONTENT (txID =
// Checksum256(type‖user‖asset‖amount), NO nonce). Two definitions of "same op".
// So two GENUINE withdraws (distinct txHashes -> neither short-circuits the EVM
// binding) with byte-identical D-Chain frames collided on the D-Chain seen: index:
// the second returned the FIRST realized amount VERBATIM, debiting NOTHING, while
// the precompile's releaseNativeFromVault paid from the shared 0x9010 vault AGAIN
// for a burn that never happened. Repeatable until the vault (other users' funds)
// is drained.
//
// THE FIX: thread the EVM txHash through the clob_withdraw/clob_deposit frame as a
// 32-byte idempotency ref that the D-Chain folds into its content-addressed seen:
// key. Now "same op" means ONE thing end to end: a same-tx replay dedups at both
// layers (preserved), but a GENUINE second withdraw (distinct tx -> distinct ref)
// is distinct on the D-Chain too -> processed fresh -> re-clamps to CURRENT
// available (0 after the first) -> realized 0 -> the vault releases NOTHING.
//
// These tests use the hardened fakeCLOB, which models the D-Chain seen: index
// faithfully (returns the cached realized on a content/ref replay, NOT a live
// debit). On the PRE-fix code (all custody frames carrying the same content
// regardless of txHash) the second withdraw would collide on seen: and the vault
// would pay twice; this file asserts it does NOT.

// custodyVaultInvariant is the THEFT DETECTOR. The 0x9010 vault must always hold
// exactly the sum of every account's D-Chain balance for that asset (the fake
// ledger is the available-balance double; there is no locked balance in these
// custody-only scenarios). If the vault ever exceeds Σledger we stranded value; if
// it ever falls BELOW Σledger we MINTED a release the ledger never backed — the
// drain. balanceOf(0x9010 vault) == Σ available[*][asset] (+ Σ locked, here 0).
func custodyVaultInvariant(t *testing.T, f *fakeCLOB, sdb *txStateDB, asset Currency, where string) {
	t.Helper()
	vault := vaultBal(sdb)
	var ledgerSum uint64
	f.mu.Lock()
	want := assetID(asset) // FULL 32-byte injective asset id (native == all-zero)
	for k, v := range f.ledger {
		// ledgerKey is user[16]||asset[32]; the asset is the trailing 32 bytes.
		if len(k) != 16+32 {
			f.mu.Unlock()
			t.Fatalf("%s: fake ledger key wrong width %d", where, len(k))
		}
		if [32]byte([]byte(k)[16:48]) == want {
			ledgerSum += v
		}
	}
	f.mu.Unlock()
	if vault != ledgerSum {
		t.Fatalf("%s: VAULT-vs-LEDGER INVARIANT BROKEN: vault(0x9010)=%d != Σledger=%d (delta %d). "+
			"vault > Σledger strands funds; vault < Σledger is the DRAIN (a release the ledger never burned).",
			where, vault, ledgerSum, int64(vault)-int64(ledgerSum))
	}
}

// txh derives a guaranteed-VALID, distinct 32-byte tx hash from a label. (Note:
// common.HexToHash silently zero-fills a NON-hex string — "0xWITHDRAW1" decodes to
// the ZERO hash, which would make every "distinct" tx collide on the zero hash and
// quietly disarm the EVM binding. BytesToHash takes arbitrary bytes and right-pads
// into 32 bytes, so distinct labels always give distinct, non-zero hashes.)
func txh(label string) common.Hash { return common.BytesToHash([]byte(label)) }

// TestCustody_DistinctTxHashWithdrawDoesNotDrainVault is RED's exact PoC as a
// regression test. deposit 1000 -> withdraw#1 (txHash A) realized 1000, avail->0
// -> withdraw#2 (txHash B, DISTINCT, identical amount) MUST return realized 0 and
// release NOTHING from the vault.
//
// PRE-fix: withdraw#2's frame was byte-identical to #1 (txHash not in the frame),
// so it collided on the D-Chain seen: index, replayed realized 1000, and the vault
// paid a second 1000 it did not have backing for -> theft. This asserts the vault
// is NOT drained.
func TestCustody_DistinctTxHashWithdrawDoesNotDrainVault(t *testing.T) {
	// Two users so the vault holds OTHER people's funds — the drain target. The
	// attacker is `caller`; the victim's funds sit in the shared 0x9010 vault.
	pm, f, sdb, attacker := custodyPM(t, 2000)
	victim := common.HexToAddress("0x2222222222222222222222222222222222222222")
	sdb.balances[victim] = mustU256(5000)

	// Victim deposits 5000 into the shared vault (their claim is a D-Chain balance).
	sdb.txHash = txh("V1")
	simulateDepositValueTransfer(sdb, victim, 5000)
	if err := pm.Deposit(sdb, victim, NativeCurrency, big.NewInt(5000)); err != nil {
		t.Fatalf("victim deposit: %v", err)
	}

	// Attacker deposits 1000 (their legitimate claim).
	const dep = uint64(1000)
	sdb.txHash = txh("A0")
	simulateDepositValueTransfer(sdb, attacker, dep)
	if err := pm.Deposit(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("attacker deposit: %v", err)
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after deposits") // vault == 6000 == Σledger

	vaultBeforeAttack := vaultBal(sdb)
	attackerWalletBefore := walletBal(sdb, attacker)

	// withdraw#1 (txHash A): legitimate. Realized 1000, attacker available -> 0.
	sdb.txHash = txh("AA11")
	r1, err := pm.Withdraw(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(dep))
	if err != nil {
		t.Fatalf("withdraw#1: %v", err)
	}
	if r1.Uint64() != dep {
		t.Fatalf("withdraw#1 realized = %d, want %d", r1.Uint64(), dep)
	}
	if got := fakeAvail(f, attacker, NativeCurrency); got != 0 {
		t.Fatalf("attacker available after withdraw#1 = %d, want 0", got)
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after withdraw#1") // vault == 5000 == Σledger(victim)

	// withdraw#2 (txHash B, DISTINCT from A, IDENTICAL amount 1000). This is the
	// attack: a second GENUINE withdraw whose D-Chain frame was byte-identical to #1
	// pre-fix. It MUST now realize 0 (attacker has 0 available) and release NOTHING.
	sdb.txHash = txh("BB22")
	r2, err := pm.Withdraw(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(dep))
	if err != nil {
		t.Fatalf("withdraw#2: %v", err)
	}
	if r2.Uint64() != 0 {
		t.Fatalf("THEFT: withdraw#2 (distinct txHash) realized = %d, want 0 — the D-Chain seen: "+
			"index replayed the first realized amount against an already-paid vault (vault drain)", r2.Uint64())
	}

	// THE THEFT DETECTOR: the vault released nothing on withdraw#2. The victim's
	// 5000 is intact; the attacker did not extract more than their 1000.
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after withdraw#2 (attack)")
	if got := vaultBal(sdb); got != vaultBeforeAttack-dep {
		t.Fatalf("vault = %d after the attack, want %d (released exactly the ONE legitimate 1000, "+
			"not a second drained 1000)", got, vaultBeforeAttack-dep)
	}
	if got := walletBal(sdb, attacker); got != attackerWalletBefore+dep {
		t.Fatalf("attacker wallet = %d, want %d (extracted exactly their own 1000, no stolen funds)",
			got, attackerWalletBefore+dep)
	}
	// Victim can still withdraw their full 5000 — their funds were never drained.
	sdb.txHash = txh("V9")
	rv, err := pm.Withdraw(sdb, victim, NativeCurrency, big.NewInt(5000))
	if err != nil {
		t.Fatalf("victim withdraw: %v", err)
	}
	if rv.Uint64() != 5000 {
		t.Fatalf("victim realized = %d, want 5000 (their funds must be intact after the attack)", rv.Uint64())
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after victim drains") // vault == 0 == Σledger
}

// TestCustody_RepeatedDistinctTxHashWithdrawsCannotOverdraw hammers the attack:
// after one legitimate withdraw drains the attacker's balance, MANY further
// distinct-txHash withdraws of the same amount must each realize 0 and release
// nothing. Pre-fix, each would have drained another 1000 from the vault. This is
// the "repeatable until the vault is drained" property, asserted closed.
func TestCustody_RepeatedDistinctTxHashWithdrawsCannotOverdraw(t *testing.T) {
	pm, f, sdb, attacker := custodyPM(t, 1000)
	victim := common.HexToAddress("0x3333333333333333333333333333333333333333")
	sdb.balances[victim] = mustU256(10_000)

	sdb.txHash = txh("VV")
	simulateDepositValueTransfer(sdb, victim, 10_000)
	if err := pm.Deposit(sdb, victim, NativeCurrency, big.NewInt(10_000)); err != nil {
		t.Fatalf("victim deposit: %v", err)
	}

	const dep = uint64(1000)
	sdb.txHash = txh("D0")
	simulateDepositValueTransfer(sdb, attacker, dep)
	if err := pm.Deposit(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("attacker deposit: %v", err)
	}

	vaultAfterDeposits := vaultBal(sdb) // 11_000
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after deposits")

	// First (legitimate) withdraw drains the attacker's 1000.
	sdb.txHash = txh("W000")
	if r, err := pm.Withdraw(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil || r.Uint64() != dep {
		t.Fatalf("legit withdraw realized=%v err=%v, want 1000", r, err)
	}

	// 25 more genuine withdraws, each a DISTINCT txHash, each asking for 1000. Each
	// must realize 0 (no balance) and release nothing. Pre-fix this loop would have
	// drained 25_000 from a vault holding only the victim's 10_000.
	for i := 0; i < 25; i++ {
		sdb.txHash = common.BytesToHash([]byte{0xAB, byte(i)})
		r, err := pm.Withdraw(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(dep))
		if err != nil {
			t.Fatalf("attack withdraw %d: %v", i, err)
		}
		if r.Uint64() != 0 {
			t.Fatalf("DRAIN at iteration %d: realized %d, want 0 (vault being looted via seen: replay)", i, r.Uint64())
		}
		custodyVaultInvariant(t, f, sdb, NativeCurrency, "during repeated attack")
	}

	// Vault fell by exactly the ONE legitimate 1000; the victim's 10_000 is intact.
	if got := vaultBal(sdb); got != vaultAfterDeposits-dep {
		t.Fatalf("vault = %d after 26 withdraws, want %d (only the single legit 1000 left)", got, vaultAfterDeposits-dep)
	}
}

// TestCustody_SameTxHashWithdrawReplayStillDedups proves the FIX PRESERVES the
// legitimate same-tx idempotency: the EVM re-executes one withdraw tx ~5× and only
// the canonical exec commits StateDB, so a same-txHash replay must release exactly
// once (it short-circuits on the EVM binding before reaching the D-Chain). This is
// the property the bug fix must NOT break.
func TestCustody_SameTxHashWithdrawReplayStillDedups(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	const dep = uint64(600)
	sdb.txHash = txh("DEAD")
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("deposit: %v", err)
	}

	// Same txHash for both withdraw executions (the EVM's repeated exec of ONE tx).
	sdb.txHash = txh("WREPLAY")
	r1, err := pm.Withdraw(sdb, caller, NativeCurrency, big.NewInt(200))
	if err != nil {
		t.Fatalf("withdraw#1: %v", err)
	}
	r2, err := pm.Withdraw(sdb, caller, NativeCurrency, big.NewInt(200))
	if err != nil {
		t.Fatalf("withdraw#2 (same-tx replay): %v", err)
	}
	if r1.Uint64() != 200 || r2.Uint64() != 200 {
		t.Fatalf("same-tx replay realized r1=%d r2=%d, want 200/200 (idempotent return)", r1.Uint64(), r2.Uint64())
	}
	// Released exactly ONCE: vault and ledger each fell by exactly 200, not 400.
	if got := vaultBal(sdb); got != dep-200 {
		t.Fatalf("vault = %d after same-tx replay, want %d (released ONCE)", got, dep-200)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep-200 {
		t.Fatalf("available = %d after same-tx replay, want %d (burned ONCE)", got, dep-200)
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after same-tx replay")
}

// TestCustody_DistinctTxHashDepositDoesNotStrandLock is the HIGH #1 mirror: two
// GENUINE deposits (distinct txHashes, identical amount) each lock msg.value in the
// vault and each MUST credit the D-Chain ledger separately. Pre-fix, the second
// deposit's D-Chain frame was byte-identical to the first, so the D-Chain
// content-deduped it (credited once) while BOTH EVM txs locked the vault -> the
// second lock was stranded (vault > Σledger). This asserts the second deposit
// credits and the invariant holds (no strand).
func TestCustody_DistinctTxHashDepositDoesNotStrandLock(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 5000)
	const dep = uint64(1000)

	// deposit#1 (txHash A): lock 1000, credit 1000.
	sdb.txHash = txh("DEP_A")
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("deposit#1: %v", err)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("available after deposit#1 = %d, want %d", got, dep)
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after deposit#1")

	// deposit#2 (txHash B, DISTINCT, IDENTICAL amount). A second genuine deposit:
	// the EVM locks another 1000 in the vault, and the D-Chain MUST credit another
	// 1000 (distinct ref -> distinct txID -> not a seen: replay). Pre-fix the
	// D-Chain would dedup this and credit nothing, stranding the second lock.
	sdb.txHash = txh("DEP_B")
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("deposit#2: %v", err)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != 2*dep {
		t.Fatalf("STRAND: available after deposit#2 = %d, want %d — the second genuine deposit was "+
			"content-deduped by the D-Chain while its vault lock stood, stranding it", got, 2*dep)
	}
	// THE INVARIANT: vault (2000 locked) == Σledger (2000 credited). No strand.
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after deposit#2")

	// And both deposits are fully withdrawable (the claim matches the lock).
	sdb.txHash = txh("DEP_WD")
	r, err := pm.Withdraw(sdb, caller, NativeCurrency, new(big.Int).SetUint64(2*dep))
	if err != nil {
		t.Fatalf("withdraw all: %v", err)
	}
	if r.Uint64() != 2*dep {
		t.Fatalf("withdraw realized = %d, want %d (both deposits claimable)", r.Uint64(), 2*dep)
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after withdraw all")
}

// TestCustody_SameTxHashDepositReplayStillDedups proves the FIX PRESERVES same-tx
// deposit idempotency (the EVM's ~5× re-exec of one deposit credits once).
func TestCustody_SameTxHashDepositReplayStillDedups(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 5000)
	const dep = uint64(800)
	sdb.txHash = txh("SAMEDEP")
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("deposit#1: %v", err)
	}
	// Replay the identical tx (same txHash). Must credit once.
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("deposit#2 (same-tx replay): %v", err)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("available after same-tx deposit replay = %d, want %d (credited ONCE)", got, dep)
	}
	custodyVaultInvariant(t, f, sdb, NativeCurrency, "after same-tx deposit replay")
}

// mustU256 builds a uint256 balance for test seeding.
func mustU256(v uint64) *uint256.Int { return uint256.NewInt(v) }
