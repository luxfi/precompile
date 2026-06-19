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

// custody_redteam_poc_test.go pins RED's two CRITICAL custody PoCs as PERMANENT
// regression tests, each FLIPPED from an exploit into a defense-holds assertion:
//
//   CRIT #2 (asset-key collision -> native-vault drain): a worthless ERC-20 whose
//     address has 8 leading-zero bytes folded — under the old 8-byte asset handle —
//     to the SAME ledger key as native LUX (address(0) -> handle 0). Depositing the
//     junk token therefore minted a NATIVE claim, and withdrawing native then
//     drained real wei the junk token never backed. With the FULL 32-byte injective
//     asset id, the junk token credits its OWN distinct key and a native withdraw
//     drains ZERO. Asserted below.
//
//   CRIT #1 (deposit reentrancy -> double mint): a malicious ERC-20 re-enters the
//     custody entrypoint during its transferFrom sub-call. Without the global
//     non-reentrant guard the reentrant pull lands inside the observed-delta window
//     and BOTH calls mint, so minted > vault backing. With the guard the nested call
//     is refused (ErrCustodyReentrant) and minted == vault. Asserted below.

// junkTokenAddr has 8 LEADING ZERO BYTES — the exact shape that collided with native
// LUX under the old assetHandle fold (BE(address[0:8]) == 0 == native handle). Its
// trailing bytes are non-zero so assetID (left-pad address into 32 bytes) yields a
// NON-zero id distinct from native's all-zero id.
var junkTokenAddr = common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")

// TestCustody_JunkTokenDepositDoesNotDrainNative is RED CRIT #2 flipped: a junk
// ERC-20 deposit credits its OWN asset key, NEVER native, so a native withdraw by
// the depositor drains ZERO and the victim's native wei is untouched.
//
// PRE-fix: assetHandle(junkToken)=0=assetHandle(native), so the junk deposit
// credited the NATIVE key (minting a native claim) and a native withdraw drained
// the native vault. POST-fix the two keys are distinct (32-byte injective id), so
// the junk deposit cannot mint any native claim.
func TestCustody_JunkTokenDepositDoesNotDrainNative(t *testing.T) {
	pm, f, sdb, reg, attacker := custodyPMToken(t, 0)

	// A VICTIM holds real native LUX inside the 0x9010 vault (the drain target).
	victim := common.HexToAddress("0x9999999999999999999999999999999999999999")
	const victimNative = uint64(5000)
	sdb.balances[victim] = uint256.NewInt(victimNative)
	// EVM pre-moves the victim's msg.value into the vault, then the native deposit
	// locks it and mints the victim's native available balance.
	sdb.SubBalance(victim, uint256.NewInt(victimNative))
	sdb.AddBalance(poolManagerAddr, uint256.NewInt(victimNative))
	sdb.setTxHash(common.HexToHash("0x1111000000000000000000000000000000000000000000000000000000001111"))
	if err := pm.Deposit(sdb, victim, NativeCurrency, new(big.Int).SetUint64(victimNative)); err != nil {
		t.Fatalf("victim native deposit: %v", err)
	}

	// Sanity: the junk token's address WOULD have folded to the native key under the
	// old 8-byte handle (leading 8 address bytes are zero), but its full id is NOT
	// the native (all-zero) id — the collision is closed at the key.
	if junkTokenAddr.Bytes()[0] != 0 || junkTokenAddr.Bytes()[7] != 0 {
		t.Fatalf("junk token address must have 8 leading zero bytes to model the old-fold collision")
	}
	if assetID(erc20Curr(junkTokenAddr)) == assetID(NativeCurrency) {
		t.Fatalf("junk token id collides with native id — the drain class is NOT closed")
	}

	// The ATTACKER deposits the junk token (its own real backing in the vault). Under
	// the old fold this credited the NATIVE key; now it credits the junk token's key.
	junk := newMockToken(0)
	reg.register(junkTokenAddr, junk)
	const junkAmt = uint64(1_000_000)
	junk.mint(attacker, junkAmt)
	junk.approve(attacker, poolManagerAddr, junkAmt)
	sdb.setTxHash(common.HexToHash("0x2222000000000000000000000000000000000000000000000000000000002222"))
	if err := pm.Deposit(sdb, attacker, erc20Curr(junkTokenAddr), new(big.Int).SetUint64(junkAmt)); err != nil {
		t.Fatalf("attacker junk deposit: %v", err)
	}

	// THE FLIP: the junk deposit credited the JUNK key, NOT native. The attacker has
	// ZERO native available — no native claim was minted by the junk deposit.
	if got := fakeAvail(f, attacker, NativeCurrency); got != 0 {
		t.Fatalf("attacker native available = %d, want 0 (junk deposit must NOT mint a native claim)", got)
	}
	// The junk token credited its OWN distinct key for exactly the deposited amount.
	if got := fakeAvail(f, attacker, erc20Curr(junkTokenAddr)); got != junkAmt {
		t.Fatalf("attacker junk available = %d, want %d (credited its own asset key)", got, junkAmt)
	}

	// The attacker tries to withdraw NATIVE — the drain. It must release ZERO: the
	// attacker has no native claim, so the native vault (holding the victim's wei) is
	// untouched.
	sdb.setTxHash(common.HexToHash("0x3333000000000000000000000000000000000000000000000000000000003333"))
	realized, err := pm.Withdraw(sdb, attacker, NativeCurrency, new(big.Int).SetUint64(victimNative))
	if err != nil {
		t.Fatalf("attacker native withdraw: %v", err)
	}
	if realized.Sign() != 0 {
		t.Fatalf("attacker native withdraw realized %d, want 0 (NATIVE-VAULT DRAIN via asset-key collision)", realized)
	}
	// The native vault still holds exactly the victim's wei — nothing drained.
	if got := vaultBal(sdb.txStateDB); got != victimNative {
		t.Fatalf("native vault = %d after attack, want %d (victim's wei must be intact)", got, victimNative)
	}
	// The victim can still withdraw their full native balance — their funds were
	// never drained by the junk token.
	sdb.setTxHash(common.HexToHash("0x4444000000000000000000000000000000000000000000000000000000004444"))
	rv, err := pm.Withdraw(sdb, victim, NativeCurrency, new(big.Int).SetUint64(victimNative))
	if err != nil {
		t.Fatalf("victim native withdraw: %v", err)
	}
	if rv.Uint64() != victimNative {
		t.Fatalf("victim native withdraw realized %d, want %d (victim funds must be fully recoverable)", rv.Uint64(), victimNative)
	}
}

// reentrantVault wraps a tokenStateDB and, on the FIRST transferFrom of a deposit,
// re-enters the custody entrypoint (pm.Deposit) DURING the token sub-call — the
// exact reentrancy window RED CRIT #1 exploits. It records the nested call's error
// so the test can assert the guard refused it. The nested attempt uses a DIFFERENT
// amount to prove the guard is GLOBAL (a per-(txHash,asset,amount) flag would let a
// distinct-amount variant slip through).
type reentrantVault struct {
	*tokenStateDB
	pm        *PoolManager
	caller    common.Address
	asset     common.Address
	reentered bool
	nestedErr error
}

func (s *reentrantVault) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if !s.reentered {
		s.reentered = true
		// RE-ENTER the custody entrypoint mid-transfer, with a DIFFERENT amount. The
		// global guard (set before this sub-call) must refuse it.
		s.nestedErr = s.pm.Deposit(s, s.caller, erc20Curr(s.asset), new(big.Int).Add(amount, big.NewInt(1)))
	}
	return s.tokenStateDB.TransferTokenFrom(token, from, to, amount)
}

// TestCustody_DepositReentrancyRefused_MintEqualsVault is RED CRIT #1 flipped: a
// malicious token re-entering Deposit during its transferFrom is refused by the
// global non-reentrant guard, so exactly ONE deposit is minted and the D-Chain
// claim equals the vault backing (no double mint).
func TestCustody_DepositReentrancyRefused_MintEqualsVault(t *testing.T) {
	pm, f, base, reg, caller := custodyPMToken(t, 0)
	evil := newMockToken(0)
	reg.register(lusdAddr, evil)

	const dep = uint64(1000)
	evil.mint(caller, 10_000)
	evil.approve(caller, poolManagerAddr, 10_000) // ample allowance so a 2nd pull COULD happen

	// Wrap the token-capable stateDB so its transferFrom re-enters pm.Deposit.
	rv := &reentrantVault{tokenStateDB: base, pm: pm, caller: caller, asset: lusdAddr}

	// The outer deposit succeeds; the reentrant nested deposit (mid-transferFrom) is
	// refused by the guard.
	if err := pm.Deposit(rv, caller, erc20Curr(lusdAddr), new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("outer deposit: %v", err)
	}

	// THE FLIP: the nested re-entry was REFUSED with ErrCustodyReentrant — it minted
	// nothing.
	if !rv.reentered {
		t.Fatal("reentrancy hook never fired — the test did not exercise the guard")
	}
	if !errors.Is(rv.nestedErr, ErrCustodyReentrant) {
		t.Fatalf("nested reentrant deposit err = %v, want ErrCustodyReentrant (double-mint window NOT closed)", rv.nestedErr)
	}

	// Exactly ONE transferFrom happened (the nested call was refused BEFORE its own
	// pull), and the D-Chain credited exactly ONE deposit.
	if evil.transfers != 1 {
		t.Fatalf("token transfers = %d, want 1 (the reentrant pull must be refused before transferring)", evil.transfers)
	}
	minted := fakeAvail(f, caller, erc20Curr(lusdAddr))
	if minted != dep {
		t.Fatalf("D-Chain minted = %d, want %d (a double mint would show %d)", minted, dep, 2*dep)
	}
	// minted == vault backing: the precompile holds exactly the deposited token and
	// the ledger claim matches it — no unbacked claim.
	vaultHeld := evil.balanceOf(poolManagerAddr).Uint64()
	if minted != vaultHeld {
		t.Fatalf("MINT != VAULT: minted=%d vault=%d (reentrancy minted an unbacked claim)", minted, vaultHeld)
	}
	if got := loadVaultLedger(rv.tokenStateDB, lusdAddr).Uint64(); got != dep {
		t.Fatalf("vault ledger = %d, want %d (one deposit's backing)", got, dep)
	}
}
