// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// custody_unbound_test.go pins R3 (defense-in-depth): a custody op whose StateDB
// carries NO originating-tx identity (a zero txHash, i.e. the bind lookup returns
// bound==false) is REFUSED before any value moves. A zero ref is a full-length 64B
// frame so length checks don't catch it, yet it would collide on the D-Chain seen:
// dedup key and reopen the replay/drain class. A committed EVM tx always supplies a
// unique non-zero hash, so refusing the unbound path closes the door without
// touching any real on-chain custody op (and is a prerequisite for the ERC-20 rail).

// TestCustody_Deposit_RejectsUnboundNoMint: a deposit with a zero txHash (unbound)
// is refused — no vault lock, no D-Chain mint.
func TestCustody_Deposit_RejectsUnboundNoMint(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)
	// Force the unbound path: a zero txHash means no valid EVM tx context.
	sdb.txHash = common.Hash{}

	const dep = uint64(250)
	// Even if the EVM had moved msg.value into the vault, the unbound deposit must
	// refuse BEFORE crediting the ledger — never mint against a zero idempotency ref.
	simulateDepositValueTransfer(sdb, caller, dep)

	err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep))
	if !errors.Is(err, ErrCustodyUnbound) {
		t.Fatalf("unbound deposit err = %v, want ErrCustodyUnbound", err)
	}
	// No D-Chain mint occurred.
	if got := fakeAvail(f, caller, NativeCurrency); got != 0 {
		t.Fatalf("D-Chain available = %d after refused unbound deposit, want 0 (no mint)", got)
	}
}

// TestCustody_Withdraw_RejectsUnboundNoRelease: a withdraw with a zero txHash
// (unbound) is refused — realized 0, no ledger burn, and the vault is NOT touched
// even though it holds releasable funds from a prior (bound) deposit.
func TestCustody_Withdraw_RejectsUnboundNoRelease(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000)

	// First, a NORMAL bound deposit so the ledger AND the vault hold real funds the
	// unbound withdraw could (wrongly) release. custodyPM seeds a non-zero txHash.
	const dep = uint64(400)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("seed deposit: %v", err)
	}
	if got := vaultBal(sdb); got != dep {
		t.Fatalf("vault after seed deposit = %d, want %d", got, dep)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("ledger after seed deposit = %d, want %d", got, dep)
	}

	// Now force the unbound path and attempt a withdraw.
	sdb.txHash = common.Hash{}
	realized, err := pm.Withdraw(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep))
	if !errors.Is(err, ErrCustodyUnbound) {
		t.Fatalf("unbound withdraw err = %v, want ErrCustodyUnbound", err)
	}
	if realized.Sign() != 0 {
		t.Fatalf("unbound withdraw realized = %v, want 0", realized)
	}
	// The ledger was NOT burned and the vault was NOT released.
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("ledger after refused unbound withdraw = %d, want %d (no burn)", got, dep)
	}
	if got := vaultBal(sdb); got != dep {
		t.Fatalf("vault after refused unbound withdraw = %d, want %d (no release)", got, dep)
	}
}

// TestCustody_BoundOpStillWorks: the normal path — a deposit then withdraw, both
// with a real (non-zero) txHash — still locks/mints and burns/releases exactly,
// proving R3 only refuses the unbound path and does not regress real custody.
func TestCustody_BoundOpStillWorks(t *testing.T) {
	pm, f, sdb, caller := custodyPM(t, 1000) // custodyPM sets a non-zero txHash

	const dep = uint64(300)
	simulateDepositValueTransfer(sdb, caller, dep)
	if err := pm.Deposit(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep)); err != nil {
		t.Fatalf("bound deposit: %v", err)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != dep {
		t.Fatalf("ledger after bound deposit = %d, want %d", got, dep)
	}
	if got := vaultBal(sdb); got != dep {
		t.Fatalf("vault after bound deposit = %d, want %d", got, dep)
	}

	// A DISTINCT tx (the EVM gives the withdraw its own hash) withdraws the balance.
	sdb.txHash = common.HexToHash("0xb0undw1thdraw")
	realized, err := pm.Withdraw(sdb, caller, NativeCurrency, new(big.Int).SetUint64(dep))
	if err != nil {
		t.Fatalf("bound withdraw: %v", err)
	}
	if realized.Uint64() != dep {
		t.Fatalf("bound withdraw realized = %v, want %d", realized, dep)
	}
	if got := fakeAvail(f, caller, NativeCurrency); got != 0 {
		t.Fatalf("ledger after bound withdraw = %d, want 0 (burned)", got)
	}
	if got := vaultBal(sdb); got != 0 {
		t.Fatalf("vault after bound withdraw = %d, want 0 (released)", got)
	}
}
