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

// zzmop_zap_test.go covers native_zap.go — the two-phase value core every 0x9999 money
// handler composes. The invariants:
//
//   - NO MINT, NO RAID: a release refuses when its OWN pot cannot back it, and the two
//     pots (swap seamReserve / LP committedPositions) are orthogonal — neither can be
//     drawn down through the other's release.
//   - NEVER WRAP: the native release checks the vault's real balance first, because
//     SubBalance is uint256-MODULAR from a precompile.
//   - FAIL-SECURE ERC-20: an under-delivering token refuses rather than crediting the
//     requested amount against value that never arrived.

// zzmpVaultDB is a minimal dex.StateDB that ALSO implements erc20Vault directly (the
// non-adapter arm of stateDBERC20). shortBps skims a fraction off every delivery so the
// under-delivery guard can be driven; failFrom makes a named holder's transferFrom fail.
type zzmpVaultDB struct {
	*MockStateDB
	tok      map[common.Address]map[common.Address]*big.Int
	shortBps int64
	failFrom map[common.Address]bool
}

func zzmpNewVaultDB() *zzmpVaultDB {
	return &zzmpVaultDB{
		MockStateDB: NewMockStateDB(),
		tok:         make(map[common.Address]map[common.Address]*big.Int),
		failFrom:    make(map[common.Address]bool),
	}
}

func (v *zzmpVaultDB) cell(token, holder common.Address) *big.Int {
	if v.tok[token] == nil {
		v.tok[token] = make(map[common.Address]*big.Int)
	}
	if v.tok[token][holder] == nil {
		v.tok[token][holder] = big.NewInt(0)
	}
	return v.tok[token][holder]
}

func (v *zzmpVaultDB) mint(token, holder common.Address, amount int64) {
	// cell() creates the inner map on demand, so it has to run BEFORE the assignment:
	// Go evaluates the index expression on the LEFT as an operand, and a nil inner map
	// there panics on assignment no matter what the right-hand side would have created.
	cur := v.cell(token, holder)
	v.tok[token][holder] = new(big.Int).Add(cur, big.NewInt(amount))
}

func (v *zzmpVaultDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	return new(big.Int).Set(v.cell(token, owner))
}

func (v *zzmpVaultDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if v.failFrom[from] {
		return errors.New("zzmp: token transferFrom reverted")
	}
	bal := v.cell(token, from)
	if bal.Cmp(amount) < 0 {
		return errors.New("zzmp: insufficient token balance")
	}
	v.tok[token][from] = new(big.Int).Sub(bal, amount)
	delivered := new(big.Int).Set(amount)
	if v.shortBps > 0 {
		fee := new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(v.shortBps)), big.NewInt(10_000))
		delivered.Sub(delivered, fee)
	}
	v.tok[token][to] = new(big.Int).Add(v.cell(token, to), delivered)
	return nil
}

func (v *zzmpVaultDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	return v.TransferTokenFrom(token, poolManagerAddr9999, to, amount)
}

var (
	_ StateDB    = (*zzmpVaultDB)(nil)
	_ erc20Vault = (*zzmpVaultDB)(nil)
)

// zzmpToken is a fixed ERC-20 address for the zap-level unit tests.
var zzmpToken = common.HexToAddress("0x0000000000000000000000000000000000007A11")

// ---------------------------------------------------------------------------
// native value moves
// ---------------------------------------------------------------------------

func TestZzmpMoveNativeIntoVaultRefusesAShortCaller(t *testing.T) {
	db := NewMockStateDB()
	caller := common.HexToAddress("0x0000000000000000000000000000000000001111")

	if err := moveNativeIntoVault(db, caller, 100); !errors.Is(err, ErrNativeFundsShort) {
		t.Fatalf("unfunded caller: want ErrNativeFundsShort, got %v", err)
	}
	if got := db.GetBalance(poolManagerAddr9999); got.Sign() != 0 {
		t.Fatalf("a refused move credited the vault: %s", got)
	}
	if got := db.GetBalance(caller); got.Sign() != 0 {
		t.Fatalf("a refused move debited the caller: %s", got)
	}

	// Exactly-funded is admitted; one short is refused (the boundary).
	db.AddBalance(caller, uint256.NewInt(99))
	if err := moveNativeIntoVault(db, caller, 100); !errors.Is(err, ErrNativeFundsShort) {
		t.Fatalf("caller one unit short: want ErrNativeFundsShort, got %v", err)
	}
	db.AddBalance(caller, uint256.NewInt(1))
	if err := moveNativeIntoVault(db, caller, 100); err != nil {
		t.Fatalf("exactly-funded caller: %v", err)
	}
	if got := db.GetBalance(caller).Uint64(); got != 0 {
		t.Fatalf("caller balance after the move: want 0, got %d", got)
	}
	if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != 100 {
		t.Fatalf("vault balance after the move: want 100, got %d", got)
	}
}

// TestZzmpMoveNativeOutOfVaultAbortsRatherThanWrapping is the underflow invariant:
// SubBalance is uint256-MODULAR from a precompile, so an unbacked release must ABORT.
func TestZzmpMoveNativeOutOfVaultAbortsRatherThanWrapping(t *testing.T) {
	db := NewMockStateDB()
	to := common.HexToAddress("0x0000000000000000000000000000000000002222")

	if err := moveNativeOutOfVault(db, to, 1); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("empty vault release: want ErrNativeSettleUnbacked, got %v", err)
	}
	if got := db.GetBalance(poolManagerAddr9999); got.Sign() != 0 {
		t.Fatalf("the vault balance WRAPPED to %s instead of aborting", got)
	}
	if got := db.GetBalance(to); got.Sign() != 0 {
		t.Fatalf("an aborted release still credited %s", got)
	}

	db.AddBalance(poolManagerAddr9999, uint256.NewInt(50))
	if err := moveNativeOutOfVault(db, to, 51); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("one-over release: want ErrNativeSettleUnbacked, got %v", err)
	}
	if err := moveNativeOutOfVault(db, to, 50); err != nil {
		t.Fatalf("exact release: %v", err)
	}
	if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != 0 {
		t.Fatalf("vault after the exact release: want 0, got %d", got)
	}
	if got := db.GetBalance(to).Uint64(); got != 50 {
		t.Fatalf("recipient after the exact release: want 50, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// pot accounting — orthogonal, never negative
// ---------------------------------------------------------------------------

// TestZzmpPotReleasesRefuseWhatTheirOwnPotCannotBack pins BOTH the no-mint rule and the
// orthogonality of the two pots: seam value can never be released through the LP rail
// and vice versa.
func TestZzmpPotReleasesRefuseWhatTheirOwnPotCannotBack(t *testing.T) {
	db := NewMockStateDB()
	aid := assetID(Currency{Address: zzmpToken})

	// Empty pots refuse any release.
	if err := recordSeamRelease(db, aid, 1); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("empty seam release: want ErrNativeSettleUnbacked, got %v", err)
	}
	if err := recordCommittedRelease(db, aid, 1); !errors.Is(err, ErrLPCollectUnbacked) {
		t.Fatalf("empty committed release: want ErrLPCollectUnbacked, got %v", err)
	}

	// Fund ONLY the swap rail; the LP rail must still refuse (no cross-rail raid).
	recordSeamLock(db, aid, 1_000)
	if got := loadSeamReserve(db, aid); got.Int64() != 1_000 {
		t.Fatalf("seamReserve after lock: want 1000, got %s", got)
	}
	if err := recordCommittedRelease(db, aid, 1); !errors.Is(err, ErrLPCollectUnbacked) {
		t.Fatalf("LP release against a SWAP-funded pot: want ErrLPCollectUnbacked, got %v", err)
	}
	if got := loadSeamReserve(db, aid); got.Int64() != 1_000 {
		t.Fatalf("a refused LP release drew down the swap pot: %s", got)
	}

	// Fund ONLY the LP rail on a second asset; the swap rail must refuse there.
	other := assetID(Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000009999")})
	recordCommittedLock(db, other, 500)
	if err := recordSeamRelease(db, other, 1); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("swap release against an LP-funded pot: want ErrNativeSettleUnbacked, got %v", err)
	}
	if got := loadCommittedPositions(db, other); got.Int64() != 500 {
		t.Fatalf("a refused swap release drew down the LP pot: %s", got)
	}

	// Exact-size releases drain each pot to zero and never go negative.
	if err := recordSeamRelease(db, aid, 1_001); !errors.Is(err, ErrNativeSettleUnbacked) {
		t.Fatalf("one-over seam release: want ErrNativeSettleUnbacked, got %v", err)
	}
	if err := recordSeamRelease(db, aid, 1_000); err != nil {
		t.Fatalf("exact seam release: %v", err)
	}
	if got := loadSeamReserve(db, aid); got.Sign() != 0 {
		t.Fatalf("seamReserve after the exact release: want 0, got %s", got)
	}
	if err := recordCommittedRelease(db, other, 501); !errors.Is(err, ErrLPCollectUnbacked) {
		t.Fatalf("one-over committed release: want ErrLPCollectUnbacked, got %v", err)
	}
	if err := recordCommittedRelease(db, other, 500); err != nil {
		t.Fatalf("exact committed release: %v", err)
	}
	if got := loadCommittedPositions(db, other); got.Sign() != 0 {
		t.Fatalf("committedPositions after the exact release: want 0, got %s", got)
	}
	// A zero-size release is always backed (nothing leaves).
	if err := recordSeamRelease(db, aid, 0); err != nil {
		t.Fatalf("zero seam release: %v", err)
	}
	if err := recordCommittedRelease(db, aid, 0); err != nil {
		t.Fatalf("zero committed release: %v", err)
	}
}

// ---------------------------------------------------------------------------
// pullERC20Terminal — the conservation guard that replaces the observed-delta credit
// ---------------------------------------------------------------------------

func TestZzmpPullERC20TerminalRefusesUnderDelivery(t *testing.T) {
	v := zzmpNewVaultDB()
	from := common.HexToAddress("0x0000000000000000000000000000000000003333")
	v.mint(zzmpToken, from, 10_000)

	// Honest token: exactly `amount` arrives.
	if err := pullERC20Terminal(v, zzmpToken, from, big.NewInt(1_000)); err != nil {
		t.Fatalf("honest pull: %v", err)
	}
	if got := v.TokenBalanceOf(zzmpToken, poolManagerAddr9999); got.Int64() != 1_000 {
		t.Fatalf("vault holding after the pull: want 1000, got %s", got)
	}

	// Fee-on-transfer: the vault receives less, so the pull REFUSES (never under-backed).
	v.shortBps = 100 // 1% skimmed in transit
	if err := pullERC20Terminal(v, zzmpToken, from, big.NewInt(10_000-1_000)); !errors.Is(err, ErrERC20UnderDelivered) {
		t.Fatalf("under-delivering token: want ErrERC20UnderDelivered, got %v", err)
	}
	v.shortBps = 0

	// A reverting transferFrom surfaces as a wrapped transfer failure, never swallowed.
	v.failFrom[from] = true
	if err := pullERC20Terminal(v, zzmpToken, from, big.NewInt(1)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("reverting token: want ErrERC20TransferFailed, got %v", err)
	}
	v.failFrom[from] = false

	// A REBASING-UP token (delivers more than asked) is accepted: the surplus is a vault
	// donation and the credit is still the requested amount.
	v.mint(zzmpToken, from, 1_000) // the refused pulls above already debited `from` (the
	// EVM frame revert that would undo them is the host's job, not the double's)
	v.shortBps = -10_000 // negative fee => delivers 2x
	before := v.TokenBalanceOf(zzmpToken, poolManagerAddr9999)
	if err := pullERC20Terminal(v, zzmpToken, from, big.NewInt(100)); err != nil {
		t.Fatalf("over-delivering token must be accepted, got %v", err)
	}
	if got := new(big.Int).Sub(v.TokenBalanceOf(zzmpToken, poolManagerAddr9999), before); got.Cmp(big.NewInt(100)) < 0 {
		t.Fatalf("over-delivery delivered less than requested: %s", got)
	}
	// pushERC20Terminal is the mirror: a failing transfer surfaces as a refusal.
	v.shortBps = 0
	v.failFrom[poolManagerAddr9999] = true
	if err := pushERC20Terminal(v, zzmpToken, from, big.NewInt(1)); !errors.Is(err, ErrERC20TransferFailed) {
		t.Fatalf("reverting push: want ErrERC20TransferFailed, got %v", err)
	}
	v.failFrom[poolManagerAddr9999] = false
	if err := pushERC20Terminal(v, zzmpToken, from, big.NewInt(1)); err != nil {
		t.Fatalf("honest push: %v", err)
	}
}

// ---------------------------------------------------------------------------
// lockAssetIn / commitAssetIn — the composed two-phase input locks
// ---------------------------------------------------------------------------

// TestZzmpLockAndCommitRefuseZeroAndUnderfundedNative pins the fail-fast: an unbacked
// native lock records NOTHING (no pot credit, no `record` callback) even absent an EVM
// revert, so a rolled-back frame is defence in depth rather than the only protection.
func TestZzmpLockAndCommitRefuseZeroAndUnderfundedNative(t *testing.T) {
	caller := common.HexToAddress("0x0000000000000000000000000000000000004444")

	for _, tc := range []struct {
		name string
		fn   func(StateDB, common.Address, [32]byte, common.Address, uint64, func() error) (uint64, error)
		pot  func(stateKV, [32]byte) *big.Int
	}{
		{"lockAssetIn", lockAssetIn, loadSeamReserve},
		{"commitAssetIn", commitAssetIn, loadCommittedPositions},
	} {
		db := NewMockStateDB()
		var recorded int

		// Zero is never a valid lock size.
		if _, err := tc.fn(db, caller, [32]byte{}, common.Address{}, 0, func() error { recorded++; return nil }); !errors.Is(err, ErrNativeBadAmount) {
			t.Fatalf("%s(0): want ErrNativeBadAmount, got %v", tc.name, err)
		}
		// An underfunded NATIVE lock fails fast: nothing recorded, nothing staged.
		if _, err := tc.fn(db, caller, [32]byte{}, common.Address{}, 100, func() error { recorded++; return nil }); !errors.Is(err, ErrNativeFundsShort) {
			t.Fatalf("%s(underfunded): want ErrNativeFundsShort, got %v", tc.name, err)
		}
		if recorded != 0 {
			t.Fatalf("%s ran its record callback for a refused lock", tc.name)
		}
		if got := tc.pot(db, [32]byte{}); got.Sign() != 0 {
			t.Fatalf("%s credited its pot for a refused lock: %s", tc.name, got)
		}

		// A funded native lock moves the value and credits the pot exactly once.
		db.AddBalance(caller, uint256.NewInt(100))
		locked, err := tc.fn(db, caller, [32]byte{}, common.Address{}, 100, func() error { recorded++; return nil })
		if err != nil {
			t.Fatalf("%s(funded): %v", tc.name, err)
		}
		if locked != 100 || recorded != 1 {
			t.Fatalf("%s(funded): locked=%d recorded=%d", tc.name, locked, recorded)
		}
		if got := tc.pot(db, [32]byte{}); got.Int64() != 100 {
			t.Fatalf("%s pot after the lock: want 100, got %s", tc.name, got)
		}
		if got := db.GetBalance(caller).Uint64(); got != 0 {
			t.Fatalf("%s left %d with the caller", tc.name, got)
		}
		if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != 100 {
			t.Fatalf("%s vault balance: want 100, got %d", tc.name, got)
		}

		// A `record` that refuses aborts the lock: the error propagates rather than
		// being swallowed, and the native value never moves.
		boom := errors.New("zzmp record refused")
		db.AddBalance(caller, uint256.NewInt(50))
		if _, err := tc.fn(db, caller, [32]byte{}, common.Address{}, 50, func() error { return boom }); !errors.Is(err, boom) {
			t.Fatalf("%s with a failing record: want the record error, got %v", tc.name, err)
		}
		if got := db.GetBalance(caller).Uint64(); got != 50 {
			t.Fatalf("%s moved value despite a failing record: caller has %d", tc.name, got)
		}
	}
}

// TestZzmpLockAndCommitERC20AreTerminalAndFailSecure covers the ERC-20 arm of both
// composed locks: a vault-less StateDB refuses, an under-delivering token refuses, and
// an honest token settles for exactly the requested amount.
func TestZzmpLockAndCommitERC20AreTerminalAndFailSecure(t *testing.T) {
	caller := common.HexToAddress("0x0000000000000000000000000000000000005555")
	aid := assetID(Currency{Address: zzmpToken})

	for _, tc := range []struct {
		name string
		fn   func(StateDB, common.Address, [32]byte, common.Address, uint64, func() error) (uint64, error)
		pot  func(stateKV, [32]byte) *big.Int
	}{
		{"lockAssetIn", lockAssetIn, loadSeamReserve},
		{"commitAssetIn", commitAssetIn, loadCommittedPositions},
	} {
		// (a) No ERC-20 vault capability at all -> fail closed.
		plain := NewMockStateDB()
		if _, err := tc.fn(plain, caller, aid, zzmpToken, 10, nil); !errors.Is(err, ErrNativeERC20Vault) {
			t.Fatalf("%s with no vault capability: want ErrNativeERC20Vault, got %v", tc.name, err)
		}

		// (b) Honest token: the pot rises by exactly the requested amount and the token
		//     really lands in the vault.
		v := zzmpNewVaultDB()
		v.mint(zzmpToken, caller, 1_000)
		var recorded int
		locked, err := tc.fn(v, caller, aid, zzmpToken, 400, func() error { recorded++; return nil })
		if err != nil {
			t.Fatalf("%s honest erc20: %v", tc.name, err)
		}
		if locked != 400 || recorded != 1 {
			t.Fatalf("%s honest erc20: locked=%d recorded=%d", tc.name, locked, recorded)
		}
		if got := tc.pot(v, aid); got.Int64() != 400 {
			t.Fatalf("%s pot: want 400, got %s", tc.name, got)
		}
		if got := v.TokenBalanceOf(zzmpToken, poolManagerAddr9999); got.Int64() != 400 {
			t.Fatalf("%s vault token holding: want 400, got %s", tc.name, got)
		}

		// (c) A `record` refusal aborts BEFORE the terminal pull — no token moves.
		boom := errors.New("zzmp record refused")
		if _, err := tc.fn(v, caller, aid, zzmpToken, 100, func() error { return boom }); !errors.Is(err, boom) {
			t.Fatalf("%s erc20 with a failing record: want the record error, got %v", tc.name, err)
		}
		if got := v.TokenBalanceOf(zzmpToken, poolManagerAddr9999); got.Int64() != 400 {
			t.Fatalf("%s pulled a token despite a failing record: %s", tc.name, got)
		}

		// (d) Under-delivery refuses (fail-secure), and a reverting token refuses.
		v.shortBps = 500
		if _, err := tc.fn(v, caller, aid, zzmpToken, 100, nil); !errors.Is(err, ErrERC20UnderDelivered) {
			t.Fatalf("%s under-delivering erc20: want ErrERC20UnderDelivered, got %v", tc.name, err)
		}
		v.shortBps = 0
		v.failFrom[caller] = true
		if _, err := tc.fn(v, caller, aid, zzmpToken, 100, nil); !errors.Is(err, ErrERC20TransferFailed) {
			t.Fatalf("%s reverting erc20: want ErrERC20TransferFailed, got %v", tc.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ensureVaultAccountPersists
// ---------------------------------------------------------------------------

// zzmpNonceDB is a StateDB that models an account nonce, so the vault-persistence
// marker's bump is observable.
type zzmpNonceDB struct {
	*MockStateDB
	nonces map[common.Address]uint64
	sets   int
}

func (d *zzmpNonceDB) GetNonce(a common.Address) uint64 { return d.nonces[a] }
func (d *zzmpNonceDB) SetNonce(a common.Address, n uint64) {
	d.sets++
	d.nonces[a] = n
}

// TestZzmpEnsureVaultAccountPersistsIsIdempotentAndOptional pins the EIP-158 fix: the
// vault account is bumped NON-EMPTY once and only once, and a host that models no
// empty-account reaping is left alone (the marker is a safe no-op).
func TestZzmpEnsureVaultAccountPersistsIsIdempotentAndOptional(t *testing.T) {
	// A StateDB with NO nonce capability: nothing to protect, nothing to do, no panic.
	zzmpNoPanic(t, "ensureVaultAccountPersists on a nonce-less StateDB", func() {
		ensureVaultAccountPersists(NewMockStateDB())
	})

	d := &zzmpNonceDB{MockStateDB: NewMockStateDB(), nonces: make(map[common.Address]uint64)}
	ensureVaultAccountPersists(d)
	if d.nonces[poolManagerAddr9999] != 1 {
		t.Fatalf("the vault account was not marked non-empty: nonce=%d", d.nonces[poolManagerAddr9999])
	}
	if d.sets != 1 {
		t.Fatalf("expected exactly one nonce write, got %d", d.sets)
	}
	// Idempotent: a second call does not bump again.
	ensureVaultAccountPersists(d)
	if d.sets != 1 || d.nonces[poolManagerAddr9999] != 1 {
		t.Fatalf("the marker is not idempotent: sets=%d nonce=%d", d.sets, d.nonces[poolManagerAddr9999])
	}
	// An already-elevated nonce is left exactly as it is (never reset downward).
	d.nonces[poolManagerAddr9999] = 42
	ensureVaultAccountPersists(d)
	if d.nonces[poolManagerAddr9999] != 42 {
		t.Fatalf("the marker clobbered a live nonce: %d", d.nonces[poolManagerAddr9999])
	}
	// It touches ONLY the vault account.
	if len(d.nonces) != 1 {
		t.Fatalf("the marker touched %d accounts, want only 0x9999", len(d.nonces))
	}
}

// TestZzmpVaultAccountIsMarkedOnTheFirst9999Write proves the marker fires through the
// production choke point — the adapter's SetState — rather than only when called
// directly, so no writer can miss it.
func TestZzmpVaultAccountIsMarkedOnTheFirst9999Write(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	// The harness's StateDB reports nonce 0 and swallows SetNonce, so the observable
	// property here is that the write path runs the marker without panicking and the
	// slot still lands.
	key := makeStorageKey([]byte("zzmp/mark"), []byte{0x01})
	zzmpNoPanic(t, "first 0x9999 storage write", func() {
		db.SetState(poolManagerAddr9999, key, common.Hash{31: 9})
	})
	if got := db.GetState(poolManagerAddr9999, key); got != (common.Hash{31: 9}) {
		t.Fatalf("the marked write did not land: %x", got)
	}
	if !db.vaultMarked {
		t.Fatal("the first 0x9999 write must arm the vault-persistence marker")
	}
	// A write to ANOTHER address does not arm it.
	fresh := newPoolStateAdapter(h.state)
	fresh.SetState(common.HexToAddress("0x0000000000000000000000000000000000001234"), key, common.Hash{31: 1})
	if fresh.vaultMarked {
		t.Fatal("a write to a foreign address must not arm the vault marker")
	}
}
