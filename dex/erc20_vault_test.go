// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// erc20_vault_test.go provides a FAITHFUL in-memory ERC-20 double for exercising
// the precompile's ERC-20 custody rail. The double models a real token's invariant:
// balanceOf is the SOLE source of truth and is mutated ONLY by the token's own
// transfer/transferFrom logic (respecting allowances). The precompile NEVER writes
// these balances directly — and CANNOT: the erc20Vault seam the precompile reaches
// the token through exposes only TokenBalanceOf/TransferTokenFrom/TransferTokenTo,
// with NO balance-write method, so the forbidden balance-slot-poke path that broke
// autoSettle is structurally unreachable. The tests assert the precompile touches
// the token ONLY through transferFrom/transfer, counted by mockToken.transfers (the
// load-bearing move-count that pins "no slot poke").

// mockToken is one ERC-20 contract's state: per-holder balances and per-(owner,
// spender) allowances. feeBps, if non-zero, models a fee-on-transfer token: a
// transferFrom/transfer of `amount` debits the sender `amount` but credits the
// recipient `amount - fee`, so the recipient observes LESS than requested (the fee
// is burned here for simplicity — what matters is the recipient's OBSERVED delta).
type mockToken struct {
	balances  map[common.Address]*big.Int
	allowance map[common.Address]map[common.Address]*big.Int
	feeBps    uint64 // fee in basis points on transfer (0 = standard token)
	// transfers counts genuine transfer/transferFrom moves — the load-bearing
	// "no slot poke" assertion. There is no direct-balance-write counter because
	// there is no balance-write path: the erc20Vault seam the precompile uses
	// exposes none, so an out-of-band mutation is structurally impossible to reach.
	// (The sole direct writes in this double are mint/credit/debit, which ARE the
	// token's own transfer logic + test-only seeding, never a precompile poke.)
	transfers int
	// revertTransfer, if true, makes every transfer/transferFrom revert (models a
	// token that rejects the move) — for the OZ-safe failure path.
	revertTransfer bool
	// returnsFalse, if true, makes transfer/transferFrom return false instead of
	// reverting (models a non-reverting token that signals failure via the bool).
	returnsFalse bool
}

func newMockToken(feeBps uint64) *mockToken {
	return &mockToken{
		balances:  make(map[common.Address]*big.Int),
		allowance: make(map[common.Address]map[common.Address]*big.Int),
		feeBps:    feeBps,
	}
}

func (t *mockToken) balanceOf(a common.Address) *big.Int {
	if b, ok := t.balances[a]; ok {
		return new(big.Int).Set(b)
	}
	return big.NewInt(0)
}

// mint seeds a holder's balance — test setup ONLY (models the holder already owning
// the token before any custody op). This is the sole legitimate direct write, used
// only by tests to establish preconditions, and is NOT counted as a transfer.
func (t *mockToken) mint(a common.Address, amount uint64) {
	t.mintBig(a, new(big.Int).SetUint64(amount))
}

// mintBig seeds a holder with an arbitrary-precision balance (for the uint64-ledger
// boundary test, where the deposit amount must exceed 2^64-1).
func (t *mockToken) mintBig(a common.Address, amount *big.Int) {
	cur := t.balanceOf(a)
	t.balances[a] = new(big.Int).Add(cur, amount)
}

func (t *mockToken) approveBig(owner, spender common.Address, amount *big.Int) {
	if t.allowance[owner] == nil {
		t.allowance[owner] = make(map[common.Address]*big.Int)
	}
	t.allowance[owner][spender] = new(big.Int).Set(amount)
}

func (t *mockToken) approve(owner, spender common.Address, amount uint64) {
	if t.allowance[owner] == nil {
		t.allowance[owner] = make(map[common.Address]*big.Int)
	}
	t.allowance[owner][spender] = new(big.Int).SetUint64(amount)
}

func (t *mockToken) getAllowance(owner, spender common.Address) *big.Int {
	if m, ok := t.allowance[owner]; ok {
		if v, ok := m[spender]; ok {
			return new(big.Int).Set(v)
		}
	}
	return big.NewInt(0)
}

// credit applies a transfer's recipient leg, applying the fee-on-transfer haircut.
// Returns the amount actually credited (== amount for a standard token, < amount
// for a fee token).
func (t *mockToken) credit(to common.Address, amount *big.Int) *big.Int {
	credited := new(big.Int).Set(amount)
	if t.feeBps > 0 {
		fee := new(big.Int).Mul(amount, new(big.Int).SetUint64(t.feeBps))
		fee.Div(fee, big.NewInt(10_000))
		credited.Sub(credited, fee)
	}
	cur := t.balanceOf(to)
	t.balances[to] = new(big.Int).Add(cur, credited)
	return credited
}

// debit removes amount from `from` (the full requested amount; the fee is taken on
// the credit side). Returns false if `from` lacks the balance.
func (t *mockToken) debit(from common.Address, amount *big.Int) bool {
	cur := t.balanceOf(from)
	if cur.Cmp(amount) < 0 {
		return false
	}
	t.balances[from] = new(big.Int).Sub(cur, amount)
	return true
}

// mockTokenRegistry maps token addresses to their mockToken state. This is the
// "EVM world state" of ERC-20 contracts the precompile sub-calls reach.
type mockTokenRegistry struct {
	tokens map[common.Address]*mockToken
}

func newMockTokenRegistry() *mockTokenRegistry {
	return &mockTokenRegistry{tokens: make(map[common.Address]*mockToken)}
}

func (r *mockTokenRegistry) register(addr common.Address, t *mockToken) {
	r.tokens[addr] = t
}

func (r *mockTokenRegistry) get(addr common.Address) *mockToken {
	return r.tokens[addr]
}

// tokenStateDB is a txStateDB that ALSO implements the erc20Vault capability,
// backed by a mockTokenRegistry. It is the test analog of poolStateAdapter's
// production erc20Vault binding (which sub-calls the real token); here the "sub-call"
// resolves against the in-memory registry, modeling transferFrom/transfer/balanceOf
// with full allowance + fee-on-transfer fidelity.
type tokenStateDB struct {
	*txStateDB
	registry *mockTokenRegistry
}

func (s *tokenStateDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	t := s.registry.get(token)
	if t == nil {
		return big.NewInt(0)
	}
	return t.balanceOf(owner)
}

func (s *tokenStateDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	t := s.registry.get(token)
	if t == nil {
		return ErrERC20TransferFailed
	}
	if t.revertTransfer {
		return ErrERC20TransferFailed
	}
	if t.returnsFalse {
		// A non-reverting token that signals failure via the bool: nothing moves.
		return ErrERC20TransferFailed
	}
	// Allowance check (transferFrom uses the from->spender(0x9010) allowance).
	allow := t.getAllowance(from, poolManagerAddr)
	if allow.Cmp(amount) < 0 {
		return ErrERC20TransferFailed
	}
	if !t.debit(from, amount) {
		return ErrERC20TransferFailed
	}
	t.allowance[from][poolManagerAddr] = new(big.Int).Sub(allow, amount)
	t.credit(to, amount)
	t.transfers++
	return nil
}

func (s *tokenStateDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	t := s.registry.get(token)
	if t == nil {
		return ErrERC20TransferFailed
	}
	if t.revertTransfer || t.returnsFalse {
		return ErrERC20TransferFailed
	}
	// transfer moves from the vault (0x9010, the precompile self).
	if !t.debit(poolManagerAddr, amount) {
		return ErrERC20TransferFailed
	}
	t.credit(to, amount)
	t.transfers++
	return nil
}

var _ erc20Vault = (*tokenStateDB)(nil)

// custodyPMToken builds a PoolManager wired to a fresh fakeCLOB + a tokenStateDB
// (txIdentified + erc20Vault), so the ERC-20 custody rail engages end-to-end
// against the in-memory token double. Returns the manager, the fake book, the
// token-capable stateDB, the registry, and the caller address. The caller is funded
// with `nativeSeed` native LUX (for any native legs in the same test).
func custodyPMToken(t *testing.T, nativeSeed uint64) (*PoolManager, *fakeCLOB, *tokenStateDB, *mockTokenRegistry, common.Address) {
	t.Helper()
	f := newFakeCLOB()
	withFakeCLOB(t, f)
	zap := NewZAPEngine("fake:0", 2*time.Second)
	t.Cleanup(func() { _ = zap.Close() })
	pm := NewPoolManager(zap)
	base := &txStateDB{MockStateDB: NewMockStateDB()}
	base.txHash = common.HexToHash("0xdead00000000000000000000000000000000000000000000000000000000beef")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	base.balances[caller] = uint256.NewInt(nativeSeed)
	sdb := &tokenStateDB{txStateDB: base, registry: newMockTokenRegistry()}
	return pm, f, sdb, sdb.registry, caller
}

// setTxHash lets a test give the stateDB a distinct tx identity (a genuinely
// distinct custody op), so idempotency bindings and the D-Chain seen: index treat
// it as a new operation rather than a replay.
func (s *tokenStateDB) setTxHash(h common.Hash) { s.txHash = h }
