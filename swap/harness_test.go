// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"context"
	"encoding/binary"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockState implements contract.StateDB AND the erc20Vault capability. Token
// balances live in a simple ledger so the conservation invariant can be checked
// against the precompile's own reserve accounting.
// ---------------------------------------------------------------------------

type stateKey struct {
	addr common.Address
	key  common.Hash
}

type mockState struct {
	storage map[stateKey]common.Hash
	logs    []*ethtypes.Log
	// token -> owner -> balance
	tokens map[common.Address]map[common.Address]*big.Int

	// negative-test knobs:
	failTransfer map[common.Address]bool // tokens whose transfer always fails
	feeBps       map[common.Address]int  // fee-on-transfer: bps withheld on transferFrom
	reenter      func()                  // invoked once inside the next transferFrom
}

func newMockState() *mockState {
	return &mockState{
		storage:      make(map[stateKey]common.Hash),
		tokens:       make(map[common.Address]map[common.Address]*big.Int),
		failTransfer: make(map[common.Address]bool),
		feeBps:       make(map[common.Address]int),
	}
}

func (m *mockState) bal(token, owner common.Address) *big.Int {
	if m.tokens[token] == nil {
		return big.NewInt(0)
	}
	if v := m.tokens[token][owner]; v != nil {
		return v
	}
	return big.NewInt(0)
}

func (m *mockState) setBal(token, owner common.Address, v *big.Int) {
	if m.tokens[token] == nil {
		m.tokens[token] = make(map[common.Address]*big.Int)
	}
	m.tokens[token][owner] = v
}

func (m *mockState) fund(token, owner common.Address, amt *big.Int) {
	m.setBal(token, owner, new(big.Int).Add(m.bal(token, owner), amt))
}

// --- erc20Vault capability ---

func (m *mockState) TokenBalanceOf(token, owner common.Address) *big.Int {
	return new(big.Int).Set(m.bal(token, owner))
}

func (m *mockState) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if m.failTransfer[token] {
		return errTokenReverted
	}
	if m.bal(token, from).Cmp(amount) < 0 {
		return errTokenReverted
	}
	if r := m.reenter; r != nil {
		m.reenter = nil // fire exactly once
		r()
	}
	m.setBal(token, from, new(big.Int).Sub(m.bal(token, from), amount))
	credit := amount
	if bps := m.feeBps[token]; bps > 0 { // fee-on-transfer: deliver less than `amount`
		fee := new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(int64(bps))), big.NewInt(10000))
		credit = new(big.Int).Sub(amount, fee)
	}
	m.setBal(token, to, new(big.Int).Add(m.bal(token, to), credit))
	return nil
}

func (m *mockState) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	if m.failTransfer[token] {
		return errTokenReverted
	}
	if m.bal(token, swapAddr).Cmp(amount) < 0 {
		return errTokenReverted
	}
	m.setBal(token, swapAddr, new(big.Int).Sub(m.bal(token, swapAddr), amount))
	m.setBal(token, to, new(big.Int).Add(m.bal(token, to), amount))
	return nil
}

// --- contract.StateDB ---

func (m *mockState) GetState(addr common.Address, key common.Hash) common.Hash {
	return m.storage[stateKey{addr, key}]
}

func (m *mockState) SetState(addr common.Address, key, value common.Hash) common.Hash {
	k := stateKey{addr, key}
	prev := m.storage[k]
	m.storage[k] = value
	return prev
}

func (m *mockState) AddLog(l *ethtypes.Log)         { m.logs = append(m.logs, l) }
func (m *mockState) Logs() []*ethtypes.Log          { return m.logs }
func (m *mockState) TxHash() common.Hash            { return common.Hash{} }
func (m *mockState) Snapshot() int                  { return 0 }
func (m *mockState) RevertToSnapshot(int)           {}
func (m *mockState) CreateAccount(common.Address)   {}
func (m *mockState) Exist(common.Address) bool      { return true }
func (m *mockState) GetNonce(common.Address) uint64 { return 0 }

func (m *mockState) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}

func (m *mockState) GetBalance(common.Address) *uint256.Int { return uint256.NewInt(0) }
func (m *mockState) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *mockState) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *mockState) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int  { return big.NewInt(0) }
func (m *mockState) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *mockState) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *mockState) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}

// ---------------------------------------------------------------------------
// mock AccessibleState + BlockContext with a settable clock.
// ---------------------------------------------------------------------------

type mockBlock struct{ ts uint64 }

func (b *mockBlock) Number() *big.Int                                       { return big.NewInt(1) }
func (b *mockBlock) Timestamp() uint64                                      { return b.ts }
func (b *mockBlock) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

type mockAccessible struct {
	db  *mockState
	blk *mockBlock
}

func (a *mockAccessible) GetStateDB() contract.StateDB                     { return a.db }
func (a *mockAccessible) GetBlockContext() contract.BlockContext           { return a.blk }
func (a *mockAccessible) GetConsensusContext() context.Context             { return context.Background() }
func (a *mockAccessible) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (a *mockAccessible) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

// ---------------------------------------------------------------------------
// env: a precompile + state + clock bundle with typed call helpers.
// ---------------------------------------------------------------------------

type env struct {
	c   *SwapContract
	st  *mockAccessible
	gas uint64
}

// eqBig asserts two *big.Int values are numerically equal (Cmp == 0), avoiding
// the nil-vs-empty `abs` pitfall of reflect-based require.Equal on big.Int.
func eqBig(t require.TestingT, want, got *big.Int) {
	require.Truef(t, want.Cmp(got) == 0, "want %s, got %s", want, got)
}

func newEnv(now uint64) *env {
	return &env{
		c:   &SwapContract{},
		st:  &mockAccessible{db: newMockState(), blk: &mockBlock{ts: now}},
		gas: 10_000_000,
	}
}

func (e *env) now() uint64                       { return e.st.blk.ts }
func (e *env) setNow(ts uint64)                  { e.st.blk.ts = ts }
func (e *env) db() *mockState                    { return e.st.db }
func (e *env) reserve(a common.Address) *big.Int { return loadReserve(e.db(), a) }

func selBytes(sel uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sel)
	return b
}

func leftPad(b []byte) []byte {
	w := make([]byte, 32)
	copy(w[32-len(b):], b)
	return w
}

func addrArg(a common.Address) []byte { return leftPad(a.Bytes()) }
func amountArg(v *big.Int) []byte     { return leftPad(v.Bytes()) }
func u64Arg(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return leftPad(b)
}

// lock encodes and runs a lock call, returning the swapId and result.
func (e *env) lock(caller common.Address, hashlock common.Hash, recipient, refund, asset common.Address, amount *big.Int, timeout uint64, readOnly bool) (common.Hash, []byte, error) {
	in := selBytes(selLock)
	in = append(in, hashlock[:]...)
	in = append(in, addrArg(recipient)...)
	in = append(in, addrArg(refund)...)
	in = append(in, addrArg(asset)...)
	in = append(in, amountArg(amount)...)
	in = append(in, u64Arg(timeout)...)
	ret, _, err := e.c.Run(e.st, caller, swapAddr, in, e.gas, readOnly)
	var id common.Hash
	if err == nil {
		copy(id[:], ret)
	}
	return id, ret, err
}

func (e *env) claim(caller common.Address, swapId common.Hash, preimage [32]byte, readOnly bool) ([]byte, error) {
	in := selBytes(selClaim)
	in = append(in, swapId[:]...)
	in = append(in, preimage[:]...)
	ret, _, err := e.c.Run(e.st, caller, swapAddr, in, e.gas, readOnly)
	return ret, err
}

func (e *env) refund(caller common.Address, swapId common.Hash, readOnly bool) ([]byte, error) {
	in := selBytes(selRefund)
	in = append(in, swapId[:]...)
	ret, _, err := e.c.Run(e.st, caller, swapAddr, in, e.gas, readOnly)
	return ret, err
}

func (e *env) getSwap(swapId common.Hash, readOnly bool) ([]byte, error) {
	in := append(selBytes(selGetSwap), swapId[:]...)
	ret, _, err := e.c.Run(e.st, common.Address{}, swapAddr, in, e.gas, readOnly)
	return ret, err
}

func (e *env) getPreimage(hashlock common.Hash, readOnly bool) ([32]byte, error) {
	in := append(selBytes(selGetPreimage), hashlock[:]...)
	ret, _, err := e.c.Run(e.st, common.Address{}, swapAddr, in, e.gas, readOnly)
	var p [32]byte
	if err == nil {
		copy(p[:], ret)
	}
	return p, err
}
