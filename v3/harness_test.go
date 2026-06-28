// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"context"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// errTokenReverted is what the mock ERC-20 returns on an insufficient-balance or
// otherwise failed transfer (the OZ-safe revert the vault surface expects).
var errTokenReverted = errors.New("token transfer reverted")

// ---------------------------------------------------------------------------
// mockState implements contract.StateDB AND the erc20Vault capability. Token
// balances live in a simple ledger so the custody conservation invariant
// (reserve[asset] == balanceOf(v3Addr, asset)) can be checked against the
// precompile's own accounting. Mirrors swap/harness_test.go.
// ---------------------------------------------------------------------------

type stateKey struct {
	addr common.Address
	key  common.Hash
}

type mockState struct {
	storage map[stateKey]common.Hash
	logs    []*ethtypes.Log
	tokens  map[common.Address]map[common.Address]*big.Int // token -> owner -> balance
	native  map[common.Address]*big.Int                    // addr -> native LUX balance
}

func newMockState() *mockState {
	return &mockState{
		storage: make(map[stateKey]common.Hash),
		tokens:  make(map[common.Address]map[common.Address]*big.Int),
		native:  make(map[common.Address]*big.Int),
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

// --- native LUX ledger ---

func (m *mockState) nativeBal(a common.Address) *big.Int {
	if v := m.native[a]; v != nil {
		return v
	}
	return big.NewInt(0)
}

func (m *mockState) setNative(a common.Address, v *big.Int) { m.native[a] = v }

func (m *mockState) fundNative(a common.Address, amt *big.Int) {
	m.setNative(a, new(big.Int).Add(m.nativeBal(a), amt))
}

// --- erc20Vault capability ---

func (m *mockState) TokenBalanceOf(token, owner common.Address) *big.Int {
	return new(big.Int).Set(m.bal(token, owner))
}

func (m *mockState) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if m.bal(token, from).Cmp(amount) < 0 {
		return errTokenReverted
	}
	m.setBal(token, from, new(big.Int).Sub(m.bal(token, from), amount))
	m.setBal(token, to, new(big.Int).Add(m.bal(token, to), amount))
	return nil
}

func (m *mockState) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	if m.bal(token, v3Addr).Cmp(amount) < 0 {
		return errTokenReverted
	}
	m.setBal(token, v3Addr, new(big.Int).Sub(m.bal(token, v3Addr), amount))
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

func (m *mockState) GetBalance(a common.Address) *uint256.Int {
	return uint256.MustFromBig(m.nativeBal(a))
}

func (m *mockState) AddBalance(a common.Address, amt *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prior := m.nativeBal(a)
	m.setNative(a, new(big.Int).Add(prior, amt.ToBig()))
	return *uint256.MustFromBig(prior)
}

func (m *mockState) SubBalance(a common.Address, amt *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prior := m.nativeBal(a)
	m.setNative(a, new(big.Int).Sub(prior, amt.ToBig()))
	return *uint256.MustFromBig(prior)
}
func (m *mockState) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int  { return big.NewInt(0) }
func (m *mockState) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *mockState) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *mockState) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}

// ---------------------------------------------------------------------------
// mock AccessibleState + BlockContext.
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
// env: a precompile + state bundle with typed, ABI-encoding call helpers.
// ---------------------------------------------------------------------------

type env struct {
	c   *V3Contract
	st  *mockAccessible
	gas uint64
}

func newEnv() *env {
	return &env{
		c:   &V3Contract{},
		st:  &mockAccessible{db: newMockState(), blk: &mockBlock{ts: 1}},
		gas: 50_000_000,
	}
}

func (e *env) db() *mockState                    { return e.st.db }
func (e *env) reserve(a common.Address) *big.Int { return loadReserve(e.db(), a) }

// eqBig asserts two *big.Int values are numerically equal (avoids the nil-vs-empty
// abs pitfall of reflect-based require.Equal on big.Int).
func eqBig(t require.TestingT, want, got *big.Int) {
	require.Truef(t, want.Cmp(got) == 0, "want %s, got %s", want, got)
}

// ---- ABI encoders (compose the package word codecs) ----

func selBytes(sel uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sel)
	return b
}

func pkWords(c0, c1 common.Address, fee uint32, tickSpacing int32) []byte {
	out := make([]byte, 0, 128)
	out = append(out, addressWord(c0)...)
	out = append(out, addressWord(c1)...)
	out = append(out, uintWord(big.NewInt(int64(fee))).Bytes()...)
	out = append(out, intWord(big.NewInt(int64(tickSpacing))).Bytes()...)
	return out
}

func tickWord(t int32) []byte   { return intWord(big.NewInt(int64(t))).Bytes() }
func uintArg(v *big.Int) []byte { return uintWord(v).Bytes() }
func intArg(v *big.Int) []byte  { return intWord(v).Bytes() }
func boolArg(b bool) []byte {
	w := make([]byte, 32)
	if b {
		w[31] = 1
	}
	return w
}

// ---- typed calls (poolKey passed via fields) ----

type poolCfg struct {
	c0, c1      common.Address
	fee         uint32
	tickSpacing int32
}

func (p poolCfg) words() []byte { return pkWords(p.c0, p.c1, p.fee, p.tickSpacing) }

func (e *env) initialize(p poolCfg, sqrtPriceX96 *big.Int, readOnly bool) (int32, error) {
	in := append(selBytes(selInitialize), p.words()...)
	in = append(in, uintArg(sqrtPriceX96)...)
	ret, _, err := e.c.Run(e.st, common.Address{}, v3Addr, in, e.gas, readOnly)
	if err != nil {
		return 0, err
	}
	return int32(wordToInt(common.BytesToHash(ret[0:32])).Int64()), nil
}

func (e *env) mint(caller common.Address, p poolCfg, lower, upper int32, amount *big.Int, readOnly bool) (a0, a1 *big.Int, err error) {
	in := append(selBytes(selMint), p.words()...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	in = append(in, uintArg(amount)...)
	ret, _, err := e.c.Run(e.st, caller, v3Addr, in, e.gas, readOnly)
	if err != nil {
		return nil, nil, err
	}
	return wordToUint(common.BytesToHash(ret[0:32])), wordToUint(common.BytesToHash(ret[32:64])), nil
}

func (e *env) burn(caller common.Address, p poolCfg, lower, upper int32, amount *big.Int) (a0, a1 *big.Int, err error) {
	in := append(selBytes(selBurn), p.words()...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	in = append(in, uintArg(amount)...)
	ret, _, err := e.c.Run(e.st, caller, v3Addr, in, e.gas, false)
	if err != nil {
		return nil, nil, err
	}
	return wordToUint(common.BytesToHash(ret[0:32])), wordToUint(common.BytesToHash(ret[32:64])), nil
}

func (e *env) collect(caller common.Address, p poolCfg, lower, upper int32, a0Req, a1Req *big.Int) (a0, a1 *big.Int, err error) {
	in := append(selBytes(selCollect), p.words()...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	in = append(in, uintArg(a0Req)...)
	in = append(in, uintArg(a1Req)...)
	ret, _, err := e.c.Run(e.st, caller, v3Addr, in, e.gas, false)
	if err != nil {
		return nil, nil, err
	}
	return wordToUint(common.BytesToHash(ret[0:32])), wordToUint(common.BytesToHash(ret[32:64])), nil
}

func (e *env) swap(caller common.Address, p poolCfg, zeroForOne bool, amountSpecified, sqrtLimit *big.Int) (a0, a1 *big.Int, err error) {
	in := append(selBytes(selSwap), p.words()...)
	in = append(in, boolArg(zeroForOne)...)
	in = append(in, intArg(amountSpecified)...)
	in = append(in, uintArg(sqrtLimit)...)
	ret, _, err := e.c.Run(e.st, caller, v3Addr, in, e.gas, false)
	if err != nil {
		return nil, nil, err
	}
	return wordToInt(common.BytesToHash(ret[0:32])), wordToInt(common.BytesToHash(ret[32:64])), nil
}

func (e *env) slot0(p poolCfg) (sqrtPriceX96 *big.Int, tick int32) {
	in := append(selBytes(selSlot0), p.words()...)
	ret, _, err := e.c.Run(e.st, common.Address{}, v3Addr, in, e.gas, true)
	if err != nil {
		panic(err)
	}
	return wordToUint(common.BytesToHash(ret[0:32])), int32(wordToInt(common.BytesToHash(ret[32:64])).Int64())
}

func (e *env) liquidityOf(p poolCfg) *big.Int {
	in := append(selBytes(selLiquidity), p.words()...)
	ret, _, err := e.c.Run(e.st, common.Address{}, v3Addr, in, e.gas, true)
	if err != nil {
		panic(err)
	}
	return wordToUint(common.BytesToHash(ret[0:32]))
}

// positionOf returns (liquidity, tokensOwed0, tokensOwed1) for a caller position.
func (e *env) positionOf(owner common.Address, p poolCfg, lower, upper int32) (liq, owed0, owed1 *big.Int) {
	in := append(selBytes(selPositions), p.words()...)
	in = append(in, addressWord(owner)...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	ret, _, err := e.c.Run(e.st, common.Address{}, v3Addr, in, e.gas, true)
	if err != nil {
		panic(err)
	}
	return wordToUint(common.BytesToHash(ret[0:32])),
		wordToUint(common.BytesToHash(ret[96:128])),
		wordToUint(common.BytesToHash(ret[128:160]))
}
