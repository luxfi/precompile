// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package anchor

import (
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// --- mock infrastructure ---

type testStateDB struct {
	state map[common.Address]map[common.Hash]common.Hash
}

func newTestStateDB() *testStateDB {
	return &testStateDB{state: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *testStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if m.state[addr] == nil { return common.Hash{} }
	return m.state[addr][key]
}
func (m *testStateDB) SetState(addr common.Address, key, val common.Hash) common.Hash {
	if m.state[addr] == nil { m.state[addr] = make(map[common.Hash]common.Hash) }
	old := m.state[addr][key]; m.state[addr][key] = val; return old
}
func (m *testStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (m *testStateDB) GetNonce(common.Address) uint64 { return 0 }
func (m *testStateDB) GetBalance(common.Address) *uint256.Int { return new(uint256.Int) }
func (m *testStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int { return uint256.Int{} }
func (m *testStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int { return uint256.Int{} }
func (m *testStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int { return big.NewInt(0) }
func (m *testStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *testStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *testStateDB) CreateAccount(common.Address) {}
func (m *testStateDB) Exist(common.Address) bool { return false }
func (m *testStateDB) AddLog(*ethtypes.Log) {}
func (m *testStateDB) Logs() []*ethtypes.Log { return nil }
func (m *testStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) { return nil, false }
func (m *testStateDB) TxHash() common.Hash { return common.Hash{} }
func (m *testStateDB) Snapshot() int { return 0 }
func (m *testStateDB) RevertToSnapshot(int) {}

var _ contract.StateDB = (*testStateDB)(nil)

type testBlockCtx struct{}
func (t *testBlockCtx) Number() *big.Int { return big.NewInt(1) }
func (t *testBlockCtx) Timestamp() uint64 { return 1000 }
func (t *testBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte { return nil }
var _ contract.BlockContext = (*testBlockCtx)(nil)

type testChainCfg struct{}
func (t *testChainCfg) IsDurango(uint64) bool { return true }

type testPrecompileEnv struct{}
func (t *testPrecompileEnv) ReadOnly() bool { return false }

type testAS struct{ db *testStateDB }
func (t *testAS) GetStateDB() contract.StateDB { return t.db }
func (t *testAS) GetBlockContext() contract.BlockContext { return &testBlockCtx{} }
func (t *testAS) GetConsensusContext() context.Context { return context.Background() }
func (t *testAS) GetChainConfig() precompileconfig.ChainConfig { return &testChainCfg{} }
func (t *testAS) GetPrecompileEnv() contract.PrecompileEnvironment { return &testPrecompileEnv{} }
var _ contract.AccessibleState = (*testAS)(nil)

func newTestAS() *testAS { return &testAS{db: newTestStateDB()} }

// --- helpers ---

func abiUint64(v uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], v)
	return b
}

// --- Config ---

type fakeConfig struct{}
func (f *fakeConfig) Key() string { return "fake" }
func (f *fakeConfig) Timestamp() *uint64 { return nil }
func (f *fakeConfig) IsDisabled() bool { return false }
func (f *fakeConfig) Equal(precompileconfig.Config) bool { return false }
func (f *fakeConfig) Verify(precompileconfig.ChainConfig) error { return nil }

func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&testChainCfg{}))
	require.True(t, cfg.Equal(&Config{}))
	require.False(t, cfg.Equal(&fakeConfig{}))

	ts := uint64(42)
	cfg2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg2.Timestamp())

	cfg3 := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, cfg3.IsDisabled())
}

func TestConfigurator(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.NoError(t, c.Configure(&testChainCfg{}, cfg, newTestStateDB(), &testBlockCtx{}))
}

func TestModuleRegistered(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
}

// --- Run: submit edge cases ---

func TestSubmitOutOfGas(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorSubmit, make([]byte, 96)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestSubmitShortData(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorSubmit, make([]byte, 10)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

// --- Run: get edge cases ---

func TestGetOutOfGas(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorGet, make([]byte, 64)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestGetShortData(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorGet, make([]byte, 10)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

// --- Run: getLatest edge cases ---

func TestGetLatestOutOfGas(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorGetLatest, make([]byte, 32)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestGetLatestShortData(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorGetLatest, make([]byte, 10)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

// --- Run: list edge cases ---

func TestListOutOfGas(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorList, make([]byte, 96)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestListShortData(t *testing.T) {
	p := &anchorPrecompile{}
	input := append(selectorList, make([]byte, 10)...)
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

func TestListToBeforeFrom(t *testing.T) {
	p := &anchorPrecompile{}
	state := newTestAS()
	appID := [32]byte{0x01}
	data := make([]byte, 96)
	copy(data[:32], appID[:])
	binary.BigEndian.PutUint64(data[56:64], 10)  // from=10
	binary.BigEndian.PutUint64(data[88:96], 5)   // to=5 (invalid)
	input := append(selectorList, data...)
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

func TestListRangeTooLarge(t *testing.T) {
	p := &anchorPrecompile{}
	state := newTestAS()
	appID := [32]byte{0x01}
	data := make([]byte, 96)
	copy(data[:32], appID[:])
	binary.BigEndian.PutUint64(data[56:64], 1)    // from=1
	binary.BigEndian.PutUint64(data[88:96], 1000)  // to=1000 (range=999 > 256)
	input := append(selectorList, data...)
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, 10000000, false)
	require.ErrorIs(t, err, ErrRangeTooLarge)
}

func TestListInsufficientGasForRange(t *testing.T) {
	p := &anchorPrecompile{}
	state := newTestAS()
	appID := [32]byte{0x01}
	data := make([]byte, 96)
	copy(data[:32], appID[:])
	binary.BigEndian.PutUint64(data[56:64], 1)
	binary.BigEndian.PutUint64(data[88:96], 100) // 99 entries
	input := append(selectorList, data...)
	// Base gas is enough but range gas is not
	_, _, err := p.Run(state, common.Address{}, ContractAddress, input, GasListBase+10, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

// --- Run: invalid selector ---

func TestRunInvalidSelector(t *testing.T) {
	p := &anchorPrecompile{}
	_, _, err := p.Run(newTestAS(), common.Address{}, ContractAddress, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 100000, false)
	require.ErrorIs(t, err, ErrInvalidSelector)
}

// --- Full lifecycle: submit + get + getLatest + list ---

func TestFullLifecycle(t *testing.T) {
	p := &anchorPrecompile{}
	state := newTestAS()
	caller := common.HexToAddress("0x1234")

	appID := [32]byte{0x42}
	root1 := [32]byte{0xAA}
	root2 := [32]byte{0xBB}

	// Submit height 1
	// Layout: appID(32) + padding(24) + height(8) + root(32) = 96 bytes
	data := make([]byte, 96)
	copy(data[:32], appID[:])
	binary.BigEndian.PutUint64(data[56:64], 1) // height=1 at offset 56 (after 24-byte ABI pad)
	copy(data[64:96], root1[:])
	input := append(selectorSubmit, data...)
	ret, _, err := p.Run(state, caller, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.NotNil(t, ret)

	// Submit height 2
	data2 := make([]byte, 96)
	copy(data2[:32], appID[:])
	binary.BigEndian.PutUint64(data2[56:64], 2)
	copy(data2[64:96], root2[:])
	input2 := append(selectorSubmit, data2...)
	_, _, err = p.Run(state, caller, ContractAddress, input2, 100000, false)
	require.NoError(t, err)

	// Submit non-monotonic (height 1 again) should fail
	_, _, err = p.Run(state, caller, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrHeightNotMonotonic)

	// Get height 1
	getData := make([]byte, 64)
	copy(getData[:32], appID[:])
	binary.BigEndian.PutUint64(getData[56:64], 1)
	getInput := append(selectorGet, getData...)
	ret, _, err = p.Run(state, caller, ContractAddress, getInput, 100000, false)
	require.NoError(t, err)
	require.Equal(t, root1[:], ret)

	// Get height 999 (not found)
	getData2 := make([]byte, 64)
	copy(getData2[:32], appID[:])
	binary.BigEndian.PutUint64(getData2[56:64], 999)
	getInput2 := append(selectorGet, getData2...)
	_, _, err = p.Run(state, caller, ContractAddress, getInput2, 100000, false)
	require.ErrorIs(t, err, ErrAnchorNotFound)

	// GetLatest
	latestData := make([]byte, 32)
	copy(latestData[:32], appID[:])
	latestInput := append(selectorGetLatest, latestData...)
	ret, _, err = p.Run(state, caller, ContractAddress, latestInput, 100000, false)
	require.NoError(t, err)
	h := binary.BigEndian.Uint64(ret[24:32])
	require.Equal(t, uint64(2), h)

	// List [1, 3)
	listData := make([]byte, 96)
	copy(listData[:32], appID[:])
	binary.BigEndian.PutUint64(listData[56:64], 1)
	binary.BigEndian.PutUint64(listData[88:96], 3)
	listInput := append(selectorList, listData...)
	ret, _, err = p.Run(state, caller, ContractAddress, listInput, 100000, false)
	require.NoError(t, err)
	require.NotNil(t, ret)
}
