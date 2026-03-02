package harness

import (
	"context"
	"math/big"
	"sync"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// MockStateDB is a minimal in-memory state backend for testing stateful
// precompiles (bridge, anchor, compute, DEX). Thread-safe.
type MockStateDB struct {
	mu       sync.RWMutex
	state    map[common.Address]map[common.Hash]common.Hash
	balances map[common.Address]*uint256.Int
	nonces   map[common.Address]uint64
	logs     []*ethtypes.Log

	// Snapshots for revert
	snapshots map[int]map[common.Address]map[common.Hash]common.Hash
	snapID    int
}

func NewMockStateDB() *MockStateDB {
	return &MockStateDB{
		state:     make(map[common.Address]map[common.Hash]common.Hash),
		balances:  make(map[common.Address]*uint256.Int),
		nonces:    make(map[common.Address]uint64),
		logs:      make([]*ethtypes.Log, 0),
		snapshots: make(map[int]map[common.Address]map[common.Hash]common.Hash),
	}
}

func (m *MockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.state[addr]; ok {
		return s[key]
	}
	return common.Hash{}
}

func (m *MockStateDB) SetState(addr common.Address, key, value common.Hash) common.Hash {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state[addr] == nil {
		m.state[addr] = make(map[common.Hash]common.Hash)
	}
	prev := m.state[addr][key]
	m.state[addr][key] = value
	return prev
}

func (m *MockStateDB) SetNonce(addr common.Address, n uint64, _ tracing.NonceChangeReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[addr] = n
}

func (m *MockStateDB) GetNonce(addr common.Address) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nonces[addr]
}

func (m *MockStateDB) GetBalance(addr common.Address) *uint256.Int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if b, ok := m.balances[addr]; ok {
		return b.Clone()
	}
	return uint256.NewInt(0)
}

func (m *MockStateDB) AddBalance(addr common.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.balances[addr] == nil {
		m.balances[addr] = uint256.NewInt(0)
	}
	prev := *m.balances[addr]
	m.balances[addr].Add(m.balances[addr], amount)
	return prev
}

func (m *MockStateDB) SubBalance(addr common.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.balances[addr] == nil {
		m.balances[addr] = uint256.NewInt(0)
	}
	prev := *m.balances[addr]
	m.balances[addr].Sub(m.balances[addr], amount)
	return prev
}

func (m *MockStateDB) GetBalanceMultiCoin(addr common.Address, coinID common.Hash) *big.Int {
	return big.NewInt(0)
}

func (m *MockStateDB) AddBalanceMultiCoin(addr common.Address, coinID common.Hash, amount *big.Int) {}
func (m *MockStateDB) SubBalanceMultiCoin(addr common.Address, coinID common.Hash, amount *big.Int) {}

func (m *MockStateDB) CreateAccount(addr common.Address) {}
func (m *MockStateDB) Exist(addr common.Address) bool    { return true }

func (m *MockStateDB) AddLog(l *ethtypes.Log) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, l)
}

func (m *MockStateDB) Logs() []*ethtypes.Log {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ethtypes.Log, len(m.logs))
	copy(out, m.logs)
	return out
}

func (m *MockStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}

func (m *MockStateDB) TxHash() common.Hash { return common.Hash{} }

func (m *MockStateDB) Snapshot() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapID++
	snap := make(map[common.Address]map[common.Hash]common.Hash)
	for addr, slots := range m.state {
		snap[addr] = make(map[common.Hash]common.Hash)
		for k, v := range slots {
			snap[addr][k] = v
		}
	}
	m.snapshots[m.snapID] = snap
	return m.snapID
}

func (m *MockStateDB) RevertToSnapshot(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if snap, ok := m.snapshots[id]; ok {
		m.state = snap
	}
}

// MockBlockContext satisfies contract.BlockContext.
type MockBlockContext struct {
	BlockNumber    *big.Int
	BlockTimestamp uint64
}

func (b *MockBlockContext) Number() *big.Int    { return b.BlockNumber }
func (b *MockBlockContext) Timestamp() uint64   { return b.BlockTimestamp }
func (b *MockBlockContext) GetPredicateResults(common.Hash, common.Address) []byte {
	return nil
}

// MockChainConfig satisfies precompileconfig.ChainConfig.
type MockChainConfig struct{}

func (c *MockChainConfig) IsDurango(t uint64) bool { return true }

// MockAccessibleState ties MockStateDB + MockBlockContext + MockChainConfig together.
type MockAccessibleState struct {
	DB    *MockStateDB
	Block *MockBlockContext
	Chain *MockChainConfig
}

func NewMockAccessibleState() *MockAccessibleState {
	return &MockAccessibleState{
		DB: NewMockStateDB(),
		Block: &MockBlockContext{
			BlockNumber:    big.NewInt(1),
			BlockTimestamp: 1700000000,
		},
		Chain: &MockChainConfig{},
	}
}

func (s *MockAccessibleState) GetStateDB() contract.StateDB               { return s.DB }
func (s *MockAccessibleState) GetBlockContext() contract.BlockContext       { return s.Block }
func (s *MockAccessibleState) GetConsensusContext() context.Context         { return context.Background() }
func (s *MockAccessibleState) GetChainConfig() precompileconfig.ChainConfig { return s.Chain }
func (s *MockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }
