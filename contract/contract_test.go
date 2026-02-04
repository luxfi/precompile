// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// MockStateDB implements contract.StateDB interface for testing
type MockStateDB struct {
	storage  map[common.Address]map[common.Hash]common.Hash
	balances map[common.Address]*uint256.Int
	nonces   map[common.Address]uint64
	logs     []*ethtypes.Log
}

func NewMockStateDB() *MockStateDB {
	return &MockStateDB{
		storage:  make(map[common.Address]map[common.Hash]common.Hash),
		balances: make(map[common.Address]*uint256.Int),
		nonces:   make(map[common.Address]uint64),
		logs:     make([]*ethtypes.Log, 0),
	}
}

func (m *MockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if m.storage[addr] == nil {
		return common.Hash{}
	}
	return m.storage[addr][key]
}

func (m *MockStateDB) SetState(addr common.Address, key, value common.Hash) common.Hash {
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	prev := m.storage[addr][key]
	m.storage[addr][key] = value
	return prev
}

func (m *MockStateDB) GetBalance(addr common.Address) *uint256.Int {
	if bal, ok := m.balances[addr]; ok {
		return bal.Clone()
	}
	return uint256.NewInt(0)
}

func (m *MockStateDB) AddBalance(addr common.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	if m.balances[addr] == nil {
		m.balances[addr] = uint256.NewInt(0)
	}
	prev := m.balances[addr].Clone()
	m.balances[addr] = new(uint256.Int).Add(m.balances[addr], amount)
	return *prev
}

func (m *MockStateDB) SubBalance(addr common.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	if m.balances[addr] == nil {
		m.balances[addr] = uint256.NewInt(0)
	}
	prev := m.balances[addr].Clone()
	m.balances[addr] = new(uint256.Int).Sub(m.balances[addr], amount)
	return *prev
}

func (m *MockStateDB) SetNonce(addr common.Address, nonce uint64, _ tracing.NonceChangeReason) {
	m.nonces[addr] = nonce
}

func (m *MockStateDB) GetNonce(addr common.Address) uint64 {
	return m.nonces[addr]
}

func (m *MockStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int {
	return big.NewInt(0)
}

func (m *MockStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *MockStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (m *MockStateDB) CreateAccount(common.Address)                              {}
func (m *MockStateDB) Exist(common.Address) bool                                 { return true }
func (m *MockStateDB) AddLog(log *ethtypes.Log)                                  { m.logs = append(m.logs, log) }
func (m *MockStateDB) Logs() []*ethtypes.Log                                     { return m.logs }
func (m *MockStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}
func (m *MockStateDB) TxHash() common.Hash  { return common.Hash{} }
func (m *MockStateDB) Snapshot() int        { return 0 }
func (m *MockStateDB) RevertToSnapshot(int) {}

// MockBlockContext implements BlockContext interface for testing
type MockBlockContext struct {
	number    *big.Int
	timestamp uint64
}

func NewMockBlockContext(number int64, timestamp uint64) *MockBlockContext {
	return &MockBlockContext{
		number:    big.NewInt(number),
		timestamp: timestamp,
	}
}

func (m *MockBlockContext) Number() *big.Int {
	return m.number
}

func (m *MockBlockContext) Timestamp() uint64 {
	return m.timestamp
}

func (m *MockBlockContext) GetPredicateResults(common.Hash, common.Address) []byte {
	return nil
}

// MockChainConfig implements precompileconfig.ChainConfig for testing
type MockChainConfig struct {
	durangoTime uint64
}

func NewMockChainConfig(durangoTime uint64) *MockChainConfig {
	return &MockChainConfig{durangoTime: durangoTime}
}

func (m *MockChainConfig) IsDurango(time uint64) bool {
	return time >= m.durangoTime
}

// MockPrecompileEnv implements PrecompileEnvironment for testing
type MockPrecompileEnv struct {
	readOnly bool
}

func NewMockPrecompileEnv(readOnly bool) *MockPrecompileEnv {
	return &MockPrecompileEnv{readOnly: readOnly}
}

func (m *MockPrecompileEnv) ReadOnly() bool {
	return m.readOnly
}

// MockAccessibleState implements AccessibleState interface for testing
type MockAccessibleState struct {
	stateDB       StateDB
	blockContext  BlockContext
	chainConfig   precompileconfig.ChainConfig
	precompileEnv PrecompileEnvironment
	activated     bool // for activation tests
}

func NewMockAccessibleState(stateDB StateDB, blockContext BlockContext) *MockAccessibleState {
	return &MockAccessibleState{
		stateDB:       stateDB,
		blockContext:  blockContext,
		chainConfig:   NewMockChainConfig(0),
		precompileEnv: NewMockPrecompileEnv(false),
		activated:     true,
	}
}

func (m *MockAccessibleState) GetStateDB() StateDB {
	return m.stateDB
}

func (m *MockAccessibleState) GetBlockContext() BlockContext {
	return m.blockContext
}

func (m *MockAccessibleState) GetConsensusContext() context.Context {
	return context.Background()
}

func (m *MockAccessibleState) GetChainConfig() precompileconfig.ChainConfig {
	return m.chainConfig
}

func (m *MockAccessibleState) GetPrecompileEnv() PrecompileEnvironment {
	return m.precompileEnv
}

// Test constants
var (
	testCaller = common.HexToAddress("0x1234567890123456789012345678901234567890")
	testAddr   = common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
)

// =============================================================================
// StatefulPrecompileFunction Tests
// =============================================================================

func TestNewStatefulPrecompileFunction(t *testing.T) {
	selector := []byte{0x01, 0x02, 0x03, 0x04}
	executeCalled := false

	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		executeCalled = true
		return []byte("result"), suppliedGas - 100, nil
	}

	fn := NewStatefulPrecompileFunction(selector, execute)

	require.NotNil(t, fn)
	require.Equal(t, selector, fn.selector)
	require.NotNil(t, fn.execute)
	require.Nil(t, fn.activation)

	// Verify execute is set correctly
	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
	_, _, err := fn.execute(state, testCaller, testAddr, nil, 1000, false)
	require.NoError(t, err)
	require.True(t, executeCalled)
}

func TestNewStatefulPrecompileFunctionWithActivator(t *testing.T) {
	selector := []byte{0x01, 0x02, 0x03, 0x04}
	activationCalled := false

	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return []byte("result"), suppliedGas, nil
	}

	activation := func(accessibleState AccessibleState) bool {
		activationCalled = true
		return true
	}

	fn := NewStatefulPrecompileFunctionWithActivator(selector, execute, activation)

	require.NotNil(t, fn)
	require.Equal(t, selector, fn.selector)
	require.NotNil(t, fn.execute)
	require.NotNil(t, fn.activation)

	// Verify activation is set correctly
	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
	fn.IsActivated(state)
	require.True(t, activationCalled)
}

func TestStatefulPrecompileFunctionIsActivated(t *testing.T) {
	selector := []byte{0x01, 0x02, 0x03, 0x04}
	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return nil, suppliedGas, nil
	}

	t.Run("nil activation returns true", func(t *testing.T) {
		fn := NewStatefulPrecompileFunction(selector, execute)
		state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
		require.True(t, fn.IsActivated(state))
	})

	t.Run("activation returns true", func(t *testing.T) {
		activation := func(accessibleState AccessibleState) bool { return true }
		fn := NewStatefulPrecompileFunctionWithActivator(selector, execute, activation)
		state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
		require.True(t, fn.IsActivated(state))
	})

	t.Run("activation returns false", func(t *testing.T) {
		activation := func(accessibleState AccessibleState) bool { return false }
		fn := NewStatefulPrecompileFunctionWithActivator(selector, execute, activation)
		state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
		require.False(t, fn.IsActivated(state))
	})

	t.Run("activation based on state", func(t *testing.T) {
		activation := func(accessibleState AccessibleState) bool {
			return accessibleState.GetBlockContext().Timestamp() > 500
		}
		fn := NewStatefulPrecompileFunctionWithActivator(selector, execute, activation)

		stateLow := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 100))
		stateHigh := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))

		require.False(t, fn.IsActivated(stateLow))
		require.True(t, fn.IsActivated(stateHigh))
	})
}

// =============================================================================
// StatefulPrecompileContract Tests
// =============================================================================

func TestNewStatefulPrecompileContract(t *testing.T) {
	selector1 := []byte{0x01, 0x02, 0x03, 0x04}
	selector2 := []byte{0x05, 0x06, 0x07, 0x08}

	execute1 := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return []byte("result1"), suppliedGas, nil
	}
	execute2 := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return []byte("result2"), suppliedGas, nil
	}

	t.Run("create contract with multiple functions", func(t *testing.T) {
		fn1 := NewStatefulPrecompileFunction(selector1, execute1)
		fn2 := NewStatefulPrecompileFunction(selector2, execute2)

		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)
		require.NotNil(t, contract)
	})

	t.Run("create contract with fallback", func(t *testing.T) {
		fallback := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
			return []byte("fallback"), suppliedGas, nil
		}

		contract, err := NewStatefulPrecompileContract(fallback, nil)
		require.NoError(t, err)
		require.NotNil(t, contract)
	})

	t.Run("duplicate selector error", func(t *testing.T) {
		fn1 := NewStatefulPrecompileFunction(selector1, execute1)
		fn2 := NewStatefulPrecompileFunction(selector1, execute2) // same selector

		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.Error(t, err)
		require.Nil(t, contract)
		require.Contains(t, err.Error(), "duplicated function selector")
	})

	t.Run("empty functions list", func(t *testing.T) {
		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{})
		require.NoError(t, err)
		require.NotNil(t, contract)
	})
}

func TestStatefulPrecompileContractRun(t *testing.T) {
	selector1 := []byte{0x01, 0x02, 0x03, 0x04}
	selector2 := []byte{0x05, 0x06, 0x07, 0x08}

	execute1 := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return []byte("result1"), suppliedGas - 100, nil
	}
	execute2 := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return append([]byte("result2:"), input...), suppliedGas - 200, nil
	}

	fn1 := NewStatefulPrecompileFunction(selector1, execute1)
	fn2 := NewStatefulPrecompileFunction(selector2, execute2)

	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))

	t.Run("run with valid selector1", func(t *testing.T) {
		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)

		input := append(selector1, []byte("input data")...)
		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, input, 1000, false)

		require.NoError(t, err)
		require.Equal(t, []byte("result1"), ret)
		require.Equal(t, uint64(900), remainingGas)
	})

	t.Run("run with valid selector2 and input", func(t *testing.T) {
		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)

		inputData := []byte("hello")
		input := append(selector2, inputData...)
		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, input, 1000, false)

		require.NoError(t, err)
		require.Equal(t, []byte("result2:hello"), ret)
		require.Equal(t, uint64(800), remainingGas)
	})

	t.Run("run with invalid selector", func(t *testing.T) {
		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)

		invalidSelector := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		input := append(invalidSelector, []byte("data")...)
		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, input, 1000, false)

		require.Error(t, err)
		require.Nil(t, ret)
		require.Equal(t, uint64(1000), remainingGas) // gas returned on error
		require.Contains(t, err.Error(), "invalid function selector")
	})

	t.Run("run with short input (missing selector)", func(t *testing.T) {
		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)

		shortInput := []byte{0x01, 0x02} // only 2 bytes, need 4
		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, shortInput, 1000, false)

		require.Error(t, err)
		require.Nil(t, ret)
		require.Equal(t, uint64(1000), remainingGas)
		require.Contains(t, err.Error(), "missing function selector")
	})

	t.Run("run with empty input and fallback", func(t *testing.T) {
		fallback := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
			return []byte("fallback called"), suppliedGas - 50, nil
		}

		contract, err := NewStatefulPrecompileContract(fallback, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)

		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, []byte{}, 1000, false)

		require.NoError(t, err)
		require.Equal(t, []byte("fallback called"), ret)
		require.Equal(t, uint64(950), remainingGas)
	})

	t.Run("run with empty input and no fallback", func(t *testing.T) {
		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
		require.NoError(t, err)

		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, []byte{}, 1000, false)

		require.Error(t, err)
		require.Nil(t, ret)
		require.Equal(t, uint64(1000), remainingGas)
		require.Contains(t, err.Error(), "missing function selector")
	})

	t.Run("run with nil input and fallback", func(t *testing.T) {
		fallback := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
			require.Nil(t, input) // fallback receives nil
			return []byte("fallback nil"), suppliedGas, nil
		}

		contract, err := NewStatefulPrecompileContract(fallback, []*StatefulPrecompileFunction{fn1})
		require.NoError(t, err)

		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, nil, 1000, false)

		require.NoError(t, err)
		require.Equal(t, []byte("fallback nil"), ret)
		require.Equal(t, uint64(1000), remainingGas)
	})
}

func TestStatefulPrecompileContractRunWithActivation(t *testing.T) {
	selector := []byte{0x01, 0x02, 0x03, 0x04}

	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return []byte("executed"), suppliedGas, nil
	}

	t.Run("function activated", func(t *testing.T) {
		activation := func(accessibleState AccessibleState) bool { return true }
		fn := NewStatefulPrecompileFunctionWithActivator(selector, execute, activation)

		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn})
		require.NoError(t, err)

		state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
		input := append(selector, []byte("data")...)
		ret, _, err := contract.Run(state, testCaller, testAddr, input, 1000, false)

		require.NoError(t, err)
		require.Equal(t, []byte("executed"), ret)
	})

	t.Run("function not activated", func(t *testing.T) {
		activation := func(accessibleState AccessibleState) bool { return false }
		fn := NewStatefulPrecompileFunctionWithActivator(selector, execute, activation)

		contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn})
		require.NoError(t, err)

		state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
		input := append(selector, []byte("data")...)
		ret, remainingGas, err := contract.Run(state, testCaller, testAddr, input, 1000, false)

		require.Error(t, err)
		require.Nil(t, ret)
		require.Equal(t, uint64(1000), remainingGas)
		require.Contains(t, err.Error(), "invalid non-activated function selector")
	})
}

func TestStatefulPrecompileContractRunReadOnly(t *testing.T) {
	selector := []byte{0x01, 0x02, 0x03, 0x04}
	readOnlyReceived := false

	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		readOnlyReceived = readOnly
		return []byte("result"), suppliedGas, nil
	}

	fn := NewStatefulPrecompileFunction(selector, execute)
	contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn})
	require.NoError(t, err)

	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))

	t.Run("readOnly=false passed through", func(t *testing.T) {
		readOnlyReceived = false
		input := append(selector, []byte("data")...)
		_, _, err := contract.Run(state, testCaller, testAddr, input, 1000, false)
		require.NoError(t, err)
		require.False(t, readOnlyReceived)
	})

	t.Run("readOnly=true passed through", func(t *testing.T) {
		readOnlyReceived = false
		input := append(selector, []byte("data")...)
		_, _, err := contract.Run(state, testCaller, testAddr, input, 1000, true)
		require.NoError(t, err)
		require.True(t, readOnlyReceived)
	})
}

func TestStatefulPrecompileContractRunErrorPropagation(t *testing.T) {
	selector := []byte{0x01, 0x02, 0x03, 0x04}
	testError := errors.New("execution failed")

	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return nil, suppliedGas - 50, testError
	}

	fn := NewStatefulPrecompileFunction(selector, execute)
	contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn})
	require.NoError(t, err)

	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
	input := append(selector, []byte("data")...)
	ret, remainingGas, err := contract.Run(state, testCaller, testAddr, input, 1000, false)

	require.Error(t, err)
	require.Equal(t, testError, err)
	require.Nil(t, ret)
	require.Equal(t, uint64(950), remainingGas) // gas deducted by execute
}

// =============================================================================
// Gas Calculation Tests (DeductGas)
// =============================================================================

func TestDeductGas(t *testing.T) {
	t.Run("sufficient gas", func(t *testing.T) {
		remaining, err := DeductGas(1000, 100)
		require.NoError(t, err)
		require.Equal(t, uint64(900), remaining)
	})

	t.Run("exact gas", func(t *testing.T) {
		remaining, err := DeductGas(100, 100)
		require.NoError(t, err)
		require.Equal(t, uint64(0), remaining)
	})

	t.Run("insufficient gas", func(t *testing.T) {
		remaining, err := DeductGas(50, 100)
		require.Error(t, err)
		require.Equal(t, ErrOutOfGas, err)
		require.Equal(t, uint64(0), remaining)
	})

	t.Run("zero required gas", func(t *testing.T) {
		remaining, err := DeductGas(1000, 0)
		require.NoError(t, err)
		require.Equal(t, uint64(1000), remaining)
	})

	t.Run("zero supplied gas with zero required", func(t *testing.T) {
		remaining, err := DeductGas(0, 0)
		require.NoError(t, err)
		require.Equal(t, uint64(0), remaining)
	})

	t.Run("zero supplied gas with non-zero required", func(t *testing.T) {
		remaining, err := DeductGas(0, 1)
		require.Error(t, err)
		require.Equal(t, ErrOutOfGas, err)
		require.Equal(t, uint64(0), remaining)
	})

	t.Run("large values", func(t *testing.T) {
		supplied := uint64(1<<63 - 1) // max int64 as uint64
		required := uint64(1000)
		remaining, err := DeductGas(supplied, required)
		require.NoError(t, err)
		require.Equal(t, supplied-required, remaining)
	})
}

func TestGasConstants(t *testing.T) {
	// Verify gas constants are reasonable
	// WriteGasCostPerSlot and ReadGasCostPerSlot are untyped constants
	require.Equal(t, 20_000, WriteGasCostPerSlot)
	require.Equal(t, 5_000, ReadGasCostPerSlot)
	// Log gas constants are explicitly typed as uint64
	require.Equal(t, uint64(375), LogGas)
	require.Equal(t, uint64(375), LogTopicGas)
	require.Equal(t, uint64(8), LogDataGas)
}

// =============================================================================
// Function Selector Tests (CalculateFunctionSelector)
// =============================================================================

func TestCalculateFunctionSelector(t *testing.T) {
	t.Run("simple function no params", func(t *testing.T) {
		selector := CalculateFunctionSelector("getBalance()")
		require.Len(t, selector, SelectorLen)
	})

	t.Run("function with single param", func(t *testing.T) {
		selector := CalculateFunctionSelector("getBalance(address)")
		require.Len(t, selector, SelectorLen)
	})

	t.Run("function with multiple params", func(t *testing.T) {
		selector := CalculateFunctionSelector("setBalance(address,uint256)")
		require.Len(t, selector, SelectorLen)
	})

	t.Run("function with three params", func(t *testing.T) {
		selector := CalculateFunctionSelector("transfer(address,address,uint256)")
		require.Len(t, selector, SelectorLen)
	})

	t.Run("deterministic output", func(t *testing.T) {
		sig := "setBalance(address,uint256)"
		selector1 := CalculateFunctionSelector(sig)
		selector2 := CalculateFunctionSelector(sig)
		require.Equal(t, selector1, selector2)
	})

	t.Run("different signatures produce different selectors", func(t *testing.T) {
		selector1 := CalculateFunctionSelector("getBalance(address)")
		selector2 := CalculateFunctionSelector("setBalance(address,uint256)")
		require.NotEqual(t, selector1, selector2)
	})

	t.Run("known selector - transfer(address,uint256)", func(t *testing.T) {
		// Standard ERC20 transfer function selector
		selector := CalculateFunctionSelector("transfer(address,uint256)")
		// 0xa9059cbb is the known selector for transfer(address,uint256)
		expected := []byte{0xa9, 0x05, 0x9c, 0xbb}
		require.Equal(t, expected, selector)
	})

	t.Run("known selector - balanceOf(address)", func(t *testing.T) {
		// Standard ERC20 balanceOf function selector
		selector := CalculateFunctionSelector("balanceOf(address)")
		// 0x70a08231 is the known selector for balanceOf(address)
		expected := []byte{0x70, 0xa0, 0x82, 0x31}
		require.Equal(t, expected, selector)
	})
}

func TestCalculateFunctionSelectorPanics(t *testing.T) {
	invalidSignatures := []struct {
		name      string
		signature string
	}{
		{"empty string", ""},
		{"no parentheses", "transfer"},
		{"unclosed parentheses", "transfer(address"},
		{"spaces in signature", "transfer (address, uint256)"},
		{"no function name", "(address,uint256)"},
		{"invalid chars", "transfer@(address)"},
	}

	for _, tc := range invalidSignatures {
		t.Run(tc.name, func(t *testing.T) {
			require.Panics(t, func() {
				CalculateFunctionSelector(tc.signature)
			})
		})
	}
}

func TestSelectorLen(t *testing.T) {
	require.Equal(t, 4, SelectorLen)
}

// =============================================================================
// ParseABI Tests
// =============================================================================

func TestParseABI(t *testing.T) {
	t.Run("valid simple ABI", func(t *testing.T) {
		rawABI := `[{"type":"function","name":"getBalance","inputs":[{"name":"addr","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`
		abi := ParseABI(rawABI)
		require.NotNil(t, abi)
		require.Contains(t, abi.Methods, "getBalance")
	})

	t.Run("valid complex ABI", func(t *testing.T) {
		rawABI := `[
			{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]},
			{"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
			{"type":"event","name":"Transfer","inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}
		]`
		abi := ParseABI(rawABI)
		require.NotNil(t, abi)
		require.Contains(t, abi.Methods, "transfer")
		require.Contains(t, abi.Methods, "balanceOf")
		require.Contains(t, abi.Events, "Transfer")
	})

	t.Run("empty ABI", func(t *testing.T) {
		rawABI := `[]`
		abi := ParseABI(rawABI)
		require.NotNil(t, abi)
		require.Empty(t, abi.Methods)
	})
}

func TestParseABIPanics(t *testing.T) {
	invalidABIs := []struct {
		name   string
		rawABI string
	}{
		{"invalid JSON", `{invalid json}`},
		{"not an array", `{"type":"function"}`},
		{"malformed function", `[{"type":"function","inputs":"not_an_array"}]`},
	}

	for _, tc := range invalidABIs {
		t.Run(tc.name, func(t *testing.T) {
			require.Panics(t, func() {
				ParseABI(tc.rawABI)
			})
		})
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestContractIntegration(t *testing.T) {
	// Create a complete precompile contract with multiple functions
	getBalanceSelector := CalculateFunctionSelector("getBalance(address)")
	setBalanceSelector := CalculateFunctionSelector("setBalance(address,uint256)")

	// Track calls for verification
	getBalanceCalled := false
	setBalanceCalled := false

	getBalance := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		getBalanceCalled = true
		gas, err := DeductGas(suppliedGas, ReadGasCostPerSlot)
		if err != nil {
			return nil, 0, err
		}
		return common.LeftPadBytes([]byte{0x64}, 32), gas, nil // return 100
	}

	setBalance := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		if readOnly {
			return nil, suppliedGas, errors.New("cannot call setBalance in read-only mode")
		}
		setBalanceCalled = true
		gas, err := DeductGas(suppliedGas, WriteGasCostPerSlot)
		if err != nil {
			return nil, 0, err
		}
		return nil, gas, nil
	}

	fn1 := NewStatefulPrecompileFunction(getBalanceSelector, getBalance)
	fn2 := NewStatefulPrecompileFunction(setBalanceSelector, setBalance)

	contract, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn1, fn2})
	require.NoError(t, err)

	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))

	t.Run("call getBalance", func(t *testing.T) {
		getBalanceCalled = false
		input := append(getBalanceSelector, common.LeftPadBytes(testCaller.Bytes(), 32)...)
		ret, gas, err := contract.Run(state, testCaller, testAddr, input, 100000, false)

		require.NoError(t, err)
		require.True(t, getBalanceCalled)
		require.Equal(t, uint64(100000-ReadGasCostPerSlot), gas)
		require.Len(t, ret, 32)
	})

	t.Run("call setBalance", func(t *testing.T) {
		setBalanceCalled = false
		input := append(setBalanceSelector, common.LeftPadBytes(testCaller.Bytes(), 32)...)
		input = append(input, common.LeftPadBytes([]byte{0x64}, 32)...) // value 100

		_, gas, err := contract.Run(state, testCaller, testAddr, input, 100000, false)

		require.NoError(t, err)
		require.True(t, setBalanceCalled)
		require.Equal(t, uint64(100000-WriteGasCostPerSlot), gas)
	})

	t.Run("call setBalance in read-only mode", func(t *testing.T) {
		input := append(setBalanceSelector, common.LeftPadBytes(testCaller.Bytes(), 32)...)
		_, _, err := contract.Run(state, testCaller, testAddr, input, 100000, true)

		require.Error(t, err)
		require.Contains(t, err.Error(), "read-only mode")
	})

	t.Run("getBalance with insufficient gas", func(t *testing.T) {
		input := append(getBalanceSelector, common.LeftPadBytes(testCaller.Bytes(), 32)...)
		_, _, err := contract.Run(state, testCaller, testAddr, input, 1000, false) // not enough gas

		require.Error(t, err)
		require.Equal(t, ErrOutOfGas, err)
	})
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkCalculateFunctionSelector(b *testing.B) {
	signatures := []string{
		"getBalance(address)",
		"setBalance(address,uint256)",
		"transfer(address,address,uint256)",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateFunctionSelector(signatures[i%len(signatures)])
	}
}

func BenchmarkDeductGas(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeductGas(100000, 5000)
	}
}

func BenchmarkContractRun(b *testing.B) {
	selector := CalculateFunctionSelector("getBalance(address)")
	execute := func(accessibleState AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		return []byte{0x01}, suppliedGas - 100, nil
	}

	fn := NewStatefulPrecompileFunction(selector, execute)
	contract, _ := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn})
	state := NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
	input := append(selector, common.LeftPadBytes(testCaller.Bytes(), 32)...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		contract.Run(state, testCaller, testAddr, input, 100000, false)
	}
}

func BenchmarkParseABI(b *testing.B) {
	rawABI := `[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]}]`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseABI(rawABI)
	}
}
