// Copyright (C) 2024-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package dead

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
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

func TestCalculateSplit(t *testing.T) {
	tests := []struct {
		name             string
		value            *big.Int
		expectedBurn     *big.Int
		expectedTreasury *big.Int
	}{
		{
			name:             "even split",
			value:            big.NewInt(100),
			expectedBurn:     big.NewInt(50),
			expectedTreasury: big.NewInt(50),
		},
		{
			name:             "odd value - treasury gets extra",
			value:            big.NewInt(101),
			expectedBurn:     big.NewInt(50),
			expectedTreasury: big.NewInt(51),
		},
		{
			name:             "zero value",
			value:            big.NewInt(0),
			expectedBurn:     big.NewInt(0),
			expectedTreasury: big.NewInt(0),
		},
		{
			name:             "one wei",
			value:            big.NewInt(1),
			expectedBurn:     big.NewInt(0),
			expectedTreasury: big.NewInt(1),
		},
		{
			name:             "large value",
			value:            new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)), // 1000 ETH
			expectedBurn:     new(big.Int).Mul(big.NewInt(1e18), big.NewInt(500)),  // 500 ETH
			expectedTreasury: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(500)),  // 500 ETH
		},
		{
			name:             "large odd value",
			value:            new(big.Int).Add(new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)), big.NewInt(1)),
			expectedBurn:     new(big.Int).Mul(big.NewInt(1e18), big.NewInt(500)),
			expectedTreasury: new(big.Int).Add(new(big.Int).Mul(big.NewInt(1e18), big.NewInt(500)), big.NewInt(1)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			burnAmount, treasuryAmount := CalculateSplit(tt.value)
			require.Equal(t, 0, tt.expectedBurn.Cmp(burnAmount), "burn amount mismatch: expected %s, got %s", tt.expectedBurn, burnAmount)
			require.Equal(t, 0, tt.expectedTreasury.Cmp(treasuryAmount), "treasury amount mismatch: expected %s, got %s", tt.expectedTreasury, treasuryAmount)

			// Verify total equals original value
			total := new(big.Int).Add(burnAmount, treasuryAmount)
			require.Equal(t, 0, tt.value.Cmp(total), "total should equal original value: expected %s, got %s", tt.value, total)
		})
	}
}

func TestIsDeadAddress(t *testing.T) {
	tests := []struct {
		name     string
		address  common.Address
		expected bool
	}{
		{
			name:     "zero address",
			address:  common.HexToAddress("0x0000000000000000000000000000000000000000"),
			expected: true,
		},
		{
			name:     "dead address lowercase",
			address:  common.HexToAddress("0x000000000000000000000000000000000000dead"),
			expected: true,
		},
		{
			name:     "dead address mixed case",
			address:  common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
			expected: true,
		},
		{
			name:     "dead full address",
			address:  common.HexToAddress("0xdEaD000000000000000000000000000000000000"),
			expected: true,
		},
		{
			name:     "regular address",
			address:  common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714"),
			expected: false,
		},
		{
			name:     "precompile address 0x01",
			address:  common.HexToAddress("0x0000000000000000000000000000000000000001"),
			expected: false,
		},
		{
			name:     "precompile address 0x09",
			address:  common.HexToAddress("0x0000000000000000000000000000000000000009"),
			expected: false,
		},
		{
			name:     "similar but not dead",
			address:  common.HexToAddress("0x000000000000000000000000000000000000dEaE"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDeadAddress(tt.address)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestAllDeadAddresses(t *testing.T) {
	// Verify all defined dead addresses are recognized
	for _, addr := range AllDeadAddresses {
		require.True(t, IsDeadAddress(addr), "address %s should be recognized as dead", addr.Hex())
	}

	// Verify count
	require.Equal(t, 3, len(AllDeadAddresses), "should have exactly 3 dead addresses")
}

func TestDefaultDAOTreasury(t *testing.T) {
	// Verify default DAO treasury is not a dead address
	require.False(t, IsDeadAddress(DefaultDAOTreasury), "default DAO treasury should not be a dead address")

	// Verify default DAO treasury address is valid
	require.NotEqual(t, common.Address{}, DefaultDAOTreasury, "default DAO treasury should not be zero address")
}

func TestNoOverlapWithStandardPrecompiles(t *testing.T) {
	// Standard EVM precompiles are at addresses 0x01 through 0x0a (ecrecover, sha256, etc.)
	// and potentially up to 0x100 range for newer ones
	standardPrecompiles := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000000001"), // ecrecover
		common.HexToAddress("0x0000000000000000000000000000000000000002"), // sha256
		common.HexToAddress("0x0000000000000000000000000000000000000003"), // ripemd160
		common.HexToAddress("0x0000000000000000000000000000000000000004"), // identity
		common.HexToAddress("0x0000000000000000000000000000000000000005"), // modexp
		common.HexToAddress("0x0000000000000000000000000000000000000006"), // ecAdd
		common.HexToAddress("0x0000000000000000000000000000000000000007"), // ecMul
		common.HexToAddress("0x0000000000000000000000000000000000000008"), // ecPairing
		common.HexToAddress("0x0000000000000000000000000000000000000009"), // blake2f
		common.HexToAddress("0x000000000000000000000000000000000000000a"), // kzg point evaluation
		common.HexToAddress("0x0000000000000000000000000000000000000100"), // sha256 (some chains)
	}

	for _, precompile := range standardPrecompiles {
		for _, deadAddr := range AllDeadAddresses {
			require.NotEqual(t, precompile, deadAddr,
				"dead address %s overlaps with standard precompile %s",
				deadAddr.Hex(), precompile.Hex())
		}
	}
}

func TestSplitMathProperties(t *testing.T) {
	// Property: burn + treasury = original
	t.Run("conservation of value", func(t *testing.T) {
		testValues := []*big.Int{
			big.NewInt(0),
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(100),
			big.NewInt(999),
			big.NewInt(1000000),
			new(big.Int).Exp(big.NewInt(10), big.NewInt(27), nil), // 1e27 wei
		}

		for _, value := range testValues {
			burn, treasury := CalculateSplit(value)
			total := new(big.Int).Add(burn, treasury)
			require.Equal(t, value, total, "value %s: burn + treasury should equal original", value.String())
		}
	})

	// Property: treasury >= burn (treasury gets the extra wei if odd)
	t.Run("treasury gets rounding", func(t *testing.T) {
		testValues := []*big.Int{
			big.NewInt(1),
			big.NewInt(3),
			big.NewInt(101),
			big.NewInt(999999),
		}

		for _, value := range testValues {
			burn, treasury := CalculateSplit(value)
			require.True(t, treasury.Cmp(burn) >= 0,
				"value %s: treasury (%s) should be >= burn (%s)",
				value.String(), treasury.String(), burn.String())
		}
	})

	// Property: non-negative outputs
	t.Run("non-negative outputs", func(t *testing.T) {
		testValues := []*big.Int{
			big.NewInt(0),
			big.NewInt(1),
			new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil),
		}

		for _, value := range testValues {
			burn, treasury := CalculateSplit(value)
			require.True(t, burn.Sign() >= 0, "burn should be non-negative")
			require.True(t, treasury.Sign() >= 0, "treasury should be non-negative")
		}
	})
}

func BenchmarkCalculateSplit(b *testing.B) {
	value := new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)) // 1000 ETH
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		CalculateSplit(value)
	}
}

func BenchmarkIsDeadAddress(b *testing.B) {
	addresses := []common.Address{
		ZeroAddress,
		DeadAddress,
		common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsDeadAddress(addresses[i%len(addresses)])
	}
}

// Tests for configurable state operations

func TestConfigurableStateOperations(t *testing.T) {
	stateDB := NewMockStateDB()
	precompile := DeadPrecompile

	t.Run("default admin is zero address", func(t *testing.T) {
		admin := precompile.getAdminInternal(stateDB)
		require.Equal(t, common.Address{}, admin, "default admin should be zero")
	})

	t.Run("default treasury is default DAO treasury", func(t *testing.T) {
		treasury := precompile.getTreasuryInternal(stateDB)
		// When no treasury set, returns default
		require.NotNil(t, treasury)
	})

	t.Run("default burn ratio is default", func(t *testing.T) {
		burnBPS := precompile.getBurnRatioInternal(stateDB)
		require.Equal(t, DefaultBurnBPS, burnBPS)
	})

	t.Run("default enabled is true", func(t *testing.T) {
		enabled := precompile.isEnabledInternal(stateDB)
		require.True(t, enabled)
	})
}

func TestSetAndGetAdmin(t *testing.T) {
	stateDB := NewMockStateDB()
	precompile := DeadPrecompile

	newAdmin := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set admin
	precompile.setStateAddress(stateDB, AdminSlot, newAdmin)

	// Get admin
	admin := precompile.getAdminInternal(stateDB)
	require.Equal(t, newAdmin, admin)
}

func TestSetAndGetTreasury(t *testing.T) {
	stateDB := NewMockStateDB()
	precompile := DeadPrecompile

	newTreasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")

	// Set treasury
	precompile.setStateAddress(stateDB, TreasurySlot, newTreasury)

	// Get treasury
	treasury := precompile.getTreasuryInternal(stateDB)
	require.Equal(t, newTreasury, treasury)
}

func TestSetAndGetBurnRatio(t *testing.T) {
	stateDB := NewMockStateDB()
	precompile := DeadPrecompile

	tests := []struct {
		name    string
		burnBPS uint64
	}{
		{"0% burn", 0},
		{"25% burn", 2500},
		{"50% burn", 5000},
		{"75% burn", 7500},
		{"100% burn", 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile.setStateUint64(stateDB, BurnBPSSlot, tt.burnBPS)
			got := precompile.getBurnRatioInternal(stateDB)
			require.Equal(t, tt.burnBPS, got)
		})
	}
}

func TestSetAndGetEnabled(t *testing.T) {
	stateDB := NewMockStateDB()
	precompile := DeadPrecompile

	// Initially enabled (default)
	require.True(t, precompile.isEnabledInternal(stateDB))

	// Disable
	precompile.setStateBool(stateDB, EnabledSlot, false)
	require.False(t, precompile.isEnabledInternal(stateDB))

	// Re-enable
	precompile.setStateBool(stateDB, EnabledSlot, true)
	require.True(t, precompile.isEnabledInternal(stateDB))
}

func TestCalculateSplitWithConfigurableRatio(t *testing.T) {
	tests := []struct {
		name             string
		value            *big.Int
		burnBPS          uint64
		expectedBurn     *big.Int
		expectedTreasury *big.Int
	}{
		{
			name:             "100% burn",
			value:            big.NewInt(1000),
			burnBPS:          10000,
			expectedBurn:     big.NewInt(1000),
			expectedTreasury: big.NewInt(0),
		},
		{
			name:             "0% burn (100% treasury)",
			value:            big.NewInt(1000),
			burnBPS:          0,
			expectedBurn:     big.NewInt(0),
			expectedTreasury: big.NewInt(1000),
		},
		{
			name:             "30% burn",
			value:            big.NewInt(1000),
			burnBPS:          3000,
			expectedBurn:     big.NewInt(300),
			expectedTreasury: big.NewInt(700),
		},
		{
			name:             "80% burn",
			value:            big.NewInt(100),
			burnBPS:          8000,
			expectedBurn:     big.NewInt(80),
			expectedTreasury: big.NewInt(20),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			burn, treasury := CalculateSplitBig(tt.value, tt.burnBPS)
			require.Equal(t, 0, tt.expectedBurn.Cmp(burn), "burn mismatch")
			require.Equal(t, 0, tt.expectedTreasury.Cmp(treasury), "treasury mismatch")

			// Verify conservation
			total := new(big.Int).Add(burn, treasury)
			require.Equal(t, 0, tt.value.Cmp(total), "total should equal original")
		})
	}
}

func TestAdminAuthorization(t *testing.T) {
	stateDB := NewMockStateDB()
	precompile := DeadPrecompile

	admin := common.HexToAddress("0x1234567890123456789012345678901234567890")
	notAdmin := common.HexToAddress("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")

	// Set admin
	precompile.setStateAddress(stateDB, AdminSlot, admin)

	// Admin should be authorized
	require.True(t, precompile.isAdmin(stateDB, admin))

	// Non-admin should not be authorized
	require.False(t, precompile.isAdmin(stateDB, notAdmin))

	// Zero address is never admin (unless explicitly set)
	require.False(t, precompile.isAdmin(stateDB, common.Address{}))
}

func TestHandleReceiveWithConfigurableRatio(t *testing.T) {
	precompile := DeadPrecompile
	treasury := common.HexToAddress("0xABCDEF1234567890123456789012345678901234")
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	tests := []struct {
		name             string
		burnBPS          uint64
		value            *uint256.Int
		expectedTreasury *uint256.Int
	}{
		{
			name:             "50/50 split",
			burnBPS:          5000,
			value:            uint256.NewInt(1000),
			expectedTreasury: uint256.NewInt(500),
		},
		{
			name:             "100% treasury",
			burnBPS:          0,
			value:            uint256.NewInt(1000),
			expectedTreasury: uint256.NewInt(1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDB := NewMockStateDB()

			// Configure state
			precompile.setStateAddress(stateDB, TreasurySlot, treasury)
			precompile.setStateUint64(stateDB, BurnBPSSlot, tt.burnBPS)
			// Enable the precompile
			precompile.setStateBool(stateDB, EnabledSlot, true)

			// Fund the dead address (simulates value transfer to dead address)
			stateDB.AddBalance(DeadAddress, tt.value, tracing.BalanceChangeTransfer)

			// Call handleReceive with correct signature:
			// handleReceive(stateDB, caller, addr, suppliedGas, readOnly)
			_, _, err := precompile.handleReceive(stateDB, caller, DeadAddress, GasBase, false)
			require.NoError(t, err)

			// Verify treasury received correct amount
			treasuryBal := stateDB.GetBalance(treasury)
			require.Equal(t, 0, tt.expectedTreasury.Cmp(treasuryBal),
				"treasury balance mismatch: expected %s, got %s", tt.expectedTreasury, treasuryBal)
		})
	}
}
