// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package compute

import (
	"context"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

var (
	caller1 = common.HexToAddress("0x1111111111111111111111111111111111111111")
	caller2 = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

func TestAddress(t *testing.T) {
	expected := "0x0300000000000000000000000000000000000010"
	require.Equal(t, expected, ContractAddress.Hex())
}

func TestRegisterProvider(t *testing.T) {
	state := newMockState()
	gpuType := common.BytesToHash([]byte("A100-80GB"))
	teeAttest := common.BytesToHash([]byte("attestation-data"))

	input := make([]byte, 1+64)
	input[0] = OpRegisterProvider
	copy(input[1:33], gpuType.Bytes())
	copy(input[33:65], teeAttest.Bytes())

	result, gas, err := Precompile.Run(state, caller1, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.True(t, gas < 100000)
	require.Len(t, result, 32)

	// Provider ID should be keccak256(caller, nonce=0)
	expectedID := common.BytesToHash(crypto.Keccak256(caller1.Bytes(), common.Hash{}.Bytes()))
	require.Equal(t, expectedID.Bytes(), result)

	// Verify stored GPU type
	stored := state.stateDB.GetState(ContractAddress, storageSlot("provider", expectedID.Bytes()))
	require.Equal(t, gpuType, stored)
}

func TestSubmitJob(t *testing.T) {
	state := newMockState()
	modelHash := common.BytesToHash([]byte("model-sha256"))
	inputHash := common.BytesToHash([]byte("input-sha256"))
	maxPrice := common.BytesToHash(padTo32(big.NewInt(1e15).Bytes()))

	input := make([]byte, 1+96)
	input[0] = OpSubmitJob
	copy(input[1:33], modelHash.Bytes())
	copy(input[33:65], inputHash.Bytes())
	copy(input[65:97], maxPrice.Bytes())

	result, gas, err := Precompile.Run(state, caller2, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.True(t, gas < 100000)
	require.Len(t, result, 32)

	// Verify job stored
	jobID := common.BytesToHash(result)
	storedModel := state.stateDB.GetState(ContractAddress, storageSlot("job", jobID.Bytes()))
	require.Equal(t, modelHash, storedModel)
}

func TestClaimReward(t *testing.T) {
	state := newMockState()

	// First register a provider
	regInput := make([]byte, 1+64)
	regInput[0] = OpRegisterProvider
	copy(regInput[1:33], common.BytesToHash([]byte("GPU")).Bytes())
	copy(regInput[33:65], common.BytesToHash([]byte("TEE")).Bytes())
	_, _, err := Precompile.Run(state, caller1, ContractAddress, regInput, 100000, false)
	require.NoError(t, err)

	// Submit a job
	jobInput := make([]byte, 1+96)
	jobInput[0] = OpSubmitJob
	copy(jobInput[1:33], common.BytesToHash([]byte("model")).Bytes())
	copy(jobInput[33:65], common.BytesToHash([]byte("input")).Bytes())
	copy(jobInput[65:97], padTo32(big.NewInt(1000).Bytes()))
	jobResult, _, err := Precompile.Run(state, caller2, ContractAddress, jobInput, 100000, false)
	require.NoError(t, err)

	jobID := common.BytesToHash(jobResult)
	outputHash := common.BytesToHash([]byte("output-result"))

	// Claim as provider
	claimInput := make([]byte, 1+64)
	claimInput[0] = OpClaimReward
	copy(claimInput[1:33], jobID.Bytes())
	copy(claimInput[33:65], outputHash.Bytes())

	result, _, err := Precompile.Run(state, caller1, ContractAddress, claimInput, 100000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "claim should succeed")

	// Verify status is claimed
	status := state.stateDB.GetState(ContractAddress, storageSlot("job.status", jobID.Bytes()))
	require.Equal(t, byte(StatusClaimed), status[31])
}

func TestClaimReward_AlreadyClaimed(t *testing.T) {
	state := newMockState()

	// Register + submit + claim
	regInput := make([]byte, 1+64)
	regInput[0] = OpRegisterProvider
	copy(regInput[1:33], padTo32([]byte("GPU")))
	copy(regInput[33:65], padTo32([]byte("TEE")))
	_, _, _ = Precompile.Run(state, caller1, ContractAddress, regInput, 100000, false)

	jobInput := make([]byte, 1+96)
	jobInput[0] = OpSubmitJob
	copy(jobInput[1:33], padTo32([]byte("model")))
	copy(jobInput[33:65], padTo32([]byte("input")))
	copy(jobInput[65:97], padTo32(big.NewInt(1000).Bytes()))
	jobResult, _, _ := Precompile.Run(state, caller2, ContractAddress, jobInput, 100000, false)

	jobID := common.BytesToHash(jobResult)
	claimInput := make([]byte, 1+64)
	claimInput[0] = OpClaimReward
	copy(claimInput[1:33], jobID.Bytes())
	copy(claimInput[33:65], padTo32([]byte("output")))
	_, _, _ = Precompile.Run(state, caller1, ContractAddress, claimInput, 100000, false)

	// Try to claim again
	_, _, err := Precompile.Run(state, caller1, ContractAddress, claimInput, 100000, false)
	require.ErrorIs(t, err, ErrJobAlreadyClaimed)
}

func TestVerifyCompute(t *testing.T) {
	state := newMockState()

	// Register + submit + claim
	regInput := make([]byte, 1+64)
	regInput[0] = OpRegisterProvider
	copy(regInput[1:33], padTo32([]byte("GPU")))
	copy(regInput[33:65], padTo32([]byte("TEE")))
	_, _, _ = Precompile.Run(state, caller1, ContractAddress, regInput, 100000, false)

	jobInput := make([]byte, 1+96)
	jobInput[0] = OpSubmitJob
	copy(jobInput[1:33], padTo32([]byte("model")))
	copy(jobInput[33:65], padTo32([]byte("input")))
	copy(jobInput[65:97], padTo32(big.NewInt(1000).Bytes()))
	jobResult, _, _ := Precompile.Run(state, caller2, ContractAddress, jobInput, 100000, false)

	jobID := common.BytesToHash(jobResult)
	outputHash := common.BytesToHash(padTo32([]byte("output")))

	claimInput := make([]byte, 1+64)
	claimInput[0] = OpClaimReward
	copy(claimInput[1:33], jobID.Bytes())
	copy(claimInput[33:65], outputHash.Bytes())
	_, _, _ = Precompile.Run(state, caller1, ContractAddress, claimInput, 100000, false)

	// Compute correct attestation: keccak256(jobID, outputHash)
	attestation := common.BytesToHash(crypto.Keccak256(jobID.Bytes(), outputHash.Bytes()))

	verifyInput := make([]byte, 1+64)
	verifyInput[0] = OpVerifyCompute
	copy(verifyInput[1:33], jobID.Bytes())
	copy(verifyInput[33:65], attestation.Bytes())

	result, _, err := Precompile.Run(state, caller1, ContractAddress, verifyInput, 200000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "verify should succeed")

	// Status should be verified
	status := state.stateDB.GetState(ContractAddress, storageSlot("job.status", jobID.Bytes()))
	require.Equal(t, byte(StatusVerified), status[31])
}

func TestVerifyCompute_BadAttestation(t *testing.T) {
	state := newMockState()

	// Register + submit + claim
	regInput := make([]byte, 1+64)
	regInput[0] = OpRegisterProvider
	copy(regInput[1:33], padTo32([]byte("GPU")))
	copy(regInput[33:65], padTo32([]byte("TEE")))
	_, _, _ = Precompile.Run(state, caller1, ContractAddress, regInput, 100000, false)

	jobInput := make([]byte, 1+96)
	jobInput[0] = OpSubmitJob
	copy(jobInput[1:33], padTo32([]byte("model")))
	copy(jobInput[33:65], padTo32([]byte("input")))
	copy(jobInput[65:97], padTo32(big.NewInt(1000).Bytes()))
	jobResult, _, _ := Precompile.Run(state, caller2, ContractAddress, jobInput, 100000, false)

	jobID := common.BytesToHash(jobResult)
	claimInput := make([]byte, 1+64)
	claimInput[0] = OpClaimReward
	copy(claimInput[1:33], jobID.Bytes())
	copy(claimInput[33:65], padTo32([]byte("output")))
	_, _, _ = Precompile.Run(state, caller1, ContractAddress, claimInput, 100000, false)

	// Bad attestation
	verifyInput := make([]byte, 1+64)
	verifyInput[0] = OpVerifyCompute
	copy(verifyInput[1:33], jobID.Bytes())
	copy(verifyInput[33:65], padTo32([]byte("wrong-attestation")))

	result, _, err := Precompile.Run(state, caller1, ContractAddress, verifyInput, 200000, false)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "verify should fail with bad attestation")
}

func TestGetPrice(t *testing.T) {
	input := make([]byte, 1+64)
	input[0] = OpGetPrice
	copy(input[1:33], padTo32([]byte("model")))
	copy(input[33:65], padTo32(big.NewInt(1024).Bytes()))

	result, _, err := Precompile.Run(newMockState(), caller1, ContractAddress, input, 100000, false)
	require.NoError(t, err)

	price := new(big.Int).SetBytes(result)
	// 1024 * 1000 = 1024000
	require.Equal(t, big.NewInt(1024000), price)
}

func TestReadOnlyState(t *testing.T) {
	state := newMockState()

	// RegisterProvider should fail in readOnly mode
	input := make([]byte, 1+64)
	input[0] = OpRegisterProvider
	_, _, err := Precompile.Run(state, caller1, ContractAddress, input, 100000, true)
	require.ErrorIs(t, err, ErrReadOnlyState)

	// SubmitJob should fail in readOnly mode
	input2 := make([]byte, 1+96)
	input2[0] = OpSubmitJob
	_, _, err = Precompile.Run(state, caller1, ContractAddress, input2, 100000, true)
	require.ErrorIs(t, err, ErrReadOnlyState)
}

func TestInvalidInput(t *testing.T) {
	state := newMockState()
	_, _, err := Precompile.Run(state, caller1, ContractAddress, nil, 100000, false)
	require.ErrorIs(t, err, ErrInvalidInput)

	_, _, err = Precompile.Run(state, caller1, ContractAddress, []byte{0xFF}, 100000, false)
	require.ErrorIs(t, err, ErrUnknownOp)
}

// --- Mock infrastructure ---

type mockStateDB struct {
	storage map[common.Address]map[common.Hash]common.Hash
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{storage: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if m.storage[addr] == nil {
		return common.Hash{}
	}
	return m.storage[addr][key]
}

func (m *mockStateDB) SetState(addr common.Address, key, value common.Hash) common.Hash {
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	prev := m.storage[addr][key]
	m.storage[addr][key] = value
	return prev
}

func (m *mockStateDB) GetBalance(common.Address) *uint256.Int { return uint256.NewInt(0) }
func (m *mockStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *mockStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *mockStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int    { return big.NewInt(0) }
func (m *mockStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (m *mockStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (m *mockStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason)  {}
func (m *mockStateDB) GetNonce(common.Address) uint64                              { return 0 }
func (m *mockStateDB) CreateAccount(common.Address)                                {}
func (m *mockStateDB) Exist(common.Address) bool                                   { return true }
func (m *mockStateDB) AddLog(*ethtypes.Log)                                        {}
func (m *mockStateDB) Logs() []*ethtypes.Log                                       { return nil }
func (m *mockStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) { return nil, false }
func (m *mockStateDB) TxHash() common.Hash                                         { return common.Hash{} }
func (m *mockStateDB) Snapshot() int                                               { return 0 }
func (m *mockStateDB) RevertToSnapshot(int)                                        {}

type mockBlockContext struct{}

func (m *mockBlockContext) Number() *big.Int                                       { return big.NewInt(1) }
func (m *mockBlockContext) Timestamp() uint64                                      { return 0 }
func (m *mockBlockContext) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

type mockChainConfig struct{}

func (m *mockChainConfig) IsDurango(uint64) bool { return true }

type mockPrecompileEnv struct{}

func (m *mockPrecompileEnv) ReadOnly() bool { return false }

type mockAccessibleState struct {
	stateDB *mockStateDB
}

func newMockState() *mockAccessibleState {
	return &mockAccessibleState{stateDB: newMockStateDB()}
}

func (m *mockAccessibleState) GetStateDB() contract.StateDB           { return m.stateDB }
func (m *mockAccessibleState) GetBlockContext() contract.BlockContext { return &mockBlockContext{} }
func (m *mockAccessibleState) GetConsensusContext() context.Context   { return context.Background() }
func (m *mockAccessibleState) GetChainConfig() precompileconfig.ChainConfig {
	return &mockChainConfig{}
}
func (m *mockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return &mockPrecompileEnv{}
}
