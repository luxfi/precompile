// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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
	if m.state[addr] == nil {
		return common.Hash{}
	}
	return m.state[addr][key]
}

func (m *testStateDB) SetState(addr common.Address, key, val common.Hash) common.Hash {
	if m.state[addr] == nil {
		m.state[addr] = make(map[common.Hash]common.Hash)
	}
	old := m.state[addr][key]
	m.state[addr][key] = val
	return old
}

func (m *testStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (m *testStateDB) GetNonce(common.Address) uint64                             { return 0 }
func (m *testStateDB) GetBalance(common.Address) *uint256.Int                     { return new(uint256.Int) }
func (m *testStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *testStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *testStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int    { return big.NewInt(0) }
func (m *testStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (m *testStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (m *testStateDB) CreateAccount(common.Address)                                {}
func (m *testStateDB) Exist(common.Address) bool                                   { return false }
func (m *testStateDB) AddLog(*ethtypes.Log)                                        {}
func (m *testStateDB) Logs() []*ethtypes.Log                                       { return nil }
func (m *testStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) { return nil, false }
func (m *testStateDB) TxHash() common.Hash                                         { return common.Hash{} }
func (m *testStateDB) Snapshot() int                                               { return 0 }
func (m *testStateDB) RevertToSnapshot(int)                                        {}

var _ contract.StateDB = (*testStateDB)(nil)

type testBlockCtx struct{}

func (t *testBlockCtx) Number() *big.Int                                       { return big.NewInt(1) }
func (t *testBlockCtx) Timestamp() uint64                                      { return 1000 }
func (t *testBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

var _ contract.BlockContext = (*testBlockCtx)(nil)

type testChainCfg struct{}

func (t *testChainCfg) IsDurango(uint64) bool { return true }

var _ precompileconfig.ChainConfig = (*testChainCfg)(nil)

type testPrecompileEnv struct{}

func (t *testPrecompileEnv) ReadOnly() bool { return false }

var _ contract.PrecompileEnvironment = (*testPrecompileEnv)(nil)

type testAccessibleState struct {
	db *testStateDB
}

func (t *testAccessibleState) GetStateDB() contract.StateDB                 { return t.db }
func (t *testAccessibleState) GetBlockContext() contract.BlockContext       { return &testBlockCtx{} }
func (t *testAccessibleState) GetConsensusContext() context.Context         { return context.Background() }
func (t *testAccessibleState) GetChainConfig() precompileconfig.ChainConfig { return &testChainCfg{} }
func (t *testAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return &testPrecompileEnv{}
}

var _ contract.AccessibleState = (*testAccessibleState)(nil)

func newTestAS() *testAccessibleState {
	return &testAccessibleState{db: newTestStateDB()}
}

// --- Config tests ---

type fakeConfig struct{}

func (f *fakeConfig) Key() string                               { return "fake" }
func (f *fakeConfig) Timestamp() *uint64                        { return nil }
func (f *fakeConfig) IsDisabled() bool                          { return false }
func (f *fakeConfig) Equal(precompileconfig.Config) bool        { return false }
func (f *fakeConfig) Verify(precompileconfig.ChainConfig) error { return nil }

func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&testChainCfg{}))

	// Equal same
	require.True(t, cfg.Equal(&Config{}))
	// Equal different type
	require.False(t, cfg.Equal(&fakeConfig{}))
	// Disabled
	cfg3 := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, cfg3.IsDisabled())
	require.False(t, cfg.Equal(cfg3))
	// Timestamp
	ts := uint64(100)
	cfg4 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg4.Timestamp())
}

func TestConfigurator(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, c.Configure(&testChainCfg{}, cfg, newTestStateDB(), &testBlockCtx{}))
}

// --- RequiredGas ---

func TestRequiredGas(t *testing.T) {
	c := &AIMiningContract{}
	for _, tt := range []struct {
		sel uint32
		gas uint64
	}{
		{SelectorVerifyMLDSA, GasVerifyMLDSA},
		{SelectorCalculateReward, GasCalculateReward},
		{SelectorVerifyTEE, GasVerifyTEE},
		{SelectorIsSpent, GasIsSpent},
		{SelectorMarkSpent, GasMarkSpent},
		{SelectorComputeWorkId, GasComputeWorkId},
		{0xDEADBEEF, GasCalculateReward},
	} {
		input := make([]byte, 4)
		binary.BigEndian.PutUint32(input, tt.sel)
		require.Equal(t, tt.gas, c.RequiredGas(input))
	}
	require.Equal(t, GasCalculateReward, c.RequiredGas([]byte{1}))
}

// --- Run dispatcher ---

func TestRunTooShort(t *testing.T) {
	c := &AIMiningContract{}
	_, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, []byte{1}, 100000, false)
	require.Error(t, err)
}

func TestRunUnknownSelector(t *testing.T) {
	c := &AIMiningContract{}
	input := make([]byte, 4)
	binary.BigEndian.PutUint32(input, 0xDEADBEEF)
	_, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.Error(t, err)
}

func TestRunComputeWorkId(t *testing.T) {
	c := &AIMiningContract{}
	input := make([]byte, 4+72)
	binary.BigEndian.PutUint32(input[:4], SelectorComputeWorkId)
	copy(input[4:36], []byte{1, 2, 3})
	copy(input[36:68], []byte{4, 5, 6})
	binary.BigEndian.PutUint64(input[68:76], 96369)

	ret, gas, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.Len(t, ret, 32)
	require.Less(t, gas, uint64(100000))

	// Out of gas
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, input, 10, false)
	require.Error(t, err)

	// Short data
	short := make([]byte, 4+10)
	binary.BigEndian.PutUint32(short[:4], SelectorComputeWorkId)
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, short, 100000, false)
	require.Error(t, err)
}

func TestRunIsSpentAndMarkSpent(t *testing.T) {
	c := &AIMiningContract{}
	state := newTestAS()
	workId := [32]byte{0xAB}

	// IsSpent
	isInput := make([]byte, 4+32)
	binary.BigEndian.PutUint32(isInput[:4], SelectorIsSpent)
	copy(isInput[4:], workId[:])
	ret, _, err := c.Run(state, common.Address{}, ContractAddress, isInput, 100000, false)
	require.NoError(t, err)
	require.Equal(t, byte(0), ret[31])

	// MarkSpent
	mkInput := make([]byte, 4+32)
	binary.BigEndian.PutUint32(mkInput[:4], SelectorMarkSpent)
	copy(mkInput[4:], workId[:])
	ret, _, err = c.Run(state, common.Address{}, ContractAddress, mkInput, 100000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])

	// IsSpent again
	ret, _, err = c.Run(state, common.Address{}, ContractAddress, isInput, 100000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])

	// Double mark
	_, _, err = c.Run(state, common.Address{}, ContractAddress, mkInput, 100000, false)
	require.Error(t, err)

	// Read-only mark
	_, _, err = c.Run(state, common.Address{}, ContractAddress, mkInput, 100000, true)
	require.Error(t, err)

	// Gas edge cases
	_, _, err = c.Run(state, common.Address{}, ContractAddress, mkInput, 100, false)
	require.Error(t, err)
	_, _, err = c.Run(state, common.Address{}, ContractAddress, isInput, 10, false)
	require.Error(t, err)

	// Short data
	shortIs := make([]byte, 4+10)
	binary.BigEndian.PutUint32(shortIs[:4], SelectorIsSpent)
	_, _, err = c.Run(state, common.Address{}, ContractAddress, shortIs, 100000, false)
	require.Error(t, err)

	shortMk := make([]byte, 4+10)
	binary.BigEndian.PutUint32(shortMk[:4], SelectorMarkSpent)
	_, _, err = c.Run(state, common.Address{}, ContractAddress, shortMk, 100000, false)
	require.Error(t, err)
}

func TestRunCalculateReward(t *testing.T) {
	c := &AIMiningContract{}
	wp := BuildWorkProof([32]byte{1}, [32]byte{2}, 1700000000, PrivacyConfidential, 60, nil)
	data := make([]byte, len(wp)+8)
	copy(data, wp)
	binary.BigEndian.PutUint64(data[len(wp):], 96369)

	input := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(input[:4], SelectorCalculateReward)
	copy(input[4:], data)

	ret, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.Len(t, ret, 32)

	// OOG
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100, false)
	require.Error(t, err)

	// Short
	short := make([]byte, 4+10)
	binary.BigEndian.PutUint32(short[:4], SelectorCalculateReward)
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, short, 100000, false)
	require.Error(t, err)
}

func TestRunVerifyTEE(t *testing.T) {
	c := &AIMiningContract{}
	receipt := make([]byte, 48)
	binary.BigEndian.PutUint64(receipt[32:40], 1700000000)
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 1)
	}

	data := make([]byte, 4+len(receipt)+4+len(sig))
	binary.BigEndian.PutUint32(data[:4], uint32(len(receipt)))
	copy(data[4:], receipt)
	binary.BigEndian.PutUint32(data[4+len(receipt):], uint32(len(sig)))
	copy(data[4+len(receipt)+4:], sig)

	input := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(input[:4], SelectorVerifyTEE)
	copy(input[4:], data)

	ret, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])

	// OOG
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100, false)
	require.Error(t, err)

	// Short
	short := make([]byte, 4+4)
	binary.BigEndian.PutUint32(short[:4], SelectorVerifyTEE)
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, short, 100000, false)
	require.Error(t, err)
}

func TestRunVerifyMLDSAShortAndOOG(t *testing.T) {
	c := &AIMiningContract{}
	short := make([]byte, 4+10)
	binary.BigEndian.PutUint32(short[:4], SelectorVerifyMLDSA)
	_, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, short, 100000, false)
	require.Error(t, err)

	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, short, 100, false)
	require.Error(t, err)
}

// encodeMLDSAInput builds the length-prefixed input: [pkLen(4)][pk][msgLen(4)][msg][sigLen(4)][sig]
func encodeMLDSAInput(pk, msg, sig []byte) []byte {
	buf := make([]byte, 4+len(pk)+4+len(msg)+4+len(sig))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(pk)))
	copy(buf[4:], pk)
	off := 4 + len(pk)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(msg)))
	copy(buf[off+4:], msg)
	off += 4 + len(msg)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(sig)))
	copy(buf[off+4:], sig)
	return buf
}

func TestRunVerifyMLDSARealSig(t *testing.T) {
	c := &AIMiningContract{}

	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubBytes, err := pub.MarshalBinary()
	require.NoError(t, err)
	msg := []byte("run verify test")
	sig := make([]byte, MLDSA44SignatureSize)
	require.NoError(t, mldsa44.SignTo(priv, msg, nil, true, sig))

	data := encodeMLDSAInput(pubBytes, msg, sig)
	input := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(input[:4], SelectorVerifyMLDSA)
	copy(input[4:], data)

	ret, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])

	// Invalid pubkey length overflow
	badPK := make([]byte, 4+10)
	binary.BigEndian.PutUint32(badPK[:4], 0xFFFFFFFF) // huge length
	fullBad := make([]byte, 4+len(badPK))
	binary.BigEndian.PutUint32(fullBad[:4], SelectorVerifyMLDSA)
	copy(fullBad[4:], badPK)
	// But input is short, so "input too short" first -- need 96+ bytes
	// Pad to 96 to get past first check, then hit pubkey length check
	padded := make([]byte, 4+100)
	binary.BigEndian.PutUint32(padded[:4], SelectorVerifyMLDSA)
	binary.BigEndian.PutUint32(padded[4:8], 0xFFFF) // pubkeyLen = huge
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, padded, 100000, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid pubkey length")

	// Invalid message length
	fakeData := make([]byte, 200)
	binary.BigEndian.PutUint32(fakeData[:4], 10) // pkLen=10
	// pk at 4:14, then msgLen at 14:18
	binary.BigEndian.PutUint32(fakeData[14:18], 0xFFFF) // msgLen = huge
	fullFake := make([]byte, 4+len(fakeData))
	binary.BigEndian.PutUint32(fullFake[:4], SelectorVerifyMLDSA)
	copy(fullFake[4:], fakeData)
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, fullFake, 100000, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid message length")

	// Invalid signature length
	fakeData2 := make([]byte, 200)
	binary.BigEndian.PutUint32(fakeData2[:4], 10)        // pkLen=10
	binary.BigEndian.PutUint32(fakeData2[14:18], 10)     // msgLen=10
	binary.BigEndian.PutUint32(fakeData2[28:32], 0xFFFF) // sigLen = huge
	fullFake2 := make([]byte, 4+len(fakeData2))
	binary.BigEndian.PutUint32(fullFake2[:4], SelectorVerifyMLDSA)
	copy(fullFake2[4:], fakeData2)
	_, _, err = c.Run(newTestAS(), common.Address{}, ContractAddress, fullFake2, 100000, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature length")
}

// --- ML-DSA 44 and 87 ---

func TestVerifyMLDSA44(t *testing.T) {
	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubBytes, err := pub.MarshalBinary()
	require.NoError(t, err)
	msg := []byte("mldsa44")
	sig := make([]byte, MLDSA44SignatureSize)
	require.NoError(t, mldsa44.SignTo(priv, msg, nil, true, sig))

	valid, err := VerifyMLDSA(pubBytes, msg, sig)
	require.NoError(t, err)
	require.True(t, valid)

	// Wrong sig size
	_, err = VerifyMLDSA(pubBytes, msg, sig[:100])
	require.ErrorIs(t, err, ErrInvalidSignatureSize)
}

func TestVerifyMLDSA87(t *testing.T) {
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubBytes, err := pub.MarshalBinary()
	require.NoError(t, err)
	msg := []byte("mldsa87")
	sig := make([]byte, MLDSA87SignatureSize)
	require.NoError(t, mldsa87.SignTo(priv, msg, nil, true, sig))

	valid, err := VerifyMLDSA(pubBytes, msg, sig)
	require.NoError(t, err)
	require.True(t, valid)

	_, err = VerifyMLDSA(pubBytes, msg, sig[:100])
	require.ErrorIs(t, err, ErrInvalidSignatureSize)
}

// --- TEE edge cases ---

func TestVerifyTEEEdgeCases(t *testing.T) {
	receipt := make([]byte, 48)
	_, err := VerifyTEE(receipt, []byte{})
	require.ErrorIs(t, err, ErrTEESignatureInvalid)

	_, err = VerifyTEE(receipt, make([]byte, 32))
	require.ErrorIs(t, err, ErrTEESignatureInvalid)
}

// --- GPU ---

func TestGPUFunctions(t *testing.T) {
	_ = GPUAvailable()
	_ = GPUBackend()
	require.Equal(t, 8, GPUThreshold())
}

func TestGPUStats(t *testing.T) {
	ResetGPUStats()
	s := GPUStats()
	require.Zero(t, s.TotalVerifications)
}

// --- BatchAccumulator ---

func TestBatchAccumulator(t *testing.T) {
	ba := NewBatchAccumulator(2)
	require.Equal(t, 0, ba.Size())
	ba.Flush() // empty flush

	results := make([]bool, 0)
	cb := func(v bool, _ error) { results = append(results, v) }

	pk := make([]byte, MLDSA65PublicKeySize)
	msg := []byte("test")
	sig := make([]byte, MLDSA65SignatureSize)

	for range 7 {
		require.False(t, ba.Add(pk, msg, sig, cb))
	}
	require.Equal(t, 7, ba.Size())
	require.True(t, ba.Add(pk, msg, sig, cb)) // flush at 8
	require.Equal(t, 0, ba.Size())
	require.Len(t, results, 8)

	ba.Add(pk, msg, sig, cb)
	ba.Flush()
	require.Equal(t, 0, ba.Size())
}

// --- Batch ---

func TestBatchVerifyMLDSA(t *testing.T) {
	r, err := BatchVerifyMLDSA([][]byte{make([]byte, MLDSA65PublicKeySize)}, [][]byte{[]byte("m")}, [][]byte{make([]byte, MLDSA65SignatureSize)})
	require.NoError(t, err)
	require.False(t, r[0])
}

func TestBatchVerifyTEE(t *testing.T) {
	r, s, err := BatchVerifyTEE([][]byte{make([]byte, 48), make([]byte, 10)})
	require.NoError(t, err)
	require.Len(t, r, 2)
	require.Equal(t, uint8(0), s[1])
}

func TestBatchCalculateReward(t *testing.T) {
	wp := BuildWorkProof([32]byte{}, [32]byte{}, 0, PrivacyPublic, 1, nil)
	r, err := BatchCalculateReward([][]byte{wp, []byte("bad")}, 1)
	require.NoError(t, err)
	require.True(t, r[0].Sign() > 0)
	require.Zero(t, r[1].Sign())

	r, err = BatchCalculateReward(nil, 1)
	require.NoError(t, err)
	require.Nil(t, r)
}

// --- ParseWorkProof no TEE ---

func TestParseWorkProofNoTEE(t *testing.T) {
	p := BuildWorkProof([32]byte{0xAA}, [32]byte{0xBB}, 999, PrivacySovereign, 42, nil)
	_, _, ts, priv, cm, tee, err := ParseWorkProof(p)
	require.NoError(t, err)
	require.Equal(t, uint64(999), ts)
	require.Equal(t, PrivacySovereign, priv)
	require.Equal(t, uint32(42), cm)
	require.Nil(t, tee)

	_, _, _, _, _, _, err = ParseWorkProof([]byte{1})
	require.ErrorIs(t, err, ErrInvalidWorkProof)
}

// --- Module ---

func TestModuleRegistered(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
}
