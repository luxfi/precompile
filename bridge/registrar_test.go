// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// --- test scaffolding for the AccessibleState surface ------------------------

type regStateDB struct {
	store map[common.Address]map[common.Hash]common.Hash
}

func newRegState() *regStateDB {
	return &regStateDB{store: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *regStateDB) GetState(a common.Address, k common.Hash) common.Hash {
	s := m.store[a]
	if s == nil {
		return common.Hash{}
	}
	return s[k]
}

func (m *regStateDB) SetState(a common.Address, k, v common.Hash) common.Hash {
	s := m.store[a]
	if s == nil {
		s = make(map[common.Hash]common.Hash)
		m.store[a] = s
	}
	prev := s[k]
	s[k] = v
	return prev
}

func (*regStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (*regStateDB) GetNonce(common.Address) uint64                              { return 0 }
func (*regStateDB) GetBalance(common.Address) *uint256.Int                      { return new(uint256.Int) }
func (*regStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (*regStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (*regStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int { return big.NewInt(0) }
func (*regStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (*regStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (*regStateDB) CreateAccount(common.Address)                              {}
func (*regStateDB) Exist(common.Address) bool                                 { return false }
func (*regStateDB) AddLog(*ethtypes.Log)                                      {}
func (*regStateDB) Logs() []*ethtypes.Log                                     { return nil }
func (*regStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}
func (*regStateDB) TxHash() common.Hash  { return common.Hash{} }
func (*regStateDB) Snapshot() int        { return 0 }
func (*regStateDB) RevertToSnapshot(int) {}

var _ contract.StateDB = (*regStateDB)(nil)

type regBlockCtx struct{}

func (*regBlockCtx) Number() *big.Int                                           { return big.NewInt(1) }
func (*regBlockCtx) Timestamp() uint64                                          { return 1700000000 }
func (*regBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte     { return nil }

type regChainCfg struct{}

func (*regChainCfg) IsDurango(uint64) bool { return true }

type regEnv struct{}

func (*regEnv) ReadOnly() bool { return false }

type regAS struct{ db *regStateDB }

func (a *regAS) GetStateDB() contract.StateDB                  { return a.db }
func (a *regAS) GetBlockContext() contract.BlockContext        { return &regBlockCtx{} }
func (a *regAS) GetConsensusContext() context.Context          { return context.Background() }
func (a *regAS) GetChainConfig() precompileconfig.ChainConfig  { return &regChainCfg{} }
func (a *regAS) GetPrecompileEnv() contract.PrecompileEnvironment { return &regEnv{} }

func newRegAS() *regAS { return &regAS{db: newRegState()} }

// --- operator generation -----------------------------------------------------

type operator struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

func newOperator(t *testing.T) *operator {
	t.Helper()
	k, err := crypto.GenerateKey()
	require.NoError(t, err)
	// Derive the Ethereum-style address from the public key. The crypto pkg's
	// PubkeyToAddress returns its own Address type, so we go through bytes.
	pubBytes := crypto.FromECDSAPub(&k.PublicKey)
	addr := common.BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
	return &operator{key: k, addr: addr}
}

func operatorAddrs(ops []*operator) []common.Address {
	out := make([]common.Address, len(ops))
	for i, op := range ops {
		out[i] = op.addr
	}
	return out
}

func signByAll(t *testing.T, ops []*operator, sel byte, payload []byte) [][]byte {
	t.Helper()
	digest := registrarDigest(sel, payload)
	sigs := make([][]byte, len(ops))
	for i, op := range ops {
		sig, err := crypto.Sign(digest, op.key)
		require.NoError(t, err)
		sigs[i] = sig
	}
	return sigs
}

// --- payload helpers ---------------------------------------------------------

func buildRegisterPayload(id ChainID, name string, evm bool, gw common.Address) []byte {
	out := make([]byte, 0, 4+1+len(name)+1+20)
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], uint32(id))
	out = append(out, idBuf[:]...)
	out = append(out, byte(len(name)))
	out = append(out, []byte(name)...)
	if evm {
		out = append(out, 0x01)
	} else {
		out = append(out, 0x00)
	}
	out = append(out, gw.Bytes()...)
	return out
}

func buildUnregisterPayload(id ChainID) []byte {
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], uint32(id))
	return idBuf[:]
}

func buildSetGatewayPayload(id ChainID, gw common.Address) []byte {
	out := make([]byte, 0, 4+20)
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], uint32(id))
	out = append(out, idBuf[:]...)
	out = append(out, gw.Bytes()...)
	return out
}

func appendSigs(payload []byte, sigs [][]byte) []byte {
	out := make([]byte, 0, len(payload)+1+len(sigs)*argSigLen)
	out = append(out, payload...)
	out = append(out, byte(len(sigs)))
	for _, s := range sigs {
		out = append(out, s...)
	}
	return out
}

func runRegistrar(t *testing.T, state *regAS, sel byte, body []byte, gas uint64) ([]byte, uint64, error) {
	t.Helper()
	input := append([]byte{sel}, body...)
	return RegistrarPrecompile.Run(state, common.Address{}, ContractRegistrarAddress, input, gas, false)
}

// --- tests -------------------------------------------------------------------

func TestRegistrar_RoundTrip_RegisterThenGet(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	id := ChainID(96369)
	name := "lux"
	gw := common.HexToAddress("0x1111111111111111111111111111111111111111")

	payload := buildRegisterPayload(id, name, true, gw)
	sigs := signByAll(t, ops[:2], SelectorRegisterChain, payload)
	body := appendSigs(payload, sigs)

	ret, gasLeft, err := runRegistrar(t, state, SelectorRegisterChain, body, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, uint64(1_000_000-GasRegisterChain), gasLeft)
	require.Equal(t, uint64(0), binary.BigEndian.Uint64(ret[24:32]))

	// GetCount = 1
	ret, _, err = runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(ret[24:32]))

	// GetChain(0) round-trips.
	idxBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(idxBuf, 0)
	ret, _, err = runRegistrar(t, state, SelectorGetChain, idxBuf, 100_000)
	require.NoError(t, err)

	gotID := ChainID(binary.BigEndian.Uint32(ret[0:4]))
	gotNameLen := int(ret[4])
	gotName := string(ret[5 : 5+gotNameLen])
	gotEVM := ret[5+gotNameLen] == 0x01
	gotGW := common.BytesToAddress(ret[6+gotNameLen : 6+gotNameLen+20])

	require.Equal(t, id, gotID)
	require.Equal(t, name, gotName)
	require.True(t, gotEVM)
	require.Equal(t, gw, gotGW)
}

func TestRegistrar_ReRegisterFails(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	id := ChainID(1)
	name := "ethereum"
	gw := common.Address{}

	register := func() error {
		payload := buildRegisterPayload(id, name, true, gw)
		sigs := signByAll(t, ops, SelectorRegisterChain, payload)
		_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
		return err
	}
	require.NoError(t, register())
	require.ErrorIs(t, register(), ErrAlreadyRegistered)
}

func TestRegistrar_UnregisterDecrementsCount(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	// Register three chains.
	chains := []Chain{
		{ID: 1, Name: "ethereum", EVM: true, GatewayAt: common.HexToAddress("0xaa")},
		{ID: 2, Name: "polygon", EVM: true, GatewayAt: common.HexToAddress("0xbb")},
		{ID: 3, Name: "optimism", EVM: true, GatewayAt: common.HexToAddress("0xcc")},
	}
	for _, c := range chains {
		payload := buildRegisterPayload(c.ID, c.Name, c.EVM, c.GatewayAt)
		sigs := signByAll(t, ops, SelectorRegisterChain, payload)
		_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
		require.NoError(t, err)
	}

	// Count = 3
	ret, _, err := runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(3), binary.BigEndian.Uint64(ret[24:32]))

	// Unregister middle (id=2). The slot should be compacted with the last row.
	payload := buildUnregisterPayload(2)
	sigs := signByAll(t, ops, SelectorUnregisterChain, payload)
	_, _, err = runRegistrar(t, state, SelectorUnregisterChain, appendSigs(payload, sigs), 1_000_000)
	require.NoError(t, err)

	ret, _, err = runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(2), binary.BigEndian.Uint64(ret[24:32]))

	// id=2 is gone.
	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	_, ok := r.Get(2)
	require.False(t, ok)

	// id=1 and id=3 remain.
	_, ok = r.Get(1)
	require.True(t, ok)
	_, ok = r.Get(3)
	require.True(t, ok)
}

func TestRegistrar_UnregisterLastRow(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	chains := []Chain{
		{ID: 10, Name: "ten", EVM: true, GatewayAt: common.Address{}},
		{ID: 20, Name: "twenty", EVM: true, GatewayAt: common.Address{}},
	}
	for _, c := range chains {
		payload := buildRegisterPayload(c.ID, c.Name, c.EVM, c.GatewayAt)
		sigs := signByAll(t, ops, SelectorRegisterChain, payload)
		_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
		require.NoError(t, err)
	}

	// Unregister the last row (id=20) — no swap needed; just zero + decrement.
	payload := buildUnregisterPayload(20)
	sigs := signByAll(t, ops, SelectorUnregisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorUnregisterChain, appendSigs(payload, sigs), 1_000_000)
	require.NoError(t, err)

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	_, ok := r.Get(20)
	require.False(t, ok)
	c, ok := r.Get(10)
	require.True(t, ok)
	require.Equal(t, "ten", c.Name)
}

func TestRegistrar_UnregisterUnknownFails(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildUnregisterPayload(999)
	sigs := signByAll(t, ops, SelectorUnregisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorUnregisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrNotRegistered)
}

func TestRegistrar_AuthBelowThresholdReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	payload := buildRegisterPayload(42, "answer", true, common.Address{})

	// Only 1 signature when threshold is 2.
	sigs := signByAll(t, ops[:1], SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestRegistrar_AuthFromNonOperatorReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	stranger := newOperator(t)
	payload := buildRegisterPayload(42, "answer", true, common.Address{})

	// One real operator + one stranger — only 1 valid signature, threshold=2.
	sigs := signByAll(t, []*operator{ops[0], stranger}, SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestRegistrar_AuthDuplicateSignerReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	payload := buildRegisterPayload(42, "answer", true, common.Address{})

	// Same operator signs twice.
	sigs := signByAll(t, []*operator{ops[0], ops[0]}, SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrDuplicateSigner)
}

func TestRegistrar_AuthGarbageSignatureReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildRegisterPayload(42, "answer", true, common.Address{})
	// 65 zero bytes — Ecrecover fails or recovers a non-operator.
	garbage := make([][]byte, 1)
	garbage[0] = make([]byte, argSigLen)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, garbage), 1_000_000)
	require.Error(t, err)
}

func TestRegistrar_AuthWrongSelectorReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	id := ChainID(7)
	payload := buildRegisterPayload(id, "x", true, common.Address{})
	// Sign with the WRONG selector — should not authorize a Register call.
	sigs := signByAll(t, ops, SelectorSetGateway, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestRegistrar_SetGatewayPatchesField(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	id := ChainID(96369)
	name := "lux"
	oldGW := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	newGW := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	payload := buildRegisterPayload(id, name, true, oldGW)
	sigs := signByAll(t, ops, SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.NoError(t, err)

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	c, ok := r.Get(id)
	require.True(t, ok)
	require.Equal(t, oldGW, c.GatewayAt)

	// SetGateway.
	payload = buildSetGatewayPayload(id, newGW)
	sigs = signByAll(t, ops, SelectorSetGateway, payload)
	_, _, err = runRegistrar(t, state, SelectorSetGateway, appendSigs(payload, sigs), 1_000_000)
	require.NoError(t, err)

	c, ok = r.Get(id)
	require.True(t, ok)
	require.Equal(t, newGW, c.GatewayAt)
	// Other fields preserved.
	require.Equal(t, id, c.ID)
	require.Equal(t, name, c.Name)
	require.True(t, c.EVM)
}

func TestRegistrar_SetGatewayUnknownReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildSetGatewayPayload(99999, common.Address{})
	sigs := signByAll(t, ops, SelectorSetGateway, payload)
	_, _, err := runRegistrar(t, state, SelectorSetGateway, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrNotRegistered)
}

func TestRegistrar_RegisterRoundTripsThroughStateRegistry(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	id := ChainID(36963)
	name := "hanzo"
	gw := common.HexToAddress("0x9999999999999999999999999999999999999999")

	payload := buildRegisterPayload(id, name, true, gw)
	sigs := signByAll(t, ops, SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.NoError(t, err)

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	c, ok := r.Get(id)
	require.True(t, ok)
	require.Equal(t, name, c.Name)
	require.Equal(t, gw, c.GatewayAt)
	require.True(t, c.EVM)
}

func TestRegistrar_GetCountOnEmpty(t *testing.T) {
	state := newRegAS()
	ret, gasLeft, err := runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000-GasGetCount), gasLeft)
	require.Equal(t, uint64(0), binary.BigEndian.Uint64(ret[24:32]))
}

func TestRegistrar_GetChainOutOfRange(t *testing.T) {
	state := newRegAS()
	idxBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(idxBuf, 5)
	_, _, err := runRegistrar(t, state, SelectorGetChain, idxBuf, 100_000)
	require.ErrorIs(t, err, ErrIndexOutOfRange)
}

func TestRegistrar_GetChainShortInput(t *testing.T) {
	state := newRegAS()
	_, _, err := runRegistrar(t, state, SelectorGetChain, []byte{1, 2, 3}, 100_000)
	require.ErrorIs(t, err, ErrRegistrarInputTooShort)
}

func TestRegistrar_UnknownSelector(t *testing.T) {
	state := newRegAS()
	_, _, err := RegistrarPrecompile.Run(
		state, common.Address{}, ContractRegistrarAddress,
		[]byte{0xff, 0, 0, 0}, 100_000, false,
	)
	require.ErrorIs(t, err, ErrRegistrarUnknownSelector)
}

func TestRegistrar_EmptyInput(t *testing.T) {
	state := newRegAS()
	_, _, err := RegistrarPrecompile.Run(
		state, common.Address{}, ContractRegistrarAddress,
		nil, 100_000, false,
	)
	require.ErrorIs(t, err, ErrRegistrarInputTooShort)
}

func TestRegistrar_ReadOnlyRegisterReverts(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	sigs := signByAll(t, ops, SelectorRegisterChain, payload)
	body := appendSigs(payload, sigs)
	input := append([]byte{SelectorRegisterChain}, body...)
	_, _, err := RegistrarPrecompile.Run(state, common.Address{}, ContractRegistrarAddress, input, 1_000_000, true)
	require.ErrorIs(t, err, ErrRegistrarReadOnly)
}

func TestRegistrar_RegisterOOG(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	sigs := signByAll(t, ops, SelectorRegisterChain, payload)
	body := appendSigs(payload, sigs)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, body, 100)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestRegistrar_NameTooLong(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	long := "this-name-is-definitely-more-than-thirty-two-bytes"
	payload := buildRegisterPayload(42, long, true, common.Address{})
	sigs := signByAll(t, ops, SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrChainNameTooLong)
}

func TestRegistrar_UnseededGovernanceRejectsWrites(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	// Note: SeedGovernance NOT called.

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	sigs := signByAll(t, ops, SelectorRegisterChain, payload)
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, appendSigs(payload, sigs), 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)
}

// --- Configuration & module registration ------------------------------------

func TestRegistrar_ModuleRegistered(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractRegistrarAddress, Module.Address)

	// The init() side-effect registered the module — RegisteredModules() must include it.
	all := modules.RegisteredModules()
	found := false
	for _, m := range all {
		if m.Address == ContractRegistrarAddress {
			require.Equal(t, ConfigKey, m.ConfigKey)
			found = true
			break
		}
	}
	require.True(t, found, "registrar module not in modules.RegisteredModules()")
}

func TestRegistrar_ConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&regChainCfg{}))
	require.True(t, cfg.Equal(&Config{}))

	ts := uint64(42)
	cfg2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg2.Timestamp())

	cfg3 := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, cfg3.IsDisabled())
}

func TestRegistrar_ConfigVerify(t *testing.T) {
	cfg := &Config{
		Operators: []string{"0x1111111111111111111111111111111111111111"},
		Threshold: 1,
	}
	require.NoError(t, cfg.Verify(&regChainCfg{}))

	// Bad threshold.
	bad := &Config{
		Operators: []string{"0x1111111111111111111111111111111111111111"},
		Threshold: 5,
	}
	require.Error(t, bad.Verify(&regChainCfg{}))

	// Bad address.
	bad2 := &Config{
		Operators: []string{"not-a-hex"},
		Threshold: 1,
	}
	require.Error(t, bad2.Verify(&regChainCfg{}))
}

func TestRegistrar_ConfigEqual(t *testing.T) {
	a := &Config{
		Operators: []string{"0x1111111111111111111111111111111111111111"},
		Threshold: 1,
	}
	b := &Config{
		Operators: []string{"0x1111111111111111111111111111111111111111"},
		Threshold: 1,
	}
	require.True(t, a.Equal(b))

	c := &Config{
		Operators: []string{"0x2222222222222222222222222222222222222222"},
		Threshold: 1,
	}
	require.False(t, a.Equal(c))

	d := &Config{
		Operators: []string{"0x1111111111111111111111111111111111111111"},
		Threshold: 2,
	}
	require.False(t, a.Equal(d))

	require.False(t, a.Equal(&Config{}))
}

func TestRegistrar_ConfiguratorSeeds(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig().(*Config)
	cfg.Operators = []string{"0x1234567890abcdef1234567890abcdef12345678"}
	cfg.Threshold = 1

	state := newRegState()
	require.NoError(t, c.Configure(&regChainCfg{}, cfg, state, &regBlockCtx{}))

	// Governance should be readable.
	ops, threshold, err := loadGovernance(state)
	require.NoError(t, err)
	require.Equal(t, uint32(1), threshold)
	require.Len(t, ops, 1)
	require.Equal(t,
		common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		ops[0],
	)
}

func TestRegistrar_ConfiguratorEmptyConfigNoOp(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig() // empty Config
	state := newRegState()
	require.NoError(t, c.Configure(&regChainCfg{}, cfg, state, &regBlockCtx{}))

	// Empty governance → writes are still unauthorized.
	_, _, err := loadGovernance(state)
	require.ErrorIs(t, err, ErrUnauthorized)
}

// --- Domain separator pinning -----------------------------------------------

func TestRegistrar_DomainSeparatorPinned(t *testing.T) {
	// If anyone changes the domain separator, every off-chain signer is broken.
	// This test exists to make that change loud.
	require.Equal(t, "lux.bridge.registrar.v1", DomainSeparator)
}

func TestRegistrar_DigestPayloadShape(t *testing.T) {
	// Pin the exact byte shape of registrarDigest. If this changes, on-chain
	// and off-chain disagree silently.
	payload := []byte{0x01, 0x02, 0x03}
	got := registrarDigest(SelectorRegisterChain, payload)
	expected := crypto.Keccak256(append(
		append([]byte("lux.bridge.registrar.v1"), SelectorRegisterChain),
		payload...,
	))
	require.Equal(t, expected, got)
}

// --- Gas constants pinning --------------------------------------------------

func TestRegistrar_GasCostsPinned(t *testing.T) {
	require.Equal(t, uint64(60_000), GasRegisterChain)
	require.Equal(t, uint64(30_000), GasUnregisterChain)
	require.Equal(t, uint64(22_000), GasSetGateway)
	require.Equal(t, uint64(700), GasGetCount)
	require.Equal(t, uint64(2_400), GasGetChain)
}

// --- Address pinning --------------------------------------------------------

func TestRegistrar_AddressPinned(t *testing.T) {
	require.Equal(t,
		common.HexToAddress("0x0400000000000000000000000000000000000046"),
		ContractRegistrarAddress,
	)
	require.Equal(t,
		common.HexToAddress("0x0400000000000000000000000000000000000040"),
		BridgeGatewayCanonicalAddress,
	)
}
