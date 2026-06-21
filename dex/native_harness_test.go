// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/luxfi/vm/chains/atomic"
)

// native_harness_test.go is the SHARED test harness for the native C<->D atomic
// 0x9999 money path. It replaces the BLS-era settleHarness (quarantined under
// _deprecated_bls): no validator set, no cert — instead a REAL in-memory atomic
// shared memory (atomic.NewMemory over memdb) wired into an AtomicState-capable
// accessible state, so SettleSwap and the dexvm import/export operate over the
// genuine bidirectional shared-memory channel (not a fake).
//
// The harness exposes the C-Chain's SharedMemory to the precompile (via
// nativeAtomicState) and the D-Chain's SharedMemory to the dexvm-side test driver,
// so a C->D Put is readable by D via Get(cChainID) and a D->C Put is readable by C
// via Get(dChainID) — the real platformvm import/export semantics.

// nativeAtomicState implements BOTH contract.AccessibleState and
// contract.AtomicState so SettleSwap's `state.(contract.AtomicState)` assertion
// succeeds and reaches a real SharedMemory + chain identity.
type nativeAtomicState struct {
	stateDB   *MockStateDB
	sm        atomic.SharedMemory
	networkID uint32
	chainID   ids.ID // THIS chain (C)
	cChainID  ids.ID
	txID      ids.ID
	callIndex uint32
}

// --- AccessibleState ---
func (m *nativeAtomicState) GetStateDB() contract.StateDB {
	return &contractStateDBWrapper{inner: m.stateDB}
}
func (m *nativeAtomicState) GetBlockContext() contract.BlockContext {
	return &mockBlockCtx{number: big.NewInt(int64(m.stateDB.blockNumber))}
}
func (m *nativeAtomicState) GetConsensusContext() context.Context             { return context.Background() }
func (m *nativeAtomicState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (m *nativeAtomicState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

// --- AtomicState ---
func (m *nativeAtomicState) AtomicMemory() atomic.SharedMemory { return m.sm }
func (m *nativeAtomicState) NetworkID() uint32                 { return m.networkID }
func (m *nativeAtomicState) ChainID() ids.ID                   { return m.chainID }
func (m *nativeAtomicState) CChainID() ids.ID                  { return m.cChainID }
func (m *nativeAtomicState) TxID() ids.ID                      { return m.txID }
func (m *nativeAtomicState) CallIndex() uint32                 { return m.callIndex }

var _ contract.AccessibleState = (*nativeAtomicState)(nil)
var _ contract.AtomicState = (*nativeAtomicState)(nil)

// settleHarness wires a 0x9999 contract over a real atomic shared-memory channel.
// cSM is the C-Chain side (used by the precompile); dSM is the D-Chain side (used
// by the dexvm-side test driver in the round-trip test).
type settleHarness struct {
	c            *SettleContract
	state        *nativeAtomicState
	mem          *atomic.Memory
	cSM          atomic.SharedMemory
	dSM          atomic.SharedMemory
	dChainID     ids.ID
	cChainID     ids.ID
	networkID    uint32
	key          PoolKey
	params       SwapParams
	caller       common.Address
	lastFlushed  uint64          // harness's parent-boundary seq for the flush window
	memdbBacking *memdb.Database // shared-memory backing db (for batch tests)
}

func newSettleHarness(t testing.TB) *settleHarness {
	return newSettleHarnessN(t, 3)
}

// newSettleHarnessN keeps the n parameter for source-compat with call sites; the
// native model has no validator count, so n is ignored (kept so existing surface
// tests that pass a count still compile).
func newSettleHarnessN(t testing.TB, _ int) *settleHarness {
	t.Helper()
	cChainID := ids.ID{0xCC}
	dChainID := ids.ID{0xDD}
	backing := memdb.New()
	mem := atomic.NewMemory(backing)
	cSM := mem.NewSharedMemory(cChainID)
	dSM := mem.NewSharedMemory(dChainID)

	state := &nativeAtomicState{
		stateDB:   NewMockStateDB(),
		sm:        cSM,
		networkID: 1,
		chainID:   cChainID,
		cChainID:  cChainID,
		txID:      ids.ID{0x7A}, // a fixed tx id for the harness; tests vary callIndex/txID
		callIndex: 0,
	}
	h := &settleHarness{
		c:            &SettleContract{protocolFeeController: common.HexToAddress("0xFEE0000000000000000000000000000000000001")},
		state:        state,
		mem:          mem,
		cSM:          cSM,
		dSM:          dSM,
		dChainID:     dChainID,
		cChainID:     cChainID,
		networkID:    1,
		caller:       common.HexToAddress("0x1111111111111111111111111111111111111111"),
		memdbBacking: backing,
	}
	// V4 pool: currency0 = native (0x0), currency1 = token 0x..02. zeroForOne = swap
	// native in, token out. AmountSpecified < 0 (exact-input) for the native intent.
	h.key = PoolKey{
		Currency0:   Currency{Address: common.Address{}},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
	h.params = SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-100), SqrtPriceLimitX96: big.NewInt(0)}

	// Configure the native-seam chain identity + D-Chain target (as Configure would).
	kv := newPoolStateAdapter(h.state)
	var c32, d32 [32]byte
	copy(c32[:], cChainID[:])
	copy(d32[:], dChainID[:])
	SetSettleChainIdentity(kv, h.networkID, c32)
	SetSettleDChainTarget(kv, d32)
	return h
}

// outToken is the harness pool's currency1 (the swap output for ZeroForOne).
func (h *settleHarness) outToken() common.Address { return h.key.Currency1.Address }

// outAssetID is the injective AssetID of the output token.
func (h *settleHarness) outAssetID() [32]byte { return assetID(h.key.Currency1) }

// inAssetID is the injective AssetID of the input (native) currency.
func (h *settleHarness) inAssetID() [32]byte { return assetID(h.key.Currency0) }

// wrapper returns the harness's contract.StateDB as the erc20Vault-capable wrapper.
func (h *settleHarness) wrapper() *contractStateDBWrapper {
	return h.state.GetStateDB().(*contractStateDBWrapper)
}

// fundCallerNative seeds the caller's native balance so it can fund an intent.
func (h *settleHarness) fundCallerNative(amount int64) {
	h.state.stateDB.AddBalance(h.caller, uint256.NewInt(uint64(amount)))
}

// fundVaultOut seeds the 0x9999 vault's OUTPUT token into the SEAM RESERVE (the seam's
// own pot — operator-seeded counterparty backing), so a D->C settlement credit is
// backed (no mint). Mirrors day-1 operator seeding of the seam reserve, NOT a
// depositor's claim.
func (h *settleHarness) fundVaultOut(amount int64) {
	h.wrapper().mintTestToken(h.outToken(), poolManagerAddr9999, big.NewInt(amount))
	storeSeamReserve(newPoolStateAdapter(h.state), h.outAssetID(), big.NewInt(amount))
}

// fundVaultNativeOut seeds the 0x9999 vault's NATIVE holdings into the SEAM RESERVE
// (for a native D->C credit). The vault self-balance and the seam reserve move in
// lockstep.
func (h *settleHarness) fundVaultNativeOut(amount int64) {
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(uint64(amount)))
	storeSeamReserve(newPoolStateAdapter(h.state), [32]byte{}, big.NewInt(amount))
}

// seedCommittedNative seeds the 0x9999 vault's NATIVE holdings into the COMMITTED-
// POSITIONS pot (the LP rail's own reserve — operator fee backing, the symmetric
// analog of fundVaultNativeOut for the swap rail). The vault self-balance and the
// committedPositions pot move in lockstep, so a fee collect that exceeds an LP's own
// principal commit is backed without raiding any other pot. Used by the fee tests.
func (h *settleHarness) seedCommittedNative(amount int64) {
	db := newPoolStateAdapter(h.state)
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(uint64(amount)))
	cur := loadCommittedPositions(db, [32]byte{})
	storeCommittedPositions(db, [32]byte{}, new(big.Int).Add(cur, big.NewInt(amount)))
}

// commitNativePosition drives a native LP COMMIT through the 0x9999 modifyLiquidity
// selector: it funds the caller, runs the ADD, flushes the staged C->D object, and
// returns the position record id (MakerOrderID) and the C->D commit object id
// (DerivePositionCommitID, read off the record). The commit moves `amount` from the
// caller's CSpendable balance into committedPositions (DCommitted).
func (h *settleHarness) commitNativePosition(t testing.TB, tickLower, tickUpper int24, amount int64, salt [32]byte) (recordID, commitObjID ids.ID) {
	t.Helper()
	h.fundCallerNative(amount)
	hookData := []byte{makerEnvelopeTag[0], makerEnvelopeTag[1], makerEnvelopeTag[2], makerEnvelopeTag[3], byte(MakerSideBid)}
	args := buildModifyLiquidityArgs(h.key, tickLower, tickUpper, big.NewInt(amount), salt, hookData)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorModifyLiquidity, args), 5_000_000, false)
	if err != nil {
		t.Fatalf("commitNativePosition ADD: %v", err)
	}
	var rid [32]byte
	copy(rid[:], out[0:32])
	h.flushStaged(t)
	db := newPoolStateAdapter(h.state)
	commit := db.GetState(poolManagerAddr9999, orderSlot(rid, orderCommitObjSuffix))
	return ids.ID(rid), ids.ID(commit)
}

// collectNative drives a native LP COLLECT/WITHDRAW through the 0x9999
// collectPosition selector: it consumes the D->C object at outputID for `amount` of
// native, crediting the caller out of committedPositions. Returns the call error.
func (h *settleHarness) collectNative(outputID ids.ID, amount uint64) ([]byte, error) {
	input := EncodeCollectPositionInput(outputID, [32]byte{}, amount)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorCollectPosition, input), 5_000_000, false)
	return out, err
}

// flushStaged simulates the HOST's block-accept cross-domain commit using the
// DETERMINISTIC parent->current seq window (FlushAcceptedAtomicOps), the same model
// the production host uses. It tracks the harness's last-flushed seq as the "parent"
// boundary and the current state seq as the "accepted" boundary, applies that
// window to the C-Chain shared memory, and advances the boundary. No state mutation
// (the records are append-only consensus data) — exactly the production semantics.
func (h *settleHarness) flushStaged(t testing.TB) {
	t.Helper()
	// The staged ops live in the precompile's StateDB (the MockStateDB), which is the
	// AtomicStateReader for the flush.
	if err := FlushAcceptedAtomicOps(h.parentSeqState(), h.state.stateDB, h.cSM, nil); err != nil {
		t.Fatalf("flushStaged: %v", err)
	}
	h.lastFlushed = ReadStagedAtomicSeq(h.state.stateDB)
}

// parentSeqState returns a read view whose staged seq is the harness's last-flushed
// boundary, so FlushAcceptedAtomicOps derives the window (lastFlushed, current].
func (h *settleHarness) parentSeqState() AtomicStateReader {
	return &seqOnlyState{seq: h.lastFlushed}
}

// seqOnlyState is a minimal AtomicStateReader that reports a fixed staged seq (the
// parent boundary) and zero for every other slot — enough for ReadStagedAtomicSeq.
type seqOnlyState struct{ seq uint64 }

func (s *seqOnlyState) GetState(addr common.Address, key common.Hash) common.Hash {
	if key == stageSeqKey {
		var w common.Hash
		putU64(w[24:32], s.seq)
		return w
	}
	return common.Hash{}
}

// putDtoCObject simulates the dexvm's executeExport: it PUTs a D->C atomic object
// into shared memory keyed by the C chain (so the precompile reads it via
// Get(dChainID)). owner/asset/amount are the recorded value the C side will bind.
func (h *settleHarness) putDtoCObject(t testing.TB, owner common.Address, outputID ids.ID, asset [32]byte, amount uint64) {
	t.Helper()
	obj := encodeAtomicObject(owner, asset, amount)
	reqs := map[ids.ID]*atomic.Requests{
		h.cChainID: {PutRequests: []*atomic.Element{{
			Key:    outputID[:],
			Value:  obj,
			Traits: [][]byte{owner[:]},
		}}},
	}
	// The D side applies to the C chain's partition (D is the source).
	if err := h.dSM.Apply(reqs); err != nil {
		t.Fatalf("putDtoCObject: %v", err)
	}
}

// readCtoDObject simulates the dexvm's executeImport READ: it Gets the C->D object
// the precompile PUT (keyed by the D chain), readable by D via Get(cChainID).
func (h *settleHarness) readCtoDObject(t testing.TB, intentID ids.ID) ([]byte, bool) {
	t.Helper()
	vals, err := h.dSM.Get(h.cChainID, [][]byte{intentID[:]})
	if err != nil || len(vals) != 1 || len(vals[0]) == 0 {
		return nil, false
	}
	return vals[0], true
}

// settlementCalldata builds a Phase-B swap calldata that consumes a D->C object.
func (h *settleHarness) settlementCalldata(outputID ids.ID, amount uint64) []byte {
	return buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, amount))
}

// intentCalldata builds a Phase-A swap calldata (empty hookData => intent).
func (h *settleHarness) intentCalldata() []byte {
	return buildSwapCalldata(h.key, h.params, nil)
}

// buildSwapCalldata encodes a V4 swap call (UNCHANGED ABI) carrying hookData. The
// 4-byte selector is prepended by the caller (h.c.Run strips it); here we return
// the ABI args + hookData tail that Run sees as `data`.
func buildSwapCalldata(key PoolKey, params SwapParams, hookData []byte) []byte {
	args := make([]byte, 288)
	copy(args[0:160], EncodePoolKeyABI(key))
	if params.ZeroForOne {
		args[191] = 1
	}
	if params.AmountSpecified != nil {
		// store two's-complement-free magnitude with a sign marker in the high bit is
		// not needed; DecodeSwapInput reads the 32-byte word as a signed big.Int. We
		// encode negative exact-input as the 256-bit two's complement.
		v := params.AmountSpecified
		if v.Sign() < 0 {
			// two's complement in 256 bits
			mod := new(big.Int).Lsh(big.NewInt(1), 256)
			tc := new(big.Int).Add(mod, v)
			tc.FillBytes(args[192:224])
		} else {
			v.FillBytes(args[192:224])
		}
	}
	if params.SqrtPriceLimitX96 != nil {
		params.SqrtPriceLimitX96.FillBytes(args[224:256])
	}
	binary.BigEndian.PutUint64(args[280:288], 288) // hookData offset
	lenWord := make([]byte, 32)
	binary.BigEndian.PutUint64(lenWord[24:32], uint64(len(hookData)))
	padded := make([]byte, (len(hookData)+31)/32*32)
	copy(padded, hookData)
	return append(append(args, lenWord...), padded...)
}

// prependSelector builds calldata = 4-byte selector || data (used by the surface
// tests to call a 0x9999 selector directly). Mirrors the quarantined helper.
func prependSelector(sel uint32, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[0:4], sel)
	copy(out[4:], data)
	return out
}

// leftPad32 left-pads b into a 32-byte word (ABI word helper for the surface
// tests). Mirrors the quarantined helper.
func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
