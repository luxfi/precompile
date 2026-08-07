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

// testGovernance is the harness's per-network DEX governance controller — the address
// the mock AtomicState returns from GovernanceController(), i.e. the ONLY caller that may
// halt 0x9999 settlement or seed its pots. In production this is a governance CONTRACT
// the host wires per network; here it is a fixed test address that stands in for that
// contract. It is deliberately a non-EOA-looking sentinel distinct from the harness's
// trading caller (0x1111…) and from the retired mnemonic-derivable 0x9011… EOA, so the
// governance tests can prove only this address halts and the old EOA cannot.
var testGovernance = common.HexToAddress("0x60F0000000000000000000000000000000000A11") // "GOV ...0A11"

// nativeAtomicState implements BOTH contract.AccessibleState and
// contract.AtomicState so SettleSwap's `state.(contract.AtomicState)` assertion
// succeeds and reaches a real SharedMemory + chain identity.
type nativeAtomicState struct {
	stateDB        *MockStateDB
	sm             atomic.SharedMemory
	networkID      uint32
	chainID        ids.ID // THIS chain (C)
	cChainID       ids.ID
	dChainID       ids.ID         // the D-Chain (dexvm) peer the host resolves at runtime
	governance     common.Address // the per-network DEX governance controller (halt/seed authority)
	txID           ids.ID
	callIndex      uint32
	blockTimestamp uint64 // block time the precompile reads via GetBlockContext().Timestamp()
}

// --- AccessibleState ---
func (m *nativeAtomicState) GetStateDB() contract.StateDB {
	return &contractStateDBWrapper{inner: m.stateDB}
}
func (m *nativeAtomicState) GetBlockContext() contract.BlockContext {
	return &mockBlockCtx{number: big.NewInt(int64(m.stateDB.blockNumber)), timestamp: m.blockTimestamp}
}
func (m *nativeAtomicState) GetConsensusContext() context.Context             { return context.Background() }
func (m *nativeAtomicState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (m *nativeAtomicState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

// --- AtomicState ---
func (m *nativeAtomicState) AtomicMemory() atomic.SharedMemory    { return m.sm }
func (m *nativeAtomicState) NetworkID() uint32                    { return m.networkID }
func (m *nativeAtomicState) ChainID() ids.ID                      { return m.chainID }
func (m *nativeAtomicState) CChainID() ids.ID                     { return m.cChainID }
func (m *nativeAtomicState) GovernanceController() common.Address { return m.governance }
func (m *nativeAtomicState) DChainID() ids.ID                     { return m.dChainID }
func (m *nativeAtomicState) TxID() ids.ID                         { return m.txID }
func (m *nativeAtomicState) CallIndex() uint32                    { return m.callIndex }

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

// harnessBlockTime is an arbitrary post-genesis block timestamp for harness state.
// 0x9999 and its logs are AlwaysOn (active from genesis), so the exact value carries no
// protocol meaning — any block time exercises the live settlement path.
const harnessBlockTime uint64 = 1_700_000_000 // 2023-11-14T22:13:20Z, a normal block time

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
		stateDB:    NewMockStateDB(),
		sm:         cSM,
		networkID:  1,
		chainID:    cChainID,
		cChainID:   cChainID,
		dChainID:   dChainID,       // host-resolved D peer (runtime), as the EVM adapter supplies it
		governance: testGovernance, // the per-network governance controller the host supplies via AtomicState
		txID:       ids.ID{0x7A},   // a fixed tx id for the harness; tests vary callIndex/txID
		callIndex:  0,
		// 0x9999 and its DEXFill + Initialize logs are AlwaysOn (active from genesis,
		// no dated fork), so the harness block time carries no protocol meaning — any
		// value exercises the live path. A test that wants genesis sets blockTimestamp=0.
		blockTimestamp: harnessBlockTime,
	}
	h := &settleHarness{
		c:            &SettleContract{},
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
	// native in, token out. AmountSpecified < 0 (exact-input) for the native order.
	h.key = PoolKey{
		Currency0:   Currency{Address: common.Address{}},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
	// A cross-chain order REQUIRES a price limit (see ErrNativeOrderNoPriceLimit):
	// the taker's order executes on D, in a block they do not control, so the seam
	// refuses an unbounded order. The default harness swap therefore carries a real
	// SqrtPriceLimitX96 — the shape a router actually sends.
	h.params = SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-100), SqrtPriceLimitX96: sqrtX96For(2.0)}

	// The native-seam chain identity (networkID, cChainID) and the D-Chain peer are
	// supplied at RUNTIME by the host via the AtomicState capability (nativeAtomicState
	// above) — there is NO per-net config to seed. This mirrors production exactly:
	// 0x9999 is always-on and resolves its chain topology from the consensus context.

	// C1 admission (the value path's real-asset gate, repointed onto 0x9999): every
	// market open / swap / settle now resolves both sides through the AssetResolver, so
	// the SHARED harness installs a default resolver admitting ITS OWN market assets — the
	// native coin (currency0) and currency1 (0x..02), with live code at the token address —
	// exactly as a real chain's registry is populated. Without this, registerMarket
	// (SelectorInitialize) and every settle path fail closed ("no asset resolver
	// configured"), and tests would depend on a process-global resolver leaking from
	// another test (an order-dependent, non-hermetic green). A test that needs a DIFFERENT
	// admission policy (the C1 redteam: a restrictive or absent resolver) overrides the
	// global via InstallAssetResolver / Store; t.Cleanup restores the prior state LIFO so
	// nothing leaks. This is the ONE place the harness's market is admitted.
	h.installDefaultMarketResolver(t)
	return h
}

// installDefaultMarketResolver installs the PERMISSIONLESS resolver and gives the shared
// harness market's two sides live on-chain code (native needs none; each ERC-20 token gets
// code) and restores the prior global on cleanup. Under permissionless admission, code presence
// — not membership — is what admits an asset, so seeding code is the harness analog of two real
// deployed tokens. The admission gate then passes for the legitimate harness market in EVERY
// test by default. Tests that probe admission failure install their own resolver and leave the
// probed asset WITHOUT code (so the on-chain proof refuses it).
func (h *settleHarness) installDefaultMarketResolver(t testing.TB) {
	t.Helper()
	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h)
	if h.key.Currency1.Address != (common.Address{}) {
		r.admitERC20(t, h.key.Currency1.Address, 18) // seeds live on-chain code
	}
	if h.key.Currency0.Address != (common.Address{}) {
		r.admitERC20(t, h.key.Currency0.Address, 18) // seeds live on-chain code
	}
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("installDefaultMarketResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })
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

// fundCallerNative seeds the caller's native balance so it can fund an order.
func (h *settleHarness) fundCallerNative(amount int64) {
	h.state.stateDB.AddBalance(h.caller, uint256.NewInt(uint64(amount)))
}

// operator is the harness's DEX governance controller — the authority the mock
// AtomicState returns from GovernanceController(), the SOLE caller the governance-gated
// seed/fee/halt selectors accept. It is the per-network governance address the host
// supplies at runtime (testGovernance here), NOT a field on the SettleContract and NOT a
// hardcoded mnemonic-derivable EOA.
func (h *settleHarness) operator() common.Address { return h.state.governance }

// fundVaultOut seeds the 0x9999 vault's OUTPUT token into the SEAM RESERVE through the
// REAL operator-gated seedSeamReserve selector (FIX-4 — the production counterparty
// seed, not a test-only state poke), so a D->C settlement credit is backed (no mint).
func (h *settleHarness) fundVaultOut(amount int64) {
	// The operator holds the token; the mock vault transferFrom debits the operator's
	// balance into 0x9999 (no allowance model in the mock — honest balance check only).
	h.wrapper().mintTestToken(h.outToken(), h.operator(), big.NewInt(amount))
	data := make([]byte, 64)
	copy(data[12:32], h.outToken().Bytes())
	big.NewInt(amount).FillBytes(data[32:64])
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false); err != nil {
		panic("fundVaultOut seed: " + err.Error())
	}
}

// fundVaultNativeOut seeds the 0x9999 vault's NATIVE holdings into the SEAM RESERVE
// through the REAL seedSeamReserve selector. The host call frame moves msg.value into
// 0x9999 before Run (observed-delta), so we add the operator-delivered native first.
func (h *settleHarness) fundVaultNativeOut(amount int64) {
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(uint64(amount))) // host frame moved msg.value
	data := make([]byte, 64)                                                        // asset = address(0) (native), amount
	big.NewInt(amount).FillBytes(data[32:64])
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false); err != nil {
		panic("fundVaultNativeOut seed: " + err.Error())
	}
}

// creditPositionFeeNative credits `amount` of NATIVE earned fees into a SPECIFIC LP
// position via the REAL operator-gated creditPositionFee selector (the keeper's
// per-owner reflection of D-Chain maker-fee credits). It raises the named record's
// withdrawable + the owner reserve + the committedPositions pot together, so the LP
// can collect principal+fees while the per-owner committed bound (FIX-2) stays exact.
func (h *settleHarness) creditPositionFeeNative(t testing.TB, positionID [32]byte, amount int64) {
	t.Helper()
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(uint64(amount))) // host frame moved msg.value
	data := make([]byte, 96)
	copy(data[0:32], positionID[:])
	// asset word: native == address(0) in the right 20 bytes (left-padded), so word stays zero.
	big.NewInt(amount).FillBytes(data[64:96])
	if _, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
		prependSelector(SelectorCreditPositionFee, data), 5_000_000, false); err != nil {
		t.Fatalf("creditPositionFeeNative: %v", err)
	}
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
// collectPosition selector: it consumes the railLP D->C object at outputID for
// `amount` of native against the named position record, crediting the caller out of
// committedPositions. Returns the call error.
//
// The calldata now CARRIES the object (settle_import.go): there is no separate amount
// word, so `amount` no longer rides the wire — the credited value IS the object's
// amount. The bytes come from recordedObject, exactly as a keeper reads them off D.
func (h *settleHarness) collectNative(outputID ids.ID, amount uint64, positionID [32]byte) ([]byte, error) {
	_ = amount // the amount is inside the object; the wire no longer restates it.
	return h.collectCarrying(outputID, positionID, h.recordedObject(outputID))
}

// collectCarrying drives the SAME collectPosition selector with EXPLICIT object bytes.
// Carrying the object is the keeper's real degree of freedom now that execution never
// reads shared memory (settle_import.go), so it is also the attacker's: the redteam
// tests use this to supply bytes shared memory does NOT hold and then prove the
// resulting declaration cannot authenticate.
func (h *settleHarness) collectCarrying(outputID ids.ID, positionID [32]byte, object []byte) ([]byte, error) {
	input := EncodeCollectPositionInput(outputID, [32]byte{}, positionID, object)
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

// putDtoCObject simulates the dexvm's executeExport of a SWAP-rail (railSwap) D->C
// object — the swap rail's fill/refund settlement. It PUTs the object into shared
// memory keyed by the C chain (so ImportSettlement reads it via Get(dChainID)).
func (h *settleHarness) putDtoCObject(t testing.TB, owner common.Address, outputID ids.ID, asset [32]byte, amount uint64) {
	t.Helper()
	h.putDtoCObjectRail(t, railSwap, owner, outputID, asset, amount)
}

// putDtoCLPObject simulates the dexvm's executeWithdraw of an LP-rail (railLP) D->C
// object — the LP collect/withdraw leg ImportPositionCollect consumes.
func (h *settleHarness) putDtoCLPObject(t testing.TB, owner common.Address, outputID ids.ID, asset [32]byte, amount uint64) {
	t.Helper()
	h.putDtoCObjectRail(t, railLP, owner, outputID, asset, amount)
}

// putDtoCObjectRail PUTs a D->C atomic object of the given RAIL into shared memory
// (the dexvm export side stamps the lane). rail/owner/asset/amount are the recorded
// value the C-side consume path binds — including the rail gate.
func (h *settleHarness) putDtoCObjectRail(t testing.TB, rail Rail, owner common.Address, outputID ids.ID, asset [32]byte, amount uint64) {
	t.Helper()
	h.putDtoCObjectRailSpent(t, rail, owner, outputID, asset, amount, 0)
}

// putDtoCObjectRailSpent PUTs a D->C atomic object carrying an explicit spent witness —
// the matched-input amount the dexvm's settleFromFills stamps on a swap PROCEEDS leg. The
// existing same-asset-refund / LP-collect helpers pass spent=0 (no price is realized on
// those legs); the MEV-floor redteam test uses spent>0 to drive the realized-price check.
func (h *settleHarness) putDtoCObjectRailSpent(t testing.TB, rail Rail, owner common.Address, outputID ids.ID, asset [32]byte, amount, spent uint64) {
	t.Helper()
	obj := encodeAtomicObjectSpent(rail, owner, asset, amount, spent)
	reqs := map[ids.ID]*atomic.Requests{
		h.cChainID: {PutRequests: []*atomic.Element{{
			Key:    outputID[:],
			Value:  obj,
			Traits: [][]byte{owner[:]},
		}}},
	}
	// The D side applies to the C chain's partition (D is the source).
	if err := h.dSM.Apply(reqs); err != nil {
		t.Fatalf("putDtoCObjectRailSpent: %v", err)
	}
}

// recordedObject reads back the D->C object BYTES a test PUT into shared memory for
// outputID — the same read a keeper performs off D when it builds the settle/collect
// transaction, whose calldata now CARRIES those bytes (settle_import.go). Empty when
// nothing was recorded at that key.
func (h *settleHarness) recordedObject(outputID ids.ID) []byte {
	vals, err := h.cSM.Get(h.dChainID, [][]byte{outputID[:]})
	if err != nil || len(vals) != 1 {
		return nil
	}
	return vals[0]
}

// readCtoDObject simulates the dexvm's executeImport READ: it Gets the C->D object
// the precompile PUT (keyed by the D chain), readable by D via Get(cChainID).
func (h *settleHarness) readCtoDObject(t testing.TB, orderID ids.ID) ([]byte, bool) {
	t.Helper()
	vals, err := h.dSM.Get(h.cChainID, [][]byte{orderID[:]})
	if err != nil || len(vals) != 1 || len(vals[0]) == 0 {
		return nil, false
	}
	return vals[0], true
}

// settlementCalldata builds a Phase-B swap calldata that consumes a D->C object,
// bound to a standing per-taker swap order for the caller (auto-seeded with ample
// principal + no deadline) so the per-taker cap (MEDIUM) is satisfied. Tests that
// exercise the cap/deadline directly seed their own order and use
// settlementCalldataFor with a specific order id.
func (h *settleHarness) settlementCalldata(outputID ids.ID, amount uint64) []byte {
	orderID := h.standingOrder(amount)
	return buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, orderID, h.recordedObject(outputID)))
}

// settlementCalldataFor builds a Phase-B swap calldata naming a SPECIFIC order id
// (for the per-taker cap / deadline tests). `amount` only sizes the standing order in
// settlementCalldata; the settled value IS the carried object's amount, never a
// separate wire field.
func (h *settleHarness) settlementCalldataFor(outputID ids.ID, amount uint64, orderID ids.ID) []byte {
	_ = amount // the amount is inside the object; the wire no longer restates it.
	return buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, orderID, h.recordedObject(outputID)))
}

// orderCalldata builds a Phase-A swap calldata. After the decomplect EVERY swap routes to
// the native C<->D atomic seam: a plain (empty-hookData) swap is ALSO a Phase-A order, and
// an explicit DI01 tag is the same phase carrying an optional deadline/nonce. The async-seam
// tests drive the DI01-tagged form (deadline 0 => defaulted to a finite reclaim horizon,
// nonce 0) so they can pin the deadline/nonce; there is no longer any synchronous matcher an
// untagged swap could take instead.
func (h *settleHarness) orderCalldata() []byte {
	return buildSwapCalldata(h.key, h.params, EncodeOrderHookData(0, 0))
}

// orderCalldataWithDeadline builds a Phase-A swap calldata carrying an explicit
// deadline in the hookData body (nonce 0; the V4 SwapParams tuple is unchanged).
func (h *settleHarness) orderCalldataWithDeadline(deadline uint64) []byte {
	return buildSwapCalldata(h.key, h.params, EncodeOrderHookData(deadline, 0))
}

// orderCalldataWithNonce builds a Phase-A swap calldata carrying an explicit nonce
// (and optional deadline) in the DI01 hookData — the taker's order disambiguator that
// is folded into the (chain-observable) order id.
func (h *settleHarness) orderCalldataWithNonce(deadline, nonce uint64) []byte {
	return buildSwapCalldata(h.key, h.params, EncodeOrderHookData(deadline, nonce))
}

// standingOrder lazily seeds (once) a per-taker swap order for the caller covering
// the OUTPUT asset with ample principal and NO deadline, and returns its id. It is the
// default order settlementCalldata binds to so existing settle tests (which assert the
// object-bind / replay / rail axes) satisfy the per-taker cap without each restating it.
func (h *settleHarness) standingOrder(minPrincipal uint64) ids.ID {
	id := ids.ID{0x57, 0x7A, 0x11} // a fixed standing-order id for the harness.
	db := newPoolStateAdapter(h.state)
	rec := loadSwapOrderRecord(db, id)
	if rec.Status != swapOrderOpen || rec.Remaining < minPrincipal {
		// (Re)seed with generous principal so the cap never spuriously bites the
		// object-bind tests; cap-specific tests use seedSwapOrder with exact principal.
		principal := minPrincipal * 4
		if principal < 1_000_000 {
			principal = 1_000_000
		}
		putSwapOrderRecord(db, id, swapOrderRecord{
			Owner:     h.caller,
			AssetIn:   h.outAssetID(), // bound only on owner; asset axis is not cross-checked.
			Remaining: principal,
			Deadline:  0,
			Status:    swapOrderOpen,
		})
	}
	return id
}

// seedSwapOrder writes a per-taker swap order record directly (the test analog of
// SubmitSwapOrder's record write) and returns its id, so the per-taker cap / deadline
// / reclaim tests have a precise order (exact owner/principal/deadline) to bind to.
func (h *settleHarness) seedSwapOrder(owner common.Address, assetIn [32]byte, principal, deadline uint64, id ids.ID) ids.ID {
	putSwapOrderRecord(newPoolStateAdapter(h.state), id, swapOrderRecord{
		Owner:     owner,
		AssetIn:   assetIn,
		Remaining: principal,
		Deadline:  deadline,
		Status:    swapOrderOpen,
	})
	return id
}

// seedSwapOrderLimit seeds an order carrying the taker's OWN recorded slippage limit
// (priceLimit float64 bits, limitIsUpper side) — what SubmitSwapOrder persists from the
// taker's V4 SqrtPriceLimitX96. The MEV-floor redteam test uses it to prove ImportSettlement
// enforces the RECORDED limit (taker-authenticated), independent of any keeper relay value.
func (h *settleHarness) seedSwapOrderLimit(owner common.Address, assetIn [32]byte, principal, deadline uint64, priceLimit uint64, limitIsUpper bool, id ids.ID) ids.ID {
	putSwapOrderRecord(newPoolStateAdapter(h.state), id, swapOrderRecord{
		Owner:        owner,
		AssetIn:      assetIn,
		Remaining:    principal,
		Deadline:     deadline,
		Status:       swapOrderOpen,
		PriceLimit:   priceLimit,
		LimitIsUpper: limitIsUpper,
	})
	return id
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
