// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"math/big"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/database/prefixdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/state"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/luxfi/vm/chains/atomic"
)

// conduit_reap_test.go is the INVERSION of native_zap_realstate_test.go and the proof of
// LP-311 §5 (the gate to live): the OLD test proves the nonce MARKER is REQUIRED — that
// 0x9999's OWN seamReserve/dexcore storage survives Finalise(true) only because the marker
// keeps the account non-empty. This proves the STATELESS CONDUIT needs NO marker: it writes
// ZERO durable 0x9999 storage, so an empty 0x9999 is reaped at Finalise(true) as a NO-OP
// while the escrow (the token's trie) and the claim (a D-Chain ledger row reached via the
// HOST atomic backend) are intact and withdrawable.
//
// It runs the REAL production money path: a REAL luxfi/geth *state.StateDB with EIP-158 on
// (Finalise(deleteEmptyObjects=true) — the exact reaping point), a REAL vm.EVM Call seam
// (transferFrom on a REAL deployed ERC-20), and a REAL atomic.SharedMemory bridging C and a
// minimal-but-real D-Chain ledger venue. Nothing is mocked on the value path.

// ───────────────── the HOST atomic-staging backend (contract.AtomicStager) ─────────────────

// hostStagingAccount is the host's NON-EMPTY atomic-staging account — the "host atomic
// backend" of LP-311 §5(c). It is NOT 0x9999 (the conduit) and NOT a precompile: it is a
// plain host system account the host keeps non-empty (a nonce marker on THIS account, never
// the conduit's), so the revert-safe staged ops it holds survive Finalise(true). This mirrors
// what the production evm host adapter does; relocating the marker here — onto a genuinely
// stateful host component — is LP-311 §7's sanctioned "non-empty account" option, NOT the
// rejected workaround of marking the stateless conduit.
var hostStagingAccount = common.HexToAddress("0x0000000000000000000000000000000000009994")

// hostStager is a faithful in-test contract.AtomicStager backed by the REAL *state.StateDB
// (revert-safe, durable, journaled EVM state) for the staging record + a REAL
// atomic.SharedMemory for the eventual Accept-time flush. Both legs are exactly the
// production host adapter's: StageExport records a revert-safe C->D Put; ConsumeImport reads
// a D->C object from shared memory and records a revert-safe Remove; flush applies the window
// to shared memory (the platformvm acceptor pattern).
type hostStager struct {
	gdb      *state.StateDB
	cSM      atomic.SharedMemory // this (C) chain's shared-memory handle
	dChainID ids.ID
	staged   []stagedAtomicOp
}

type stagedAtomicOp struct {
	put    bool
	key    ids.ID
	object []byte // for puts
	owner  common.Address
}

// stageRecordKey derives a host-account storage slot for the staged op at `seq`. The record
// lives in the HOST account's storage (revert-safe + durable), keyed by a monotonic seq —
// the same seq-window mechanism the production staging uses, just relocated off 0x9999.
func stageRecordKey(seq uint64, word int) common.Hash {
	id := make([]byte, 16)
	putU64(id[0:8], seq)
	putU64(id[8:16], uint64(word))
	return makeStorageKey([]byte("lux.dex.hoststaging.v1"), id)
}

// ensureHostNonEmpty keeps the HOST staging account non-empty so EIP-158 never reaps the
// staged records. The marker is on the HOST account — never the conduit 0x9999.
func (h *hostStager) ensureHostNonEmpty() {
	if h.gdb.GetNonce(hostStagingAccount) == 0 {
		h.gdb.SetNonce(hostStagingAccount, 1, tracing.NonceChangeUnspecified)
	}
}

func (h *hostStager) StageExport(dst ids.ID, key ids.ID, object []byte) error {
	if dst != h.dChainID {
		return ErrConduitNoDPeer
	}
	if _, _, _, _, _, ok := decodeAtomicObject(object); !ok {
		return ErrConduitBadObject
	}
	owner := common.BytesToAddress(object[1:21])
	h.ensureHostNonEmpty()
	seq := uint64(len(h.staged))
	// Revert-safe durable record in the HOST account storage (NOT 0x9999): key(32)|object.
	h.gdb.SetState(hostStagingAccount, stageRecordKey(seq, 0), common.BytesToHash(key[:]))
	for i := 0; i*32 < len(object); i++ {
		var w common.Hash
		end := (i + 1) * 32
		if end > len(object) {
			end = len(object)
		}
		copy(w[:], object[i*32:end])
		h.gdb.SetState(hostStagingAccount, stageRecordKey(seq, i+1), w)
	}
	h.staged = append(h.staged, stagedAtomicOp{put: true, key: key, object: object, owner: owner})
	return nil
}

func consumedMarkerKey(src, key ids.ID) common.Hash {
	id := make([]byte, 0, 64)
	id = append(id, src[:]...)
	id = append(id, key[:]...)
	return makeStorageKey([]byte("lux.dex.hoststaging.consumed.v1"), id)
}

func (h *hostStager) ConsumeImport(src ids.ID, key ids.ID) ([]byte, bool, error) {
	if src != h.dChainID {
		return nil, false, ErrConduitNoDPeer
	}
	// EXACTLY-ONCE (within-block): the staged Remove only lands at flush/Accept, so a re-consume
	// of the same (src,key) this block must be rejected — else escrow releases twice (a mint).
	if h.gdb.GetState(hostStagingAccount, consumedMarkerKey(src, key)) != (common.Hash{}) {
		return nil, false, nil
	}
	vals, err := h.cSM.Get(src, [][]byte{key[:]})
	if err != nil || len(vals) == 0 || vals[0] == nil {
		return nil, false, nil
	}
	h.ensureHostNonEmpty()
	h.gdb.SetState(hostStagingAccount, consumedMarkerKey(src, key), common.Hash{31: 1})
	seq := uint64(len(h.staged))
	h.gdb.SetState(hostStagingAccount, stageRecordKey(seq, 0), common.BytesToHash(key[:]))
	h.staged = append(h.staged, stagedAtomicOp{put: false, key: key})
	return vals[0], true, nil
}

// flush applies the staged window to shared memory — the host's Accept-time cross-domain
// commit. C-side ops are all keyed by the D peer: a Put makes the C->D object readable by D
// (dSM.Get(cChain, key)); a Remove consumes a D->C object C read from D's partition.
func (h *hostStager) flush() error {
	if len(h.staged) == 0 {
		return nil
	}
	req := &atomic.Requests{}
	for _, op := range h.staged {
		if op.put {
			req.PutRequests = append(req.PutRequests, &atomic.Element{
				Key:    append([]byte(nil), op.key[:]...),
				Value:  append([]byte(nil), op.object...),
				Traits: [][]byte{append([]byte(nil), op.owner[:]...)},
			})
		} else {
			req.RemoveRequests = append(req.RemoveRequests, append([]byte(nil), op.key[:]...))
		}
	}
	h.staged = nil
	return h.cSM.Apply(map[ids.ID]*atomic.Requests{h.dChainID: req})
}

// ───────────────── the conduit's AccessibleState (real env + AtomicStager) ─────────────────

// conduitState implements contract.AccessibleState + AtomicState + AtomicStager over the
// REAL geth EVM env and StateDB, so conduitForwardCredit/conduitApplyRelease run unchanged
// against the real host with a real cross-chain transport.
type conduitState struct {
	sdb       *rsStateDB
	env       *rsEnv
	stager    *hostStager
	networkID uint32
	cChainID  ids.ID
	dChainID  ids.ID
}

func (s *conduitState) GetStateDB() contract.StateDB { return s.sdb }
func (s *conduitState) GetBlockContext() contract.BlockContext {
	return &rsBlockCtx{num: big.NewInt(1), ts: 1}
}
func (s *conduitState) GetConsensusContext() context.Context             { return context.Background() }
func (s *conduitState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (s *conduitState) GetPrecompileEnv() contract.PrecompileEnvironment { return s.env }

func (s *conduitState) AtomicMemory() atomic.SharedMemory    { return s.stager.cSM }
func (s *conduitState) NetworkID() uint32                    { return s.networkID }
func (s *conduitState) ChainID() ids.ID                      { return s.cChainID }
func (s *conduitState) CChainID() ids.ID                     { return s.cChainID }
func (s *conduitState) GovernanceController() common.Address { return common.Address{} }
func (s *conduitState) DChainID() ids.ID                     { return s.dChainID }
func (s *conduitState) TxID() ids.ID                         { return ids.ID(s.sdb.TxHash()) }
func (s *conduitState) CallIndex() uint32                    { return 0 }

func (s *conduitState) StageExport(dst, key ids.ID, object []byte) error {
	return s.stager.StageExport(dst, key, object)
}
func (s *conduitState) ConsumeImport(src, key ids.ID) ([]byte, bool, error) {
	return s.stager.ConsumeImport(src, key)
}

var (
	_ contract.AccessibleState = (*conduitState)(nil)
	_ contract.AtomicState     = (*conduitState)(nil)
	_ contract.AtomicStager    = (*conduitState)(nil)
)

// ───────────────── a minimal, REAL D-Chain ledger venue over shared memory ─────────────────

// dVenue is a faithful, minimal D-Chain venue: it consumes C->D objects from REAL shared
// memory and credits a checked-int ledger (mirroring dex/pkg/dchain state.go balance:), and
// exports D->C release objects. It is NOT the full consensus VM (whose own correctness is
// proven by dex/pkg/dchain/conservation_test.go); it is exactly enough to prove the CONDUIT
// side conserves value across the boundary with no mint and no loss.
type dVenue struct {
	dSM      atomic.SharedMemory
	cChainID ids.ID
	ledger   map[string]uint64 // owner(20)||asset(32) -> available
	nextRef  uint64
}

func ledgerKey(owner common.Address, asset [32]byte) string {
	var b [52]byte
	copy(b[0:20], owner[:])
	copy(b[20:52], asset[:])
	return string(b[:])
}

// importCredit consumes a C->D object by id (the deposit's intent id): it reads the recorded
// object, credits the owner's ledger by the recorded amount, and REMOVES the object (consume-
// once). Returns the credited amount. Conservation: credits EXACTLY the recorded amount.
func (d *dVenue) importCredit(t *testing.T, intentID ids.ID) uint64 {
	t.Helper()
	vals, err := d.dSM.Get(d.cChainID, [][]byte{intentID[:]})
	if err != nil || len(vals) == 0 || vals[0] == nil {
		t.Fatalf("dVenue.importCredit: no C->D object for %s (err=%v)", intentID, err)
	}
	rail, owner, asset, amount, _, ok := decodeAtomicObject(vals[0])
	if !ok || rail != railSwap {
		t.Fatalf("dVenue.importCredit: bad object rail=%d ok=%v", rail, ok)
	}
	d.ledger[ledgerKey(owner, asset)] += amount
	// consume-once: remove the C->D object from shared memory.
	if err := d.dSM.Apply(map[ids.ID]*atomic.Requests{d.cChainID: {RemoveRequests: [][]byte{intentID[:]}}}); err != nil {
		t.Fatalf("dVenue.importCredit remove: %v", err)
	}
	return amount
}

// exportRelease debits the owner's ledger by amount (fail-closed: never below zero) and Puts
// a D->C release object into shared memory under a fresh ref. Returns the ref the conduit
// consumes. Conservation: debits EXACTLY what it releases.
func (d *dVenue) exportRelease(t *testing.T, owner common.Address, asset [32]byte, amount uint64) ids.ID {
	t.Helper()
	have := d.ledger[ledgerKey(owner, asset)]
	if have < amount {
		t.Fatalf("dVenue.exportRelease: ledger short (have %d, want %d) — would mint", have, amount)
	}
	d.ledger[ledgerKey(owner, asset)] = have - amount
	d.nextRef++
	var ref ids.ID
	ref[0], ref[1] = 0xD0, 0xC0
	putU64(ref[24:32], d.nextRef)
	obj := encodeAtomicObject(railSwap, owner, asset, amount)
	if err := d.dSM.Apply(map[ids.ID]*atomic.Requests{d.cChainID: {PutRequests: []*atomic.Element{{
		Key:    append([]byte(nil), ref[:]...),
		Value:  obj,
		Traits: [][]byte{append([]byte(nil), owner[:]...)},
	}}}}); err != nil {
		t.Fatalf("dVenue.exportRelease put: %v", err)
	}
	return ref
}

// ───────────────────────────────────────── harness wiring ─────────────────────────────────

// conduitHarness bundles the rsHarness (real EVM/StateDB/tokens) with the real cross-chain
// shared memory, the host stager, and the minimal D venue.
type conduitHarness struct {
	*rsHarness
	cSM      atomic.SharedMemory
	dChainID ids.ID
	stager   *hostStager
	venue    *dVenue
}

func newConduitHarness(t *testing.T) *conduitHarness {
	t.Helper()
	h := newRSHarness(t)
	baseDB := memdb.New()
	m := atomic.NewMemory(prefixdb.New([]byte{0}, baseDB))
	dChainID := ids.ID{0xDD}
	cSM := m.NewSharedMemory(h.cChainID)
	dSM := m.NewSharedMemory(dChainID)
	stager := &hostStager{gdb: h.gdb, cSM: cSM, dChainID: dChainID}
	venue := &dVenue{dSM: dSM, cChainID: h.cChainID, ledger: map[string]uint64{}}
	return &conduitHarness{rsHarness: h, cSM: cSM, dChainID: dChainID, stager: stager, venue: venue}
}

// state builds a conduitState with `caller` as msg.sender, over the real env (so the ERC-20
// escrow legs sub-call the token), exactly as the registry bridge wires the production path.
func (h *conduitHarness) state(caller common.Address) *conduitState {
	h.newTxCtx()
	env := vm.NewPrecompileEnvironment(h.evm, caller, poolManagerAddr9999, rsGas, false)
	return &conduitState{
		sdb:       &rsStateDB{h.gdb},
		env:       &rsEnv{inner: env},
		stager:    h.stager,
		networkID: h.networkID,
		cChainID:  h.cChainID,
		dChainID:  h.dChainID,
	}
}

// is9999Empty reports the EIP-158 empty() predicate on 0x9999 exactly: nonce==0 ∧ balance==0
// ∧ codeHash==∅ (storage is NOT part of the test). When true, Finalise(true) reaps 0x9999.
func (h *conduitHarness) is9999Empty() bool {
	return h.gdb.GetNonce(poolManagerAddr9999) == 0 &&
		h.gdb.GetBalance(poolManagerAddr9999).IsZero() &&
		h.gdb.GetCodeSize(poolManagerAddr9999) == 0
}

// ─────────────────────────────────────────── THE TESTS ────────────────────────────────────

// TestConduit_OwnStorageReapIsNoOp_RealStateDB is the LP-311 §5 proof. It drives the
// stateless conduit's ERC-20 deposit→(D credit)→withdraw over a REAL *state.StateDB with
// EIP-158 on and a REAL cross-chain shared memory, asserting at every step that 0x9999 holds
// ZERO reapable own storage, is EMPTY, and is reaped at Finalise(true) as a NO-OP — while the
// escrow (token trie) and the D-backed claim are intact and withdrawable.
func TestConduit_OwnStorageReapIsNoOp_RealStateDB(t *testing.T) {
	h := newConduitHarness(t)
	const amount = 100_000
	var market [32]byte
	market[0] = 0x4D // 'M'

	// ── DEPOSIT: maker escrows QUOTE into the conduit and forwards a C->D credit. This is the
	// EXACT shape of the live bug (ERC-20 deposit on an empty 0x9999) — done with ZERO 0x9999
	// storage write.
	h.approve9999(h.maker, h.quote, big.NewInt(amount))
	st := h.state(h.maker)
	seam, err := resolveConduitSeam(st)
	if err != nil {
		t.Fatalf("resolveConduitSeam: %v", err)
	}
	intentID, err := conduitForwardCredit(st, seam, h.maker, Currency{Address: h.quote}, amount, market, 1)
	if err != nil {
		t.Fatalf("conduitForwardCredit: %v", err)
	}

	// THE INVARIANT (pre-commit): the conduit wrote NO 0x9999 storage. seamReserve[quote]==0
	// (the OLD ledger slot is untouched), the OLD 0x9999 staging seq is 0 (staging went to the
	// HOST account), and 0x9999 is EMPTY (ERC-20 deposit gave it no native balance).
	if got := h.seam(h.quote); got != 0 {
		t.Fatalf("conduit wrote seamReserve[quote]=%d to 0x9999 — must be 0 (D holds the ledger)", got)
	}
	if seq := stageSeq(newPoolStateAdapter(st)); seq != 0 {
		t.Fatalf("conduit staged to 0x9999 (seq=%d) — staging must go to the HOST account", seq)
	}
	if !h.is9999Empty() {
		t.Fatalf("0x9999 is NOT empty after ERC-20 deposit — the conduit wrote own state (balance=%s nonce=%d codeSize=%d)",
			h.gdb.GetBalance(poolManagerAddr9999), h.gdb.GetNonce(poolManagerAddr9999), h.gdb.GetCodeSize(poolManagerAddr9999))
	}
	// The escrow is REAL: the token sits in 0x9999's slot of the TOKEN's trie.
	if got := h.ercBal(h.quote, poolManagerAddr9999); got != amount {
		t.Fatalf("escrow balanceOf(quote,0x9999)=%d, want %d (the token must be in the vault)", got, amount)
	}
	// The staged C->D object lives in the HOST account (non-empty), NOT 0x9999.
	if h.gdb.GetNonce(hostStagingAccount) == 0 {
		t.Fatalf("host staging account is empty — the staged C->D object would be reaped")
	}

	// ── THE REAP: production end-of-tx commit (Finalise(deleteEmptyObjects=true)). 0x9999 is
	// empty, so it is DELETED — and that is a NO-OP: nothing of the conduit's was there.
	h.commit()
	if got := h.ercBal(h.quote, poolManagerAddr9999); got != amount {
		t.Fatalf("BUG: escrow balanceOf(quote,0x9999)=%d after Finalise(true), want %d — escrow lost?", got, amount)
	}
	if got := h.seam(h.quote); got != 0 {
		t.Fatalf("seamReserve[quote]=%d after reap — conduit must hold no ledger", got)
	}

	// ── FLUSH → D credits the maker (the host Accept-time cross-domain commit). Conservation:
	// the D ledger credits EXACTLY the escrow.
	if err := h.stager.flush(); err != nil {
		t.Fatalf("host atomic flush: %v", err)
	}
	credited := h.venue.importCredit(t, intentID)
	if credited != amount {
		t.Fatalf("D credited %d, want %d (the recorded escrow)", credited, amount)
	}
	if got := h.venue.ledger[ledgerKey(h.maker, assetID(Currency{Address: h.quote}))]; got != amount {
		t.Fatalf("D ledger[maker][quote]=%d, want %d", got, amount)
	}
	// CONSERVATION across the boundary: Σ escrow(quote) == Σ D-backed-releasable(quote).
	if escrow := h.ercBal(h.quote, poolManagerAddr9999); escrow != amount {
		t.Fatalf("conservation: escrow=%d, D-releasable=%d — must be equal", escrow, amount)
	}

	// ── WITHDRAW: D debits its ledger and exports a D->C release; the conduit consumes it and
	// pushes the token back to the maker. Still ZERO 0x9999 storage.
	releaseRef := h.venue.exportRelease(t, h.maker, assetID(Currency{Address: h.quote}), amount)
	st2 := h.state(h.maker)
	seam2, err := resolveConduitSeam(st2)
	if err != nil {
		t.Fatalf("resolveConduitSeam(withdraw): %v", err)
	}
	tokenFor := func(a [32]byte) (common.Address, bool) {
		if a == assetID(Currency{Address: h.quote}) {
			return h.quote, true
		}
		return common.Address{}, false
	}
	makerQuoteBefore := h.ercBal(h.quote, h.maker)
	owner, released, err := conduitApplyRelease(st2, seam2, releaseRef, tokenFor)
	if err != nil {
		t.Fatalf("conduitApplyRelease: %v", err)
	}
	if owner != h.maker || released != amount {
		t.Fatalf("release bound owner=%s amount=%d, want maker=%s amount=%d", owner, released, h.maker, amount)
	}
	// 0x9999 stays empty across the withdraw too (it never gained own storage).
	if !h.is9999Empty() {
		t.Fatalf("0x9999 not empty after withdraw — conduit wrote own state")
	}
	if err := h.stager.flush(); err != nil { // flush the consume's Remove.
		t.Fatalf("flush(withdraw): %v", err)
	}
	h.commit()

	// FUNDS WITHDRAWABLE: the maker's real QUOTE rose by exactly the deposit; the escrow is 0.
	if got := h.ercBal(h.quote, h.maker) - makerQuoteBefore; got != amount {
		t.Fatalf("maker QUOTE rose by %d after withdraw, want %d (funds not withdrawable)", got, amount)
	}
	if got := h.ercBal(h.quote, poolManagerAddr9999); got != 0 {
		t.Fatalf("escrow balanceOf(quote,0x9999)=%d after withdraw, want 0 (conservation: nothing stranded)", got)
	}
	if got := h.venue.ledger[ledgerKey(h.maker, assetID(Currency{Address: h.quote}))]; got != 0 {
		t.Fatalf("D ledger[maker][quote]=%d after withdraw, want 0", got)
	}
	t.Logf("LP-311 §5 PASS: ERC-20 deposit→D-credit→withdraw over real StateDB; 0x9999 held ZERO " +
		"own storage, was reaped at Finalise(true) as a no-op, escrow+claim intact, funds withdrawable, conservation held")
}

// TestConduit_ReapDiscriminator_HostAccountVsConduit is the crisp RED/GREEN discriminator:
// the SAME staged record is REAPED when written to the empty conduit (0x9999) and SURVIVES
// when written to the non-empty host account — proving the relocation, not a marker on the
// conduit, is what dissolves the hazard.
func TestConduit_ReapDiscriminator_HostAccountVsConduit(t *testing.T) {
	gdb, err := state.New(ethtypes.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	slot := makeStorageKey([]byte("lux.dex.reap.probe"), []byte{0x01})
	val := common.Hash{31: 0xAB}

	// RED — write to the EMPTY conduit 0x9999 (no marker): reaped at Finalise(true).
	gdb.SetTxContext(common.Hash{0x01}, 1)
	gdb.SetState(poolManagerAddr9999, slot, val)
	if gdb.GetState(poolManagerAddr9999, slot) != val {
		t.Fatalf("pre-commit: 0x9999 slot not set")
	}
	gdb.Finalise(true)
	if got := gdb.GetState(poolManagerAddr9999, slot); got != (common.Hash{}) {
		t.Fatalf("RED expectation broken: 0x9999 slot survived reaping (=%s) — the hazard is gone already?", got.Hex())
	}
	t.Logf("RED confirmed: an own-storage slot on the EMPTY 0x9999 is REAPED at Finalise(true) (the live bug)")

	// GREEN — write to the NON-EMPTY host staging account: survives Finalise(true).
	gdb.SetTxContext(common.Hash{0x02}, 2)
	gdb.SetNonce(hostStagingAccount, 1, tracing.NonceChangeUnspecified) // host marker on the HOST account
	gdb.SetState(hostStagingAccount, slot, val)
	gdb.Finalise(true)
	if got := gdb.GetState(hostStagingAccount, slot); got != val {
		t.Fatalf("GREEN broken: host-account staged record was reaped (=%s) — host account not kept non-empty", got.Hex())
	}
	// And the conduit, written nothing, is reap-immune by emptiness.
	if got := gdb.GetState(poolManagerAddr9999, slot); got != (common.Hash{}) {
		t.Fatalf("0x9999 unexpectedly holds storage")
	}
	t.Logf("GREEN confirmed: the SAME record on the NON-EMPTY host account SURVIVES Finalise(true); " +
		"the conduit holds nothing → reaping it is a no-op")
}

// TestConduit_DoubleConsumeRejected proves the within-block exactly-once guard: a second
// conduitApplyRelease of the SAME D->C object id (before the staged Remove flushes at Accept)
// finds nothing and releases NO escrow — closing the double-release mint hole. This is the
// adversarial case Red would drive: the object is still in shared memory until flush.
func TestConduit_DoubleConsumeRejected(t *testing.T) {
	h := newConduitHarness(t)
	const amount = 7_000
	asset := assetID(Currency{Address: h.quote})

	// Fund the conduit's escrow for the release (deposit path), credit the D ledger, and export
	// a single D->C release object.
	h.approve9999(h.maker, h.quote, big.NewInt(amount))
	st := h.state(h.maker)
	seam, err := resolveConduitSeam(st)
	if err != nil {
		t.Fatalf("resolveConduitSeam: %v", err)
	}
	var market [32]byte
	intentID, err := conduitForwardCredit(st, seam, h.maker, Currency{Address: h.quote}, amount, market, 1)
	if err != nil {
		t.Fatalf("conduitForwardCredit: %v", err)
	}
	h.commit()
	if err := h.stager.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	h.venue.importCredit(t, intentID)
	releaseRef := h.venue.exportRelease(t, h.maker, asset, amount)

	tokenFor := func(a [32]byte) (common.Address, bool) {
		if a == asset {
			return h.quote, true
		}
		return common.Address{}, false
	}

	// First consume: releases exactly `amount`.
	st2 := h.state(h.maker)
	seam2, _ := resolveConduitSeam(st2)
	before := h.ercBal(h.quote, h.maker)
	owner, released, err := conduitApplyRelease(st2, seam2, releaseRef, tokenFor)
	if err != nil || owner != h.maker || released != amount {
		t.Fatalf("first release: owner=%s released=%d err=%v (want maker, %d)", owner, released, err, amount)
	}

	// Second consume of the SAME ref, SAME block (Remove not yet flushed; object still in
	// shared memory). MUST find nothing and release NOTHING — else escrow is double-spent.
	_, _, err2 := conduitApplyRelease(st2, seam2, releaseRef, tokenFor)
	if err2 != ErrConduitNoFill {
		t.Fatalf("double-consume NOT rejected (err=%v) — escrow double-release / mint hole open", err2)
	}
	h.commit()

	// Net: the maker received exactly ONE `amount`, never two.
	if got := h.ercBal(h.quote, h.maker) - before; got != amount {
		t.Fatalf("maker received %d across a double-consume, want exactly %d (no double release)", got, amount)
	}
	t.Logf("exactly-once PASS: second consume of the same D->C ref in-block found nothing, "+
		"released 0; maker netted exactly %d (no mint)", amount)
}
