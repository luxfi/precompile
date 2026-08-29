// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/vm/chains/atomic"
)

// zzblueA_dchain_test.go pins the MONEY-IN path (native_zap.go's two-phase lock/commit),
// its D->C credit siblings (native_dchain_client.go), and the closed-on-ramp refusals
// (dchain_client.go).
//
// The property under test throughout is the NATIVE-ZAP discipline: no 0x9999 self-write
// may follow a nested EVM call. A test that only checks the RESULT of a lock cannot see
// that discipline break — the balances land either way. So the fakes here record the
// ORDERED SEQUENCE of effects (0x9999 storage writes, the record callback, and each
// token sub-call) and the assertions are on that ordering, not merely on the outcome.

// ─────────────────────────── ordered-effect fakes ───────────────────────────

// blueAKV is a minimal dex.StateDB that records the order of its effects. It
// deliberately implements NEITHER erc20Vault NOR nonceMarker, so it is the input that
// drives the ErrNativeERC20Vault arm and ensureVaultAccountPersists' no-op arm. Balance
// arithmetic is uint256-MODULAR (exactly like the production SubBalance from a
// precompile), so an unguarded underflow WRAPS here rather than being caught by the
// fake — which is what makes the vault-underflow assertions meaningful.
type blueAKV struct {
	slots map[common.Address]map[common.Hash]common.Hash
	bal   map[common.Address]*uint256.Int
	live  map[common.Address]bool
	logs  []*ethtypes.Log
	ops   []string
}

func blueANewKV() *blueAKV {
	return &blueAKV{
		slots: map[common.Address]map[common.Hash]common.Hash{},
		bal:   map[common.Address]*uint256.Int{},
		live:  map[common.Address]bool{},
	}
}

func (k *blueAKV) GetState(addr common.Address, key common.Hash) common.Hash {
	return k.slots[addr][key]
}

func (k *blueAKV) SetState(addr common.Address, key, value common.Hash) {
	if k.slots[addr] == nil {
		k.slots[addr] = map[common.Hash]common.Hash{}
	}
	k.slots[addr][key] = value
	if addr == poolManagerAddr9999 {
		k.ops = append(k.ops, "set9999")
	}
}

func (k *blueAKV) GetBalance(addr common.Address) *uint256.Int {
	if v, ok := k.bal[addr]; ok {
		return v
	}
	return uint256.NewInt(0)
}

func (k *blueAKV) AddBalance(addr common.Address, amount *uint256.Int) {
	k.bal[addr] = new(uint256.Int).Add(k.GetBalance(addr), amount)
	k.ops = append(k.ops, "addBalance")
}

func (k *blueAKV) SubBalance(addr common.Address, amount *uint256.Int) {
	k.bal[addr] = new(uint256.Int).Sub(k.GetBalance(addr), amount) // modular, as in production
	k.ops = append(k.ops, "subBalance")
}

func (k *blueAKV) Exist(addr common.Address) bool        { return k.live[addr] }
func (k *blueAKV) CreateAccount(addr common.Address)     { k.live[addr] = true }
func (k *blueAKV) GetBlockNumber() uint64                { return 1 }
func (k *blueAKV) AddLog(log *ethtypes.Log)              { k.logs = append(k.logs, log) }
func (k *blueAKV) setBalance(a common.Address, v uint64) { k.bal[a] = uint256.NewInt(v) }

var _ StateDB = (*blueAKV)(nil)

// blueAVaultDB adds the erc20Vault capability to blueAKV. `delivered` chooses how much
// of a requested transfer the recipient ACTUALLY receives, which is how the
// under-delivery boundary (a fee-on-transfer token) is swept.
type blueAVaultDB struct {
	*blueAKV
	tok       map[common.Address]map[common.Address]*big.Int
	delivered func(*big.Int) *big.Int
	failXfer  bool
}

func blueANewVaultDB() *blueAVaultDB {
	return &blueAVaultDB{
		blueAKV: blueANewKV(),
		tok:     map[common.Address]map[common.Address]*big.Int{},
	}
}

func (v *blueAVaultDB) bag(token, holder common.Address) *big.Int {
	if v.tok[token] == nil {
		v.tok[token] = map[common.Address]*big.Int{}
	}
	if v.tok[token][holder] == nil {
		v.tok[token][holder] = big.NewInt(0)
	}
	return v.tok[token][holder]
}

// mint resets a token's ledger and gives holder exactly amount.
func (v *blueAVaultDB) mint(token, holder common.Address, amount int64) {
	v.tok[token] = map[common.Address]*big.Int{holder: big.NewInt(amount)}
}

func (v *blueAVaultDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	v.ops = append(v.ops, "balanceOf")
	return new(big.Int).Set(v.bag(token, owner))
}

func (v *blueAVaultDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	v.ops = append(v.ops, "transferFrom")
	if v.failXfer {
		return errors.New("blueA: token reverted")
	}
	if v.bag(token, from).Cmp(amount) < 0 {
		return errors.New("blueA: insufficient token balance")
	}
	got := amount
	if v.delivered != nil {
		got = v.delivered(amount)
	}
	v.tok[token][from] = new(big.Int).Sub(v.bag(token, from), amount)
	v.tok[token][to] = new(big.Int).Add(v.bag(token, to), got)
	return nil
}

func (v *blueAVaultDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	v.ops = append(v.ops, "transferTo")
	if v.failXfer {
		return errors.New("blueA: token reverted")
	}
	if v.bag(token, poolManagerAddr9999).Cmp(amount) < 0 {
		return errors.New("blueA: vault holds too little")
	}
	v.tok[token][poolManagerAddr9999] = new(big.Int).Sub(v.bag(token, poolManagerAddr9999), amount)
	v.tok[token][to] = new(big.Int).Add(v.bag(token, to), amount)
	return nil
}

var (
	_ StateDB    = (*blueAVaultDB)(nil)
	_ erc20Vault = (*blueAVaultDB)(nil)
)

// blueANonceDB is blueAKV plus the OPTIONAL nonceMarker capability, so the
// vault-account persistence marker can be observed (and its idempotence pinned).
type blueANonceDB struct {
	*blueAKV
	nonces map[common.Address]uint64
}

func blueANewNonceDB() *blueANonceDB {
	return &blueANonceDB{blueAKV: blueANewKV(), nonces: map[common.Address]uint64{}}
}

func (n *blueANonceDB) GetNonce(addr common.Address) uint64 { return n.nonces[addr] }

func (n *blueANonceDB) SetNonce(addr common.Address, nonce uint64) {
	n.nonces[addr] = nonce
	n.ops = append(n.ops, "setNonce")
}

var _ nonceMarker = (*blueANonceDB)(nil)

// ─────────────────────────── trace helpers ───────────────────────────

func blueACount(ops []string, want string) int {
	n := 0
	for _, o := range ops {
		if o == want {
			n++
		}
	}
	return n
}

// blueAFirst / blueALast return the first / last index of an op, or -1.
func blueAFirst(ops []string, want string) int {
	for i, o := range ops {
		if o == want {
			return i
		}
	}
	return -1
}

func blueALast(ops []string, want string) int {
	last := -1
	for i, o := range ops {
		if o == want {
			last = i
		}
	}
	return last
}

// blueAAssertTerminalPull is THE native-zap property: the ERC-20 transferFrom is the
// frame's terminal external effect, with every 0x9999 accounting write already done.
// It fails if any 0x9999 write follows the pull — the exact shape of the dropped-write
// fund-strand this module exists to dissolve.
func blueAAssertTerminalPull(t *testing.T, ops []string) {
	t.Helper()
	pull := blueAFirst(ops, "transferFrom")
	if pull < 0 {
		t.Fatalf("no terminal transferFrom in trace %v", ops)
	}
	if n := blueACount(ops, "transferFrom"); n != 1 {
		t.Fatalf("want exactly 1 transferFrom, got %d in %v", n, ops)
	}
	writes := blueALast(ops, "set9999")
	if writes < 0 {
		t.Fatalf("no 0x9999 accounting write in trace %v", ops)
	}
	if writes > pull {
		t.Fatalf("0x9999 write at %d FOLLOWS the terminal transferFrom at %d: %v", writes, pull, ops)
	}
	// The only effects after the pull are the delivery check's own balance read.
	for _, o := range ops[pull+1:] {
		if o != "balanceOf" {
			t.Fatalf("effect %q follows the terminal transferFrom: %v", o, ops)
		}
	}
}

// ─────────────────────────── production-path env ───────────────────────────

// blueATraceDB is the harness contract.StateDB with an ordered trace on the two things
// whose relative order is the whole point: 0x9999 storage writes and token sub-calls.
// Everything else is inherited, so this observes the REAL adapter path.
type blueATraceDB struct {
	*contractStateDBWrapper
	ops []string
}

func (w *blueATraceDB) SetState(addr common.Address, key, value common.Hash) common.Hash {
	if addr == poolManagerAddr9999 {
		w.ops = append(w.ops, "set9999")
	}
	return w.contractStateDBWrapper.SetState(addr, key, value)
}

func (w *blueATraceDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	w.ops = append(w.ops, "balanceOf")
	return w.contractStateDBWrapper.TokenBalanceOf(token, owner)
}

func (w *blueATraceDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	w.ops = append(w.ops, "transferFrom")
	return w.contractStateDBWrapper.TransferTokenFrom(token, from, to, amount)
}

func (w *blueATraceDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	w.ops = append(w.ops, "transferTo")
	return w.contractStateDBWrapper.TransferTokenTo(token, to, amount)
}

// blueAEnv is a self-contained C<->D environment: a real atomic shared memory (both
// sides), a mock StateDB behind the tracing wrapper, and the AccessibleState +
// AtomicState surface the client methods take. It installs NO package globals, so
// every test using it is order-independent.
// The chain ids are the EMBEDDED nativeAtomicState's own fields (promoted, never
// shadowed) so that closing the seam in a test — e.dChainID = ids.Empty — changes the
// value DChainID() actually reports.
type blueAEnv struct {
	*nativeAtomicState
	db       *blueATraceDB
	cSM, dSM atomic.SharedMemory
}

func (e *blueAEnv) GetStateDB() contract.StateDB { return e.db }

func blueANewEnv(t *testing.T) *blueAEnv {
	t.Helper()
	cChainID, dChainID := ids.ID{0xCC}, ids.ID{0xDD}
	mem := atomic.NewMemory(memdb.New())
	mock := NewMockStateDB()
	e := &blueAEnv{
		nativeAtomicState: &nativeAtomicState{
			stateDB:        mock,
			sm:             mem.NewSharedMemory(cChainID),
			networkID:      1,
			chainID:        cChainID,
			cChainID:       cChainID,
			dChainID:       dChainID,
			governance:     testGovernance,
			txID:           ids.ID{0x7A},
			blockTimestamp: harnessBlockTime,
		},
		db:  &blueATraceDB{contractStateDBWrapper: &contractStateDBWrapper{inner: mock}},
		dSM: mem.NewSharedMemory(dChainID),
	}
	e.cSM = e.sm
	return e
}

var (
	_ contract.AccessibleState = (*blueAEnv)(nil)
	_ contract.AtomicState     = (*blueAEnv)(nil)
)

// kv is the adapter every client method builds internally — the same view the tests
// read state back through.
func (e *blueAEnv) kv() *poolStateAdapter { return newPoolStateAdapter(e) }

// putD stages a D->C object under the C partition (what the dexvm's export does), so
// the C-side consume paths read it via Get(dChainID, key).
func (e *blueAEnv) putD(t *testing.T, key ids.ID, value []byte) {
	t.Helper()
	if err := e.dSM.Apply(map[ids.ID]*atomic.Requests{
		e.cChainID: {PutRequests: []*atomic.Element{{Key: key[:], Value: value, Traits: [][]byte{}}}},
	}); err != nil {
		t.Fatalf("putD: %v", err)
	}
}

var blueAAlice = common.HexToAddress("0xA11CE00000000000000000000000000000000001")
var blueABob = common.HexToAddress("0xB0B0000000000000000000000000000000000002")
var blueAToken = common.HexToAddress("0x00000000000000000000000000000000000000CC")

// TestBlueAEnsureVaultAccountPersists pins property (9): the marker only ever bumps a
// ZERO nonce (idempotent, and it never overwrites a real nonce), and a StateDB that
// models no empty-account reaping is a safe no-op rather than a panic.
func TestBlueAEnsureVaultAccountPersists(t *testing.T) {
	t.Run("no nonceMarker is a no-op", func(t *testing.T) {
		db := blueANewKV()
		ensureVaultAccountPersists(db)
		if len(db.ops) != 0 || len(db.slots) != 0 {
			t.Fatalf("marker touched a non-nonceMarker StateDB: ops=%v slots=%v", db.ops, db.slots)
		}
	})

	t.Run("zero nonce is bumped once", func(t *testing.T) {
		db := blueANewNonceDB()
		ensureVaultAccountPersists(db)
		if got := db.nonces[poolManagerAddr9999]; got != 1 {
			t.Fatalf("nonce = %d after first mark, want 1", got)
		}
		ensureVaultAccountPersists(db)
		if got := db.nonces[poolManagerAddr9999]; got != 1 {
			t.Fatalf("nonce = %d after second mark, want 1 (idempotent)", got)
		}
		if n := blueACount(db.ops, "setNonce"); n != 1 {
			t.Fatalf("SetNonce called %d times, want 1 (idempotent)", n)
		}
	})

	t.Run("a live nonce is never overwritten", func(t *testing.T) {
		db := blueANewNonceDB()
		db.nonces[poolManagerAddr9999] = 7
		ensureVaultAccountPersists(db)
		if got := db.nonces[poolManagerAddr9999]; got != 7 {
			t.Fatalf("nonce = %d, want 7 (only a zero nonce is bumped)", got)
		}
		if n := blueACount(db.ops, "setNonce"); n != 0 {
			t.Fatalf("SetNonce called %d times on a live nonce, want 0", n)
		}
	})
}

// ═══════════════ native_dchain_client.go — the D->C credit helpers ═══════════════

// ═══════════════ native_dchain_client.go — the closed-seam refusals ═══════════════

// ═══════════════ the closed on-ramp: the synchronous Engine surface ═══════════════

// blueAEngineRefuses drives every Engine method and asserts it refuses with
// ErrDChainUnavailable, returns a ZERO delta, and mutates neither the pool it is handed
// nor the caller's view of it. Quote is the one benign exception: it returns zero rather
// than an error so a router treats it as "no route" instead of a failure.
func blueAEngineRefuses(t *testing.T, name string, eng Engine) {
	t.Helper()
	pool := &Pool{
		SqrtPriceX96: new(big.Int).Set(Q96), Tick: 42, Liquidity: big.NewInt(1_000),
		FeeGrowth0X128: big.NewInt(1), FeeGrowth1X128: big.NewInt(2),
		ProtocolFees0: big.NewInt(3), ProtocolFees1: big.NewInt(4),
	}
	before := *pool
	ps := NewPoolState(pool, 60, 3000)

	if tick, err := eng.Initialize(new(big.Int).Set(Q96)); !errors.Is(err, ErrDChainUnavailable) || tick != 0 {
		t.Fatalf("%s.Initialize = (%d, %v), want (0, ErrDChainUnavailable)", name, tick, err)
	}
	delta, err := eng.Swap(ps, blueAAlice, SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-100)})
	if !errors.Is(err, ErrDChainUnavailable) || !delta.IsZero() {
		t.Fatalf("%s.Swap = (%v, %v), want (zero, ErrDChainUnavailable)", delta, err, name)
	}
	d0, d1, merr := eng.ModifyLiquidity(ps, blueAAlice, ModifyLiquidityParams{LiquidityDelta: big.NewInt(5)})
	if !errors.Is(merr, ErrDChainUnavailable) || !d0.IsZero() || !d1.IsZero() {
		t.Fatalf("%s.ModifyLiquidity = (%v, %v, %v), want (zero, zero, ErrDChainUnavailable)", name, d0, d1, merr)
	}
	dd, derr := eng.Donate(ps, big.NewInt(7), big.NewInt(8))
	if !errors.Is(derr, ErrDChainUnavailable) || !dd.IsZero() {
		t.Fatalf("%s.Donate = (%v, %v), want (zero, ErrDChainUnavailable)", name, dd, derr)
	}
	// Quote is a read-only estimate: a benign zero, NOT an error, so router fallbacks
	// treat the absent chain as "no route" rather than a hard failure.
	q := eng.Quote(pool, big.NewInt(1_000), true)
	if q == nil || q.Sign() != 0 {
		t.Fatalf("%s.Quote = %v, want a non-nil zero", name, q)
	}
	if eng.Brand() == "" {
		t.Fatalf("%s.Brand is empty", name)
	}
	// A refusal moves no value: the pool it was handed is byte-identical.
	if pool.Tick != before.Tick ||
		pool.SqrtPriceX96.Cmp(before.SqrtPriceX96) != 0 ||
		pool.Liquidity.Cmp(before.Liquidity) != 0 ||
		pool.FeeGrowth0X128.Cmp(before.FeeGrowth0X128) != 0 ||
		pool.FeeGrowth1X128.Cmp(before.FeeGrowth1X128) != 0 ||
		pool.ProtocolFees0.Cmp(before.ProtocolFees0) != 0 ||
		pool.ProtocolFees1.Cmp(before.ProtocolFees1) != 0 {
		t.Fatalf("%s mutated the pool it refused: %+v -> %+v", name, before, *pool)
	}
	if len(ps.Positions) != 0 || len(ps.Ticks) != 0 {
		t.Fatalf("%s created position/tick state on a refusal", name)
	}
}

// TestBlueAClosedOnRampRefusesEveryEngineOp: BOTH closed-on-ramp clients — the
// no-local-D-Chain default and the native seam's deprecated synchronous surface — refuse
// every Engine operation identically. This is the fail-closed default a node runs with no
// local D-Chain: it never fabricates a fill.
func TestBlueAClosedOnRampRefusesEveryEngineOp(t *testing.T) {
	blueAEngineRefuses(t, "dchainUnavailable", newDChainUnavailable())
	blueAEngineRefuses(t, "NativeDChainClient", NewNativeDChainClient("Blue A DEX"))
}

// TestBlueANativeClientBrand: the brand is the white-label identity; an empty brand falls
// back to the OSS default rather than surfacing as an empty string in logs.
func TestBlueANativeClientBrand(t *testing.T) {
	if got := NewNativeDChainClient("").Brand(); got != "Lux DEX" {
		t.Fatalf("default brand = %q, want %q", got, "Lux DEX")
	}
	if got := NewNativeDChainClient("Blue A DEX").Brand(); got != "Blue A DEX" {
		t.Fatalf("brand = %q, want %q", got, "Blue A DEX")
	}
	if got := newDChainUnavailable().Brand(); got != "DEX (local D-Chain unavailable)" {
		t.Fatalf("unavailable brand = %q", got)
	}
}
