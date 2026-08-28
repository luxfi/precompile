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

func blueATokenAsset() [32]byte { return assetID(Currency{Address: blueAToken}) }

// ═══════════════════ native_zap.go — the two-phase input lock ═══════════════════

// TestBlueALockAssetInTerminalPull pins property (1): on the ERC-20 leg every 0x9999
// accounting write — the seam credit AND the caller's `record` callback — precedes the
// single transferFrom, which is the frame's terminal external effect. Asserted on the
// ORDER, not on the resulting balances, because the balances land either way.
func TestBlueALockAssetInTerminalPull(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lock  func(StateDB, func() error) (uint64, error)
		pot   func(stateKV) *big.Int
		other func(stateKV) *big.Int
	}{
		{
			name: "lockAssetIn/seamReserve",
			lock: func(db StateDB, rec func() error) (uint64, error) {
				return lockAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, 500, rec)
			},
			pot:   func(db stateKV) *big.Int { return loadSeamReserve(db, blueATokenAsset()) },
			other: func(db stateKV) *big.Int { return loadCommittedPositions(db, blueATokenAsset()) },
		},
		{
			name: "commitAssetIn/committedPositions",
			lock: func(db StateDB, rec func() error) (uint64, error) {
				return commitAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, 500, rec)
			},
			pot:   func(db stateKV) *big.Int { return loadCommittedPositions(db, blueATokenAsset()) },
			other: func(db stateKV) *big.Int { return loadSeamReserve(db, blueATokenAsset()) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := blueANewVaultDB()
			db.mint(blueAToken, blueAAlice, 900)
			recorded := 0
			locked, err := tc.lock(db, func() error {
				recorded++
				db.ops = append(db.ops, "record")
				db.SetState(poolManagerAddr9999, common.Hash{0x01}, common.Hash{0x02})
				return nil
			})
			if err != nil || locked != 500 {
				t.Fatalf("lock = (%d, %v), want (500, nil)", locked, err)
			}
			if recorded != 1 {
				t.Fatalf("record ran %d times, want 1", recorded)
			}
			blueAAssertTerminalPull(t, db.ops)
			if rec, pull := blueAFirst(db.ops, "record"), blueAFirst(db.ops, "transferFrom"); rec > pull {
				t.Fatalf("record at %d runs AFTER the terminal pull at %d: %v", rec, pull, db.ops)
			}
			if got := tc.pot(db); got.Cmp(big.NewInt(500)) != 0 {
				t.Fatalf("own pot = %s, want 500", got)
			}
			// The two pots are orthogonal: a lock on one leaves the other at zero.
			if got := tc.other(db); got.Sign() != 0 {
				t.Fatalf("sibling pot = %s, want 0 (pots must not cross)", got)
			}
			if got := db.bag(blueAToken, poolManagerAddr9999); got.Cmp(big.NewInt(500)) != 0 {
				t.Fatalf("vault token balance = %s, want 500", got)
			}
		})
	}
}

// TestBlueASubmitSwapIntentTerminalPull is the SAME ordering property proven on the
// PRODUCTION call path (SubmitSwapIntent -> lockAssetIn), through the real
// poolStateAdapter — so the discipline is pinned where the money actually moves, not
// only on the helper in isolation.
func TestBlueASubmitSwapIntentTerminalPull(t *testing.T) {
	e := blueANewEnv(t)
	e.db.mintTestToken(blueAToken, blueAAlice, big.NewInt(1_000))
	e.db.ops = nil // ignore the mint's own bookkeeping

	id, err := nativeClient.SubmitSwapIntent(e, e, IntentRequest{
		Account:     blueAAlice,
		AssetIn:     blueATokenAsset(),
		AmountIn:    400,
		AssetInAddr: blueAToken,
		MarketID:    [32]byte{0x11},
		Recipient:   blueAAlice,
		Deadline:    harnessBlockTime + 1000,
	})
	if err != nil || id == ids.Empty {
		t.Fatalf("SubmitSwapIntent = (%s, %v), want a real id and nil", id, err)
	}
	blueAAssertTerminalPull(t, e.db.ops)

	kv := e.kv()
	if got := loadSeamReserve(kv, blueATokenAsset()); got.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("seamReserve = %s, want 400", got)
	}
	if rec := loadSwapIntentRecord(kv, id); rec.Status != swapIntentOpen || rec.Remaining != 400 || rec.Owner != blueAAlice {
		t.Fatalf("intent record = %+v, want open/400/alice", rec)
	}
	if got := e.db.TokenBalanceOf(blueAToken, poolManagerAddr9999); got.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("vault token = %s, want 400", got)
	}
}

// TestBlueANativeFailFastRecordsNothing pins property (2): an underfunded NATIVE lock
// must record NOTHING — not the pot, not the caller's `record` — rather than leaning on
// the EVM revert. The sweep crosses the exact boundary (balance == amount-1 / amount),
// because a `<=` where `<` belongs would let a caller lock one unit more than it holds.
func TestBlueANativeFailFastRecordsNothing(t *testing.T) {
	const amount uint64 = 100
	for _, rail := range []struct {
		name string
		lock func(StateDB, func() error) (uint64, error)
		pot  func(stateKV) *big.Int
	}{
		{"lockAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return lockAssetIn(db, blueAAlice, [32]byte{}, common.Address{}, amount, r)
		}, func(db stateKV) *big.Int { return loadSeamReserve(db, [32]byte{}) }},
		{"commitAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return commitAssetIn(db, blueAAlice, [32]byte{}, common.Address{}, amount, r)
		}, func(db stateKV) *big.Int { return loadCommittedPositions(db, [32]byte{}) }},
	} {
		for _, bal := range []uint64{amount - 1, amount, amount + 1} {
			t.Run(rail.name+"/bal", func(t *testing.T) {
				db := blueANewVaultDB()
				db.setBalance(blueAAlice, bal)
				recorded := 0
				locked, err := rail.lock(db, func() error { recorded++; return nil })

				if bal < amount {
					if !errors.Is(err, ErrNativeFundsShort) {
						t.Fatalf("bal=%d: err = %v, want ErrNativeFundsShort", bal, err)
					}
					if locked != 0 {
						t.Fatalf("bal=%d: locked = %d, want 0", bal, locked)
					}
					if recorded != 0 {
						t.Fatalf("bal=%d: record ran %d times on a refused lock, want 0", bal, recorded)
					}
					if got := rail.pot(db); got.Sign() != 0 {
						t.Fatalf("bal=%d: pot = %s after a refused lock, want 0", bal, got)
					}
					if len(db.ops) != 0 {
						t.Fatalf("bal=%d: refused lock left effects %v, want none", bal, db.ops)
					}
					if got := db.GetBalance(blueAAlice).Uint64(); got != bal {
						t.Fatalf("bal=%d: caller balance moved to %d", bal, got)
					}
					if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != 0 {
						t.Fatalf("bal=%d: vault credited %d on a refused lock", bal, got)
					}
					return
				}
				if err != nil || locked != amount {
					t.Fatalf("bal=%d: lock = (%d, %v), want (%d, nil)", bal, locked, err, amount)
				}
				if recorded != 1 {
					t.Fatalf("bal=%d: record ran %d times, want 1", bal, recorded)
				}
				if got := rail.pot(db); got.Cmp(new(big.Int).SetUint64(amount)) != 0 {
					t.Fatalf("bal=%d: pot = %s, want %d", bal, got, amount)
				}
				if got := db.GetBalance(blueAAlice).Uint64(); got != bal-amount {
					t.Fatalf("bal=%d: caller balance = %d, want %d", bal, got, bal-amount)
				}
				if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != amount {
					t.Fatalf("bal=%d: vault balance = %d, want %d", bal, got, amount)
				}
				// A native lock makes NO nested call at all — that is why it never lost a write.
				if n := blueACount(db.ops, "transferFrom") + blueACount(db.ops, "balanceOf"); n != 0 {
					t.Fatalf("bal=%d: native lock made %d token sub-calls, want 0: %v", bal, n, db.ops)
				}
			})
		}
	}
}

// TestBlueALockZeroAmountRefused pins property (3): a zero amount is refused outright,
// before any state is touched. Zero would otherwise burn a replay slot and stage an
// empty C->D object.
func TestBlueALockZeroAmountRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		lock func(StateDB, func() error) (uint64, error)
	}{
		{"lockAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return lockAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, 0, r)
		}},
		{"commitAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return commitAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, 0, r)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := blueANewVaultDB()
			db.mint(blueAToken, blueAAlice, 900)
			recorded := 0
			locked, err := tc.lock(db, func() error { recorded++; return nil })
			if !errors.Is(err, ErrNativeBadAmount) {
				t.Fatalf("err = %v, want ErrNativeBadAmount", err)
			}
			if locked != 0 || recorded != 0 || len(db.ops) != 0 {
				t.Fatalf("zero-amount lock did work: locked=%d recorded=%d ops=%v", locked, recorded, db.ops)
			}
		})
	}
}

// TestBlueALockRecordErrorAborts pins property (4): the caller's own accounting is
// authoritative — when `record` refuses, the lock reports THAT error verbatim and Phase B
// never runs, so no token ever moves for a refused lock.
func TestBlueALockRecordErrorAborts(t *testing.T) {
	sentinel := errors.New("blueA: caller accounting refused")
	for _, tc := range []struct {
		name string
		lock func(StateDB, func() error) (uint64, error)
	}{
		{"lockAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return lockAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, 300, r)
		}},
		{"commitAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return commitAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, 300, r)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := blueANewVaultDB()
			db.mint(blueAToken, blueAAlice, 900)
			locked, err := tc.lock(db, func() error { return sentinel })
			if !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want the record callback's own error", err)
			}
			if locked != 0 {
				t.Fatalf("locked = %d on a refused record, want 0", locked)
			}
			if n := blueACount(db.ops, "transferFrom"); n != 0 {
				t.Fatalf("Phase B ran (%d transferFrom) after record refused: %v", n, db.ops)
			}
			if got := db.bag(blueAToken, poolManagerAddr9999); got.Sign() != 0 {
				t.Fatalf("vault received %s tokens for a refused lock", got)
			}
		})
	}
}

// TestBlueALockWithoutERC20Vault pins property (5): a StateDB with no ERC-20 vault
// refuses the token leg (never faking a credit) while the NATIVE leg on the SAME
// StateDB still settles — so the refusal is scoped to the capability that is missing.
func TestBlueALockWithoutERC20Vault(t *testing.T) {
	for _, tc := range []struct {
		name string
		lock func(StateDB, [32]byte, common.Address) (uint64, error)
		pot  func(stateKV, [32]byte) *big.Int
	}{
		{"lockAssetIn", func(db StateDB, a [32]byte, addr common.Address) (uint64, error) {
			return lockAssetIn(db, blueAAlice, a, addr, 250, nil)
		}, loadSeamReserve},
		{"commitAssetIn", func(db StateDB, a [32]byte, addr common.Address) (uint64, error) {
			return commitAssetIn(db, blueAAlice, a, addr, 250, nil)
		}, loadCommittedPositions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := blueANewKV() // no erc20Vault capability
			db.setBalance(blueAAlice, 1_000)

			locked, err := tc.lock(db, blueATokenAsset(), blueAToken)
			if !errors.Is(err, ErrNativeERC20Vault) {
				t.Fatalf("token leg err = %v, want ErrNativeERC20Vault", err)
			}
			if locked != 0 {
				t.Fatalf("token leg locked %d without a vault", locked)
			}

			nativeLocked, nerr := tc.lock(db, [32]byte{}, common.Address{})
			if nerr != nil || nativeLocked != 250 {
				t.Fatalf("native leg = (%d, %v), want (250, nil) on the same StateDB", nativeLocked, nerr)
			}
			if got := tc.pot(db, [32]byte{}); got.Cmp(big.NewInt(250)) != 0 {
				t.Fatalf("native pot = %s, want 250", got)
			}
		})
	}
}

// TestBlueAPullERC20TerminalDelivery pins property (6): the guard is `delivered >=
// amount`. The sweep across amount-1 / amount / amount+1 is what separates a correct
// guard from an inverted one — an inverted guard accepts the short delivery (crediting
// value the vault never received) and refuses the exact one (stranding honest funds).
func TestBlueAPullERC20TerminalDelivery(t *testing.T) {
	const amount int64 = 1_000
	for _, delta := range []int64{-1, 0, +1} {
		t.Run("delta", func(t *testing.T) {
			db := blueANewVaultDB()
			db.mint(blueAToken, blueAAlice, 10_000)
			db.delivered = func(req *big.Int) *big.Int {
				return new(big.Int).Add(req, big.NewInt(delta))
			}
			err := pullERC20Terminal(db, blueAToken, blueAAlice, big.NewInt(amount))
			if delta < 0 {
				if !errors.Is(err, ErrERC20UnderDelivered) {
					t.Fatalf("delivered=%d: err = %v, want ErrERC20UnderDelivered", amount+delta, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("delivered=%d: err = %v, want nil (>= requested settles)", amount+delta, err)
			}
			if got := db.bag(blueAToken, poolManagerAddr9999); got.Cmp(big.NewInt(amount+delta)) != 0 {
				t.Fatalf("vault holds %s, want %d", got, amount+delta)
			}
		})
	}

	t.Run("reverting token", func(t *testing.T) {
		db := blueANewVaultDB()
		db.mint(blueAToken, blueAAlice, 10_000)
		db.failXfer = true
		err := pullERC20Terminal(db, blueAToken, blueAAlice, big.NewInt(amount))
		if !errors.Is(err, ErrERC20TransferFailed) {
			t.Fatalf("err = %v, want ErrERC20TransferFailed", err)
		}
	})

	// The same boundary reached through the money path, on BOTH rails: a fee-on-transfer
	// token must not leave a pot credited for value the vault never received.
	for _, rail := range []struct {
		name string
		lock func(StateDB) (uint64, error)
	}{
		{"through lockAssetIn", func(db StateDB) (uint64, error) {
			return lockAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, uint64(amount), nil)
		}},
		{"through commitAssetIn", func(db StateDB) (uint64, error) {
			return commitAssetIn(db, blueAAlice, blueATokenAsset(), blueAToken, uint64(amount), nil)
		}},
	} {
		t.Run(rail.name, func(t *testing.T) {
			db := blueANewVaultDB()
			db.mint(blueAToken, blueAAlice, 10_000)
			db.delivered = func(req *big.Int) *big.Int { return new(big.Int).Sub(req, big.NewInt(1)) }
			locked, err := rail.lock(db)
			if !errors.Is(err, ErrERC20UnderDelivered) || locked != 0 {
				t.Fatalf("%s = (%d, %v), want (0, ErrERC20UnderDelivered)", rail.name, locked, err)
			}
		})
	}
}

// TestBlueANativeMoveGuardIsNotRedundant proves the fail-fast at the top of the lock is a
// PRE-check, not a substitute for the guard inside moveNativeIntoVault. If anything
// between the two reduces the caller's balance, the move must still refuse — because
// SubBalance from a precompile is uint256-MODULAR and would otherwise WRAP the caller to
// a near-2^256 balance while crediting the vault. The `record` callback here spends the
// caller's balance to open exactly that window.
func TestBlueANativeMoveGuardIsNotRedundant(t *testing.T) {
	const amount uint64 = 500
	for _, rail := range []struct {
		name string
		lock func(StateDB, func() error) (uint64, error)
	}{
		{"lockAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return lockAssetIn(db, blueAAlice, [32]byte{}, common.Address{}, amount, r)
		}},
		{"commitAssetIn", func(db StateDB, r func() error) (uint64, error) {
			return commitAssetIn(db, blueAAlice, [32]byte{}, common.Address{}, amount, r)
		}},
	} {
		t.Run(rail.name, func(t *testing.T) {
			db := blueANewVaultDB()
			db.setBalance(blueAAlice, amount) // passes the fail-fast
			locked, err := rail.lock(db, func() error {
				db.SubBalance(blueAAlice, uint256.NewInt(1)) // ... and is short by the time of the move
				return nil
			})
			if !errors.Is(err, ErrNativeFundsShort) || locked != 0 {
				t.Fatalf("%s = (%d, %v), want (0, ErrNativeFundsShort)", rail.name, locked, err)
			}
			if got := db.GetBalance(blueAAlice).Uint64(); got != amount-1 {
				t.Fatalf("caller balance = %d, want %d (the move must not have run)", got, amount-1)
			}
			if got := db.GetBalance(poolManagerAddr9999); got.Sign() != 0 {
				t.Fatalf("vault credited %s from a refused move", got)
			}
		})
	}
}

// TestBlueAPotsCannotCross pins property (7): the swap-rail seam reserve and the LP
// committed-positions pot are orthogonal in BOTH directions. A commit can never be
// released through the seam rail, and a seam lock can never be released through the LP
// rail — and a refused cross-rail release moves no value at all.
func TestBlueAPotsCannotCross(t *testing.T) {
	const amount uint64 = 750

	t.Run("commit cannot exit through the seam rail", func(t *testing.T) {
		db := blueANewVaultDB()
		db.setBalance(blueAAlice, amount)
		if locked, err := commitAssetIn(db, blueAAlice, [32]byte{}, common.Address{}, amount, nil); err != nil || locked != amount {
			t.Fatalf("commitAssetIn = (%d, %v)", locked, err)
		}
		vaultBefore := db.GetBalance(poolManagerAddr9999).Uint64()
		err := creditSettlementOutput(db, blueAAlice, [32]byte{}, amount)
		if !errors.Is(err, ErrNativeSettleUnbacked) {
			t.Fatalf("seam-rail release of an LP commit: err = %v, want ErrNativeSettleUnbacked", err)
		}
		if got := loadCommittedPositions(db, [32]byte{}); got.Cmp(new(big.Int).SetUint64(amount)) != 0 {
			t.Fatalf("committedPositions = %s after a refused seam release, want %d", got, amount)
		}
		if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != vaultBefore {
			t.Fatalf("vault balance moved from %d to %d on a refused release", vaultBefore, got)
		}
	})

	t.Run("seam lock cannot exit through the LP rail", func(t *testing.T) {
		db := blueANewVaultDB()
		db.setBalance(blueAAlice, amount)
		if locked, err := lockAssetIn(db, blueAAlice, [32]byte{}, common.Address{}, amount, nil); err != nil || locked != amount {
			t.Fatalf("lockAssetIn = (%d, %v)", locked, err)
		}
		vaultBefore := db.GetBalance(poolManagerAddr9999).Uint64()
		err := creditPositionCollect(db, blueAAlice, [32]byte{}, amount)
		if !errors.Is(err, ErrLPCollectUnbacked) {
			t.Fatalf("LP-rail release of a seam lock: err = %v, want ErrLPCollectUnbacked", err)
		}
		if got := loadSeamReserve(db, [32]byte{}); got.Cmp(new(big.Int).SetUint64(amount)) != 0 {
			t.Fatalf("seamReserve = %s after a refused LP release, want %d", got, amount)
		}
		if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != vaultBefore {
			t.Fatalf("vault balance moved from %d to %d on a refused release", vaultBefore, got)
		}
	})
}

// TestBlueARecordCommittedReleaseBoundary sweeps the LP pot's release guard across the
// exact boundary. `held == amount` must settle to zero; `held == amount-1` must refuse
// and leave the pot untouched.
func TestBlueARecordCommittedReleaseBoundary(t *testing.T) {
	const amount uint64 = 400
	for _, held := range []uint64{amount - 1, amount, amount + 1} {
		t.Run("held", func(t *testing.T) {
			db := blueANewKV()
			storeCommittedPositions(db, [32]byte{}, new(big.Int).SetUint64(held))
			err := recordCommittedRelease(db, [32]byte{}, amount)
			if held < amount {
				if !errors.Is(err, ErrLPCollectUnbacked) {
					t.Fatalf("held=%d: err = %v, want ErrLPCollectUnbacked", held, err)
				}
				if got := loadCommittedPositions(db, [32]byte{}); got.Uint64() != held {
					t.Fatalf("held=%d: pot changed to %s on a refusal", held, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("held=%d: err = %v, want nil", held, err)
			}
			if got := loadCommittedPositions(db, [32]byte{}); got.Uint64() != held-amount {
				t.Fatalf("held=%d: pot = %s, want %d", held, got, held-amount)
			}
		})
	}
}

// TestBlueAMoveNativeVaultGuards pins property (8): SubBalance is uint256-MODULAR from a
// precompile, so a missing guard WRAPS instead of reverting — turning an unbacked release
// into an astronomically funded vault. Both directions are swept across the boundary, and
// the refusal must leave the balances byte-identical.
func TestBlueAMoveNativeVaultGuards(t *testing.T) {
	const amount uint64 = 600

	t.Run("out of vault", func(t *testing.T) {
		for _, vault := range []uint64{amount - 1, amount, amount + 1} {
			db := blueANewKV()
			db.setBalance(poolManagerAddr9999, vault)
			err := moveNativeOutOfVault(db, blueABob, amount)
			if vault < amount {
				if !errors.Is(err, ErrNativeSettleUnbacked) {
					t.Fatalf("vault=%d: err = %v, want ErrNativeSettleUnbacked", vault, err)
				}
				if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != vault {
					t.Fatalf("vault=%d: balance changed to %d on a refusal", vault, got)
				}
				if got := db.GetBalance(blueABob); got.Sign() != 0 {
					t.Fatalf("vault=%d: recipient credited %s on a refusal", vault, got)
				}
				if len(db.ops) != 0 {
					t.Fatalf("vault=%d: refusal produced effects %v", vault, db.ops)
				}
				continue
			}
			if err != nil {
				t.Fatalf("vault=%d: err = %v, want nil", vault, err)
			}
			if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != vault-amount {
				t.Fatalf("vault=%d: balance = %d, want %d", vault, got, vault-amount)
			}
			if got := db.GetBalance(blueABob).Uint64(); got != amount {
				t.Fatalf("vault=%d: recipient = %d, want %d", vault, got, amount)
			}
		}
	})

	t.Run("into vault", func(t *testing.T) {
		for _, caller := range []uint64{amount - 1, amount, amount + 1} {
			db := blueANewKV()
			db.setBalance(blueAAlice, caller)
			err := moveNativeIntoVault(db, blueAAlice, amount)
			if caller < amount {
				if !errors.Is(err, ErrNativeFundsShort) {
					t.Fatalf("caller=%d: err = %v, want ErrNativeFundsShort", caller, err)
				}
				if got := db.GetBalance(blueAAlice).Uint64(); got != caller {
					t.Fatalf("caller=%d: balance changed to %d on a refusal", caller, got)
				}
				if got := db.GetBalance(poolManagerAddr9999); got.Sign() != 0 {
					t.Fatalf("caller=%d: vault credited %s on a refusal", caller, got)
				}
				continue
			}
			if err != nil {
				t.Fatalf("caller=%d: err = %v, want nil", caller, err)
			}
			if got := db.GetBalance(blueAAlice).Uint64(); got != caller-amount {
				t.Fatalf("caller=%d: balance = %d, want %d", caller, got, caller-amount)
			}
			if got := db.GetBalance(poolManagerAddr9999).Uint64(); got != amount {
				t.Fatalf("caller=%d: vault = %d, want %d", caller, got, amount)
			}
		}
	})
}

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

// TestBlueACreditPathsNeedAnERC20Vault: both credit helpers debit their pot in Phase A
// and then need the vault for the terminal push. Without the capability they refuse —
// they never push and never claim success.
func TestBlueACreditPathsNeedAnERC20Vault(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seed   func(stateKV, *big.Int)
		credit func(StateDB) error
	}{
		{"creditSettlementOutput", func(db stateKV, v *big.Int) { storeSeamReserve(db, blueATokenAsset(), v) },
			func(db StateDB) error { return creditSettlementOutput(db, blueABob, blueATokenAsset(), 100) }},
		{"creditPositionCollect", func(db stateKV, v *big.Int) { storeCommittedPositions(db, blueATokenAsset(), v) },
			func(db StateDB) error { return creditPositionCollect(db, blueABob, blueATokenAsset(), 100) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := blueANewKV() // pot is fully backed; only the vault capability is missing
			tc.seed(db, big.NewInt(100))
			if err := tc.credit(db); !errors.Is(err, ErrNativeERC20Vault) {
				t.Fatalf("err = %v, want ErrNativeERC20Vault", err)
			}
		})
	}
}

// TestBlueACreditPathsDeriveTheToken: the terminal push settles the recorded asset, and
// the token it moves is DERIVED from the recorded asset id — the credit cannot be
// redirected to a token the caller names.
func TestBlueACreditPathsDeriveTheToken(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seed   func(stateKV, *big.Int)
		read   func(stateKV) *big.Int
		credit func(StateDB) error
	}{
		{"creditSettlementOutput",
			func(db stateKV, v *big.Int) { storeSeamReserve(db, blueATokenAsset(), v) },
			func(db stateKV) *big.Int { return loadSeamReserve(db, blueATokenAsset()) },
			func(db StateDB) error { return creditSettlementOutput(db, blueABob, blueATokenAsset(), 300) }},
		{"creditPositionCollect",
			func(db stateKV, v *big.Int) { storeCommittedPositions(db, blueATokenAsset(), v) },
			func(db stateKV) *big.Int { return loadCommittedPositions(db, blueATokenAsset()) },
			func(db StateDB) error { return creditPositionCollect(db, blueABob, blueATokenAsset(), 300) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := blueANewVaultDB()
			tc.seed(db, big.NewInt(500))
			db.mint(blueAToken, poolManagerAddr9999, 500)
			if err := tc.credit(db); err != nil {
				t.Fatalf("credit = %v, want nil", err)
			}
			if got := db.bag(blueAToken, blueABob); got.Cmp(big.NewInt(300)) != 0 {
				t.Fatalf("recipient holds %s of the DERIVED token, want 300", got)
			}
			if got := tc.read(db); got.Cmp(big.NewInt(200)) != 0 {
				t.Fatalf("pot = %s after the credit, want 200", got)
			}
			// The push is terminal: nothing writes 0x9999 after it.
			if push, write := blueAFirst(db.ops, "transferTo"), blueALast(db.ops, "set9999"); push < 0 || write > push {
				t.Fatalf("0x9999 write at %d follows the terminal push at %d: %v", write, push, db.ops)
			}
		})
	}
}

// ═══════════════ native_dchain_client.go — the closed-seam refusals ═══════════════

// blueAClientRefusals drives every value-moving client method and returns the error each
// gives, so the "seam is closed" cases can be swept in one table.
func blueAClientRefusals(t *testing.T, e *blueAEnv) map[string]error {
	t.Helper()
	req := IntentRequest{
		Account: blueAAlice, AssetIn: [32]byte{}, AmountIn: 100,
		AssetInAddr: common.Address{}, MarketID: [32]byte{0x11}, Recipient: blueAAlice,
	}
	claim := SettlementClaim{OutputID: ids.ID{0x01}, Asset: [32]byte{}, Amount: 100, Recipient: blueAAlice}
	out := map[string]error{}
	_, out["SubmitSwapIntent"] = nativeClient.SubmitSwapIntent(e, e, req)
	_, out["SubmitModifyLiquidity"] = nativeClient.SubmitModifyLiquidity(e, e, req)
	_, _, out["SubmitPositionCommit"] = nativeClient.SubmitPositionCommit(e, e, req)
	_, out["ImportSettlement"] = nativeClient.ImportSettlement(e, e, claim)
	_, out["ImportPositionCollect"] = nativeClient.ImportPositionCollect(e, e, claim)
	_, out["ReclaimIntent"] = nativeClient.ReclaimIntent(e, e, blueAAlice, ids.ID{0x02})
	return out
}

// TestBlueASeamClosedRefusesEveryValueMove: a node with no atomic memory, or with no
// D-Chain on this network, must refuse EVERY value-moving method and move nothing. This
// is the fail-closed default a node runs before the dexvm exists — the seam must not mint.
func TestBlueASeamClosedRefusesEveryValueMove(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(*blueAEnv)
	}{
		{"no atomic memory", func(e *blueAEnv) { e.sm = nil }},
		{"no D-Chain on this network", func(e *blueAEnv) { e.dChainID = ids.Empty }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := blueANewEnv(t)
			e.db.inner.AddBalance(blueAAlice, uint256.NewInt(10_000))
			tc.close(e)

			for name, err := range blueAClientRefusals(t, e) {
				if !errors.Is(err, ErrNativeNoAtomicMemory) {
					t.Fatalf("%s: err = %v, want ErrNativeNoAtomicMemory", name, err)
				}
			}
			if got := e.db.inner.GetBalance(blueAAlice).Uint64(); got != 10_000 {
				t.Fatalf("caller balance = %d, want 10000 (a closed seam moves nothing)", got)
			}
			if got := e.db.inner.GetBalance(poolManagerAddr9999); got.Sign() != 0 {
				t.Fatalf("vault balance = %s, want 0 (a closed seam moves nothing)", got)
			}
			if got := loadSeamReserve(e.kv(), [32]byte{}); got.Sign() != 0 {
				t.Fatalf("seamReserve = %s, want 0", got)
			}
			if got := loadCommittedPositions(e.kv(), [32]byte{}); got.Sign() != 0 {
				t.Fatalf("committedPositions = %s, want 0", got)
			}
		})
	}
}

// TestBlueASubmitZeroAmountRefused: both C->D submit legs refuse a zero amount before
// deriving an id or staging an object.
func TestBlueASubmitZeroAmountRefused(t *testing.T) {
	e := blueANewEnv(t)
	req := IntentRequest{Account: blueAAlice, AssetIn: [32]byte{}, AmountIn: 0, Recipient: blueAAlice}

	if id, err := nativeClient.SubmitSwapIntent(e, e, req); !errors.Is(err, ErrNativeBadAmount) || id != ids.Empty {
		t.Fatalf("SubmitSwapIntent = (%s, %v), want (empty, ErrNativeBadAmount)", id, err)
	}
	id, locked, err := nativeClient.SubmitPositionCommit(e, e, req)
	if !errors.Is(err, ErrNativeBadAmount) || id != ids.Empty || locked != 0 {
		t.Fatalf("SubmitPositionCommit = (%s, %d, %v), want (empty, 0, ErrNativeBadAmount)", id, locked, err)
	}
	if got := ReadStagedAtomicSeq(e.db.inner); got != 0 {
		t.Fatalf("staged %d atomic ops for a zero-amount submit, want 0", got)
	}
}

// TestBlueASubmitReplayRefused: re-submitting the SAME intent (a re-executed / reorged C
// tx) is refused by the durable replay guard on BOTH rails. The value-safety half holds
// with no help from the EVM: the caller is NOT debited a second time.
func TestBlueASubmitReplayRefused(t *testing.T) {
	t.Run("swap rail", func(t *testing.T) {
		e := blueANewEnv(t)
		e.db.inner.AddBalance(blueAAlice, uint256.NewInt(1_000))
		req := IntentRequest{
			Account: blueAAlice, AssetIn: [32]byte{}, AmountIn: 200,
			MarketID: [32]byte{0x11}, Recipient: blueAAlice, Nonce: 9,
		}
		first, err := nativeClient.SubmitSwapIntent(e, e, req)
		if err != nil {
			t.Fatalf("first submit: %v", err)
		}
		afterFirst := e.db.inner.GetBalance(blueAAlice).Uint64()

		second, rerr := nativeClient.SubmitSwapIntent(e, e, req)
		if !errors.Is(rerr, ErrNativeIntentReplay) {
			t.Fatalf("replay err = %v, want ErrNativeIntentReplay", rerr)
		}
		if second != ids.Empty {
			t.Fatalf("replay returned id %s, want empty", second)
		}
		if got := e.db.inner.GetBalance(blueAAlice).Uint64(); got != afterFirst {
			t.Fatalf("caller debited twice: %d -> %d", afterFirst, got)
		}
		if rec := loadSwapIntentRecord(e.kv(), first); rec.Remaining != 200 {
			t.Fatalf("intent remaining = %d after a refused replay, want 200", rec.Remaining)
		}
		// The optimistic Phase-A seam credit DOES land before the replay guard fires; the
		// EVM revert is what discards it (the id binds the locked amount, so the guard
		// cannot be checked earlier). Recorded here so a reordering that drops the revert
		// dependence is visible.
		if got := loadSeamReserve(e.kv(), [32]byte{}); got.Cmp(big.NewInt(400)) != 0 {
			t.Fatalf("seamReserve = %s; the refused replay's optimistic credit is expected "+
				"to stand until the EVM reverts the frame (want 400)", got)
		}
	})

	t.Run("LP rail", func(t *testing.T) {
		e := blueANewEnv(t)
		e.db.inner.AddBalance(blueAAlice, uint256.NewInt(1_000))
		req := IntentRequest{
			Account: blueAAlice, AssetIn: [32]byte{}, AmountIn: 200,
			MarketID: [32]byte{0x22}, Recipient: blueAAlice,
		}
		if _, _, err := nativeClient.SubmitPositionCommit(e, e, req); err != nil {
			t.Fatalf("first commit: %v", err)
		}
		afterFirst := e.db.inner.GetBalance(blueAAlice).Uint64()

		id, locked, rerr := nativeClient.SubmitPositionCommit(e, e, req)
		if !errors.Is(rerr, ErrLPCommitReplay) || id != ids.Empty || locked != 0 {
			t.Fatalf("replay = (%s, %d, %v), want (empty, 0, ErrLPCommitReplay)", id, locked, rerr)
		}
		if got := e.db.inner.GetBalance(blueAAlice).Uint64(); got != afterFirst {
			t.Fatalf("caller debited twice: %d -> %d", afterFirst, got)
		}
	})
}

// TestBlueAImportRefusesMalformedObject: a shared-memory value that is not EXACTLY the
// canonical object width is never reinterpreted into a credit, on either rail. The sweep
// covers short, long, and empty-but-present records.
func TestBlueAImportRefusesMalformedObject(t *testing.T) {
	canonical := encodeAtomicObject(railSwap, blueAAlice, [32]byte{}, 100)
	for _, bad := range [][]byte{
		canonical[:len(canonical)-1],
		append(append([]byte{}, canonical...), 0x00),
		{0x00},
	} {
		e := blueANewEnv(t)
		key := ids.ID{0x42}
		e.putD(t, key, bad)
		claim := SettlementClaim{OutputID: key, Asset: [32]byte{}, Amount: 100, Recipient: blueAAlice}

		credited, err := nativeClient.ImportSettlement(e, e, claim)
		if !errors.Is(err, ErrNativeSettleMalformed) || credited != 0 {
			t.Fatalf("ImportSettlement(%d bytes) = (%d, %v), want (0, ErrNativeSettleMalformed)", len(bad), credited, err)
		}
		credited, err = nativeClient.ImportPositionCollect(e, e, claim)
		if !errors.Is(err, ErrNativeSettleMalformed) || credited != 0 {
			t.Fatalf("ImportPositionCollect(%d bytes) = (%d, %v), want (0, ErrNativeSettleMalformed)", len(bad), credited, err)
		}
		if got := e.db.inner.GetBalance(blueAAlice); got.Sign() != 0 {
			t.Fatalf("a malformed object credited %s", got)
		}
	}
}

// TestBlueAImportSettlementRefusesZeroAmount: a well-formed object recording ZERO is
// refused rather than consumed. A zero credit would otherwise burn the object's one-time
// replay slot for nothing.
func TestBlueAImportSettlementRefusesZeroAmount(t *testing.T) {
	e := blueANewEnv(t)
	key := ids.ID{0x43}
	e.putD(t, key, encodeAtomicObject(railSwap, blueAAlice, [32]byte{}, 0))
	claim := SettlementClaim{OutputID: key, Asset: [32]byte{}, Amount: 0, Recipient: blueAAlice}

	credited, err := nativeClient.ImportSettlement(e, e, claim)
	if !errors.Is(err, ErrNativeSettleAmount) || credited != 0 {
		t.Fatalf("= (%d, %v), want (0, ErrNativeSettleAmount)", credited, err)
	}
	if isSettlementConsumed(e.kv(), key) {
		t.Fatalf("a refused zero-amount object was marked consumed")
	}
}

// blueASeedCollect wires a complete, passing LP-collect scenario and returns its claim.
// Individual tests then break exactly ONE binding so the assertion names the gate.
func blueASeedCollect(t *testing.T, e *blueAEnv, owner common.Address, positionID [32]byte, amount uint64) SettlementClaim {
	t.Helper()
	key := ids.ID{0x55}
	e.putD(t, key, encodeAtomicObject(railLP, owner, [32]byte{}, amount))
	storeRestingOrder(e.kv(), positionID, RestingOrder{
		Owner:       owner,
		LockedAsset: [32]byte{},
		LockedAmt:   new(big.Int).SetUint64(amount),
		Status:      OrderStatusOpen,
	})
	return SettlementClaim{
		OutputID: key, Asset: [32]byte{}, Amount: amount,
		Recipient: owner, PositionID: positionID,
	}
}

// TestBlueAImportPositionCollectGates walks the per-gate refusals of the LP collect. Each
// case breaks ONE binding of an otherwise-valid claim, so a passing test names exactly
// which gate is load-bearing — and every refusal must leave the pot and the vault intact.
func TestBlueAImportPositionCollectGates(t *testing.T) {
	positionID := [32]byte{0x77}

	t.Run("recorded asset must match the claim", func(t *testing.T) {
		e := blueANewEnv(t)
		claim := blueASeedCollect(t, e, blueAAlice, positionID, 100)
		claim.Asset = blueATokenAsset() // recorded object is native
		credited, err := nativeClient.ImportPositionCollect(e, e, claim)
		if !errors.Is(err, ErrNativeSettleAsset) || credited != 0 {
			t.Fatalf("= (%d, %v), want (0, ErrNativeSettleAsset)", credited, err)
		}
	})

	t.Run("the named position must belong to the recorded owner", func(t *testing.T) {
		e := blueANewEnv(t)
		claim := blueASeedCollect(t, e, blueAAlice, positionID, 100)
		// Re-point the position record at Bob: Alice's object may not draw on it.
		storeRestingOrder(e.kv(), positionID, RestingOrder{
			Owner: blueABob, LockedAsset: [32]byte{}, LockedAmt: big.NewInt(100), Status: OrderStatusOpen,
		})
		storeCommittedPositions(e.kv(), [32]byte{}, big.NewInt(100))
		e.db.inner.AddBalance(poolManagerAddr9999, uint256.NewInt(100))

		credited, err := nativeClient.ImportPositionCollect(e, e, claim)
		if !errors.Is(err, ErrLPCollectNoPosition) || credited != 0 {
			t.Fatalf("= (%d, %v), want (0, ErrLPCollectNoPosition)", credited, err)
		}
		if got := loadCommittedPositions(e.kv(), [32]byte{}); got.Cmp(big.NewInt(100)) != 0 {
			t.Fatalf("pot = %s after a refused cross-owner collect, want 100", got)
		}
		if got := e.db.inner.GetBalance(blueAAlice); got.Sign() != 0 {
			t.Fatalf("a cross-owner collect credited %s", got)
		}
	})

	t.Run("an unbacked LP pot refuses the credit", func(t *testing.T) {
		e := blueANewEnv(t)
		claim := blueASeedCollect(t, e, blueAAlice, positionID, 100)
		// Every bind passes; the committedPositions pot is simply empty (NO MINT).
		credited, err := nativeClient.ImportPositionCollect(e, e, claim)
		if !errors.Is(err, ErrLPCollectUnbacked) || credited != 0 {
			t.Fatalf("= (%d, %v), want (0, ErrLPCollectUnbacked)", credited, err)
		}
		if got := e.db.inner.GetBalance(blueAAlice); got.Sign() != 0 {
			t.Fatalf("an unbacked collect credited %s", got)
		}
		// The per-owner reserve never goes negative even on this path.
		if got := loadLockedReserve(e.kv(), blueAAlice, [32]byte{}); got.Sign() < 0 {
			t.Fatalf("per-owner reserve went negative: %s", got)
		}
	})
}

// TestBlueACollectPositionReserveNeverNegative: the per-owner committed reserve is a
// defense-in-depth accumulator that can legitimately lag the record. A collect larger
// than the recorded reserve must floor it at zero, never wrap it.
func TestBlueACollectPositionReserveNeverNegative(t *testing.T) {
	e := blueANewEnv(t)
	positionID := [32]byte{0x78}
	claim := blueASeedCollect(t, e, blueAAlice, positionID, 100)
	storeCommittedPositions(e.kv(), [32]byte{}, big.NewInt(100))
	e.db.inner.AddBalance(poolManagerAddr9999, uint256.NewInt(100))
	storeLockedReserve(e.kv(), blueAAlice, [32]byte{}, big.NewInt(40)) // deliberately short

	credited, err := nativeClient.ImportPositionCollect(e, e, claim)
	if err != nil || credited != 100 {
		t.Fatalf("collect = (%d, %v), want (100, nil)", credited, err)
	}
	if got := loadLockedReserve(e.kv(), blueAAlice, [32]byte{}); got.Sign() != 0 {
		t.Fatalf("per-owner reserve = %s, want 0 (clamped, never wrapped)", got)
	}
	if got := e.db.inner.GetBalance(blueAAlice).Uint64(); got != 100 {
		t.Fatalf("LP credited %d, want 100", got)
	}
	if got := loadCommittedPositions(e.kv(), [32]byte{}); got.Sign() != 0 {
		t.Fatalf("pot = %s after a full collect, want 0", got)
	}
	if loadRestingOrder(e.kv(), positionID).Status != OrderStatusCancelled {
		t.Fatalf("a fully collected position must be terminal")
	}
}

// TestBlueAReclaimIntentGates: the reclaim is one-time and never pays out unbacked. Both
// arms must refund nothing.
func TestBlueAReclaimIntentGates(t *testing.T) {
	intentID := ids.ID{0x91}

	seed := func(e *blueAEnv) {
		putSwapIntentRecord(e.kv(), intentID, swapIntentRecord{
			Owner:     blueAAlice,
			AssetIn:   [32]byte{},
			Remaining: 250,
			Deadline:  harnessBlockTime - 1, // already past
			Status:    swapIntentOpen,
		})
	}

	t.Run("already reclaimed", func(t *testing.T) {
		e := blueANewEnv(t)
		seed(e)
		markSwapIntentReclaimed(e.kv(), intentID, 1)
		storeSeamReserve(e.kv(), [32]byte{}, big.NewInt(250))
		e.db.inner.AddBalance(poolManagerAddr9999, uint256.NewInt(250))

		refunded, err := nativeClient.ReclaimIntent(e, e, blueAAlice, intentID)
		if !errors.Is(err, ErrReclaimReplay) || refunded != 0 {
			t.Fatalf("= (%d, %v), want (0, ErrReclaimReplay)", refunded, err)
		}
		if got := e.db.inner.GetBalance(blueAAlice); got.Sign() != 0 {
			t.Fatalf("a replayed reclaim paid out %s", got)
		}
		if got := loadSeamReserve(e.kv(), [32]byte{}); got.Cmp(big.NewInt(250)) != 0 {
			t.Fatalf("seamReserve = %s after a replayed reclaim, want 250", got)
		}
	})

	t.Run("unbacked seam reserve", func(t *testing.T) {
		e := blueANewEnv(t)
		seed(e)
		// The pot is empty: the refund must refuse rather than mint.
		refunded, err := nativeClient.ReclaimIntent(e, e, blueAAlice, intentID)
		if !errors.Is(err, ErrNativeSettleUnbacked) || refunded != 0 {
			t.Fatalf("= (%d, %v), want (0, ErrNativeSettleUnbacked)", refunded, err)
		}
		if got := e.db.inner.GetBalance(blueAAlice); got.Sign() != 0 {
			t.Fatalf("an unbacked reclaim paid out %s", got)
		}
	})
}

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
