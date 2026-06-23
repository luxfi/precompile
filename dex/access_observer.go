// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/zeebo/blake3"

	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// access_observer.go is the ACCESS-SET SOUNDNESS substrate for the 0x9999 Block-STM
// scheduler. It is the anti-fork floor the locked execution model rests on.
//
// THE PROBLEM (the fork vector): the scheduler (evm/core/parallel) runs non-conflicting
// 0x9999 settlements in parallel and serializes only true conflicts. It derives the
// conflict edges from a DECLARED write-set (PredictAccesses / PredictSwapWriteSet). If a
// handler writes a key the declaration MISSES, two settlements that truly conflict on that
// key are run in parallel, commit in the wrong order on different validators, and the chain
// FORKS — silently, because nothing rejected the block. A static predictor is INHERENTLY
// unable to name keys derived from live state (a record id, a live index count), so the
// declaration cannot be made complete by inspection alone.
//
// THE DEFENSE (three layers, defense in depth — none trusts the others):
//
//   1. The COMPLETE predictor (settle_stm_stateful.go): given a stateKV it derives the
//      live-state keys IDENTICALLY to the handler, so the declared write-set is the exact
//      superset the scheduler needs. This removes false serializations AND closes the gap
//      for the scheduler's use — but a buggy/hostile handler could still write a key NEITHER
//      predictor names, so the predictor's completeness is an OPTIMIZATION, never the floor.
//
//   2. The RUNTIME ASSERTION (AssertWriteSetWithin): the handler runs against a write-
//      OBSERVING StateDB that records every key it mutates; afterwards the observed set is
//      checked ⊆ the declared set. ANY undeclared write makes the call FAIL (return an
//      error) — so an under-declaration is a REJECTED tx, never a fork. This is the real
//      soundness guarantee: divergence is converted to a halt, fail-closed.
//
//   3. The ROOT BINDING (AccessCommitment): the declared write-set's deterministic
//      commitment is folded into the block's state root (the chains/dexvm atomic.go
//      hashInto discipline — sorted, length-prefixed). A validator that declares a
//      DIFFERENT write-set produces a different commitment => a different root => the block
//      is non-reproducible and rejected by peers. So even if the runtime assertion were
//      somehow bypassed on one node, a mis-declared block cannot reach consensus.
//
// This file provides the mechanism for (2) and (3); settle_stm_stateful.go provides (1).

// ---------------------------------------------------------------------------
// Layer 2 mechanism: the write-observing StateDB decorator + the assertion.
// ---------------------------------------------------------------------------

// writeObservingStateDB is a transparent decorator over a contract.StateDB that records
// the CANONICAL conflict key of every state mutation the wrapped handler performs. It
// forwards every call unchanged (it is a pure observer — it never alters behavior) and
// accumulates:
//
//   - every SetState(addr,key,_) UNDER 0x9999 -> the slot `key` (the conflict key); a
//     SetState under any OTHER address (a token ledger via the erc20Vault sub-call) is the
//     token contract's OWN state, OUTSIDE the 0x9999 Block-STM conflict graph, and is
//     recorded separately (foreign) so the 0x9999 subset check is not polluted by it;
//   - every {Add,Sub}Balance(account)        -> balanceSlot(account, nativeAssetID), the
//     SAME synthetic per-(account,native-asset) key PredictSwapWriteSet declares for a native
//     balance leg. NATIVE is the only asset moved via account balances (ERC-20 value moves
//     through the erc20Vault sub-call, captured as foreign token-ledger writes), so a bare
//     balance touch maps unambiguously to the native asset.
//
// The 0x9999-scoped observed set is exactly the union the conflict graph is keyed on, so
// observed0x9999 ⊆ declared is a faithful soundness check for the native settlement path —
// and the SEPARATELY-tracked foreign writes are surfaced to the adversary as the precise
// boundary of the by-construction guarantee (Red owns proving nothing conflict-relevant
// hides there).
//
// It EMBEDS contract.StateDB so every non-mutating method (and the mutators we do not need
// to observe — nonces, multicoin, snapshots) forwards verbatim to the inner StateDB; only
// the three conflict-relevant mutators (SetState + the two native balance ops) are
// overridden to record. This keeps the decorator a faithful transparent wrapper (no behavior
// change) and orthogonal (one concern: observe writes), with zero hand-written pass-throughs.
type writeObservingStateDB struct {
	contract.StateDB
	// observed are the 0x9999-namespace conflict keys (SetState under 0x9999 + native
	// balance legs) — the set the scheduler's conflict graph is keyed on.
	observed map[common.Hash]struct{}
	// foreign are state writes OUTSIDE the 0x9999 address (token-ledger SetState via the
	// erc20Vault sub-call). They are the token contract's own state, not 0x9999 conflict
	// resources; tracked so the assertion can SCOPE precisely and the boundary is explicit.
	foreign map[foreignKey]struct{}
}

// foreignKey binds a write's address to its slot so two distinct addresses writing the same
// slot hash are distinct resources (the correct conflict-resource identity for non-0x9999
// state). Used only for the foreign (out-of-scope) bucket.
type foreignKey struct {
	addr common.Address
	slot common.Hash
}

func newWriteObservingStateDB(inner contract.StateDB) *writeObservingStateDB {
	return &writeObservingStateDB{
		StateDB:  inner,
		observed: make(map[common.Hash]struct{}),
		foreign:  make(map[foreignKey]struct{}),
	}
}

func (w *writeObservingStateDB) note(k common.Hash) { w.observed[k] = struct{}{} }

// noteBalance records a native balance touch as the synthetic balanceSlot the predictor
// declares. nativeAssetID is the all-zero injective AssetID (isNativeAsset).
func (w *writeObservingStateDB) noteBalance(account common.Address) {
	w.note(balanceSlot(account, nativeAssetID))
}

// nativeAssetID is the injective AssetID of native LUX (all-zero), the asset every
// account-balance move denominates (ERC-20 moves through the vault, not account balance).
var nativeAssetID = [32]byte{}

// --- contract.StateDB pass-through (observe the mutating calls, forward everything). ---
//
// contract.StateDB is the FULL geth-facing surface; we forward every method to inner and
// intercept only the mutators that move conflict-relevant value. The signatures mirror the
// production contract.StateDB exactly (the SetState that returns the prior value, the
// balance ops that take a tracing reason), so this decorator drops in wherever a
// contract.StateDB is expected.

func (w *writeObservingStateDB) SetState(addr common.Address, key, value common.Hash) common.Hash {
	if addr == poolManagerAddr9999 {
		w.note(key) // a 0x9999 conflict slot — in the scheduler's graph.
	} else {
		w.foreign[foreignKey{addr: addr, slot: key}] = struct{}{} // token-ledger / other state.
	}
	return w.StateDB.SetState(addr, key, value)
}

func (w *writeObservingStateDB) AddBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	w.noteBalance(addr)
	return w.StateDB.AddBalance(addr, amount, reason)
}

func (w *writeObservingStateDB) SubBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	w.noteBalance(addr)
	return w.StateDB.SubBalance(addr, amount, reason)
}

// SubBalanceMultiCoin / AddBalanceMultiCoin are the multicoin (non-native asset) account
// rails. The 0x9999 native path moves value through native balance ops + the erc20Vault
// sub-call, NOT the multicoin rail, so these are not part of the native conflict graph;
// they forward verbatim through the embedded StateDB. (If a future asset path routes value
// through multicoin, its conflict key is added here AND to the predictor in lockstep.)

// --- Optional-capability forwarding (erc20Vault, codeStater).
//
// stateDBERC20 / codeStaterFor type-assert the StateDB for these OPTIONAL capabilities. The
// embedded contract.StateDB does NOT carry them (they are not part of that interface), so a
// bare embed would HIDE them from the assertion and the ERC-20 settle leg would lose its
// vault — breaking the handler under observation. We therefore forward each optional
// capability when the inner StateDB exposes it, so the decorator is capability-transparent.
//
// The erc20Vault transfer methods move value on the token's OWN ledger (the wrapper's per-
// token map / a sub-call), NOT via our SetState, so they are foreign to the 0x9999 conflict
// graph by construction — the forwarding records nothing; it only preserves the capability.

func (w *writeObservingStateDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	if v, ok := w.StateDB.(erc20Vault); ok {
		return v.TokenBalanceOf(token, owner)
	}
	return nil
}

func (w *writeObservingStateDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if v, ok := w.StateDB.(erc20Vault); ok {
		return v.TransferTokenFrom(token, from, to, amount)
	}
	return ErrSettleERC20Vault
}

func (w *writeObservingStateDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	if v, ok := w.StateDB.(erc20Vault); ok {
		return v.TransferTokenTo(token, to, amount)
	}
	return ErrSettleERC20Vault
}

// CodeSizeOf forwards the codeStater capability (EXTCODESIZE — the live-on-chain asset
// proof) when the inner StateDB exposes it; -1 (not code-capable) otherwise, matching the
// poolStateAdapter's fail-closed convention.
func (w *writeObservingStateDB) CodeSizeOf(addr common.Address) int {
	if c, ok := w.StateDB.(codeStater); ok {
		return c.CodeSizeOf(addr)
	}
	return -1
}

// GetCodeSize forwards the geth-shaped code-size capability (EXTCODESIZE). This is the EXACT
// method the poolStateAdapter type-asserts for (module.go: `GetCodeSize(common.Address) int`),
// so when a poolStateAdapter wraps THIS observer — as it does on the synchronous value path
// (runSyncSwap -> newPoolStateAdapter(observingAccessibleState) -> onChainVerifierFor) — the
// adapter stays code-capable and the C1 on-chain-asset verifier resolves. Without this
// forwarder the adapter's GetCodeSize probe would miss (the observer only exposes CodeSizeOf),
// the verifier would fail closed (ErrNoOnChainVerifier), and a perfectly real swap would revert
// under observation — masking the access-set check. The capability is read-only (no conflict
// write), so forwarding records nothing; it only preserves the verifier the handler needs. We
// forward from whichever shape the inner StateDB exposes (GetCodeSize on the geth/test wrapper,
// or CodeSizeOf on a poolStateAdapter inner), so the decorator is capability-transparent either way.
func (w *writeObservingStateDB) GetCodeSize(addr common.Address) int {
	if cs, ok := w.StateDB.(interface {
		GetCodeSize(common.Address) int
	}); ok {
		return cs.GetCodeSize(addr)
	}
	if c, ok := w.StateDB.(codeStater); ok {
		return c.CodeSizeOf(addr)
	}
	return -1
}

// observingAccessibleState wraps a contract.AccessibleState so that GetStateDB() returns
// the write-observing decorator instead of the raw StateDB. Every other capability
// (block context, atomic state, consensus context) forwards unchanged, so a handler run
// through it behaves identically except that its writes are recorded. It re-exposes the
// AtomicState capability (the 0x9999 money path requires it) by delegating to the inner.
type observingAccessibleState struct {
	inner   contract.AccessibleState
	stateDB *writeObservingStateDB
}

func (o *observingAccessibleState) GetStateDB() contract.StateDB { return o.stateDB }
func (o *observingAccessibleState) GetBlockContext() contract.BlockContext {
	return o.inner.GetBlockContext()
}
func (o *observingAccessibleState) GetConsensusContext() context.Context {
	return o.inner.GetConsensusContext()
}
func (o *observingAccessibleState) GetChainConfig() precompileconfig.ChainConfig {
	return o.inner.GetChainConfig()
}
func (o *observingAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return o.inner.GetPrecompileEnv()
}

// AtomicMemory / NetworkID / ChainID / CChainID / DChainID / TxID / CallIndex forward the
// contract.AtomicState capability when the inner state has it. The 0x9999 settle path
// asserts state.(contract.AtomicState); the wrapper must preserve that or the handler
// reverts before doing any work (and the assertion would observe nothing). We embed the
// inner's AtomicState methods by delegation, guarded so a non-atomic inner still satisfies
// the AccessibleState interface (the assertion is then a no-atomic no-op, as the handler
// itself would be).
func (o *observingAccessibleState) atomic() (contract.AtomicState, bool) {
	as, ok := o.inner.(contract.AtomicState)
	return as, ok
}

func (o *observingAccessibleState) AtomicMemory() atomic.SharedMemory {
	if as, ok := o.atomic(); ok {
		return as.AtomicMemory()
	}
	return nil
}
func (o *observingAccessibleState) NetworkID() uint32 {
	if as, ok := o.atomic(); ok {
		return as.NetworkID()
	}
	return 0
}
func (o *observingAccessibleState) ChainID() ids.ID {
	if as, ok := o.atomic(); ok {
		return as.ChainID()
	}
	return ids.Empty
}
func (o *observingAccessibleState) CChainID() ids.ID {
	if as, ok := o.atomic(); ok {
		return as.CChainID()
	}
	return ids.Empty
}
func (o *observingAccessibleState) DChainID() ids.ID {
	if as, ok := o.atomic(); ok {
		return as.DChainID()
	}
	return ids.Empty
}
func (o *observingAccessibleState) TxID() ids.ID {
	if as, ok := o.atomic(); ok {
		return as.TxID()
	}
	return ids.Empty
}
func (o *observingAccessibleState) CallIndex() uint32 {
	if as, ok := o.atomic(); ok {
		return as.CallIndex()
	}
	return 0
}

var (
	_ contract.AccessibleState = (*observingAccessibleState)(nil)
	_ contract.AtomicState     = (*observingAccessibleState)(nil)
)

// ErrAccessSetUndeclaredWrite is the FAIL-CLOSED rejection: a handler touched a conflict
// key OUTSIDE its declared write-set. The scheduler would have missed the conflict edge for
// that key, so the only safe action is to REJECT the tx/block — a divergence becomes a halt,
// never a fork. It names the offending key for the audit log.
type ErrAccessSetUndeclaredWrite struct {
	Key common.Hash
}

func (e *ErrAccessSetUndeclaredWrite) Error() string {
	return "dex: 0x9999 handler wrote an UNDECLARED conflict key " + e.Key.Hex() +
		" (Block-STM access-set violation — block rejected to prevent a fork)"
}

// AssertWriteSetWithin runs fn against a write-observing view of `state`, then verifies
// every conflict key fn mutated is within `declared`. It is the LAYER-2 fail-closed gate:
// the handler is run for real (its value movement commits exactly as without the wrapper),
// but if it writes any key outside the declaration the call returns
// ErrAccessSetUndeclaredWrite and the EVM revert rolls back the speculative writes — so a
// mis-declared settlement is rejected, never committed into a forked state.
//
// `declared` is the predicted write-set the scheduler used to place this tx in the conflict
// graph — the SOUND superset from PredictSwapWriteSet / PredictModifyLiquidityWriteSet over
// the SAME stateKV the handler will read. The check is observed ⊆ declared (a SUPERSET
// declaration is always safe — it can only cause an unnecessary serialization, never a
// missed conflict; only an UNDER-declaration forks, and that is exactly what this rejects).
//
// It returns fn's own (ret, gasLeft, err) on success; on a write-set violation it returns
// the violation error with whatever gas fn left (the EVM reverts the call frame either way).
func AssertWriteSetWithin(
	state contract.AccessibleState,
	declared map[common.Hash]struct{},
	fn func(contract.AccessibleState) ([]byte, uint64, error),
) ([]byte, uint64, error) {
	obs := newWriteObservingStateDB(state.GetStateDB())
	wrapped := &observingAccessibleState{inner: state, stateDB: obs}

	ret, gasLeft, err := fn(wrapped)
	if err != nil {
		// The handler already reverted (its writes are discarded by the EVM snapshot);
		// the access-set check is moot for a failed call — surface the handler's error.
		return ret, gasLeft, err
	}

	// observed ⊆ declared, fail-closed on the first undeclared key (deterministic: the
	// keys are sorted so the reported violation is the same on every node).
	if bad, ok := firstUndeclared(obs.observed, declared); ok {
		return nil, gasLeft, &ErrAccessSetUndeclaredWrite{Key: bad}
	}
	return ret, gasLeft, nil
}

// firstUndeclared returns the lexicographically-smallest observed key not in declared (so
// the violation is reported deterministically across validators), or ok=false if observed
// ⊆ declared.
func firstUndeclared(observed, declared map[common.Hash]struct{}) (common.Hash, bool) {
	var worst common.Hash
	found := false
	for k := range observed {
		if _, ok := declared[k]; ok {
			continue
		}
		if !found || bytesLess(k, worst) {
			worst = k
			found = true
		}
	}
	return worst, found
}

func bytesLess(a, b common.Hash) bool {
	for i := 0; i < common.HashLength; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Layer 4 mechanism: the access-set root commitment (anti-fork root binding).
// ---------------------------------------------------------------------------

// AccessCommitment is a deterministic commitment over a settlement's DECLARED write-set,
// folded into the block state root so a mis-declared block is non-reproducible. It copies
// the chains/dexvm atomic.go `hashInto` discipline byte-for-byte: the keys are SORTED (map
// iteration is randomized — the commitment must not be) and every key is length-prefixed so
// no two distinct sets collide by concatenation. The root is blake3 (the SAME hash
// makeStorageKey uses, so the money path commits with one hash family).
//
// USE: at block accept the host folds each settlement's AccessCommitment.Root() into the
// EVM state-root accumulator (the SAME place chains/dexvm folds its atomicRequests). A
// validator that declares a DIFFERENT write-set for the same block produces a different
// Root() => a different folded state root => its block is rejected by honest peers who
// recompute the canonical declaration. So the declaration itself becomes consensus-critical:
// lying about the write-set is not a silent edge-miss, it is a visibly wrong root.
type AccessCommitment struct {
	keys []common.Hash
}

// NewAccessCommitment builds a commitment over a declared write-set. The input is a set
// (map); the constructor sorts it so the commitment is canonical regardless of insertion or
// map-iteration order — the determinism the root binding requires.
func NewAccessCommitment(declared map[common.Hash]struct{}) AccessCommitment {
	keys := make([]common.Hash, 0, len(declared))
	for k := range declared {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytesLess(keys[i], keys[j]) })
	return AccessCommitment{keys: keys}
}

// hashInto folds the sorted, length-prefixed key set into h — the atomic.go discipline.
// Each key is written as len(8 bytes, big-endian) || key, and the whole run is preceded by
// the count, so neither a reorder nor a split/merge of keys can produce a colliding digest.
func (c AccessCommitment) hashInto(h interface{ Write([]byte) (int, error) }) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(c.keys)))
	_, _ = h.Write(lenBuf[:])
	for _, k := range c.keys {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(common.HashLength))
		_, _ = h.Write(lenBuf[:])
		kk := k
		_, _ = h.Write(kk[:])
	}
}

// Root returns the 32-byte blake3 commitment over the declared write-set. Deterministic:
// the same set always yields the same root, and adding/removing/altering ANY single key
// changes it (the discriminating property the anti-fork binding needs — proven in the
// root-binding test). This is the value the block-accept path folds into the state root.
func (c AccessCommitment) Root() common.Hash {
	h := blake3.New()
	c.hashInto(h)
	var out common.Hash
	h.Digest().Read(out[:])
	return out
}

// FoldAccessCommitment composes an AccessCommitment into a running state-root accumulator
// exactly as chains/dexvm folds its atomicRequests alongside the persisted state: it writes
// the prior accumulator then the commitment, length-prefixed, and returns the new
// accumulator. The block-accept wiring calls this once per settlement (in deterministic
// settle order) so the final accumulator binds the union of every settlement's declared
// write-set into the root. A single node that mis-declares any settlement's write-set lands
// on a different accumulator and its block is rejected.
//
// This is the ONE-LINE wire site for the dchain/EVM block-accept path (out of this package's
// sole-agent scope to wire, in scope to provide as a complete, tested primitive): the host
// threads `acc = FoldAccessCommitment(acc, c)` through each accepted settlement and binds the
// result into the state-root input.
func FoldAccessCommitment(acc common.Hash, c AccessCommitment) common.Hash {
	h := blake3.New()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(common.HashLength))
	_, _ = h.Write(lenBuf[:])
	a := acc
	_, _ = h.Write(a[:])
	c.hashInto(h)
	var out common.Hash
	h.Digest().Read(out[:])
	return out
}

// ensure uint256 stays imported even if the balance signatures change shape.
var _ = uint256.NewInt
