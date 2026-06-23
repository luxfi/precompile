// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"github.com/luxfi/geth/common"
)

// swap_sync_access.go is the COMPLETE, STATE-AWARE access-set predictor for the SYNCHRONOUS
// value swap (runSyncSwap) — the LP/intent-staging predictor's (settle_stm_stateful.go)
// peer for the in-process smart-order-router path. It closes B7/B8: the live 0x9999 dispatch
// routes a plain swap() to runSyncSwap, but PredictSwapWriteSet models the ASYNC SettleSwap
// seam (intent-id slots, staging) — a DIFFERENT write region. runSyncSwap instead writes the
// per-(block,market) swap counter AND the dexcore book/index/ledger rows (under 0x9999 via
// the evmStore adapter). Asserting a sync swap against the async predictor would self-DoS
// (every sync swap -> ErrAccessSetUndeclaredWrite); scheduling it against the wrong set would
// MISS the book-row/counter edges -> a silent fork. This predictor models the LIVE sync path.
//
// THE WRITE-SET runSyncSwap can touch (every key derived from the SAME helpers the handler
// uses, read against the live PRE-call state so the route-dependent keys are named exactly):
//
//	closed-form (always, regardless of route):
//	  - custodyGuardKey9999                          (enterCustodyKV/exitCustodyKV)
//	  - swapCounterKey(poolID)                       (deterministicSwapOrderID -> nextSwapCounter)
//	  - seamReserveKey(in), seamReserveKey(out)      (lockIntentInput / creditSettlementOutput)
//	  - balanceSlot(caller,native), balanceSlot(0x9999,native)  (native lock/credit legs)
//	  - dexcore market rows: market:<poolID>, asset:<poolID>    (OpenMarketChecked->OpenMarket)
//	  - dexcore book watermark: book:<poolID>        (WriteBookWatermark, on any CLOB fill)
//	  - dexcore taker ledger rows: balance:/locked: for (taker,base) and (taker,quote)
//	  - dexcore AMM reserve row: ammrow:<poolID>     (only when an AMM pool is bound)
//
//	route-dependent but BOUNDED BY THE LIVE INDEX (every crossable maker is ALREADY resting in
//	the market's order index at predict time — a swap NEVER rests its own IOC order, so the
//	only order rows it writes are EXISTING makers' rows it rewrites/deletes):
//	  - for each resting orderID in the market index:
//	      order:<poolID><orderID>, orderasset:<poolID><orderID>, orderuser:<poolID><orderID>
//	      that maker's ledger rows: balance:/locked: for (makerOwner, base) and (makerOwner, quote)
//	  - the per-market order-id index slots: indexSlot(poolID, 0..ceil(count/4))
//
// SOUNDNESS: declaring ALL resting makers (even ones a given swap does not cross) is a SUPERSET
// — over-declaration only over-serializes, never under-detects. Every EVM slot the handler can
// SetState is therefore ⊆ this set. The same higher-bar rule the staging predictor follows: a
// missed READ never forks; a missed WRITE does — so this names the writes authoritatively and
// the extended parity gate (Test9999_SyncAccessSetKeyParity_HandlerVsPredictor) proves it with
// a fail-without-it case. The ERC-20 value legs move on the TOKEN ledger (a foreign address,
// the erc20Vault sub-call) — outside the 0x9999 conflict graph by construction, the precise
// native-scoping boundary (B6).

// dexcore Store key prefixes — the SAME byte strings dexcore keys its rows by (book.go /
// ledger.go), mirrored here so the predictor reconstructs the exact []byte key the evmStore
// adapter wraps into a 0x9999 slot. coreOrderPrefix ("order:") already lives in core_store.go;
// the rest follow the same one-binding rule. Drift from dexcore's schema is a LOUD failure of
// the parity gate (the handler would write a key this set misses), never a silent fork.
var (
	coreMarketPrefix    = []byte("market:")     // market:<poolID:32>            existence row
	coreAssetPrefix     = []byte("asset:")      // asset:<poolID:32>             (base,quote) binding
	coreBookPrefix      = []byte("book:")       // book:<poolID:32>              LastOrderID watermark
	coreBalancePrefix   = []byte("balance:")    // balance:<user:32><asset:32>   available ledger
	coreLockedPrefix    = []byte("locked:")     // locked:<user:32><asset:32>    locked ledger
	coreOrderLockPrefix = []byte("orderasset:") // orderasset:<poolID:32><orderID:8>  per-order lock
	coreOrderUserPrefix = []byte("orderuser:")  // orderuser:<poolID:32><orderID:8>   per-order identity
)

// dexOrderRowSlots is the fixed number of consecutive EVM slots a dexcore order row occupies
// through the evmStore length+data layout: 1 length word + ceil(sizeof(DEXOrder)/32) data
// words. lx.EncodeRow is fixed-width (unsafe.Sizeof(DEXOrder{}) == 64 bytes), so EVERY order
// row is exactly 3 slots — deterministic, identical on every validator.
const dexOrderRowBytes = 64
const dexOrderRowSlots = 1 + (dexOrderRowBytes+31)/32 // = 3

// dexU64RowSlots is the slot count for an 8-byte uint64 ledger/watermark value: 1 length word
// + 1 data word.
const dexU64RowSlots = 2

// dexOrderLockRowSlots: orderasset row value is asset[32]|amount[8] = 40 bytes -> 1 len + 2 data.
const dexOrderLockRowSlots = 1 + (40+31)/32 // = 3

// dexOrderUserRowSlots: orderuser row value is user[16] (or 32 left-padded) = up to 32 bytes ->
// 1 len + 1 data. AccountID is 32 bytes; the handler writes user[:] (the full id), so 1 data word.
const dexOrderUserRowSlots = 2

// dexMarketSymbolRowSlots: market:/asset: rows carry a 64-byte value (PoolSymbol hex is 64
// chars; the asset binding is base[32]|quote[32] = 64 bytes) -> 1 len + 2 data.
const dexMarketSymbolRowSlots = 1 + (64+31)/32 // = 3

// dexAMMRowSlots: ammrow value is base|quote|fee|bound = 21 bytes -> 1 len + 1 data.
const dexAMMRowSlots = 2

// dexKeyBalance / dexKeyLocked build the dexcore ledger keys EXACTLY as dexcore's
// balanceLedgerKey does (<prefix><user:32><asset:32>) so valueSlot names the identical slot.
func dexKeyBalance(user, asset [32]byte) []byte { return dexBalanceLikeKey(coreBalancePrefix, user, asset) }
func dexKeyLocked(user, asset [32]byte) []byte  { return dexBalanceLikeKey(coreLockedPrefix, user, asset) }

func dexBalanceLikeKey(prefix []byte, user, asset [32]byte) []byte {
	k := make([]byte, 0, len(prefix)+32+32)
	k = append(k, prefix...)
	k = append(k, user[:]...)
	k = append(k, asset[:]...)
	return k
}

// dexKeyPoolScoped builds a <prefix><poolID:32> key (market:, asset:, book:).
func dexKeyPoolScoped(prefix []byte, poolID [32]byte) []byte {
	k := make([]byte, 0, len(prefix)+32)
	k = append(k, prefix...)
	k = append(k, poolID[:]...)
	return k
}

// dexKeyOrderScoped builds a <prefix><poolID:32><orderID:8> key (order:, orderasset:, orderuser:).
func dexKeyOrderScoped(prefix []byte, poolID [32]byte, orderID uint64) []byte {
	k := make([]byte, 0, len(prefix)+32+8)
	k = append(k, prefix...)
	k = append(k, poolID[:]...)
	var w [8]byte
	putU64(w[:], orderID)
	k = append(k, w[:]...)
	return k
}

// addDexRowSlots declares the `slots` consecutive EVM slots the evmStore length+data layout
// occupies for a dexcore key — slot 0 (the length word) plus slots 1..slots-1 (data words) —
// using the SAME valueSlot derivation the handler's evmStore uses. A row that is DELETED only
// zeroes slot 0, and a row that is PUT writes slot 0 + its data words, so declaring all `slots`
// is the exact superset of either outcome.
func addDexRowSlots(ws *writeSet, es *evmStore, key []byte, slots int) {
	for w := 0; w < slots; w++ {
		ws.add(es.valueSlot(key, w))
	}
}

// PredictSyncSwapWriteSet returns the EXACT set of 0x9999 conflict keys a SYNCHRONOUS swap
// (runSyncSwap) of (key, params, caller, hookData) can write, derived against the live stateKV
// so every route-dependent maker-row and ledger slot is named identically to the handler. It
// is the authority the runtime assertion (AssertWriteSetWithin) checks `observed ⊆ this`
// against for the LIVE sync dispatch, and the set the root binding (AccessCommitment) commits.
//
// It is held to the staging predictor's higher bar: a SUPERSET is always safe (over-declaration
// only over-serializes), so where the touched set is route-dependent (which makers cross) we
// declare ALL resting makers — read from the SAME live market index the handler will rebuild.
func PredictSyncSwapWriteSet(
	sdb stateKV,
	key PoolKey,
	params SwapParams,
	caller common.Address,
) map[common.Hash]struct{} {
	ws := newWriteSet()
	es := newEVMStore(sdb)

	poolID := key.ID()

	// (1) The custody guard — enter on entry, clear on exit (two writes, one slot).
	ws.add(custodyGuardKey9999)

	// (2) The per-(block,market) ephemeral swap counter — a DIRECT 0x9999 SetState (not an
	// evmStore row), written by deterministicSwapOrderID -> nextSwapCounter on EVERY sync swap.
	// THIS is the key PredictSwapWriteSet (the async predictor) never declares.
	ws.add(swapCounterKey(poolID))

	// (3) The value legs. base = currency0, quote = currency1 (the dexcore market keys value by
	// the left-padded asset id == assetID(currency)). in/out depend on the side; declare BOTH
	// directions' seam-reserve + native balance legs (a SUPERSET covering either side cheaply).
	base := assetID(key.Currency0)
	quote := assetID(key.Currency1)
	ws.add(seamReserveKey(base), seamReserveKey(quote))
	// Native balance legs: the lock debits the caller + credits 0x9999; the credit/refund
	// mirrors them back. ERC-20 legs move on the token ledger (foreign), not a native balanceSlot.
	ws.add(balanceSlot(caller, nativeAssetID))
	ws.add(balanceSlot(poolManagerAddr9999, nativeAssetID))

	// (4) dexcore market rows OpenMarketChecked binds (idempotent — declared whether or not the
	// market already exists; a re-open rewrites the asset binding, a first open also writes the
	// existence row).
	addDexRowSlots(ws, es, dexKeyPoolScoped(coreMarketPrefix, poolID), dexMarketSymbolRowSlots)
	addDexRowSlots(ws, es, dexKeyPoolScoped(coreAssetPrefix, poolID), dexMarketSymbolRowSlots)

	// (5) The market's LastOrderID watermark — written by WriteBookWatermark on any CLOB fill.
	addDexRowSlots(ws, es, dexKeyPoolScoped(coreBookPrefix, poolID), dexU64RowSlots)

	// (6) The taker's ledger rows: Deposit credits available; LockFromAvailable moves
	// available->locked; SettleFills/SpendLocked/CreditAvailable move both legs; the unspent
	// refund moves locked->available; drainTakerLedger debits available. All touch the taker's
	// (base,quote) balance:/locked: rows. The taker account is the left-pad of the caller.
	taker := [32]byte(accountFromAddress(caller))
	for _, asset := range [][32]byte{base, quote} {
		addDexRowSlots(ws, es, dexKeyBalance(taker, asset), dexU64RowSlots)
		addDexRowSlots(ws, es, dexKeyLocked(taker, asset), dexU64RowSlots)
	}

	// (7) The AMM reserve row — written by SetReserves IFF an AMM pool is bound for this market.
	// Read the live binding (the SAME readAMMRow the handler's buildRouter reads); declare the
	// reserve row only when bound (an unbound market routes CLOB-only and never touches it).
	predictAMMReserveWrites(ws, es, poolID)

	// (8) The route-dependent maker rows — bounded by the LIVE order index. Every order a swap
	// can cross is ALREADY resting in the market's index at predict time (a swap never rests its
	// own IOC order), so the only order:/orderasset:/orderuser: rows it can rewrite/delete are
	// these. We enumerate them from the SAME index the handler rebuilds, and for each declare
	// the order row + its lock/identity rows + that maker's ledger rows. Declaring every resting
	// maker (not just the ones this swap crosses) is the SUPERSET the soundness rule requires.
	predictRestingMakerWrites(ws, es, poolID, base, quote)

	return ws.set()
}

// predictAMMReserveWrites declares the ammrow:<poolID> reserve slots IFF an AMM pool is bound
// for the market (the handler writes them only on an AMM fill, which only happens for a bound
// pool). The binding is read from the live state — the SAME readAMMRow buildRouter consults.
func predictAMMReserveWrites(ws *writeSet, es *evmStore, poolID [32]byte) {
	if _, _, _, ok := readAMMRow(es, poolID); !ok {
		return
	}
	addDexRowSlots(ws, es, ammRowKey(poolID), dexAMMRowSlots)
}

// predictRestingMakerWrites declares, for EVERY order currently resting in the market's index,
// the full set of 0x9999 slots a fill against it could touch: the order row, the per-order lock
// row, the per-order identity row, the maker's (base,quote) ledger rows, AND the per-market
// order-id index slots. The crossable set is exactly the live index (a swap rewrites/deletes
// only existing makers), so this is the SOUND superset — read from the SAME index the handler
// rebuilds in RebuildBook.
func predictRestingMakerWrites(ws *writeSet, es *evmStore, poolID, base, quote [32]byte) {
	ids := es.indexIDs(poolID)

	// The per-market order-id index: indexRemove (full fill) rewrites count word + packed data
	// words. Declare the count slot + every data word the current count occupies. A shrink only
	// rewrites within this range; the SUPERSET is the words the CURRENT list spans.
	indexWords := 1 + (len(ids)+3)/4 // slot 0 (count) + ceil(count/4) packed words
	for w := 0; w < indexWords; w++ {
		ws.add(es.indexSlot(poolID, w))
	}

	for _, orderID := range ids {
		// The resting order row (rewrite remaining, or delete on full fill) — fixed 3 slots.
		addDexRowSlots(ws, es, dexKeyOrderScoped(coreOrderPrefix, poolID, orderID), dexOrderRowSlots)
		// The per-order reserve (decremented, or deleted at zero).
		addDexRowSlots(ws, es, dexKeyOrderScoped(coreOrderLockPrefix, poolID, orderID), dexOrderLockRowSlots)
		// The per-order full identity (deleted when the order fully fills).
		addDexRowSlots(ws, es, dexKeyOrderScoped(coreOrderUserPrefix, poolID, orderID), dexOrderUserRowSlots)

		// The maker's ledger rows. The maker's FULL settlement identity is the orderuser: row,
		// read from the live state EXACTLY as makerSettleKey resolves it. A maker placed before
		// custody has no orderuser: row; such a maker's fill fails closed (ErrMissingSettlementUser)
		// before any ledger write, so omitting its ledger keys is still sound (no write occurs) —
		// but we conservatively include the rows for every resolvable maker.
		if owner, ok := readOrderUser(es, poolID, orderID); ok {
			for _, asset := range [][32]byte{base, quote} {
				addDexRowSlots(ws, es, dexKeyBalance(owner, asset), dexU64RowSlots)
				addDexRowSlots(ws, es, dexKeyLocked(owner, asset), dexU64RowSlots)
			}
		}
	}
}

// readOrderUser reads a resting order's FULL 32-byte settlement identity from the live state,
// the SAME orderuser: row dexcore.GetOrderUser / makerSettleKey resolve. ok=false when absent
// (a pre-custody maker), in which case a fill against it fails closed before any ledger write.
func readOrderUser(es *evmStore, poolID [32]byte, orderID uint64) (owner [32]byte, ok bool) {
	v, err := es.Get(dexKeyOrderScoped(coreOrderUserPrefix, poolID, orderID))
	if err != nil || len(v) == 0 {
		return owner, false
	}
	// dexcore writes user[:] (the full 32-byte AccountID). Left-pad shorter values for safety.
	if len(v) >= 32 {
		copy(owner[:], v[len(v)-32:])
	} else {
		copy(owner[32-len(v):], v)
	}
	return owner, true
}

// ---------------------------------------------------------------------------
// L4: the access-set ROOT BINDING entry for the synchronous value path.
// ---------------------------------------------------------------------------

// SyncSwapAccessCommitment returns the deterministic AccessCommitment over the EXACT write-set a
// synchronous swap of (key, params, caller) declares — the SAME set the L2 assertion checks and
// the SAME set PredictSyncSwapWriteSet returns, derived against the pre-call state. It is the
// per-call value the block-accept path folds into the execution root via FoldAccessCommitment so
// the DECLARATION itself is consensus-bound: a validator that declares a DIFFERENT sync write-set
// for the same block lands on a different folded root and its block is rejected by honest peers
// who recompute the canonical declaration. This is layer (3) — even if the L2 runtime assertion
// were bypassed on one node, a mis-declared block cannot reach consensus.
//
// The commitment is over the DECLARED set (not the observed writes): the L2 assertion already
// proves observed ⊆ declared in-Verify (fail-closed), so binding the declaration is exactly the
// anti-lying primitive — the geth EVM state root already binds the actual writes (every declared
// key is a real 0x9999 SetState landing in the trie), and this binds the claim about which keys
// those are. Together: writes bound by the state root, declaration bound by this commitment, and
// observed ⊆ declared enforced by L2.
func SyncSwapAccessCommitment(sdb stateKV, key PoolKey, params SwapParams, caller common.Address) AccessCommitment {
	return NewAccessCommitment(PredictSyncSwapWriteSet(sdb, key, params, caller))
}

// FoldSyncSwapAccessCommitment is the ONE-LINE host wire site for the block-accept path: it
// folds a synchronous swap's declared-access commitment into the running execution-root
// accumulator, exactly as chains/dexvm folds its atomicRequests (vm.go computeStateRoot ->
// atomic.hashInto). The host threads `acc = FoldSyncSwapAccessCommitment(acc, sdb, key, params,
// caller)` through each accepted sync swap in deterministic settle order and binds the final
// accumulator into the state-root input. It is provided here (complete + tested) so the host
// wire is a single call; the host owns WHERE it folds (the EVM block-accept root / the dexvm
// computeStateRoot seam), this package owns WHAT is folded (the canonical declaration).
func FoldSyncSwapAccessCommitment(acc common.Hash, sdb stateKV, key PoolKey, params SwapParams, caller common.Address) common.Hash {
	return FoldAccessCommitment(acc, SyncSwapAccessCommitment(sdb, key, params, caller))
}
