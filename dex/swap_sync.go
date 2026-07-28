// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math"
	"math/big"

	dexcore "github.com/luxfi/dex/pkg/dex"
	lx "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// runSyncSwap is the 0x9999 dispatch entry for a SYNCHRONOUS (untagged) V4 swap — the
// on-chain smart-order-router path, and THE path every normal swap() takes. The 0x9999
// DEX precompile is ALWAYS-ON and UNCONDITIONAL (live since the Dec 25 2025 activation);
// there is NO enable gate. The decomplect collapsed "is the precompile dispatchable?" and
// "may value move?" into ONE thing: a normal swap() reaches here and the swap's own
// fail-closed controls — intrinsic to the swap, enforced on EVERY call — decide whether it
// fills:
//   - permissionless canonical admission (OpenMarketChecked: the installed resolver derives
//     each side's canonical identity on the bound network — any well-formed real reference
//     resolves, no allowlist), which fails closed (ErrNoAssetResolver) on a node that never
//     wired a resolver — replacing the old consensus-mode gate with a structural one;
//   - the live-code verifier (EXTCODESIZE on the token address) — the AUTHORITATIVE reality
//     check that admits any real on-chain ERC-20 and refuses a synthetic/code-less one;
//   - the per-swap min-out / price floor (slippage protection);
//   - the halt switches (global/market/asset);
//   - the single non-reentrant custody mutex (an ERC-20 transfer can re-enter).
//
// It needs NO cross-chain atomic capability: the whole swap is one in-process, in-trie
// transition. Returns the V4 BalanceDelta and the remaining gas.
func runSyncSwap(state contract.AccessibleState, caller common.Address, key PoolKey, params SwapParams, hookData []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, errors.New("dex: cannot swap in read-only mode")
	}
	if suppliedGas < GasSwap {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := suppliedGas - GasSwap

	stateDB := newPoolStateAdapter(state)

	// Halt gate (global/market/asset) — refuse a swap on a halted market/asset.
	if herr := checkHalt(stateDB, key, params); herr != nil {
		return nil, gasLeft, herr
	}

	// GLOBAL non-reentrant guard: the swap moves real value through the seam reserve and
	// an ERC-20 transfer can hand control to a malicious token that re-enters any 0x9999
	// entrypoint. The single mutex makes the whole money surface single-in-flight.
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	// C1: resolve the real-asset admission authority for the chain this node actually
	// runs. The runtime (networkID, cChainID) come from the host's atomic capability —
	// the SAME consensus-supplied identity 0x9999 already uses — and the installed
	// resolver's bound identity is cross-checked against them (fail-closed on mismatch).
	// A node with no resolver installed yields a nil resolver, which OpenMarketChecked
	// turns into the fail-closed ErrNoAssetResolver — a swap never admits a left-padded
	// address as a real asset.
	atomicState, ok := state.(contract.AtomicState)
	if !ok {
		return nil, gasLeft, ErrSettleNoAtomicState
	}
	resolver, err := resolverForRuntime(atomicState.NetworkID(), atomicState.CChainID())
	if err != nil {
		return nil, gasLeft, err
	}

	out, err := syncSwap(stateDB, resolver, caller, key, params, hookData)
	if err != nil {
		return nil, gasLeft, err
	}
	return out, gasLeft, nil
}

// swap_sync.go is the SYNCHRONOUS in-process 0x9999 swap path — 0x9999 as the
// on-chain SMART-ORDER-ROUTER. It decodes the V4 swap (PoolKey/SwapParams) into a
// dexcore.SwapRequest and routes it across the on-chain liquidity sources, in one
// EVM call, deterministically, atomically:
//
//   1. V4 native CLOB first (the in-process matcher over 0x9999 storage rows).
//   2. Fall through to the V2/V3 AMM pools in the SAME cEVM when the CLOB lacks depth.
//   3. Best-execution across V4 + AMM, splitting when that beats either alone.
//
// The C-Chain EVM balance delta AND the D book/fill (or AMM pool) delta land in ONE
// JOINT JOURNAL committed in a SINGLE cEVM block's state root:
//
//   - The D side (book rows, fills, custody ledger) is written DIRECTLY to 0x9999
//     storage by dexcore over the evmStore adapter — every write is a 0x9999 StateDB
//     write, already part of the block's state root.
//   - The C side (the taker's real EVM token/native balance) is moved through the
//     proven 0x9999 vault primitives (lockIntentInput / creditSettlementOutput),
//     applied from the journal's recorded C-deltas in the SAME call.
//
// One EVM snapshot covers the lock + the routing + the credit, so a revert anywhere
// (no liquidity, price-limit breach, min-out breach) rolls back BOTH surfaces — both-
// or-neither. There is NO async C->D->C, NO live ZAP in Verify: the proposer builds
// the swap with the same pure function every validator REPLAYS from block bytes +
// prior state, and the EVM state root commits the route.
//
// REAL ASSETS ONLY: an asset's identity is its real on-chain token ADDRESS (assetID
// = left-pad of the 20-byte address); native LUX is the zero address. The 0x9999
// vault holds the REAL tokens. There are NO synthetic ticker ids on this path.

// syncSwap is the synchronous 0x9999 swap handler. It is the in-process router
// replacing the async intent path for a normal same-domain swap. Returns the V4
// BalanceDelta bytes (amount0, amount1) or an error (the caller reverts).
//
// PRECONDITIONS the caller (the 0x9999 dispatch) guarantees:
//   - the global non-reentrant custody guard is held (an ERC-20 transfer can re-enter);
//   - the market exists / is openable (the maker-seed / OpenMarket path bound assets);
//   - read-only callers are rejected before here (a swap mutates).
//
// 0x9999 is AlwaysOn (active from genesis), so the DEXFill C-event fires on every filled
// swap with no activation gate — see emitDEXFillEvent below.
func syncSwap(stateDB StateDB, resolver dexcore.AssetResolver, caller common.Address, key PoolKey, params SwapParams, hookData []byte) ([]byte, error) {
	// Decode the V4 swap into the real-asset routing request (incl. the taker's min-out
	// floor from hookData and the value-path slippage-protection policy).
	req, inAssetAddr, err := buildSwapRequest(stateDB, caller, key, params, hookData)
	if err != nil {
		return nil, err
	}

	store := newEVMStore(stateDB)

	// PERMISSIONLESS: open the market over any two REAL assets — each side admitted through
	// TWO orthogonal steps BEFORE any binding or debit, with NO allowlist:
	//   - the injected AssetResolver (canonical-identity resolve, permissionless): a
	//     malformed/wrong-network/explicitly-disabled/synthetic reference REVERTS
	//     (ErrAssetNotResolved), and a node with no resolver installed fails closed
	//     (ErrNoAssetResolver); a well-formed real reference always resolves;
	//   - the live-state OnChainAssetVerifier (EXTCODESIZE on the token address — the
	//     AUTHORITATIVE reality check): a fabricated/synthetic ERC-20 (an ASCII-ticker
	//     address, a self-destructed / never-deployed contract) has no code and REVERTS
	//     (ErrAssetNotOnChain), and a non-EVM caller (no verifier) fails closed
	//     (ErrNoOnChainVerifier).
	// The left-padded address NAMES an asset but does not let it TRADE: trading requires the
	// asset to resolve AND verify on-chain. Any REAL pair opens permissionlessly. Idempotent.
	// OpenMarketChecked + the verifier read 0x9999 / token CODE size via StateDB (not a nested
	// EVM Call), so this stays in the nested-call-free Phase A.
	verifier := onChainVerifierFor(stateDB)
	if err := dexcore.OpenMarketChecked(store, resolver, verifier, req.PoolID,
		assetSideForCurrency(key.Currency0), assetSideForCurrency(key.Currency1)); err != nil {
		return nil, err
	}

	inAsset := amountInAssetOf(req)

	// ─────────────────────────────── PHASE A — accounting + native value moves ──────────────
	// Zero nested EVM calls here, so NONE of these 0x9999 writes can be dropped by the geth
	// nested-call host bug. The taker's input is credited to their dexcore-ledger available at
	// the REQUESTED amount and the seam reserve is locked; the router spends it from real,
	// seam-backed funds. The REAL input token is pulled TERMINALLY in Phase B — an ERC-20
	// under-delivery (fee-on-transfer) reverts the whole frame (pullERC20Terminal's
	// delivered>=amount guard), so the requested-amount credit is never left unbacked.
	recordSeamLock(stateDB, inAsset, req.AmountIn)
	if derr := dexcore.Deposit(store, req.TakerUser, inAsset, req.AmountIn); derr != nil {
		return nil, derr
	}
	if isNativeAsset(inAsset) {
		// Native input moves via a plain balance op (no nested call) — Phase A.
		if merr := moveNativeIntoVault(stateDB, caller, req.AmountIn); merr != nil {
			return nil, merr
		}
	}

	// Build the router (CLOB first, AMM fallthrough) and route. dexcore writes the D-side
	// effects to 0x9999 storage and records the C-side proceeds/refund in the journal.
	router := buildRouter(stateDB, req.PoolID)
	res, err := dexcore.ExecuteSwap(store, router, req)
	if err != nil {
		return nil, err
	}

	// The taker's dexcore-ledger proceeds/refund are TRANSIENT (a swap is IOC, never rests):
	// drain EXACTLY what the journal released (proceeds + refund) per asset — NOT the taker's
	// whole available — so a PRIOR deposit the taker holds (a maker-then-taker multi-role user)
	// is preserved, not stranded.
	if derr := drainTakerLedger(store, req.TakerUser, res.Journal); derr != nil {
		return nil, derr
	}

	// Record the seam-release for each taker C-credit (proceeds + unspent-input refund) — NO
	// MINT, drawn ONLY from the seam reserve. NATIVE payouts happen now (balance ops, Phase A);
	// ERC-20 payouts are collected for the terminal Phase B. The input DebitTakerInput leg is
	// already covered by the Phase-A seam lock above.
	var erc20Pays []erc20Payout
	for _, d := range res.Journal.CDeltas() {
		switch d.Kind {
		case dexcore.CTakerCreditOutput, dexcore.CTakerRefundInput:
			if !d.Amount.IsUint64() {
				return nil, ErrNativeBadAmount
			}
			amt := d.Amount.Uint64()
			if rerr := recordSeamRelease(stateDB, d.Asset, amt); rerr != nil {
				return nil, rerr
			}
			if isNativeAsset(d.Asset) {
				if merr := moveNativeOutOfVault(stateDB, caller, amt); merr != nil {
					return nil, merr
				}
			} else {
				erc20Pays = append(erc20Pays, erc20Payout{token: assetAddress(d.Asset), amount: amt})
			}
		case dexcore.CTakerDebitInput:
			// Covered by the Phase-A input lock (seam reserve + dexcore deposit) above.
		}
	}

	// (C event) Emit the DEXFill log — Phase A (a log, before any nested call). The SAME
	// indexable native-CLOB settlement signal the async Phase-B path emits, fired on the
	// SYNCHRONOUS money path. 0x9999 is AlwaysOn; the log fires whenever the route produced
	// output. amountOut is the taker's realized proceeds; poolId + taker are indexed topics.
	if res.AmountOut > 0 {
		emitDEXFillEvent(stateDB, req.PoolID, caller, new(big.Int).SetUint64(res.AmountOut), stateDB.GetBlockNumber())
	}

	// ─────────────────────────────── PHASE B — terminal ERC-20 settlements ──────────────────
	// The ONLY nested EVM calls in the swap; nothing writes 0x9999 after them. Pull the taker's
	// REAL input FIRST (so a same-asset refund push is backed), then push their real proceeds /
	// refund. A revert here rolls back the whole frame, the Phase-A accounting included.
	if !isNativeAsset(inAsset) {
		vault, ok := stateDBERC20(stateDB)
		if !ok {
			return nil, ErrNativeERC20Vault
		}
		if perr := pullERC20Terminal(vault, inAssetAddr, caller, new(big.Int).SetUint64(req.AmountIn)); perr != nil {
			return nil, perr
		}
	}
	for _, p := range erc20Pays {
		vault, ok := stateDBERC20(stateDB)
		if !ok {
			return nil, ErrNativeERC20Vault
		}
		if perr := pushERC20Terminal(vault, p.token, caller, new(big.Int).SetUint64(p.amount)); perr != nil {
			return nil, perr
		}
	}

	// Return the V4 BalanceDelta (amount0 = base leg, amount1 = quote leg).
	return swapBalanceDelta(req, res), nil
}

// erc20Payout is a taker C-credit (proceeds or unspent-input refund) deferred to the
// terminal Phase B of syncSwap, so the ERC-20 transfer is the frame's last external effect
// (after every 0x9999 accounting write) and the geth nested-call host bug has nothing to drop.
type erc20Payout struct {
	token  common.Address
	amount uint64
}

// buildSwapRequest decodes the V4 swap into a dexcore.SwapRequest over REAL assets.
// currency0 is the base, currency1 is the quote (the V4 sorted-currency convention).
// zeroForOne (sell currency0 for currency1) is a SELL of base; !zeroForOne is a BUY.
// The taker is the caller; its dexcore identity is the FULL 32-byte injective left-pad
// of its 20-byte address (12 zero bytes + the 20 address bytes, via AccountFromBytes —
// see accountFromAddress), so no two distinct addresses can ever collide as accounts.
// Returns the request and the input asset's real token address (for the vault lock).
func buildSwapRequest(stateDB StateDB, caller common.Address, key PoolKey, params SwapParams, hookData []byte) (dexcore.SwapRequest, common.Address, error) {
	if params.AmountSpecified == nil || params.AmountSpecified.Sign() == 0 {
		return dexcore.SwapRequest{}, common.Address{}, ErrInvalidAmount
	}
	// V4 sign convention: AmountSpecified < 0 is EXACT-INPUT, > 0 is EXACT-OUTPUT. The
	// synchronous router is EXACT-INPUT only (it locks the exact input and floors the
	// realized output via MinOut). An EXACT-OUTPUT swap has a maxAmountIn semantics the sync
	// router does not implement, and silently treating Abs(amount) as exact-input would lock
	// the wrong leg with NO floor — exactly the unprotected case FIX-2 forbids. Reject it
	// explicitly so an exact-output swap reverts rather than routing unprotected.
	if params.AmountSpecified.Sign() > 0 {
		return dexcore.SwapRequest{}, common.Address{}, ErrExactOutputNotSupported
	}
	mag := new(big.Int).Abs(params.AmountSpecified)
	if !mag.IsUint64() || mag.Sign() <= 0 {
		return dexcore.SwapRequest{}, common.Address{}, ErrInvalidAmount
	}

	base := assetID(key.Currency0)  // REAL: left-pad of currency0's token address
	quote := assetID(key.Currency1) // REAL: left-pad of currency1's token address
	side := lx.Sell
	inAddr := key.Currency0.Address
	if !params.ZeroForOne {
		side = lx.Buy
		inAddr = key.Currency1.Address
	}

	// Price limit: the V4 SqrtPriceLimitX96 -> CLOB quote-per-base, as a PriceInt grid
	// value (the matcher's price domain), plus which side it bounds.
	limitBits, limitIsUpper := priceLimitToCLOB(params)
	var limitPrice lx.PriceInt
	if limitBits != 0 {
		limitPrice = dexcore.PriceToInt(math.Float64frombits(limitBits))
	}

	// H3: the taker's min-out floor, decoded from the V4 hookData (DM01). This is the
	// slippage floor dexcore.enforceProceedsPriceFloor / the MinOut check enforce — so a
	// realized fill below it reverts the whole swap. A malformed DM01 body reverts here.
	minOut, _, err := decodeMinOut(hookData)
	if err != nil {
		return dexcore.SwapRequest{}, common.Address{}, err
	}

	// VALUE-PATH SLIPPAGE POLICY (the SELL-side mirror of dexcore's ErrBuyRequiresLimit):
	// an exact-input market SELL (no price limit) on this public, adversarial surface MUST
	// carry a min-out floor, else it would sweep the resting book at any price (sandwich
	// exposure). A SELL with a price limit is already protected (the limit floors price);
	// a SELL with neither is refused. (A no-limit market BUY is already refused downstream
	// by dexcore.ErrBuyRequiresLimit, so only the SELL gap is closed here.)
	if side == lx.Sell && limitPrice <= 0 && minOut == 0 {
		return dexcore.SwapRequest{}, common.Address{}, ErrSellRequiresProtection
	}

	req := dexcore.SwapRequest{
		PoolID:       key.ID(),
		TakerUser:    accountFromAddress(caller),
		Side:         side,
		Base:         base,
		Quote:        quote,
		AmountIn:     mag.Uint64(),
		OrderID:      deterministicSwapOrderID(stateDB, key.ID()),
		TimestampN:   blockTimestampNanos(stateDB),
		LimitPrice:   limitPrice,
		LimitIsUpper: limitIsUpper,
		MinOut:       minOut,
		Class:        dexcore.ClassPublicDEX,
	}
	return req, inAddr, nil
}

// accountFromAddress maps a 20-byte EVM address to the 32-byte dexcore settlement
// identity by left-padding (12 zero bytes + the 20 address bytes) — INJECTIVE, so no
// two distinct addresses ever collide as accounts (the cross-user-drain guard, sound
// for 20-byte addresses that a narrower identity could alias). It is the account-axis
// analog of assetID's left-pad on the asset axis.
func accountFromAddress(a common.Address) dexcore.AccountID {
	return dexcore.AccountFromBytes(a.Bytes())
}

// drainTakerLedger debits the TRANSIENT amount this swap added to the taker's dexcore
// available — exactly the journal's released proceeds (CTakerCreditOutput) plus the
// unspent-input refund (CTakerRefundInput) — and NOTHING more. Those amounts were
// credited to the taker's dexcore available during routing and their real value was
// released to the taker's EVM balance by applyJournalC, so they must be debited back so
// the swap leaves NO phantom dexcore balance. The swap's input-deposit leg already nets
// to zero in available (deposited -> locked -> spent), so it is not drained here.
//
// Crucially we drain ONLY the per-asset transient sum, NOT the taker's whole available:
// a taker that holds a PRIOR dexcore deposit of the market's base/quote (a multi-role
// maker-then-taker) keeps that deposit and its vault backing — draining-to-zero would
// strand it. Maker balances are untouched.
func drainTakerLedger(store dexcore.Store, taker dexcore.AccountID, j *dexcore.Journal) error {
	// Per-asset transient = sum of the journal's output credits + refund credits.
	transient := map[dexcore.AssetID]uint64{}
	for _, d := range j.CDeltas() {
		switch d.Kind {
		case dexcore.CTakerCreditOutput, dexcore.CTakerRefundInput:
			if !d.Amount.IsUint64() {
				return ErrNativeBadAmount
			}
			transient[d.Asset] += d.Amount.Uint64()
		case dexcore.CTakerDebitInput:
			// The debit (input lock) is mirrored by the dexcore Deposit->Lock->Spend, which
			// nets to zero in available; not part of the transient available to drain.
		}
	}
	for asset, amt := range transient {
		if amt == 0 {
			continue
		}
		// Debit exactly the transient. DebitAvailable fails closed if the available is
		// somehow short (a regression), never underflows — so we can never drain into a
		// prior deposit beyond the transient we credited.
		if err := dexcore.DebitAvailable(store, taker, asset, amt); err != nil {
			return err
		}
	}
	return nil
}

// swapBalanceDelta builds the V4 BalanceDelta (amount0, amount1) for the routed swap.
// amount0 is the base (currency0) leg, amount1 is the quote (currency1) leg. A SELL
// pays base (amount0 negative) and receives quote (amount1 positive); a BUY is the
// mirror. The magnitudes are the realized AmountIn/AmountOut.
func swapBalanceDelta(req dexcore.SwapRequest, res *dexcore.SwapResult) []byte {
	var amount0, amount1 *big.Int
	in := new(big.Int).SetUint64(res.AmountIn)
	out := new(big.Int).SetUint64(res.AmountOut)
	if req.Side == lx.Sell {
		// Paid base, received quote.
		amount0 = new(big.Int).Neg(in)
		amount1 = out
	} else {
		// Paid quote, received base.
		amount0 = out
		amount1 = new(big.Int).Neg(in)
	}
	return PackBalanceDelta(amount0, amount1)
}

// req.AmountInAsset returns the swap's spend asset id (quote for a BUY, base for a
// SELL). A small method-style helper on the request for the lock/deposit legs.
func amountInAssetOf(req dexcore.SwapRequest) dexcore.AssetID {
	if req.Side == lx.Buy {
		return req.Quote
	}
	return req.Base
}

// deterministicSwapOrderID derives the ephemeral swap order id from block context +
// a per-block swap counter, so it is unique within the block and identical on every
// validator (the matcher's id discipline). The IOC order never rests, so the id only
// needs in-block uniqueness; (blockNumber<<32 | counter)+1 gives it, never zero.
func deterministicSwapOrderID(stateDB StateDB, poolID [32]byte) uint64 {
	n := stateDB.GetBlockNumber()
	c := nextSwapCounter(stateDB, poolID)
	return (n << 32) | (c & 0xffffffff)
}

// swapCounterPrefix keys a per-(block,market) ephemeral swap counter so multiple
// swaps in one block on one market get distinct ids.
var swapCounterPrefix = []byte(coreStoreNamespace + "swcnt.")

func swapCounterKey(poolID [32]byte) common.Hash {
	return makeStorageKey(swapCounterPrefix, poolID[:])
}

// nextSwapCounter returns and advances the per-market swap counter for this block. It
// resets each block by encoding the block number alongside the count, so a new block
// starts fresh; within a block it monotonically increases.
func nextSwapCounter(stateDB StateDB, poolID [32]byte) uint64 {
	w := stateDB.GetState(poolManagerAddr9999, swapCounterKey(poolID))
	storedBlock := bytesToU64(w[0:8])
	count := bytesToU64(w[24:32])
	cur := stateDB.GetBlockNumber()
	if storedBlock != cur {
		count = 0
	}
	count++
	var nw common.Hash
	putU64(nw[0:8], cur)
	putU64(nw[24:32], count)
	stateDB.SetState(poolManagerAddr9999, swapCounterKey(poolID), nw)
	return count
}

// blockTimestampNanos returns the block timestamp in nanoseconds for the ephemeral
// order's timestamp. The precompile StateDB exposes the block NUMBER but not the
// timestamp directly; the ephemeral IOC order's timestamp never participates in
// resting price-time priority (it never rests), so a block-number-derived monotone
// value is a deterministic, validator-identical stand-in. Using the block number as
// the nanosecond seed keeps it deterministic without a clock.
func blockTimestampNanos(stateDB StateDB) int64 {
	return int64(stateDB.GetBlockNumber())
}
