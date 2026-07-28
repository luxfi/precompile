// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"time"

	dexcore "github.com/luxfi/dex/pkg/dex"
	lx "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// swap_custody.go is the SYNCHRONOUS-path custody + maker-placement surface — the
// "money lives in the order book" model for the on-chain router. It is the maker side
// of the product: a participant deposits REAL tokens, rests a limit order a taker's
// swap crosses, cancels it, and withdraws. Every funds-in/out leg moves REAL EVM value
// through the proven 0x9999 vault (seamReserve via lockIntentInput/creditSettlementOutput)
// AND mirrors it in the dexcore custody ledger, keeping ONE conservation invariant:
//
//	seamReserve[a]  ==  Σ over all accounts (dexcore available[a] + dexcore locked[a])
//
// A deposit adds to BOTH; a withdraw removes from BOTH; a place moves dexcore
// available -> locked (the real token stays in the vault); a fill (the swap) moves
// dexcore balances between maker and taker and moves the taker's real token in/out the
// vault to match. So the vault's real holdings always exactly back the ledger claims —
// no mint, no strand.
//
// REAL ASSETS ONLY: the asset is identified by its real token ADDRESS (assetID =
// left-pad of the 20-byte address); native LUX is the zero address. No synthetic ids.

// Sync-path selectors (computed in init via keccak4 — see registerSwapCustodySelectors).
var (
	// SelectorSwapDeposit funds a participant's dexcore-ledger balance from a REAL
	// token (native via msg.value, ERC-20 via transferFrom), backing it in the vault.
	//   swapDeposit(address asset, uint256 amount)
	SelectorSwapDeposit uint32
	// SelectorSwapWithdraw burns a participant's dexcore available and releases the
	// REAL token from the vault.
	//   swapWithdraw(address asset, uint256 amount)
	SelectorSwapWithdraw uint32
	// SelectorSwapPlace rests a maker LIMIT order on a market (locks dexcore available).
	//   swapPlace((address,address,uint24,int24,address) key, bool isBid, uint256 price, uint256 size)
	SelectorSwapPlace uint32
	// SelectorSwapCancel cancels a resting order (unlocks dexcore -> available).
	//   swapCancel((address,address,uint24,int24,address) key, uint256 orderID)
	SelectorSwapCancel uint32
)

var (
	ErrSwapCustodyReadOnly = errors.New("dex: cannot mutate swap custody in read-only mode")
	ErrSwapPlaceRejected   = errors.New("dex: resting order rejected (insufficient funds, dust, or post-only would take)")
	ErrSwapBadPriceSize    = errors.New("dex: order price/size out of range")
)

// registerSwapCustodySelectors computes the sync-path selectors. Called from the
// package init() alongside the other selector registrations.
func registerSwapCustodySelectors() {
	SelectorSwapDeposit = keccak4("swapDeposit(address,uint256)")
	SelectorSwapWithdraw = keccak4("swapWithdraw(address,uint256)")
	SelectorSwapPlace = keccak4("swapPlace((address,address,uint24,int24,address),bool,uint256,uint256)")
	SelectorSwapCancel = keccak4("swapCancel((address,address,uint24,int24,address),uint256)")
}

// runSwapDeposit funds the caller's dexcore-ledger available for an asset from a REAL
// token, backing it in the 0x9999 vault. Native (asset==0) requires the host frame to
// have moved msg.value==amount into 0x9999; ERC-20 pulls via transferFrom (observed
// delta). Mirrors the locked amount into the dexcore ledger so the ledger claim is
// exactly the vault backing. The 0x9999 rail is ALWAYS-ON (no value-activation gate);
// the deposit's safety is the intrinsic controls — the observed-delta lock (fee-on-
// transfer safe), the non-reentrant custody mutex, and conservation — not a consensus-
// mode switch. The matching EXIT (runSwapWithdraw) stays ungated so value can always leave.
func (s *SettleContract) runSwapDeposit(state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, ErrSwapCustodyReadOnly
	}
	if gas < GasDeposit {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasDeposit
	asset, amount, err := decodeAssetAmount(input)
	if err != nil {
		return nil, gasLeft, err
	}
	if !amount.IsUint64() {
		return nil, gasLeft, ErrNativeBadAmount
	}
	stateDB := newPoolStateAdapter(state)

	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	aid := assetID(asset)
	amt := amount.Uint64()
	store := newEVMStore(stateDB)
	// NATIVE-ZAP two-phase deposit (the geth nested-call fund-loss fix). lockAssetIn:
	//   PHASE A — credits seamReserve AND runs the record callback (the dexcore-ledger credit),
	//     so BOTH 0x9999 accounting writes land BEFORE any nested call;
	//   PHASE B — pulls the REAL token into the vault as the frame's TERMINAL effect.
	// The prior order (transferFrom THEN storeSeamReserve THEN dexcore.Deposit) had the host
	// drop the two post-transfer writes => seamReserve=0/available=0 while balanceOf(0x9999)
	// rose: stranded funds, zero fill. The credited amount is the REQUESTED amount; an ERC-20
	// under-delivery (fee-on-transfer) reverts the whole frame (lockAssetIn's delivered>=amt
	// guard) rather than under-crediting.
	locked, lerr := lockAssetIn(stateDB, caller, aid, asset.Address, amt, func() error {
		return dexcore.Deposit(store, accountFromAddress(caller), aid, amt)
	})
	if lerr != nil {
		return nil, gasLeft, lerr
	}
	return leftPadU64(locked), gasLeft, nil
}

// runSwapWithdraw burns the caller's dexcore available for an asset and releases the
// REAL token from the vault. Clamped to the caller's available (no over-withdraw).
//
// FAIL-SECURE EXIT — deliberately NEITHER halt-gated NOR value-gated. A withdraw returns
// the caller's OWN funds; gating it would STRAND value when the rail is halted or value
// swaps are not enabled. This mirrors the canonical rule (TestHaltBlocksNewTradingAllowsCancel
// / SelectorWithdraw|Reclaim|Collect are all exit-always): the value gate fences value-IN
// (deposit/place/swap), never value-OUT. Funds that entered the rail can ALWAYS leave.
func (s *SettleContract) runSwapWithdraw(state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, ErrSwapCustodyReadOnly
	}
	if gas < GasWithdraw {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasWithdraw
	asset, amount, err := decodeAssetAmount(input)
	if err != nil {
		return nil, gasLeft, err
	}
	if !amount.IsUint64() {
		return nil, gasLeft, ErrNativeBadAmount
	}
	stateDB := newPoolStateAdapter(state)

	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	aid := assetID(asset)
	store := newEVMStore(stateDB)
	acct := accountFromAddress(caller)
	avail, aerr := dexcore.GetAvailable(store, acct, aid)
	if aerr != nil {
		return nil, gasLeft, aerr
	}
	want := amount.Uint64()
	if want > avail {
		want = avail // clamp (no over-withdraw)
	}
	if want == 0 {
		return leftPadU64(0), gasLeft, nil
	}
	// Burn the dexcore available FIRST (CEI), then release the real token from the vault.
	if derr := dexcore.DebitAvailable(store, acct, aid, want); derr != nil {
		return nil, gasLeft, derr
	}
	if cerr := creditSettlementOutput(stateDB, caller, aid, want); cerr != nil {
		return nil, gasLeft, cerr
	}
	return leftPadU64(want), gasLeft, nil
}

// runSwapPlace rests a maker LIMIT order on a market. The market's (base,quote) are
// currency0/currency1 (REAL token addresses). isBid -> BUY (locks quote), else SELL
// (locks base). The lock draws the caller's dexcore available; the real token is
// already in the vault (from a prior swapDeposit). Returns the resting order id.
//
// Halt-gated (no value-activation gate — the 0x9999 rail is always-on): resting a NEW
// maker order is refused when the market is halted (checkHalt). Its real-asset safety is the
// permissionless admission run here (OpenMarketChecked: a place over a malformed/wrong-network
// asset REVERTS at the resolve step, and a synthetic/code-less asset REVERTS at the on-chain
// proof), which fails closed (ErrNoAssetResolver) on a node that wired no resolver. A place
// over two REAL on-chain assets binds the market permissionlessly. The EXIT (runSwapCancel) is
// NOT gated, so a resting order can always be pulled.
func (s *SettleContract) runSwapPlace(state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, ErrSwapCustodyReadOnly
	}
	if gas < GasSwap {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasSwap
	key, isBid, priceWord, sizeWord, derr := decodePlaceInput(input)
	if derr != nil {
		return nil, gasLeft, derr
	}
	if !priceWord.IsUint64() || !sizeWord.IsUint64() || priceWord.Sign() <= 0 || sizeWord.Sign() <= 0 {
		return nil, gasLeft, ErrSwapBadPriceSize
	}
	stateDB := newPoolStateAdapter(state)
	// Halt gate: refuse a new resting order on a halted market.
	if herr := checkHalt(stateDB, key, SwapParams{}); herr != nil {
		return nil, gasLeft, herr
	}

	// PERMISSIONLESS: a maker RESTING an order BINDS the market, so it must clear the SAME
	// real-asset admission a taker's swap does — else a maker could bind an arbitrary
	// (currency0, currency1) market over a fabricated/synthetic/code-less asset and rest
	// "liquidity" on it. Resolve the runtime-bound canonical-identity resolver (cross-checked
	// against the chain the node actually runs) and the live on-chain verifier, then admit
	// BOTH sides through OpenMarketChecked BEFORE binding. A place over a non-real asset
	// REVERTS (ErrAssetNotResolved / ErrAssetNotOnChain); no resolver/verifier fails closed.
	// A place over two REAL assets binds permissionlessly (no allowlist).
	atomicState, ok := state.(contract.AtomicState)
	if !ok {
		return nil, gasLeft, ErrSettleNoAtomicState
	}
	resolver, rerr := resolverForRuntime(atomicState.NetworkID(), atomicState.CChainID())
	if rerr != nil {
		return nil, gasLeft, rerr
	}

	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	store := newEVMStore(stateDB)
	verifier := onChainVerifierFor(stateDB)
	if oerr := dexcore.OpenMarketChecked(store, resolver, verifier, key.ID(),
		assetSideForCurrency(key.Currency0), assetSideForCurrency(key.Currency1)); oerr != nil {
		return nil, gasLeft, oerr
	}

	side := lx.Sell
	if isBid {
		side = lx.Buy
	}
	// Price is a PriceInt grid value (quote-per-base * PriceMultiplier); size is base
	// units. Convert to the float domain the matcher/dexcore place use.
	priceFloat := float64(priceWord.Uint64()) / float64(lx.PriceMultiplier)
	sizeFloat := float64(sizeWord.Uint64())
	orderID := deterministicSwapOrderID(stateDB, key.ID())
	ts := blockTimestampNanos(stateDB)

	ok, perr := dexcore.PlaceOrder(store, key.ID(), accountFromAddress(caller), side, priceFloat, sizeFloat, orderID, time.Unix(0, ts))
	if perr != nil {
		return nil, gasLeft, perr
	}
	if !ok {
		return nil, gasLeft, ErrSwapPlaceRejected
	}
	return leftPadU64(orderID), gasLeft, nil
}

// runSwapCancel cancels a resting order, unlocking its remaining reserve to the
// owner's dexcore available (fail-closed on a missing identity row). The real token
// stays in the vault; a subsequent swapWithdraw pulls it out.
//
// FAIL-SECURE EXIT — deliberately NEITHER halt-gated NOR value-gated, the cancel half of
// the canonical "halt blocks new trading, ALWAYS allows cancel" rule. A maker must be able
// to pull resting liquidity even on a halted or non-value-enabled node; gating cancel would
// trap the maker's locked funds (can't cancel -> can't withdraw). The value gate fences
// placing NEW orders (runSwapPlace), never cancelling existing ones.
func (s *SettleContract) runSwapCancel(state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, ErrSwapCustodyReadOnly
	}
	if gas < GasSwap {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasSwap
	key, orderID, derr := decodeCancelInput(input)
	if derr != nil {
		return nil, gasLeft, derr
	}
	stateDB := newPoolStateAdapter(state)
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	store := newEVMStore(stateDB)
	// Ownership: the cancel must be authorized by the resting order's owner. dexcore's
	// CancelOrder unlocks to the order's recorded full identity (orderuser:); we ALSO
	// require the caller to BE that owner so one account cannot cancel another's order.
	owner, ok, uerr := dexcore.GetOrderUser(store, key.ID(), orderID)
	if uerr != nil {
		return nil, gasLeft, uerr
	}
	if ok && owner != accountFromAddress(caller) {
		return nil, gasLeft, errors.New("dex: cancel not authorized (caller is not the order owner)")
	}
	cancelled, cerr := dexcore.CancelOrder(store, key.ID(), orderID)
	if cerr != nil {
		return nil, gasLeft, cerr
	}
	if !cancelled {
		return leftPadU64(0), gasLeft, nil // unknown order: no-op
	}
	return leftPadU64(1), gasLeft, nil
}

// --- decode helpers ---

// decodePlaceInput decodes swapPlace(key, isBid, price, size).
//
//	[0:160]   PoolKey
//	[160:192] isBid (bool)
//	[192:224] price (uint256, PriceInt grid)
//	[224:256] size  (uint256, base units)
func decodePlaceInput(input []byte) (PoolKey, bool, *big.Int, *big.Int, error) {
	if len(input) < 256 {
		return PoolKey{}, false, nil, nil, errors.New("dex: swapPlace input too short")
	}
	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return PoolKey{}, false, nil, nil, err
	}
	isBid := input[191] == 1
	price := new(big.Int).SetBytes(input[192:224])
	size := new(big.Int).SetBytes(input[224:256])
	return key, isBid, price, size, nil
}

// decodeCancelInput decodes swapCancel(key, orderID).
func decodeCancelInput(input []byte) (PoolKey, uint64, error) {
	if len(input) < 192 {
		return PoolKey{}, 0, errors.New("dex: swapCancel input too short")
	}
	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return PoolKey{}, 0, err
	}
	oid := new(big.Int).SetBytes(input[160:192])
	if !oid.IsUint64() {
		return PoolKey{}, 0, errors.New("dex: swapCancel orderID out of range")
	}
	return key, oid.Uint64(), nil
}

// leftPadU64 encodes a uint64 as a 32-byte ABI word.
func leftPadU64(v uint64) []byte {
	out := make([]byte, 32)
	putU64(out[24:32], v)
	return out
}
