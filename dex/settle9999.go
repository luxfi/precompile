// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
)

// settle9999.go is THE production DEX money path (LP-9999) — the NATIVE C<->D
// ATOMIC seam. C SETTLES; C never matches. The matcher is the dexvm (D-Chain),
// whose OWN consensus is the matching authority; C consumes committed D output
// through the primary-network atomic shared-memory import/export primitive (the
// SAME one platformvm and the dexvm use). There is NO BLS certificate, NO
// VerifierRegistry, NO DFillReceipt, NO certType in the value path. Value crosses
// ONLY as an atomic shared-memory object.
//
// THE V4 swap selector is two-phase, keyed on hookData (the V4 ABI is UNCHANGED —
// web/mobile already pass `bytes hookData`; only its CONTENTS select the phase):
//
//   - PHASE A — INTENT (hookData empty, or tagged INTENT): lock the taker's input
//     on C and write a C->D atomic intent object. Returns the intent id (NOT a
//     fill). D imports the object and matches under its own consensus.
//   - PHASE B — SETTLEMENT (hookData tagged SETTLE, carrying a D->C object ref):
//     consume the D->C atomic settlement object ONCE and credit the output. This
//     is the ONLY path that credits C.
//
// THE SHIP RULE (enforced structurally, not by trust): a C balance can be credited
// by 0x9999 ONLY by consuming a D->C atomic object (Phase B / ImportSettlement); a
// D order/position can be funded ONLY by consuming a C->D atomic object (Phase A /
// SubmitSwapIntent -> dexvm executeImport). No fill VALUE returned by any live
// matcher can credit C — Phase B has no fill-amount parameter; the credit is the
// RECORDED atomic object's amount, and absent a real object in shared memory it
// reverts.
//
// WHAT C ENFORCES INDEPENDENTLY vs RELIES ON D FOR (the swap rail, precisely):
//   - C enforces, with NO trust in D: the credit binds to the RECORDED object's
//     owner/asset/amount (no aliasing/re-denomination), the object's rail is railSwap
//     (no cross-rail pot drain), the object is consumed at most once (replay), the
//     credit is drawn ONLY from seamReserve (never a depositor/maker/LP pot), AND —
//     the per-taker cap (MEDIUM) — the credit is bounded by the taker's OWN intent's
//     remaining locked principal, so an over-export for one taker can never draw on
//     other takers' pooled tokenIn. C ALSO guarantees liveness independently: a locked
//     intent's principal can always exit via reclaimIntent once its deadline passes,
//     with no dependence on D or the keeper.
//   - C relies on D for: WHICH fills occurred and their amounts (D is the matcher;
//     conservation of proceeds vs refund within a single taker's locked principal is
//     enforced on D by settleFromFills' spent<=locked). C does NOT re-derive the match;
//     it bounds the blast radius of a faulty/hostile D export to the taker's OWN stake
//     (the per-taker cap) and refuses anything past the deadline.

// --- 0x9999 native-seam chain identity (networkID, cChainID, dChainID). It is NOT
// configured and NOT persisted: 0x9999 is ALWAYS-ON with zero per-net config, so the
// chain identity is resolved at RUNTIME from the host's atomic capability
// (contract.AtomicState: NetworkID()/CChainID()/DChainID(), sourced from the consensus
// context). The native intent id still binds the full (networkID, cChainID, dChainID)
// so an object minted on one chain/network can never be consumed on another — that
// binding is unchanged; only its SOURCE moved from genesis config to runtime context.

// --- Settlement value movement vault. The 0x9999 vault (the precompile self-
// address) is the counterparty reserve: a Phase-A intent locks tokenIn into the
// vault, a Phase-B settlement releases tokenOut from the vault. NO MINT — a credit
// the vault cannot back reverts (conservation).

var settleVaultPrefix = []byte(settleStateNamespace + "vlt") // per-asset vault holdings

func settleVaultKey(assetID [32]byte) common.Hash {
	return makeStorageKey(settleVaultPrefix, assetID[:])
}

func loadSettleVault(stateDB StateDB, assetID [32]byte) *big.Int {
	v := stateDB.GetState(poolManagerAddr9999, settleVaultKey(assetID))
	return new(big.Int).SetBytes(v[:])
}

func storeSettleVault(stateDB StateDB, assetID [32]byte, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr9999, settleVaultKey(assetID), w)
}

var (
	ErrSettleAmountRange   = errors.New("dex: settle amount exceeds uint256")
	ErrSettleERC20Vault    = errors.New("dex: ERC-20 settlement requires an erc20Vault-capable StateDB")
	ErrSettleNoAtomicState = errors.New("dex: 0x9999 native settle requires the cross-chain atomic capability")
)

// --- Gas model for the native seam. The C->D / D->C work is bounded: a small
// fixed shared-memory write/read + one StateDB replay slot + the value move. No
// per-validator crypto (the BLS pairing model is gone), so a flat tier suffices.
const (
	GasNativeIntent     uint64 = 40_000 // decode + lock + SM put + replay slot. Phase A emits NO log.
	GasNativeSettlement uint64 = 50_000 // decode + SM get/bind + replay slot + credit + SM remove + DEXFill log (Phase B).
)

// isNativeAsset reports whether an injective AssetID is native LUX (all-zero).
func isNativeAsset(id [32]byte) bool { return id == ([32]byte{}) }

// assetAddress recovers the 20-byte token address from an injective AssetID (the
// left-padded address; native all-zero recovers address(0)).
func assetAddress(id [32]byte) common.Address {
	var a common.Address
	copy(a[:], id[12:32])
	return a
}

// isWord reports whether v fits in 32 bytes (a uint256).
func isWord(v *big.Int) bool {
	return v != nil && v.Sign() >= 0 && v.BitLen() <= 256
}

// stateDBERC20 resolves the erc20Vault capability for the settle path (prefers a
// StateDB that directly implements erc20Vault, else the poolStateAdapter bridge).
func stateDBERC20(stateDB StateDB) (erc20Vault, bool) {
	if a, ok := stateDB.(*poolStateAdapter); ok {
		if under, ok := a.underlyingStateDB().(erc20Vault); ok {
			return under, true
		}
	}
	v, ok := stateDB.(erc20Vault)
	return v, ok
}

// nativeClient is the C<->D atomic client the 0x9999 handler routes value through.
// Single instance (stateless); brand is the OSS default (a tenant surface installs
// its own via the pool manager engine brand).
var nativeClient = NewNativeDChainClient("Lux DEX")

// SettleSwap is THE 0x9999 swap handler — the native C<->D two-phase money path.
// It decodes the V4 swap call (key, params, hookData) and dispatches on the
// hookData phase. The V4 ABI is UNCHANGED. Returns the V4 BalanceDelta on a
// Phase-B credit, or a packed intent-id marker on a Phase-A intent.
func SettleSwap(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, errors.New("dex: cannot settle in read-only mode")
	}

	key, params, hookData, err := DecodeSwapInput(input)
	if err != nil {
		return nil, suppliedGas, err
	}

	// The cross-chain atomic capability is REQUIRED — value crosses only as an
	// atomic object. A host that did not wire it (single-chain dev) reverts cleanly.
	atomicState, ok := state.(contract.AtomicState)
	if !ok || atomicState.AtomicMemory() == nil {
		return nil, suppliedGas, ErrSettleNoAtomicState
	}

	stateDB := newPoolStateAdapter(state)

	// GLOBAL non-reentrant guard for the 0x9999 custody+settle surface (the SAME single
	// slot deposit / withdraw / modifyLiquidity take). Both phases move value through
	// the seam reserve (Phase A locks tokenIn, Phase B credits tokenOut), and a phase's
	// ERC-20 transferFrom/transfer can hand control to a malicious token that re-enters
	// any 0x9999 entrypoint. Per-call CEI already orders each ledger write, but a uniform
	// mutex makes the whole money surface single-in-flight so two interleaved settles
	// can never clobber the seam-reserve read-modify-write. Set BEFORE any value movement.
	if !enterCustodyKV(stateDB) {
		return nil, suppliedGas, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	blockNumber := state.GetBlockContext().Number().Uint64()
	blockTimestamp := state.GetBlockContext().Timestamp()

	phase, body, taggedIntent := decodeSwapPhase(hookData)
	switch phase {
	case swapPhaseSettlement:
		// PHASE B — consume a D->C atomic settlement object and credit C.
		if suppliedGas < GasNativeSettlement {
			return nil, 0, errors.New("dex: out of gas")
		}
		gasLeft := suppliedGas - GasNativeSettlement

		// Halt gate (global/market/asset) — cheapest scope first.
		if herr := checkHalt(stateDB, key, params); herr != nil {
			return nil, gasLeft, herr
		}
		claim, derr := decodeSettlementBody(body, key, params, caller)
		if derr != nil {
			return nil, gasLeft, derr
		}
		credited, ierr := nativeClient.ImportSettlement(state, atomicState, claim)
		if ierr != nil {
			return nil, gasLeft, ierr
		}
		// Analytics — sharded, no global hot write.
		creditedAmt := new(big.Int).SetUint64(credited)
		accrueVolume(stateDB, key.ID(), creditedAmt, blockNumber)
		// Indexable settled-fill signal for the DEX graph / lux.exchange. Emitted
		// on the money path (Phase-B credit) so eth_getLogs surfaces native-CLOB
		// fills. accrueVolume is sharded state (not a log); this is the log. Gated on
		// the SAME dated fork as 0x9999 dispatch (defense in depth — see dexLogsActive):
		// a consensus-visible log MUST NOT enter a receipt root before the activation
		// boundary, or a re-syncing node that did not emit it would compute a different
		// root. On the relaunched chain every settlement is at/after the boundary, so
		// every settlement emits the log — no ungated window.
		if dexLogsActive(blockTimestamp) {
			emitDEXFillEvent(stateDB, key.ID(), caller, creditedAmt, blockNumber)
		}
		// V4 return: the taker received `credited` of the output asset. Map to the
		// BalanceDelta direction (output paid out to taker = negative to pool).
		delta := balanceDeltaForOutput(params, new(big.Int).SetUint64(credited))
		return PackBalanceDelta(delta.Amount0, delta.Amount1), gasLeft, nil

	default:
		// PHASE A — lock input on C and create a C->D atomic intent.
		if suppliedGas < GasNativeIntent {
			return nil, 0, errors.New("dex: out of gas")
		}
		gasLeft := suppliedGas - GasNativeIntent

		if herr := checkHalt(stateDB, key, params); herr != nil {
			return nil, gasLeft, herr
		}
		// The OPTIONAL deadline + nonce ride in an EXPLICIT DI01 intent body (the V4
		// SwapParams tuple is unchanged). They are read ONLY for a DI01-tagged intent; an
		// untagged / opaque hook body carries neither (taggedIntent=false => body ignored),
		// so a hook contract's arbitrary bytes are never mis-parsed. The deadline gates late
		// settlement + reclaim; the NONCE is folded into the intent id so it is
		// chain-observable (the off-chain keeper derives the SAME id from the SAME calldata —
		// the watch-correlation fix) and disambiguates otherwise-identical swaps.
		var deadline, nonce uint64
		if taggedIntent {
			d, n, derr := decodeIntentBody(body)
			if derr != nil {
				return nil, gasLeft, derr
			}
			deadline, nonce = d, n
		}
		req, berr := buildIntentRequest(key, params, caller, deadline, nonce)
		if berr != nil {
			return nil, gasLeft, berr
		}
		intentID, serr := nativeClient.SubmitSwapIntent(state, atomicState, req)
		if serr != nil {
			return nil, gasLeft, serr
		}
		// Return the intent id (32 bytes) so the caller / keeper can track the
		// async D->C settlement. NOT a fill — Phase A returns no output value.
		out := make([]byte, 32)
		copy(out, intentID[:])
		return out, gasLeft, nil
	}
}

// buildIntentRequest derives the C->D intent from the V4 swap: the taker is the
// caller, the input asset/amount come from the swap direction + amountSpecified
// (exact-input magnitude), the market is the pool id, the recipient defaults to the
// caller, and the deadline is the (optional) value parsed from the Phase-A hookData
// body. A non-zero deadline is persisted in the per-intent record so Phase-B refuses
// a late settlement and the locker can reclaim the principal past it.
func buildIntentRequest(key PoolKey, params SwapParams, caller common.Address, deadline, nonce uint64) (IntentRequest, error) {
	in, _ := swapAssetDirection(key, params)
	// Exact-input: AmountSpecified < 0, magnitude is the input. Exact-output is a P4
	// router concern; the native intent locks the exact input the taker commits.
	if params.AmountSpecified == nil || params.AmountSpecified.Sign() == 0 {
		return IntentRequest{}, ErrInvalidAmount
	}
	mag := new(big.Int).Abs(params.AmountSpecified)
	if !mag.IsUint64() || mag.Sign() <= 0 {
		return IntentRequest{}, ErrInvalidAmount
	}
	priceLimit, limitIsUpper := priceLimitToCLOB(params)
	return IntentRequest{
		Account:      caller,
		AssetIn:      in,
		AmountIn:     mag.Uint64(),
		AssetInAddr:  assetAddress(in),
		MarketID:     key.ID(),
		MinAmountOut: minAmountOut(params),
		PriceLimit:   priceLimit,
		LimitIsUpper: limitIsUpper,
		Recipient:    caller,
		Deadline:     deadline,
		Nonce:        nonce,
	}, nil
}

// priceLimitToCLOB converts the V4 SqrtPriceLimitX96 into the CLOB price domain the
// dexvm settles in — quote-per-base as a float64, returned as its IEEE-754 bits so it
// crosses the seam exactly (no decimal reparse). It is the slippage floor the matcher /
// settle path enforces: a fill WORSE than this is refused (bounded sandwich/MEV).
//
//	price (quote/base) = (sqrtPriceX96 / 2^96)^2 = currency1 per currency0.
//
// DIRECTION. limitIsUpper reports which side the limit bounds, matching the dexvm's
// fill-side convention:
//   - zeroForOne (sell currency0/base for currency1/quote => CLOB SELL): the V4 limit is
//     the MINIMUM sqrt price, i.e. a price FLOOR — reject fills BELOW it (limitIsUpper=false).
//   - !zeroForOne (buy currency0/base with currency1/quote => CLOB BUY): the V4 limit is
//     the MAXIMUM sqrt price, i.e. a price CEILING — reject fills ABOVE it (limitIsUpper=true).
//
// A SqrtPriceLimitX96 at/beyond the V4 sentinel bounds (MinSqrtRatio for zeroForOne,
// MaxSqrtRatio for !zeroForOne) means "no limit" — returns 0 so the settle path imposes
// no floor (the pre-existing unbounded behavior, preserved).
func priceLimitToCLOB(params SwapParams) (priceLimitBits uint64, limitIsUpper bool) {
	limitIsUpper = !params.ZeroForOne
	s := params.SqrtPriceLimitX96
	if s == nil || s.Sign() <= 0 {
		return 0, limitIsUpper // unset => no limit
	}
	// Treat the V4 "no limit" sentinels as unbounded: a zeroForOne floor at/below
	// MinSqrtRatio, or a !zeroForOne ceiling at/above MaxSqrtRatio, imposes nothing.
	if params.ZeroForOne {
		if s.Cmp(MinSqrtRatio) <= 0 {
			return 0, limitIsUpper
		}
	} else {
		if s.Cmp(MaxSqrtRatio) >= 0 {
			return 0, limitIsUpper
		}
	}
	// price = (s / 2^96)^2. Compute in float64: ratio = s / 2^96, then square. The CLOB
	// price domain is float64 (Fill.Price), so this is the exact value the settle path
	// compares against — no precision is lost beyond float64's own (the same domain the
	// matcher already operates in).
	ratio := new(big.Float).Quo(new(big.Float).SetInt(s), twoPow96Float)
	price, _ := new(big.Float).Mul(ratio, ratio).Float64()
	if price <= 0 || math.IsInf(price, 0) || math.IsNaN(price) {
		return 0, limitIsUpper // degenerate => treat as no limit rather than reject all fills
	}
	return math.Float64bits(price), limitIsUpper
}

// twoPow96Float is 2^96 as a big.Float, the V4 sqrt-price fixed-point denominator.
var twoPow96Float = new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 96))

// runSettleReclaimIntent is the reclaimIntent(bytes32 intentID) handler: the swap
// rail's deadline-reclaim. It decodes the intent id, takes the shared custody
// non-reentrant guard (the refund moves value through the seam reserve, and an ERC-20
// transfer can re-enter), and calls ReclaimIntent which refunds the remaining locked
// principal to the caller (the locker) once the deadline has passed. Returns the
// refunded amount. NOT gated by the swap halt — funds must always be able to exit.
func (s *SettleContract) runSettleReclaimIntent(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot reclaimIntent in read-only mode")
	}
	if gas < GasNativeSettlement {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasNativeSettlement

	atomicState, ok := state.(contract.AtomicState)
	if !ok || atomicState.AtomicMemory() == nil {
		return nil, gasLeft, ErrSettleNoAtomicState
	}
	if len(data) < 32 {
		return nil, gasLeft, ErrReclaimBadInput
	}
	var intentID ids.ID
	copy(intentID[:], data[0:32])

	stateDB := newPoolStateAdapter(state)
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	refunded, rerr := nativeClient.ReclaimIntent(state, atomicState, caller, intentID)
	if rerr != nil {
		return nil, gasLeft, rerr
	}
	out := make([]byte, 32)
	new(big.Int).SetUint64(refunded).FillBytes(out)
	return out, gasLeft, nil
}

// EncodeReclaimIntentInput builds reclaimIntent(bytes32) calldata for the locker's
// reclaim tx and tests.
func EncodeReclaimIntentInput(intentID ids.ID) []byte {
	out := make([]byte, 32)
	copy(out, intentID[:])
	return out
}

// ErrReclaimBadInput is returned when reclaimIntent calldata is too short to carry an
// intent id.
var ErrReclaimBadInput = errors.New("dex: reclaimIntent input too short (need bytes32 intentID)")

// balanceDeltaForOutput maps a credited output amount to the V4 BalanceDelta
// convention (output paid out to taker = negative on the output side; the input
// side already moved at Phase A so it is zero on the settlement leg).
func balanceDeltaForOutput(params SwapParams, amountOut *big.Int) BalanceDelta {
	out := new(big.Int).Neg(amountOut)
	if params.ZeroForOne {
		// token1 is the output for zeroForOne.
		return BalanceDelta{Amount0: big.NewInt(0), Amount1: out}
	}
	return BalanceDelta{Amount0: out, Amount1: big.NewInt(0)}
}

// minAmountOut derives the swap's slippage floor from V4 SwapParams (exact-output
// names the floor; exact-input leaves it to the D price limit). Routing only.
func minAmountOut(params SwapParams) *big.Int {
	if params.AmountSpecified != nil && params.AmountSpecified.Sign() > 0 {
		return new(big.Int).Set(params.AmountSpecified)
	}
	return big.NewInt(0)
}

// swapAssetDirection returns the (tokenIn, tokenOut) injective AssetIDs implied by
// the pool key and swap direction. ZeroForOne true => in=currency0, out=currency1.
func swapAssetDirection(key PoolKey, params SwapParams) (in, out [32]byte) {
	c0 := assetID(key.Currency0)
	c1 := assetID(key.Currency1)
	if params.ZeroForOne {
		return c0, c1
	}
	return c1, c0
}

// --- Fee/volume analytics: SHARDED, no global hot write slot (Block-STM rule).
const (
	feeShards = 64
	volShards = 64
)

var (
	feeBucketPrefix = []byte(settleStateNamespace + "fee")
	volBucketPrefix = []byte(settleStateNamespace + "vol")
)

func feeBucketKey(feeAssetID [32]byte, epoch uint64) common.Hash {
	id := make([]byte, 0, 40)
	id = append(id, feeAssetID[:]...)
	var e [8]byte
	putU64(e[:], epoch%feeShards)
	id = append(id, e[:]...)
	return makeStorageKey(feeBucketPrefix, id)
}

func volBucketKey(poolID [32]byte, epoch uint64) common.Hash {
	id := make([]byte, 0, 40)
	id = append(id, poolID[:]...)
	var e [8]byte
	putU64(e[:], epoch%volShards)
	id = append(id, e[:]...)
	return makeStorageKey(volBucketPrefix, id)
}

func accrueVolume(stateDB StateDB, poolID [32]byte, amount *big.Int, epoch uint64) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	k := volBucketKey(poolID, epoch)
	cur := new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, k).Bytes())
	var w common.Hash
	new(big.Int).Add(cur, amount).FillBytes(w[:])
	stateDB.SetState(poolManagerAddr9999, k, w)
}

func putU64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// _ keeps ids imported for the settlement-id types used across the file set.
var _ = ids.Empty
