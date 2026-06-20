// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle9999.go is THE production DEX money path (LP-9999). It composes the
// single-concern pieces — receipt decode (receipt.go), halt gate (halt9999.go),
// context binding (receipt.go BindToSwap), replay protection (consumedReceipt
// below), certificate verification (verifier_registry.go -> bls_cert.go), and
// value settlement (below) — into the V4 swap handler. C SETTLES; C never matches.
//
// The handler is a PURE DETERMINISTIC function of (input, caller, StateDB, block):
// the only "external" thing it touches is the cert, which it VERIFIES rather than
// queries. There is no live matcher call, no remote backend, no embedded order
// book, and no inert mode — settlement is exactly "verify a committed+certified
// D-Chain fill, then move value". Any failure reverts with no partial state.

// --- Replay protection: consumedReceipt[receiptID] -> block number (non-zero).
//
// Durable (survives restart), consensus-shared (identical on every validator
// replaying the block), and content-addressed by the D-Chain receiptID. A
// re-executed / reorged / retried C tx carrying the same receipt finds it already
// consumed and reverts — exactly-once settlement. This is the RED H1 property the
// deprecated path also required: the replay map lives in StateDB, never a process
// cache.
var consumedReceiptPrefix = []byte(settleStateNamespace + "consumed")

func consumedReceiptKey(receiptID [32]byte) common.Hash {
	return makeStorageKey(consumedReceiptPrefix, receiptID[:])
}

func isReceiptConsumed(stateDB stateKV, receiptID [32]byte) bool {
	return stateDB.GetState(poolManagerAddr9999, consumedReceiptKey(receiptID)) != (common.Hash{})
}

func markReceiptConsumed(stateDB stateKV, receiptID [32]byte, blockNumber uint64) {
	var v common.Hash
	// Store blockNumber+1 so the slot is non-zero even at genesis height 0 (a zero
	// slot reads as "not consumed"); the +1 is a presence sentinel, not a height
	// the caller reads back.
	uint256.NewInt(blockNumber + 1).WriteToSlice(v[:])
	stateDB.SetState(poolManagerAddr9999, consumedReceiptKey(receiptID), v)
}

// --- 0x9999 config (networkID, cChainID): the precompile's CONFIGURED chain
// identity, written to StateDB at Configure (durable, consensus-shared, identical
// on every validator since it comes from genesis). The receipt must name THIS
// chain; without a configured identity a malicious receipt could claim any chain.
var (
	cfgNetworkIDKey = makeStorageKey([]byte(settleStateNamespace+"cfg.net"), []byte{})
	cfgCChainIDKey  = makeStorageKey([]byte(settleStateNamespace+"cfg.cid"), []byte{})
)

// SetSettleChainIdentity records the (networkID, cChainID) the 0x9999 receipts
// must bind to. Called once at Configure from genesis config. A zero cChainID is
// allowed (single-chain dev) but then receipts must also carry the zero cChainID.
func SetSettleChainIdentity(stateDB stateKV, networkID uint32, cChainID [32]byte) {
	var n common.Hash
	uint256.NewInt(uint64(networkID)).WriteToSlice(n[:])
	stateDB.SetState(poolManagerAddr9999, cfgNetworkIDKey, n)
	var c common.Hash
	copy(c[:], cChainID[:])
	stateDB.SetState(poolManagerAddr9999, cfgCChainIDKey, c)
}

func loadSettleChainIdentity(stateDB stateKV) (uint32, [32]byte) {
	n := stateDB.GetState(poolManagerAddr9999, cfgNetworkIDKey)
	networkID := uint32(new(big.Int).SetBytes(n[:]).Uint64())
	c := stateDB.GetState(poolManagerAddr9999, cfgCChainIDKey)
	var cChainID [32]byte
	copy(cChainID[:], c[:])
	return networkID, cChainID
}

// --- Settlement value movement. The 0x9999 vault (the precompile self-address)
// is the counterparty reserve: a deposit locks tokenIn into the vault, a credit
// releases tokenOut from the vault. NO MINT — a credit that the vault cannot back
// reverts (conservation). This keeps 0x9999 pure receipt-settlement with no
// embedded balance ledger of its own beyond the per-asset vault holdings.

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
	ErrSettleUnbacked      = errors.New("dex: vault cannot back the credited amountOut (no mint)")
	ErrSettleNativeFunds   = errors.New("dex: sender has insufficient native balance for amountIn")
	ErrSettleAmountRange   = errors.New("dex: settle amount exceeds uint256")
	ErrSettleERC20Vault    = errors.New("dex: ERC-20 settlement requires an erc20Vault-capable StateDB")
	ErrSettleObservedShort = errors.New("dex: ERC-20 amountIn transfer delivered less than required (no partial settle)")
	ErrSettleDeltaOverflow = errors.New("dex: settle amountIn/amountOut exceeds int128 BalanceDelta range")
)

// --- Swap gas model: O(N) in the validator-set size and O(S) in the signer count.
//
// The cert verify is NOT constant work: ResolveValidatorSet does 1+3N StateDB reads
// + N compressed-G1 decompressions (each an isRTorsion subgroup check), then
// AggregatePublicKeys re-decodes the S signer points, then one BLS pairing. A flat
// GasSwap badly under-prices a large set (maxValidatorsPerSet is 65536), letting a
// block of such settlements force every validator to execute far more crypto wall-
// time than the gas budget models. We charge the actual shape:
//
//	gas(swap) = GasSwapBase + N*GasResolvePerValidator + S*GasAggPerSigner + GasBLSPairing
//
// calibrated so the common small set lands near the platform's PQ-verify gas tier.
// The per-validator term covers the cold-SLOAD x3 + the decompress/subgroup check
// (so a forged cert over a real set still pays the full resolve cost it induces).
const (
	GasSwapBase            uint64 = 20_000 // decode + bind + halt + replay + analytics.
	GasResolvePerValidator uint64 = 2_500  // 3 cold SLOADs + 1 G1 decompress/subgroup check.
	GasAggPerSigner        uint64 = 3_000  // re-decode + on-curve check + point add per signer.
	GasBLSPairing          uint64 = 60_000 // the final aggregate pairing (2 Miller loops + final exp).
)

// isNativeAsset reports whether an injective AssetID is native LUX (all-zero).
func isNativeAsset(id [32]byte) bool { return id == ([32]byte{}) }

// assetAddress recovers the 20-byte token address from an injective AssetID. The
// AssetID is the left-padded address (assetID(Currency)); the low 20 bytes are the
// address. Native (all-zero) recovers address(0).
func assetAddress(id [32]byte) common.Address {
	var a common.Address
	copy(a[:], id[12:32])
	return a
}

// settle moves value for a verified receipt: debit amountIn of tokenIn from the
// sender into the vault, then credit amountOut of tokenOut from the vault to the
// recipient. All-or-nothing: a failure at any leg returns an error and the EVM
// reverts the whole call (no partial state). NO MINT, conservation-checked.
//
// FAIL-FAST CONSERVATION (defense in depth): the two preconditions that can fail
// — sender lacks amountIn, vault cannot back amountOut — are checked BEFORE any
// value moves. So even if EVM revert were somehow bypassed, an under-funded or
// unbacked settle moves NOTHING. The EVM snapshot/revert is still the primary
// all-or-nothing guarantee; this ordering makes the invariant hold without it.
func settle(stateDB StateDB, r *DFillReceiptV1) error {
	if !r.AmountIn.IsUint64() && !isWord(r.AmountIn) {
		return ErrSettleAmountRange
	}
	// --- Precheck conservation before moving any value (fail-fast).
	if isNativeAsset(r.TokenInAssetID) {
		amt, of := uint256.FromBig(r.AmountIn)
		if of {
			return ErrSettleAmountRange
		}
		if stateDB.GetBalance(r.Sender).Cmp(amt) < 0 {
			return ErrSettleNativeFunds
		}
	}
	if r.AmountOut.Sign() > 0 {
		if loadSettleVault(stateDB, r.TokenOutAssetID).Cmp(r.AmountOut) < 0 {
			return ErrSettleUnbacked // NO MINT: the vault must already hold the output.
		}
	}

	// --- Debit amountIn of tokenIn from sender INTO the vault.
	if isNativeAsset(r.TokenInAssetID) {
		amt, of := uint256.FromBig(r.AmountIn)
		if of {
			return ErrSettleAmountRange
		}
		if stateDB.GetBalance(r.Sender).Cmp(amt) < 0 {
			return ErrSettleNativeFunds
		}
		stateDB.SubBalance(r.Sender, amt)
		stateDB.AddBalance(poolManagerAddr9999, amt)
		// Track vault holdings of native so the credit side can underflow-guard.
		cur := loadSettleVault(stateDB, r.TokenInAssetID)
		storeSettleVault(stateDB, r.TokenInAssetID, new(big.Int).Add(cur, r.AmountIn))
	} else {
		vault, ok := stateDBERC20(stateDB)
		if !ok {
			return ErrSettleERC20Vault
		}
		token := assetAddress(r.TokenInAssetID)
		delta, err := safeTransferTokenFrom(vault, token, r.Sender, poolManagerAddr9999, r.AmountIn)
		if err != nil {
			return err
		}
		// Observed-delta: a fee-on-transfer token may deliver less. For settlement
		// we require the FULL amountIn arrived (the receipt obligates exactly that);
		// a short delivery is refused so the vault never credits tokenOut against an
		// underfunded tokenIn (conservation).
		if delta.Cmp(r.AmountIn) < 0 {
			return ErrSettleObservedShort
		}
		cur := loadSettleVault(stateDB, r.TokenInAssetID)
		storeSettleVault(stateDB, r.TokenInAssetID, new(big.Int).Add(cur, delta))
	}

	// --- Credit amountOut of tokenOut from the vault TO the recipient.
	if r.AmountOut.Sign() == 0 {
		return nil // a zero-output fill is settled by the debit alone.
	}
	held := loadSettleVault(stateDB, r.TokenOutAssetID)
	if held.Cmp(r.AmountOut) < 0 {
		return ErrSettleUnbacked // NO MINT: the vault must already hold the output.
	}
	storeSettleVault(stateDB, r.TokenOutAssetID, new(big.Int).Sub(held, r.AmountOut))
	if isNativeAsset(r.TokenOutAssetID) {
		amt, of := uint256.FromBig(r.AmountOut)
		if of {
			return ErrSettleAmountRange
		}
		// UNDERFLOW GUARD (defense in depth): StateDB.SubBalance is uint256-modular
		// and does NOT revert on underflow when a precompile calls it directly, so a
		// vault-accounting bug could otherwise wrap 0x9999's native balance to ~2^256.
		// The vault's tracked holdings (settleVault, checked above) should never exceed
		// its real balance, so this can only fire on a regression — fail loud, never wrap.
		if stateDB.GetBalance(poolManagerAddr9999).Cmp(amt) < 0 {
			return ErrSettleUnbacked
		}
		// The vault holds this native (tracked above); pay out from the self-address.
		stateDB.SubBalance(poolManagerAddr9999, amt)
		stateDB.AddBalance(r.Recipient, amt)
	} else {
		vault, ok := stateDBERC20(stateDB)
		if !ok {
			return ErrSettleERC20Vault
		}
		token := assetAddress(r.TokenOutAssetID)
		if err := safeTransferTokenTo(vault, token, r.Recipient, r.AmountOut); err != nil {
			return err
		}
	}
	return nil
}

// isWord reports whether v fits in 32 bytes (a uint256). amountIn/out are uint256
// on the wire; this guards the uint256 conversions.
func isWord(v *big.Int) bool {
	return v != nil && v.Sign() >= 0 && v.BitLen() <= 256
}

// stateDBERC20 resolves the erc20Vault capability for the settle path. It prefers
// a StateDB that DIRECTLY implements erc20Vault (e.g. a host StateDB with native
// token access, or a test in-memory vault) and otherwise falls back to the
// poolStateAdapter's own erc20Vault (the production EVM sub-call bridge into the
// token contract). This single point keeps "where token value moves" in one place
// without complecting the production sub-call path with the direct-capability path.
func stateDBERC20(stateDB StateDB) (erc20Vault, bool) {
	// A pool-state adapter exposes its underlying StateDB; if that underlying
	// directly implements erc20Vault, prefer it (it is the authoritative ledger).
	if a, ok := stateDB.(*poolStateAdapter); ok {
		if under, ok := a.underlyingStateDB().(erc20Vault); ok {
			return under, true
		}
	}
	v, ok := stateDB.(erc20Vault)
	return v, ok
}

// --- Fee/volume analytics: SHARDED, no global hot write slot (Block-STM rule).
// feeBucket[asset][epoch % feeShards] accumulates fees; volume[pool][epoch % volShards]
// accumulates notional. Two concurrent swaps touching different assets/pools (or
// the same in different epoch shards) never serialize on a single global counter.

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

func accrueFee(stateDB StateDB, feeAssetID [32]byte, amount *big.Int, epoch uint64) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	k := feeBucketKey(feeAssetID, epoch)
	cur := new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, k).Bytes())
	var w common.Hash
	new(big.Int).Add(cur, amount).FillBytes(w[:])
	stateDB.SetState(poolManagerAddr9999, k, w)
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

// SettleSwap is THE 0x9999 swap handler. It decodes the V4 swap call (key, params,
// hookData), extracts the certified D-Chain fill receipt from hookData, and
// settles it. The V4 ABI is UNCHANGED — web/mobile already pass `bytes hookData`;
// only its CONTENTS now carry the receipt + cert. Returns the V4 BalanceDelta
// (amountOut, amountIn) on success, or reverts.
//
// settleAddr is the address the call hit (0x9999 directly, or 0x9010 forwarding).
// The receipt always binds to 0x9999 regardless, so a forwarded call settles under
// the same money path and replay namespace.
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
	// Charge the flat BASE first (decode/bind/halt/replay); the O(N)/O(S) crypto
	// terms are charged below once the validator-set size and signer count are known.
	if suppliedGas < GasSwapBase {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := suppliedGas - GasSwapBase

	key, params, hookData, err := DecodeSwapInput(input)
	if err != nil {
		return nil, gasLeft, err
	}

	receipt, cert, _, err := DecodeSettlementHookData(hookData)
	if err != nil {
		return nil, gasLeft, err
	}

	// The pool-state adapter bridges contract.StateDB to the package StateDB (and
	// forwards the erc20Vault capability) — the same adapter the 0x9010 handlers
	// use, so the settle path and the rest of the package agree on state access.
	stateDB := newPoolStateAdapter(state)
	blockTime := state.GetBlockContext().Timestamp()
	blockNumber := state.GetBlockContext().Number().Uint64()

	// (1) HALT gate — cheapest scope first; revert-safe StateDB read.
	if err := checkHalt(stateDB, receipt, cert); err != nil {
		return nil, gasLeft, err
	}

	// (2) CONTEXT binding — receipt names THIS swap on THIS chain at 0x9999.
	// In the receipt model the V4 swap's recipient is the CALLER's EVM account
	// (the account invoking swap receives amountOut); the receipt binds Recipient
	// to it. A distinct recipient is a P4 router concern carried explicitly.
	// Day-1: no operator delegation; sender MUST equal caller.
	networkID, cChainID := loadSettleChainIdentity(stateDB)
	recipient := caller
	if err := receipt.BindToSwap(key, params, caller, recipient, networkID, cChainID, blockTime, false); err != nil {
		return nil, gasLeft, err
	}

	// (3) REPLAY gate — exactly-once settlement, durable + consensus-shared.
	if isReceiptConsumed(stateDB, receipt.ReceiptID) {
		return nil, gasLeft, errors.New("dex: receipt already consumed")
	}

	// (3b) GAS for the O(N)/O(S) crypto BEFORE the expensive verify. N = the resolved
	// set size (one cheap meta SLOAD), S = popcount(SignerBitmap). Charging here means
	// a forged cert over a large registered set still pays the resolve+decompress cost
	// it forces every validator to perform — it cannot under-pay by failing late.
	n := uint64(validatorSetSize(stateDB, receipt.DChainID, cert.ValidatorSetID))
	s := uint64(bitmapPopcount(cert.SignerBitmap))
	verifyGas := n*GasResolvePerValidator + s*GasAggPerSigner + GasBLSPairing
	if gasLeft < verifyGas {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft -= verifyGas

	// (4) CERTIFICATE verify — DETERMINISTIC quorum-aggregate over the active set.
	// Day-1 one-cert-per-receipt: receiptRoot == receiptID (P3 makes it a fill
	// Merkle root + inclusion proof). Dispatch by certType through the registry.
	receiptRoot := receipt.ReceiptID
	if err := verifyCert(stateDB, receipt, receiptRoot, cert); err != nil {
		return nil, gasLeft, err
	}

	// (4b) RETURN-FIDELITY guard: the V4 BalanceDelta legs are signed int128. A fill
	// whose amountIn/amountOut cannot be faithfully reported as int128 must REVERT
	// (matching V4 toBalanceDelta, which reverts on int128 overflow) rather than
	// settle and return a truncated/sign-flipped delta. Pure deterministic check on
	// the certified amounts. Placed BEFORE the consume mark so an over-range fill
	// leaves the receipt unconsumed even absent EVM revert.
	if !FitsSignedInt128(receipt.AmountIn) || !FitsSignedInt128(receipt.AmountOut) {
		return nil, gasLeft, ErrSettleDeltaOverflow
	}

	// (5) MARK consumed — BEFORE value movement (CEI for the replay slot). This makes
	// exactly-once STRUCTURAL rather than contingent on sender==caller + no live Call:
	// the ERC-20 legs in settle() are real EVM sub-calls into attacker-listable token
	// contracts, and an operator-delegated re-entry (callerAuthorized=true, a P4 seam)
	// could otherwise re-enter swap with the SAME receipt and double-settle before the
	// mark. With the mark set first, a re-entrant frame for the same receipt hits the
	// consumed slot at step (3) and reverts. A failed settle still leaves the receipt
	// UNCONSUMED because the EVM revert rolls back this SetState too (all-or-nothing).
	markReceiptConsumed(stateDB, receipt.ReceiptID, blockNumber)

	// (6) SETTLE value — all-or-nothing, no mint, conservation-checked.
	if err := settle(stateDB, receipt); err != nil {
		return nil, gasLeft, err
	}

	// (7) Analytics — SHARDED, no global hot write.
	epoch := blockNumber
	accrueFee(stateDB, receipt.FeeAssetID, receipt.FeeAmount, epoch)
	accrueVolume(stateDB, receipt.PoolKeyHash, receipt.AmountIn, epoch)

	// V4 return: BalanceDelta packs (amount0, amount1). Map to the swap direction:
	// the taker spends amountIn (negative for the spent side) and receives amountOut.
	delta := balanceDeltaForSwap(params, receipt.AmountIn, receipt.AmountOut)
	return PackBalanceDelta(delta.Amount0, delta.Amount1), gasLeft, nil
}

// balanceDeltaForSwap maps (amountIn, amountOut) to the V4 BalanceDelta convention
// (amount0/amount1 from the pool's perspective; negative = paid out to taker,
// positive = paid in by taker — we mirror the existing PackBalanceDelta usage).
// ZeroForOne: token0 in (positive to pool), token1 out (negative to pool/taker).
func balanceDeltaForSwap(params SwapParams, amountIn, amountOut *big.Int) BalanceDelta {
	in := new(big.Int).Set(amountIn)
	out := new(big.Int).Neg(amountOut)
	if params.ZeroForOne {
		return BalanceDelta{Amount0: in, Amount1: out}
	}
	return BalanceDelta{Amount0: out, Amount1: in}
}
