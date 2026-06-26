// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/bridge"
	"github.com/luxfi/precompile/contract"
)

// intent_settle.go is the cross-chain INTENT SETTLEMENT primitive — a money primitive,
// not a router. It turns external value into the asset the USER signed for, or leaves the
// world untouched: "bridge-in becomes the desired asset, or nothing happened."
//
// The user signs ONE Intent (every value-affecting field — recipient, minOut, source/desired
// asset, amount, refund, nonce, networks). The relayer carries the Intent + its signature +
// the bridge Proof + a Swap (pool routing). The relayer can change NOTHING the user signed:
// every economic parameter is recovered from the SIGNED Intent, and the relayer-supplied Swap
// is VALIDATED against it (a pool that sells the wrong asset, yields the wrong asset, or gives
// a worse-than-signed fill REVERTS — it never silently fills differently).
//
// It COMPOSES the existing primitives and forks NONE of them:
//
//   - bridge.VerifyCompletion / bridge.CompleteBridge  (the B-Chain MPC bridge-in proof)
//   - runSyncSwap                                       (the 0x9999 synchronous atomic settle)
//   - bridge.RefundExpired                              (the permissionless timeout refund)
//
// ATOMIC-OR-REFUND (same-tx atomic-or-nothing). The bridge-in credit (the recipient's
// spendable native balance), the intent nonce-burn, and the 0x9999 synchronous swap ALL
// execute on the SAME C-Chain EVM StateDB in the SAME transaction. A SINGLE StateDB snapshot
// makes them one unit: if the swap cannot fill, RevertToSnapshot rolls back the mint AND the
// nonce-burn, and the bridge object is NEVER consumed (CompleteBridge is the LAST mutation,
// run only after the swap fills). On failure nothing was minted, nothing burned, nothing
// consumed — the inbound stays Pending and the user recovers it permissionlessly via
// bridge.RefundExpired once the bridge deadline passes.
//
// NON-CUSTODIAL TOTALITY. Every inbound ends in exactly one of two terminal states and NO
// other: (a) FILLED — the user holds the DesiredOutputAsset (>= the signed MinOut) and the
// bridge object is Completed; or (b) REFUNDABLE — nothing was credited/burned/consumed, the
// object is still Pending, recoverable by ANYONE via RefundExpired after the deadline. There
// is no operator custody and no path that strands or seizes value. The ONLY way to end up
// holding the intermediate wrapped asset is to explicitly call bridgeInOnly — the composite
// never leaves a user holding wrapped-after-failed-swap.
//
// THE BRIDGE-IN CREDIT IS THE NATIVE-BALANCE MINT, backed 1:1 by the external asset the MPC
// locked on the source chain; CompleteBridge is the authority that authorizes it. It is the
// one balance mutation a StateDB snapshot can revert atomically, so the swap's input side must
// be the pool's native side (assetID == SourceAsset == all-zero). The output side is released
// from the 0x9999 vault (conservation-checked, no output-side mint).

// Intent is the user's SIGNED settlement intent. It is the COMPLETE statement of what the user
// wants; the signature (passed alongside) covers every field via intentDigest, so a relayer
// who alters ANY field invalidates the signature. Nothing value-affecting lives outside it.
type Intent struct {
	SourceNetwork      uint32         // where the external value originates (bridge source chain)
	SourceAsset        [32]byte       // injective asset id of the inbound (native == all-zero)
	SourceAmount       uint64         // the bridged amount (must equal the bridge request amount)
	DestNetwork        uint32         // THIS chain's NetworkID — bound at verify and in the digest
	DesiredOutputAsset [32]byte       // the asset the user wants out (the swap's output side)
	MinOut             uint64         // signed slippage floor; a realized fill below it reverts
	Deadline           uint64         // unix-seconds expiry of the intent (0 => no deadline)
	Recipient          common.Address // the signer AND the sole receiver of the output
	Nonce              uint64         // per-recipient one-shot replay guard
	RefundAddress      common.Address // where a never-filled inbound is recoverable (signed)
}

// Proof is the bridge proof the relayer supplies: which bridge object (RequestID) and the
// committee signature set attesting it. Each SignerSig names a committee member by index;
// the member's public key is read from STATE (never from this proof), and the set must meet
// the committee's ⅔ weight over the canonical completion digest. It is verified WITHOUT
// consuming the object.
type Proof struct {
	RequestID [32]byte           // the B-Chain MPC inbound this proof attests
	Signers   []bridge.SignerSig // the ⅔-weight committee attestation over the completion digest
}

// Swap is the relayer-supplied ROUTING for the swap leg: which 0x9999 pool and direction. It
// carries NOTHING value-affecting — the pool's input/output sides are VALIDATED against the
// signed Intent (SourceAsset / DesiredOutputAsset), and the floor/deadline/recipient all come
// from the Intent. The relayer picks the route; the user's signature fixes the economics.
type Swap struct {
	Pool       PoolKey // the 0x9999 pool: SourceAsset <-> DesiredOutputAsset
	ZeroForOne bool    // true => sell currency0 (the native inbound) for currency1
}

// Result is the terminal report: FILLED xor REFUNDABLE — never both, never neither. Filled
// carries the V4 BalanceDelta (empty for bridgeInOnly); Refundable carries the reason the
// settlement could not proceed (the inbound was left untouched, recoverable via RefundExpired).
type Result struct {
	Filled       bool   // value delivered (swap >= MinOut, or bridge-in credited)
	BalanceDelta []byte // V4 BalanceDelta bytes (composite fill only)
	Refundable   bool   // could not proceed; nothing credited/burned/consumed; recover via RefundExpired
	Reason       error  // why it could not proceed (Refundable only)
}

// intentDomainSeparator domain-separates the intent signing digest from every other signed
// message in the system (the bridge registrar uses "lux.bridge.registrar.v1"). A signature
// over an intent can never be replayed as any other message kind.
const intentDomainSeparator = "lux.dex.intent.v1"

// intentSigLen is the fixed ECDSA signature width: r(32) || s(32) || v(1).
const intentSigLen = 65

// intentNoncePrefix namespaces the per-recipient one-shot nonce slots in 0x9999 storage.
const intentNoncePrefix = "lux.dex.intent.nonce"

var (
	// ErrIntentResolved is returned when the bridge object is already terminal
	// (completed / refunded / expired): a consumed inbound can never be re-settled. This is
	// the early replay guard; CompleteBridge re-checks at consume time (defense in depth).
	ErrIntentResolved = errors.New("dex: bridge object already completed/refunded/expired (no replay)")

	// ErrIntentBadSignature is returned when the intent signature is malformed or does not
	// recover to intent.Recipient over the domain/network/chain-bound digest. Any relayer
	// tamper of any signed field lands here (the digest changes => recovery misses Recipient).
	ErrIntentBadSignature = errors.New("dex: intent signature does not recover to the signed recipient")

	// ErrIntentNonceUsed is returned when intent.Nonce was already consumed for this recipient
	// — a replayed intent (even against a different bridge object) is refused.
	ErrIntentNonceUsed = errors.New("dex: intent nonce already used for this recipient (no replay)")

	// ErrIntentWrongNetwork is returned when intent.DestNetwork is not THIS chain's NetworkID.
	// The digest also binds NetworkID+ChainID, so a wrong-network intent fails at the signature
	// too; this is the explicit, early, clear-error guard.
	ErrIntentWrongNetwork = errors.New("dex: intent.DestNetwork is not this chain's NetworkID (no cross-network replay)")

	// ErrIntentSourceMismatch is returned when the signed intent does not match the bridge
	// object the proof attests (source network / source asset / recipient). A relayer cannot
	// pair a signed intent with a non-matching inbound.
	ErrIntentSourceMismatch = errors.New("dex: signed intent does not match the bridged inbound (source network/asset/recipient)")

	// ErrIntentBadAmount is returned when the bridged amount is non-positive, out of range, or
	// not equal to the signed SourceAmount.
	ErrIntentBadAmount = errors.New("dex: bridged amount is non-positive, out of range, or != signed SourceAmount")

	// ErrIntentDeadline is the (soft, refundable) reason reported when the signed intent has
	// expired: settlement is refused, nothing is minted/burned/consumed, the inbound stays
	// recoverable via RefundExpired.
	ErrIntentDeadline = errors.New("dex: intent deadline passed; inbound recoverable via RefundExpired")

	// ErrIntentPartialFill is the (soft, refundable) reason reported when the swap could only
	// fill part of the inbound. The default is FULL-FILL-OR-REFUND: a partial fill would leave
	// the user holding the unspent inbound as wrapped native (forbidden — bridgeInOnly is the
	// only intermediate-custody path), so a shortfall reverts and the whole inbound is
	// recoverable. The Intent carries no opt-in partial flag, so this is unconditional.
	ErrIntentPartialFill = errors.New("dex: swap filled only part of the inbound; full-fill-or-refund -> reverted, inbound recoverable via RefundExpired")

	// ErrIntentSwapAssetMismatch is returned when the relayer-supplied pool does not sell the
	// signed SourceAsset for the signed DesiredOutputAsset. The relayer routes; it never picks
	// the assets — a mismatched pool reverts rather than silently filling a different asset.
	ErrIntentSwapAssetMismatch = errors.New("dex: swap pool sides do not match the signed SourceAsset/DesiredOutputAsset")

	// ErrIntentNonNativeIn is returned when the inbound (SourceAsset) is not the native side.
	// The composite credits the inbound via the native-balance mint (the only revertible
	// credit), so the inbound must be native.
	ErrIntentNonNativeIn = errors.New("dex: intent settlement credits the inbound via the native-balance mint; SourceAsset must be native")

	// ErrIntentNotSwap is returned when bridgeInAndSwapOrRefund is called with an intent whose
	// DesiredOutputAsset == SourceAsset (a pure bridge-in). Such an intent belongs to
	// bridgeInOnly — the relayer cannot reinterpret one signed-intent kind as the other.
	ErrIntentNotSwap = errors.New("dex: intent has DesiredOutputAsset == SourceAsset (a bridge-in); use bridgeInOnly")

	// ErrIntentNotBridgeOnly is returned when bridgeInOnly is called with an intent whose
	// DesiredOutputAsset != SourceAsset (a conversion). Such an intent belongs to
	// bridgeInAndSwapOrRefund.
	ErrIntentNotBridgeOnly = errors.New("dex: intent has DesiredOutputAsset != SourceAsset (a conversion); use bridgeInAndSwapOrRefund")

	// ErrIntentNoAtomicState is returned when the host did not wire the AtomicState capability:
	// the digest binds NetworkID+ChainID, so without the chain identity the intent cannot be
	// safely verified — fail closed rather than verify an unbound signature.
	ErrIntentNoAtomicState = errors.New("dex: host exposes no chain identity (AtomicState) to bind the intent signature")
)

// bridgeInAndSwapOrRefund is THE cross-chain intent settlement primitive: external value
// becomes the SIGNED desired asset, or nothing happened.
//
// Execution order (exact, all within one C-Chain tx):
//  1. Verify the bridge proof / MPC quorum WITHOUT consuming it (VerifyCompletion-style).
//  2. Verify the intent signature (-> recipient), nonce (unused), deadline (now <= deadline),
//     and bind the signed intent to the attested inbound (network/asset/amount/recipient).
//  3. Snapshot, then materialize the inbound value (native mint of the wrapped SourceAsset).
//  4. Call the 0x9999 swap enforcing the SIGNED MinOut + DesiredOutputAsset; the relayer's
//     pool is validated against the intent (wrong/worse asset or fill => revert, not a silent
//     different fill).
//  5. Swap SUCCEEDS -> burn the nonce and consume the object (CompleteBridge — the LAST
//     mutation), commit; the output is held by intent.Recipient.
//  6. Swap FAILS -> RevertToSnapshot: mint undone, nonce un-burned, object NOT consumed,
//     refund to intent.RefundAddress via RefundExpired remains valid.
//
// A non-nil error is a hard refusal of a malformed/unauthorized call (no state changed). A
// Refundable result is a clean "could not fill, your inbound is safe" receipt (the primitive
// reverted its own writes, so it holds even when invoked outside an EVM frame). The trailing
// uint64 is the remaining gas (precompile plumbing, orthogonal to the money semantics).
func bridgeInAndSwapOrRefund(
	gw *bridge.BridgeGateway,
	state contract.AccessibleState,
	intent Intent,
	intentSig []byte,
	proof Proof,
	swap Swap,
	suppliedGas uint64,
) (Result, uint64, error) {
	// This entry settles a CONVERSION intent: external value MUST become a DIFFERENT asset. A
	// desired==source intent is a pure bridge-in — it belongs to bridgeInOnly (the ONLY
	// intermediate-custody path) — so it is refused here (a relayer cannot reinterpret one
	// signed-intent kind as the other).
	if intent.DesiredOutputAsset == intent.SourceAsset {
		return Result{}, suppliedGas, ErrIntentNotSwap
	}

	// 1-2. Verify the proof (no consume) and the signed intent. Soft reasons (expired intent /
	//       expired bridge) are refundable; everything else is a hard refusal.
	req, amt256, err := verifyIntent(state, gw, intent, intentSig, proof)
	if err != nil {
		if isRefundable(err) {
			return Result{Refundable: true, Reason: err}, suppliedGas, nil
		}
		return Result{}, suppliedGas, err
	}

	// The relayer-supplied routing is VALIDATED against the SIGNED intent: the pool must sell
	// the SourceAsset (credited via the native mint) for the DesiredOutputAsset. A pool that
	// sells/yields any other asset REVERTS — the relayer picks the route, never the assets.
	if assetID(Currency{Address: swapTokenIn(swap)}) != intent.SourceAsset ||
		assetID(Currency{Address: swapTokenOut(swap)}) != intent.DesiredOutputAsset {
		return Result{}, suppliedGas, ErrIntentSwapAssetMismatch
	}
	if !isNativeAsset(intent.SourceAsset) {
		return Result{}, suppliedGas, ErrIntentNonNativeIn
	}

	// 3. ATOMIC unit: ONE snapshot covers the mint, the swap, and the nonce-burn.
	cdb := state.GetStateDB()
	snap := cdb.Snapshot()

	// 3a. Materialize the inbound ONLY inside the tx scope: mint the wrapped SourceAsset to the
	//     recipient's native balance, backed 1:1 by the MPC-locked external asset. Reverted with
	//     the snapshot on a failed swap (no wrapped value survives a failure).
	newPoolStateAdapter(state).AddBalance(intent.Recipient, amt256)

	// 4. The 0x9999 atomic swap, enforcing the SIGNED MinOut (never a relayer value) via the
	//    DM01 hookData. syncSwap is both-or-neither and refunds unspent input; an unbacked /
	//    unfillable / min-out-breached swap returns an error and the whole unit is reverted.
	params := SwapParams{
		ZeroForOne:        swap.ZeroForOne,
		AmountSpecified:   new(big.Int).Neg(req.Amount), // negative => exact-input magnitude
		SqrtPriceLimitX96: big.NewInt(0),                // no price limit; MinOut is the floor
	}
	out, gasLeft, swapErr := runSyncSwap(state, intent.Recipient, swap.Pool, params, EncodeMinOutHookData(intent.MinOut), suppliedGas, false)
	if swapErr != nil {
		// 6. RELEASE BACK: undo the mint + any partial swap writes; the nonce is NOT burned
		//    (never reached) and the object is NOT consumed -> recoverable via RefundExpired.
		cdb.RevertToSnapshot(snap)
		return Result{Refundable: true, Reason: swapErr}, gasLeft, nil
	}

	// 4a. FULL-FILL-OR-REFUND: the WHOLE inbound must convert. A partial fill (book/AMM shallower
	//     than SourceAmount) would refund the unspent input as wrapped native — leaving the user
	//     holding wrapped-after-swap, which only bridgeInOnly may do. The Intent has no opt-in
	//     partial flag, so a shortfall reverts the entire unit (mint + partial swap undone) and
	//     the inbound stays fully recoverable.
	if !fullyConverted(out, swap.ZeroForOne, intent.SourceAmount) {
		cdb.RevertToSnapshot(snap)
		return Result{Refundable: true, Reason: ErrIntentPartialFill}, gasLeft, nil
	}

	// 5. SWAP FILLED (>= MinOut, full amount): burn the per-recipient nonce (one-shot) INSIDE the snapshot,
	//    then consume the object. CompleteBridge is the LAST mutation, so the object is consumed
	//    IFF the swap filled — and because the status flip is in StateDB under the same snapshot,
	//    a revert un-flips it (the bridge status matches the atomic EVM outcome).
	as, ok := state.(contract.AtomicState)
	if !ok { // unreachable: verifyIntent already required AtomicState. Fail SECURE.
		cdb.RevertToSnapshot(snap)
		return Result{}, gasLeft, ErrIntentNoAtomicState
	}
	markIntentNonceUsed(state, intent.Recipient, intent.Nonce)
	if cerr := gw.CompleteBridge(cdb, bridge.BridgeGatewayCanonicalAddress, as.NetworkID(), as.ChainID(), state.GetBlockContext().Timestamp(), proof.RequestID, proof.Signers); cerr != nil {
		// Unreachable under single-tx execution (pre-verified, nothing mutates the request
		// between verify and here); fail SECURE so a half-applied unit can never strand value.
		cdb.RevertToSnapshot(snap)
		return Result{}, gasLeft, cerr
	}
	return Result{Filled: true, BalanceDelta: out}, gasLeft, nil
}

// bridgeInOnly is the EXPLICIT bridge-in entry — the ONLY path that leaves a user holding the
// intermediate wrapped asset. It settles a PURE bridge-in intent (the user signed
// DesiredOutputAsset == SourceAsset: "deliver the wrapped asset, no swap"). A conversion intent
// (desired != source) belongs to bridgeInAndSwapOrRefund and is refused here, so a relayer can
// never downgrade a signed swap-intent into a bridge-only delivery.
//
// It verifies the SAME proof + intent (sig -> recipient, nonce, deadline, network/source bind),
// then credits the wrapped SourceAsset to intent.Recipient and consumes the object — under one
// snapshot so a fail-secure consume strands nothing.
func bridgeInOnly(
	gw *bridge.BridgeGateway,
	state contract.AccessibleState,
	intent Intent,
	intentSig []byte,
	proof Proof,
	suppliedGas uint64,
) (Result, uint64, error) {
	if intent.DesiredOutputAsset != intent.SourceAsset {
		return Result{}, suppliedGas, ErrIntentNotBridgeOnly
	}
	if !isNativeAsset(intent.SourceAsset) {
		return Result{}, suppliedGas, ErrIntentNonNativeIn
	}

	_, amt256, err := verifyIntent(state, gw, intent, intentSig, proof)
	if err != nil {
		if isRefundable(err) {
			return Result{Refundable: true, Reason: err}, suppliedGas, nil
		}
		return Result{}, suppliedGas, err
	}

	// One snapshot over the credit + nonce-burn so a fail-secure consume reverts both.
	cdb := state.GetStateDB()
	snap := cdb.Snapshot()
	as, ok := state.(contract.AtomicState)
	if !ok { // unreachable: verifyIntent already required AtomicState. Fail SECURE.
		cdb.RevertToSnapshot(snap)
		return Result{}, suppliedGas, ErrIntentNoAtomicState
	}
	newPoolStateAdapter(state).AddBalance(intent.Recipient, amt256)
	markIntentNonceUsed(state, intent.Recipient, intent.Nonce)
	if cerr := gw.CompleteBridge(cdb, bridge.BridgeGatewayCanonicalAddress, as.NetworkID(), as.ChainID(), state.GetBlockContext().Timestamp(), proof.RequestID, proof.Signers); cerr != nil {
		cdb.RevertToSnapshot(snap)
		return Result{}, suppliedGas, cerr
	}
	// The user holds the wrapped SourceAsset (delivered) and the object is consumed once.
	return Result{Filled: true}, suppliedGas, nil
}

// verifyIntent is the shared, MUTATION-FREE verification for both entries. It resolves the
// attested bridge object, guards replay, binds the signed intent to that object, recovers the
// signature to the recipient, and checks the nonce + deadline + proof. It returns the request
// and the inbound amount (as uint256, for the mint) on success, or an error. Soft errors
// (ErrIntentDeadline, bridge.ErrRequestExpired) are mapped to a Refundable result by the
// caller; every other error is a hard refusal. NOTHING here mutates state.
func verifyIntent(
	state contract.AccessibleState,
	gw *bridge.BridgeGateway,
	intent Intent,
	intentSig []byte,
	proof Proof,
) (*bridge.BridgeRequest, *uint256.Int, error) {
	// 0. The host must expose chain identity (NetworkID/ChainID) to bind the signature. Without
	//    it the digest cannot be computed safely — fail closed.
	as, ok := state.(contract.AtomicState)
	if !ok {
		return nil, nil, ErrIntentNoAtomicState
	}
	// The bridge request lifecycle + signer committee live in StateDB at the gateway
	// address; the deadline is judged by BLOCK time (never wall clock) so every validator
	// agrees. These are resolved once and threaded through the read-only checks.
	cdb := state.GetStateDB()
	gwAddr := bridge.BridgeGatewayCanonicalAddress
	bt := state.GetBlockContext().Timestamp()

	// 1. Resolve the inbound bridge object from StateDB.
	req, err := gw.GetRequest(cdb, gwAddr, proof.RequestID)
	if err != nil {
		return nil, nil, err // ErrRequestNotFound — swap-without-bridge-backing is impossible
	}

	// 2. Terminal-state (replay) guard: a completed/refunded/expired inbound can never be
	//    re-settled. Cheap map lookup, done before any crypto.
	switch req.Status {
	case bridge.StatusCompleted, bridge.StatusRefunded, bridge.StatusExpired:
		return nil, nil, ErrIntentResolved
	}

	// 3. Cheap intent<->object pre-binds (pure compares; reject before the expensive crypto):
	//    DestNetwork is THIS network, and the signed source network/asset/recipient match the
	//    attested object. A relayer cannot point a signed intent at a non-matching inbound.
	if intent.DestNetwork != as.NetworkID() {
		return nil, nil, ErrIntentWrongNetwork
	}
	if intent.SourceNetwork != req.SourceChain ||
		assetID(Currency{Address: req.Token}) != intent.SourceAsset ||
		req.Recipient != intent.Recipient {
		return nil, nil, ErrIntentSourceMismatch
	}

	// 4. Amount: positive, fits the swap magnitude domain (uint64) and uint256, and EQUALS the
	//    signed SourceAmount (the relayer cannot settle a different magnitude).
	amount := req.Amount
	if amount == nil || amount.Sign() <= 0 || !amount.IsUint64() || amount.Uint64() != intent.SourceAmount {
		return nil, nil, ErrIntentBadAmount
	}
	amt256, of := uint256.FromBig(amount)
	if of {
		return nil, nil, ErrIntentBadAmount
	}

	// 5. Verify the MPC bridge proof WITHOUT consuming it (shared with CompleteBridge): the
	//    request is Pending, within its block-time deadline, and a ⅔-weight quorum of the
	//    state-resident committee signed the canonical completion digest. A junk/short/sub-⅔
	//    proof hard-refuses; a bridge-expired request is reported refundable.
	if verr := gw.VerifyCompletion(cdb, gwAddr, as.NetworkID(), as.ChainID(), bt, proof.RequestID, proof.Signers); verr != nil {
		return nil, nil, verr // bridge.ErrRequestExpired is mapped to refundable by the caller
	}

	// 6. Verify the intent signature: it must recover to intent.Recipient over the
	//    domain/NetworkID/ChainID-bound digest of EVERY intent field. Any relayer tamper of any
	//    field changes the digest, so the recovery misses Recipient -> refusal.
	signer, serr := recoverIntentSigner(intentDigest(as.NetworkID(), as.ChainID(), intent), intentSig)
	if serr != nil {
		return nil, nil, serr
	}
	if signer != intent.Recipient {
		return nil, nil, ErrIntentBadSignature
	}

	// 7. Nonce one-shot (per-recipient): a used nonce is a replayed intent.
	if intentNonceUsed(state, intent.Recipient, intent.Nonce) {
		return nil, nil, ErrIntentNonceUsed
	}

	// 8. Intent deadline (soft, refundable): an expired intent is refused; nothing is
	//    minted/burned/consumed, so the inbound stays recoverable. Judged by BLOCK time.
	if intent.Deadline != 0 && bt > intent.Deadline {
		return nil, nil, ErrIntentDeadline
	}

	return req, amt256, nil
}

// isRefundable reports whether a verifyIntent / swap error is a SOFT "the inbound is safe and
// recoverable" reason (vs a hard refusal). Soft reasons leave the object Pending so the user
// recovers it via RefundExpired.
func isRefundable(err error) bool {
	return err == ErrIntentDeadline || err == bridge.ErrRequestExpired
}

// intentDigest is the canonical intent signing digest. The off-chain signer MUST produce the
// SAME bytes. It is domain-separated and bound to the LIVE chain identity (NetworkID + ChainID)
// so a signature is valid on exactly one chain — no cross-chain / cross-network replay — and
// covers EVERY intent field so a relayer can alter nothing:
//
//	keccak256(
//	  "lux.dex.intent.v1" ||
//	  networkID(4 BE) || chainID(32) ||                 // live chain binding
//	  SourceNetwork(4 BE) || SourceAsset(32) || SourceAmount(8 BE) ||
//	  DestNetwork(4 BE) || DesiredOutputAsset(32) || MinOut(8 BE) ||
//	  Deadline(8 BE) || Recipient(20) || Nonce(8 BE) || RefundAddress(20)
//	)
func intentDigest(networkID uint32, chainID ids.ID, in Intent) []byte {
	buf := make([]byte, 0, len(intentDomainSeparator)+4+32+4+32+8+4+32+8+8+20+8+20)
	buf = append(buf, []byte(intentDomainSeparator)...)
	buf = appendU32(buf, networkID)
	buf = append(buf, chainID[:]...)
	buf = appendU32(buf, in.SourceNetwork)
	buf = append(buf, in.SourceAsset[:]...)
	buf = appendU64(buf, in.SourceAmount)
	buf = appendU32(buf, in.DestNetwork)
	buf = append(buf, in.DesiredOutputAsset[:]...)
	buf = appendU64(buf, in.MinOut)
	buf = appendU64(buf, in.Deadline)
	buf = append(buf, in.Recipient.Bytes()...)
	buf = appendU64(buf, in.Nonce)
	buf = append(buf, in.RefundAddress.Bytes()...)
	return crypto.Keccak256(buf)
}

// recoverIntentSigner recovers the EVM address that produced sig over digest. sig is the fixed
// r||s||v (65 bytes) ECDSA signature; a malformed signature is refused (it cannot be the
// recipient). Mirrors the bridge registrar's recover (keccak of the 64-byte pubkey tail).
func recoverIntentSigner(digest, sig []byte) (common.Address, error) {
	if len(sig) != intentSigLen {
		return common.Address{}, ErrIntentBadSignature
	}
	pub, err := crypto.Ecrecover(digest, sig)
	if err != nil || len(pub) != 65 {
		return common.Address{}, ErrIntentBadSignature
	}
	return common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]), nil
}

// intentNonceSlot derives the 0x9999 storage slot for a per-recipient intent nonce:
// keccak256("lux.dex.intent.nonce" || recipient || nonce[8]). A non-zero value means used.
func intentNonceSlot(recipient common.Address, nonce uint64) common.Hash {
	buf := make([]byte, 0, len(intentNoncePrefix)+20+8)
	buf = append(buf, intentNoncePrefix...)
	buf = append(buf, recipient.Bytes()...)
	buf = appendU64(buf, nonce)
	var slot common.Hash
	copy(slot[:], crypto.Keccak256(buf))
	return slot
}

// intentNonceUsed reports whether (recipient, nonce) has already been consumed.
func intentNonceUsed(state contract.AccessibleState, recipient common.Address, nonce uint64) bool {
	return newPoolStateAdapter(state).GetState(poolManagerAddr9999, intentNonceSlot(recipient, nonce)) != (common.Hash{})
}

// markIntentNonceUsed records (recipient, nonce) as consumed. The write is covered by the
// caller's snapshot, so a reverted settlement un-burns the nonce (the user can retry).
func markIntentNonceUsed(state contract.AccessibleState, recipient common.Address, nonce uint64) {
	var used common.Hash
	used[31] = 1
	newPoolStateAdapter(state).SetState(poolManagerAddr9999, intentNonceSlot(recipient, nonce), used)
}

// swapTokenIn / swapTokenOut name the pool sides for the swap's direction. The inbound is sold
// (in) for the desired asset (out): currency0->currency1 for ZeroForOne, else currency1->currency0.
func swapTokenIn(s Swap) common.Address {
	if s.ZeroForOne {
		return s.Pool.Currency0.Address
	}
	return s.Pool.Currency1.Address
}

func swapTokenOut(s Swap) common.Address {
	if s.ZeroForOne {
		return s.Pool.Currency1.Address
	}
	return s.Pool.Currency0.Address
}

// fullyConverted reports whether the swap consumed the ENTIRE inbound (the input side of the
// V4 BalanceDelta equals SourceAmount). An exact-input swap pays a negative input amount; a
// full fill pays exactly -SourceAmount, a partial fill pays less. This is the full-fill-or-
// refund gate: anything short means unspent inbound would remain as wrapped native.
func fullyConverted(delta []byte, zeroForOne bool, sourceAmount uint64) bool {
	a0, a1 := UnpackBalanceDelta(delta)
	spent := a0
	if !zeroForOne {
		spent = a1
	}
	spent = new(big.Int).Neg(spent) // input delta is negative; negate to the spent magnitude
	return spent.Sign() >= 0 && spent.Cmp(new(big.Int).SetUint64(sourceAmount)) == 0
}

// appendU32 / appendU64 append a big-endian fixed-width integer (digest + slot encoders).
func appendU32(b []byte, v uint32) []byte {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	return append(b, x[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}
