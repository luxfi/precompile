// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/bridge"
)

// intent_settle_test.go is the acceptance gate for the cross-chain INTENT SETTLEMENT
// primitive (fill): external value becomes the SIGNED
// desired asset, or nothing happened. The harness composes the REAL primitives — a
// bridge.BridgeGateway with a genuine InitiateBridge'd inbound, the shared settle harness's
// native<->ERC-20 market with a REAL resting maker, and a REAL secp256k1 key whose address is
// the intent recipient (so the signature genuinely recovers to it).
//
// Market: currency0 = native (the bridged wrapped inbound, credited via the native mint),
// currency1 = 0x..02 (the ERC-20 DesiredOutputAsset). A zeroForOne swap SELLS the inbound for
// the ERC-20. A maker rests a BID (buys native with the ERC-20) so the swap's SELL crosses.
//
// The relayer is UNTRUSTED: every test that tampers a signed field (recipient, minOut, asset,
// refund, network, amount) must be REJECTED — the relayer carries only the proof + pool routing.

const (
	arrivalPriceGrid = 50 * priceMultiplierConst // 50 quote-per-base on the dexcore grid
	arrivalAmountIn  = 80                        // native the user bridges in
	arrivalProceeds  = arrivalAmountIn * 50      // 80 native @ 50 = 4000 ERC-20 out
)

var (
	arrivalMaker  = common.HexToAddress("0xaa00000000000000000000000000000000000001")
	arrivalRefund = common.HexToAddress("0xdd00000000000000000000000000000000000004") // signed RefundAddress
)

// intentSigner is a real secp256k1 keypair whose EVM address is the intent recipient/signer.
type intentSigner struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

func newIntentSigner(t *testing.T) *intentSigner {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := crypto.FromECDSAPub(&k.PublicKey)
	return &intentSigner{key: k, addr: common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])}
}

// sign signs the canonical, NetworkID/ChainID-bound digest of in with the signer's key.
func (s *intentSigner) sign(t *testing.T, h *e2eHarness, in Intent) []byte {
	t.Helper()
	sig, err := crypto.Sign(intentDigest(h.state.NetworkID(), h.state.ChainID(), in), s.key)
	if err != nil {
		t.Fatalf("Sign intent: %v", err)
	}
	return sig
}

// arrivalHarness wraps the shared settle harness's native<->ERC-20 market. The default settle
// harness installs the permissionless resolver admitting native + currency1 (0x..02), so the
// value path's admission gate passes.
func arrivalHarness(t *testing.T) *e2eHarness {
	t.Helper()
	sh := newSettleHarness(t)
	h := &e2eHarness{settleHarness: sh, key: sh.key}
	seedArrivalCommittee(t, h) // the StateDB-resident ⅔-weight completion committee
	return h
}

// arrivalTokenOut is the market's ERC-20 quote (currency1) — the DesiredOutputAsset.
func (h *e2eHarness) arrivalTokenOut() common.Address { return h.key.Currency1.Address }

// restMakerBid seeds a maker with ERC-20 quote, deposits it, and rests a BID buying the native
// base — the depth a SELL crosses. priceGrid/size set the resting order.
func (h *e2eHarness) restMakerBid(t *testing.T, priceGrid, size, deposit uint64) {
	t.Helper()
	h.mint(h.arrivalTokenOut(), arrivalMaker, int64(deposit))
	h.deposit(t, arrivalMaker, h.arrivalTokenOut(), int64(deposit))
	h.placeArgs(t, arrivalMaker, true /* isBid */, priceGrid, size)
}

// nativeBal reads an account's native (currency0) balance through the production adapter.
func (h *e2eHarness) nativeBal(addr common.Address) uint64 {
	return newPoolStateAdapter(h.state).GetBalance(addr).Uint64()
}

// blockTime is the harness's block timestamp (what the primitive reads for the intent deadline).
func (h *e2eHarness) blockTime() uint64 { return h.state.blockTimestamp }

// swapLeg is the relayer-supplied routing for the harness market (native -> ERC-20).
func (h *e2eHarness) swapLeg() Swap { return Swap{Pool: h.key, ZeroForOne: true} }

// arrivalCommittee is the harness's bridge completion committee: secp256k1 members
// whose signatures over the canonical completion digest authorize a bridge-in. The
// keys are test fixtures (generated once per test binary), NOT production secrets.
type arrivalCommittee struct {
	keys    []*ecdsa.PrivateKey
	members []bridge.CommitteeMember
}

const (
	arrivalCmteEpoch          = 1
	arrivalQuorumNum   uint16 = 2
	arrivalQuorumDen   uint16 = 3
	arrivalQuorumSigns        = 2 // distinct members that meet the ⅔ floor of 3
)

// bridgeGWAddr is where the committee + requests live (the bridge gateway, 0x0440).
var bridgeGWAddr = bridge.BridgeGatewayCanonicalAddress

func newArrivalCommittee(n int) *arrivalCommittee {
	c := &arrivalCommittee{}
	for i := 0; i < n; i++ {
		k, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		var keyID [20]byte
		copy(keyID[:], crypto.Keccak256(crypto.FromECDSAPub(&k.PublicKey)[1:])[12:])
		c.keys = append(c.keys, k)
		c.members = append(c.members, bridge.CommitteeMember{Scheme: bridge.SchemeSecp256k1, Weight: 1, KeyID: keyID})
	}
	return c
}

// arrivalCmte is the fixed 3-member, weight-1, quorum-2/3 committee. A valid proof
// needs two distinct member signatures over the completion digest.
var arrivalCmte = newArrivalCommittee(3)

// signQuorum signs digest with the first arrivalQuorumSigns members — a ⅔-meeting set.
func (c *arrivalCommittee) signQuorum(t *testing.T, digest [32]byte) []bridge.SignerSig {
	t.Helper()
	out := make([]bridge.SignerSig, 0, arrivalQuorumSigns)
	for i := 0; i < arrivalQuorumSigns; i++ {
		sig, err := crypto.Sign(digest[:], c.keys[i])
		if err != nil {
			t.Fatalf("committee sign: %v", err)
		}
		out = append(out, bridge.SignerSig{Index: uint16(i), Sig: sig})
	}
	return out
}

// seedArrivalCommittee writes the harness committee into h's StateDB so the
// completion verifier reads a real ⅔-weight set (never a threshold of one).
func seedArrivalCommittee(t *testing.T, h *e2eHarness) {
	t.Helper()
	if err := bridge.SeedCommittee(h.state.GetStateDB(), bridgeGWAddr,
		arrivalCmteEpoch, arrivalCmte.members, arrivalQuorumNum, arrivalQuorumDen); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
}

// conversionIntent builds + signs a SWAP intent: bridge native in, convert to the ERC-20 out,
// flooring the realized output at minOut, valid until deadline (0 => none), one-shot at nonce.
func (h *e2eHarness) conversionIntent(t *testing.T, s *intentSigner, minOut, deadline, nonce uint64) (Intent, []byte) {
	t.Helper()
	in := Intent{
		SourceNetwork:      bridge.ChainEthereum,
		SourceAsset:        assetID(h.key.Currency0), // native (all-zero)
		SourceAmount:       arrivalAmountIn,
		DestNetwork:        h.state.NetworkID(),
		DesiredOutputAsset: assetID(h.key.Currency1), // the ERC-20 out
		MinOut:             minOut,
		Deadline:           deadline,
		Recipient:          s.addr,
		Nonce:              nonce,
		RefundAddress:      arrivalRefund,
	}
	return in, s.sign(t, h, in)
}

// bridgeOnlyIntent builds + signs a PURE bridge-in intent (DesiredOutputAsset == SourceAsset).
func (h *e2eHarness) bridgeOnlyIntent(t *testing.T, s *intentSigner, nonce uint64) (Intent, []byte) {
	t.Helper()
	in := Intent{
		SourceNetwork:      bridge.ChainEthereum,
		SourceAsset:        assetID(h.key.Currency0), // native
		SourceAmount:       arrivalAmountIn,
		DestNetwork:        h.state.NetworkID(),
		DesiredOutputAsset: assetID(h.key.Currency0), // == source: no swap
		MinOut:             0,
		Deadline:           0,
		Recipient:          s.addr,
		Nonce:              nonce,
		RefundAddress:      arrivalRefund,
	}
	return in, s.sign(t, h, in)
}

// newArrivalGateway records ONE genuine Pending inbound in StateDB: external
// (Ethereum) -> Lux of `amount` native to recipient. The committee signs the
// request's canonical completion digest D, and RecordInbound writes Pending only
// after the ⅔-weight quorum over D verifies — so the inbound is quorum-attested,
// not planted. The returned Proof reuses that same attestation (one MPC signature
// over D both records and completes the inbound). bridgeDeadline is the request's
// block-time completion deadline.
func newArrivalGateway(t *testing.T, h *e2eHarness, recipient common.Address, amount int64, bridgeDeadline uint64) (*bridge.BridgeGateway, [32]byte, Proof) {
	t.Helper()
	gw := bridge.NewBridgeGateway()

	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	r := &bridge.BridgeRequest{
		ID:            id,
		SourceNetwork: bridge.ChainEthereum,
		SourceChain:   bridge.ChainEthereum, // the consumer matches intent.SourceNetwork to req.SourceChain
		DestNetwork:   h.state.NetworkID(),
		DestChain:     bridge.ChainLux,
		Nonce:         0,
		Deadline:      bridgeDeadline,
		Recipient:     recipient,
		Token:         common.Address{}, // native (all-zero asset id)
		Amount:        big.NewInt(amount),
	}
	d := bridge.CompletionDigest(h.state.NetworkID(), h.state.ChainID(), r)
	signers := arrivalCmte.signQuorum(t, d)
	if err := bridge.RecordInbound(h.state.GetStateDB(), bridgeGWAddr, h.state.NetworkID(), h.state.ChainID(), r, signers); err != nil {
		t.Fatalf("RecordInbound: %v", err)
	}
	return gw, id, Proof{RequestID: id, Signers: signers}
}

// requireStatus asserts the inbound's StateDB-resident bridge status.
func requireStatus(t *testing.T, h *e2eHarness, id [32]byte, want bridge.BridgeStatus) {
	t.Helper()
	req, err := bridge.NewBridgeGateway().GetRequest(h.state.GetStateDB(), bridgeGWAddr, id)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if req.Status != want {
		t.Fatalf("request status = %d, want %d", req.Status, want)
	}
}

// refund drives recovery as the inbound's OWNER (the recipient), who may recover anytime,
// at the harness block time.
func (h *e2eHarness) refund(gw *bridge.BridgeGateway, id [32]byte) error {
	r, err := gw.GetRequest(h.state.GetStateDB(), bridgeGWAddr, id)
	if err != nil {
		return err
	}
	return gw.Refund(h.state.GetStateDB(), bridgeGWAddr, r.Recipient, h.blockTime(), id)
}

// assertNativeConservation pins seamReserve[a] == Σ dexcore(available+locked)[a] for the
// market's native base and ERC-20 quote — the vault never fabricates value.
func assertNativeConservation(t *testing.T, h *e2eHarness, accts ...common.Address) {
	t.Helper()
	for _, token := range []common.Address{{} /* native */, h.arrivalTokenOut()} {
		var ledger uint64
		for _, who := range accts {
			ledger += h.dcAvail(who, token) + h.dcLocked(who, token)
		}
		if seam := h.seamReserveOf(token); seam != ledger {
			t.Fatalf("conservation violated for %x: seamReserve=%d ledger=%d", token, seam, ledger)
		}
	}
}

// --- TestBridgeInSwap_CommitsOnlyTogether: swap success => bridge consumed AND output
// delivered — both or neither.

func TestBridgeInSwap_CommitsOnlyTogether(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000) // BID 50 x 100 => 5000 quote locked

	in, sig := h.conversionIntent(t, signer, 3000 /* minOut < the 4000 fill */, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil {
		t.Fatalf("hard error: %v", err)
	}
	if !res.Filled || res.Refundable {
		t.Fatalf("expected Filled, got %+v (reason=%v)", res, res.Reason)
	}

	// The output is delivered to the SIGNED recipient; the minted native netted to zero.
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != arrivalProceeds {
		t.Fatalf("recipient tokenOut = %d, want %d", got, arrivalProceeds)
	}
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("recipient native = %d, want 0 (minted then fully sold)", got)
	}
	// The object is consumed exactly once (Completed) — committed together with the output.
	requireStatus(t, h, id, bridge.StatusCompleted)
	assertNativeConservation(t, h, arrivalMaker, signer.addr)
}

// --- TestBridgeInSwap_RevertLeavesBridgeUnconsumed: swap fail => bridge still PENDING,
// no mint.

func TestBridgeInSwap_RevertLeavesBridgeUnconsumed(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	// NO maker: the book is empty, no AMM depth — the output cannot be backed, the swap reverts.

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil {
		t.Fatalf("hard error: %v", err)
	}
	if res.Filled || !res.Refundable || res.Reason == nil {
		t.Fatalf("expected Refundable with a reason, got %+v", res)
	}
	// The object is NOT consumed — still Pending and recoverable.
	requireStatus(t, h, id, bridge.StatusPending)
	if rerr := h.refund(gw, id); rerr != nil {
		t.Fatalf("Refund must recover an unfilled inbound: %v", rerr)
	}
	requireStatus(t, h, id, bridge.StatusRefunded)
}

// --- TestBridgeInSwap_MinOutFailureRefundable: realized out < signed minOut => revert =>
// refundable to the signed RefundAddress.

func TestBridgeInSwap_MinOutFailureRefundable(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	// Maker rests at a WORSE price (40): 80 @ 40 = 3200, below the 4000 minOut => swap reverts.
	h.restMakerBid(t, 40*priceMultiplierConst, 100, 5000)
	makerLockedBefore := h.dcLocked(arrivalMaker, h.arrivalTokenOut())

	in, sig := h.conversionIntent(t, signer, 4000 /* minOut > the 3200 the book can give */, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil {
		t.Fatalf("hard error: %v", err)
	}
	if res.Filled || !res.Refundable {
		t.Fatalf("expected Refundable on a min-out breach, got %+v", res)
	}
	// No worse-than-signed fill; nothing minted; the maker's resting order is untouched.
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != 0 {
		t.Fatalf("recipient received tokenOut on a min-out-breached swap: %d", got)
	}
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("recipient native = %d, want 0 (mint reverted)", got)
	}
	if got := h.dcLocked(arrivalMaker, h.arrivalTokenOut()); got != makerLockedBefore {
		t.Fatalf("maker lock changed on a reverted swap: %d -> %d", makerLockedBefore, got)
	}
	requireStatus(t, h, id, bridge.StatusPending)
	if rerr := h.refund(gw, id); rerr != nil {
		t.Fatalf("a min-out-breached inbound must be recoverable: %v", rerr)
	}
	requireStatus(t, h, id, bridge.StatusRefunded)
}

// --- TestBridgeInSwap_DeadlineExpired: now > intent.Deadline => revert => refundable.

func TestBridgeInSwap_DeadlineExpired(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000) // ample depth — the deadline is the cause

	in, sig := h.conversionIntent(t, signer, 3000, h.blockTime()-1 /* expired */, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil {
		t.Fatalf("hard error: %v", err)
	}
	if res.Filled || !res.Refundable {
		t.Fatalf("expected Refundable on an expired intent, got %+v", res)
	}
	if res.Reason != ErrIntentDeadline {
		t.Fatalf("reason = %v, want ErrIntentDeadline", res.Reason)
	}
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("recipient native = %d, want 0 (no mint on a stale intent)", got)
	}
	requireStatus(t, h, id, bridge.StatusPending)
	if rerr := h.refund(gw, id); rerr != nil {
		t.Fatalf("Refund must recover the inbound of a stale intent: %v", rerr)
	}
	requireStatus(t, h, id, bridge.StatusRefunded)
}

// --- TestBridgeInSwap_IntentReplayRejected: the SAME signed intent (nonce) cannot settle
// twice — not even against a fresh bridge object. The per-recipient nonce is one-shot.

func TestBridgeInSwap_IntentReplayRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	h.restMakerBid(t, arrivalPriceGrid, 100, 10000) // depth for two crosses if a replay slipped

	// First settlement fills and burns the nonce.
	gw1, _, proof1 := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	in, sig := h.conversionIntent(t, signer, 3000, 0, 7)
	res, _, err := fill(gw1, h.state, in, sig, proof1, h.swapLeg(), 50_000_000)
	if err != nil || !res.Filled {
		t.Fatalf("first settlement must fill: res=%+v err=%v", res, err)
	}
	firstOut := h.ercBal(h.arrivalTokenOut(), signer.addr)

	// A SECOND, distinct bridge object with the SAME signed intent (same nonce) is rejected by
	// the per-recipient nonce one-shot — even though the object itself is fresh and fillable.
	gw2, id2, proof2 := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	res2, _, err2 := fill(gw2, h.state, in, sig, proof2, h.swapLeg(), 50_000_000)
	if err2 != ErrIntentNonceUsed {
		t.Fatalf("intent replay (reused nonce) must reject with ErrIntentNonceUsed, got res=%+v err=%v", res2, err2)
	}
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != firstOut {
		t.Fatalf("replay double-credited: tokenOut %d -> %d", firstOut, got)
	}
	// The fresh object was NOT consumed by the rejected replay — still recoverable.
	requireStatus(t, h, id2, bridge.StatusPending)

	// And replaying the SAME object id is also rejected (object consumed once).
	res3, _, err3 := fill(gw1, h.state, in, sig, proof1, h.swapLeg(), 50_000_000)
	if err3 != ErrIntentResolved {
		t.Fatalf("replaying a consumed object must reject with ErrIntentResolved, got res=%+v err=%v", res3, err3)
	}
}

// --- TestBridgeInSwap_WrongNetworkRejected: intent.DestNetwork != this NetworkID => rejected.

func TestBridgeInSwap_WrongNetworkRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	in, _ := h.conversionIntent(t, signer, 3000, 0, 1)
	in.DestNetwork = h.state.NetworkID() + 999 // a different network than the executing chain
	sig := signer.sign(t, h, in)               // honestly signed for the WRONG network

	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != ErrIntentWrongNetwork {
		t.Fatalf("wrong-network intent must reject with ErrIntentWrongNetwork, got res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusPending)
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("wrong-network intent minted %d native (must be 0)", got)
	}
}

// --- TestBridgeInSwap_WrongAssetRejected: a pool yielding != DesiredOutputAsset, or a proof
// asset != SourceAsset, is rejected (the relayer never picks the assets).

func TestBridgeInSwap_WrongAssetRejected(t *testing.T) {
	t.Run("output-asset-mismatch", func(t *testing.T) {
		h := arrivalHarness(t)
		signer := newIntentSigner(t)
		gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
		h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

		// Sign an intent wanting a DIFFERENT output asset than the relayer's pool yields.
		in, _ := h.conversionIntent(t, signer, 3000, 0, 1)
		in.DesiredOutputAsset = assetID(Currency{Address: common.HexToAddress("0x09")})
		sig := signer.sign(t, h, in) // honestly signed; the pool just doesn't match it

		res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
		if err != ErrIntentSwapAssetMismatch {
			t.Fatalf("pool yielding the wrong asset must reject with ErrIntentSwapAssetMismatch, got res=%+v err=%v", res, err)
		}
		requireStatus(t, h, id, bridge.StatusPending)
	})

	t.Run("source-asset-mismatch", func(t *testing.T) {
		h := arrivalHarness(t)
		signer := newIntentSigner(t)
		gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0) // req.Token is native (all-zero)

		// Sign an intent whose SourceAsset is NOT the native inbound the proof attests.
		in, _ := h.conversionIntent(t, signer, 3000, 0, 1)
		in.SourceAsset = assetID(Currency{Address: common.HexToAddress("0x07")})
		sig := signer.sign(t, h, in)

		res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
		if err != ErrIntentSourceMismatch {
			t.Fatalf("proof asset != SourceAsset must reject with ErrIntentSourceMismatch, got res=%+v err=%v", res, err)
		}
		requireStatus(t, h, id, bridge.StatusPending)
	})
}

// --- TestBridgeInSwap_RelayerCannotChangeRecipient: a relayer that flips the recipient on a
// signed intent is rejected; the output never reaches the relayer. (There is NO relayer
// recipient argument — the recipient lives only in the signed intent.)

func TestBridgeInSwap_RelayerCannotChangeRecipient(t *testing.T) {
	h := arrivalHarness(t)
	victim := newIntentSigner(t)
	relayer := common.HexToAddress("0xbad0000000000000000000000000000000000bad")
	gw, id, proof := newArrivalGateway(t, h, victim.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	in, sig := h.conversionIntent(t, victim, 3000, 0, 1) // signed for the victim
	in.Recipient = relayer                               // relayer redirects the output to itself, keeps the victim sig

	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	// The bridge object's recipient is the victim, so the tampered recipient fails the
	// source-bind (and would also fail the signature — the digest binds Recipient).
	if err != ErrIntentSourceMismatch {
		t.Fatalf("recipient tamper must reject with ErrIntentSourceMismatch, got res=%+v err=%v", res, err)
	}
	if got := h.ercBal(h.arrivalTokenOut(), relayer); got != 0 {
		t.Fatalf("relayer received %d tokenOut (must be 0)", got)
	}
	if got := h.nativeBal(relayer); got != 0 {
		t.Fatalf("relayer received %d native (must be 0)", got)
	}
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- TestBridgeInSwap_RelayerCannotChangeMinOut: a relayer cannot lower the signed minOut to
// force a worse fill; the SIGNED floor is what binds.

func TestBridgeInSwap_RelayerCannotChangeMinOut(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	// Book gives 80 @ 40 = 3200. The user signs a 4000 floor (refuses the 3200 fill).
	h.restMakerBid(t, 40*priceMultiplierConst, 100, 5000)

	in, sig := h.conversionIntent(t, signer, 4000 /* signed floor */, 0, 1)

	// (a) Honest call: the signed 4000 floor is enforced => the 3200 fill is refused => refundable.
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil || res.Filled || !res.Refundable {
		t.Fatalf("signed minOut must be enforced (refundable), got res=%+v err=%v", res, err)
	}

	// (b) Relayer lowers minOut to 3000 (which the book CAN meet) but keeps the 4000 signature.
	//     The digest binds MinOut, so the lowered value recovers to a non-recipient => rejected.
	tampered := in
	tampered.MinOut = 3000
	res2, _, err2 := fill(gw, h.state, tampered, sig, proof, h.swapLeg(), 50_000_000)
	if err2 != ErrIntentBadSignature {
		t.Fatalf("lowering minOut must reject with ErrIntentBadSignature, got res=%+v err=%v", res2, err2)
	}
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != 0 {
		t.Fatalf("a lowered-minOut swap filled: tokenOut=%d (must be 0)", got)
	}
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- TestBridgeInSwap_NoMintOnSwapFailure: after a failed swap, ZERO wrapped is minted (the
// single snapshot reverts the mint).

func TestBridgeInSwap_NoMintOnSwapFailure(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, _, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	// No maker => the swap cannot fill => the whole unit reverts.

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil || !res.Refundable {
		t.Fatalf("expected Refundable, got res=%+v err=%v", res, err)
	}
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("recipient native = %d after a failed swap, want 0 (mint must be reverted)", got)
	}
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != 0 {
		t.Fatalf("recipient tokenOut = %d, want 0", got)
	}
	if seam := loadSeamReserve(newPoolStateAdapter(h.state), h.inAssetID()).Uint64(); seam != 0 {
		t.Fatalf("seamReserve[native] = %d after a failed swap, want 0 (no locked inbound)", seam)
	}
}

// --- TestBridgeInSwap_NoRefundAfterConsume: once the swap commits and the object is consumed,
// the refund path REVERTS (a consumed object can never be refunded).

func TestBridgeInSwap_NoRefundAfterConsume(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil || !res.Filled {
		t.Fatalf("settlement must fill: res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusCompleted)

	// The consumed object can never be refunded — Refund rejects it.
	if rerr := h.refund(gw, id); rerr != bridge.ErrRequestAlreadyDone {
		t.Fatalf("refund of a consumed object must reject with ErrRequestAlreadyDone, got %v", rerr)
	}
	requireStatus(t, h, id, bridge.StatusCompleted)
}

// --- TestBridgeInSwap_ConsumeAfterSuccessOnly: the bridge object is consumed IFF the swap
// succeeded — the core invariant.

func TestBridgeInSwap_ConsumeAfterSuccessOnly(t *testing.T) {
	cases := []struct {
		name     string
		makerBid uint64 // 0 => empty book (unfillable)
		wantFill bool
	}{
		{"swap-succeeds-consumes", arrivalPriceGrid, true},
		{"swap-fails-does-not-consume", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := arrivalHarness(t)
			signer := newIntentSigner(t)
			gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
			if c.makerBid != 0 {
				h.restMakerBid(t, c.makerBid, 100, 5000)
			}
			in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
			res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			// Exactly one of Filled / Refundable (totality).
			if res.Filled == res.Refundable {
				t.Fatalf("terminal dichotomy broken: Filled=%v Refundable=%v", res.Filled, res.Refundable)
			}
			if c.wantFill {
				if !res.Filled {
					t.Fatalf("expected Filled, got %+v", res)
				}
				requireStatus(t, h, id, bridge.StatusCompleted) // consumed
			} else {
				if !res.Refundable {
					t.Fatalf("expected Refundable, got %+v", res)
				}
				requireStatus(t, h, id, bridge.StatusPending) // NOT consumed
			}
		})
	}
}

// --- TestBridgeInSwap_SignatureTamperRejected: a corrupted intent signature is refused.

func TestBridgeInSwap_SignatureTamperRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)

	// (a) Flip a byte in the r component => recovers to a non-recipient (or fails).
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if res, _, err := fill(gw, h.state, in, bad, proof, h.swapLeg(), 50_000_000); err != ErrIntentBadSignature {
		t.Fatalf("tampered signature must reject with ErrIntentBadSignature, got res=%+v err=%v", res, err)
	}

	// (b) A truncated / wrong-length signature is malformed.
	if res, _, err := fill(gw, h.state, in, sig[:64], proof, h.swapLeg(), 50_000_000); err != ErrIntentBadSignature {
		t.Fatalf("malformed-length signature must reject with ErrIntentBadSignature, got res=%+v err=%v", res, err)
	}

	// (c) A signature by a DIFFERENT key never recovers to the recipient.
	other := newIntentSigner(t)
	otherSig := other.sign(t, h, in)
	if res, _, err := fill(gw, h.state, in, otherSig, proof, h.swapLeg(), 50_000_000); err != ErrIntentBadSignature {
		t.Fatalf("wrong-signer signature must reject with ErrIntentBadSignature, got res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- TestBridgeInSwap_RelayerCannotChangeRefund: a relayer cannot redirect the refund
// address — it is a signed field.

func TestBridgeInSwap_RelayerCannotChangeRefund(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	in.RefundAddress = common.HexToAddress("0xbad0000000000000000000000000000000000bad") // relayer redirect

	if res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000); err != ErrIntentBadSignature {
		t.Fatalf("refund-address tamper must reject with ErrIntentBadSignature, got res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- TestBridgeInSwap_AmountTamperRejected: a relayer cannot settle a different magnitude than
// the signed SourceAmount.

func TestBridgeInSwap_AmountTamperRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	// Sign for a different SourceAmount than the bridge object carries (the object is 80).
	in, _ := h.conversionIntent(t, signer, 3000, 0, 1)
	in.SourceAmount = arrivalAmountIn + 1
	sig := signer.sign(t, h, in)

	if res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000); err != ErrIntentBadAmount {
		t.Fatalf("amount mismatch must reject with ErrIntentBadAmount, got res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- TestBridgeInSwap_PartialFillRefunds: full-fill-or-refund — a book shallower than the
// inbound reverts (no wrapped remainder left with the user), inbound recoverable.

func TestBridgeInSwap_PartialFillRefunds(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	// Depth is only 50 native (BID 50 x 50). An 80-native intent cannot FULLY convert => revert.
	h.restMakerBid(t, arrivalPriceGrid, 50, 2500)

	in, sig := h.conversionIntent(t, signer, 2000 /* a partial would meet this, but partials are refused */, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil {
		t.Fatalf("hard error: %v", err)
	}
	if res.Filled || !res.Refundable {
		t.Fatalf("a partial fill must be refused (full-fill-or-refund), got %+v", res)
	}
	if res.Reason != ErrIntentPartialFill {
		t.Fatalf("reason = %v, want ErrIntentPartialFill", res.Reason)
	}
	// No wrapped remainder, no proceeds, nothing consumed — the user holds nothing wrapped.
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("recipient native = %d, want 0 (no partial remainder)", got)
	}
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != 0 {
		t.Fatalf("recipient tokenOut = %d, want 0", got)
	}
	requireStatus(t, h, id, bridge.StatusPending)
	if rerr := h.refund(gw, id); rerr != nil {
		t.Fatalf("partial-refused inbound must be recoverable: %v", rerr)
	}
}

// --- TestBridgeInSwap_SwapAfterRefundRejected: an already-refunded object cannot be settled.

func TestBridgeInSwap_SwapAfterRefundRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	// Refund the inbound first (deadline 0 => immediate, permissionless).
	if rerr := h.refund(gw, id); rerr != nil {
		t.Fatalf("Refund: %v", rerr)
	}
	requireStatus(t, h, id, bridge.StatusRefunded)

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != ErrIntentResolved {
		t.Fatalf("settling a refunded object must reject with ErrIntentResolved, got res=%+v err=%v", res, err)
	}
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("swap-after-refund minted %d native (must be 0)", got)
	}
}

// --- TestBridgeInSwap_UnknownObjectRejected: a swap with no bridge backing is impossible.

func TestBridgeInSwap_UnknownObjectRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, _, _ := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	var unknown [32]byte
	unknown[0] = 0xFE // an id the gateway never created
	res, _, err := fill(gw, h.state, in, sig, Proof{RequestID: unknown}, h.swapLeg(), 50_000_000)
	if err != bridge.ErrRequestNotFound {
		t.Fatalf("unknown bridge object must reject with ErrRequestNotFound, got res=%+v err=%v", res, err)
	}
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("swap-without-backing minted %d native (must be 0)", got)
	}
}

// --- TestBridgeInSwap_ReentrancyCannotDoubleExecute: while the global 0x9999 custody mutex is
// held (as it is during a tokenOut ERC-20 transfer callback), a re-entrant settlement cannot
// run its swap — so it can neither double-execute nor consume-without-swap.

func TestBridgeInSwap_ReentrancyCannotDoubleExecute(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)

	// Simulate being INSIDE a swap's custody section (the reentrancy window a malicious tokenOut
	// would open): acquire the same global mutex runSyncSwap takes.
	if !enterCustodyKV(newPoolStateAdapter(h.state)) {
		t.Fatalf("could not acquire custody mutex for the reentrancy setup")
	}
	defer exitCustodyKV(newPoolStateAdapter(h.state))

	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil {
		t.Fatalf("re-entrant settlement should be a clean refundable, got hard error: %v", err)
	}
	if res.Filled || !res.Refundable {
		t.Fatalf("re-entrant settlement must be refused (refundable), got %+v", res)
	}
	if res.Reason != ErrCustodyReentrant {
		t.Fatalf("reason = %v, want ErrCustodyReentrant", res.Reason)
	}
	// Nothing minted, object NOT consumed — no double-execution, no consume-without-swap.
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("re-entrant settlement minted %d native (must be 0)", got)
	}
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- TestFill_BridgeInDeliversWrapped: a bridge-in signed intent (desired == source) credits
// the wrapped asset to the recipient with NO swap — even when the relayer supplies a route, fill
// IGNORES it (it cannot force a conversion the user never signed).

func TestFill_BridgeInDeliversWrapped(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)

	in, sig := h.bridgeOnlyIntent(t, signer, 1)
	// A non-empty route is supplied; fill MUST ignore it for a bridge-in signed intent.
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil || !res.Filled || res.BalanceDelta != nil {
		t.Fatalf("bridge-in must deliver wrapped with no swap (nil delta): res=%+v err=%v", res, err)
	}
	// The user holds the wrapped inbound as native (no swap ran); the object is consumed once.
	if got := h.nativeBal(signer.addr); got != arrivalAmountIn {
		t.Fatalf("recipient wrapped native = %d, want %d", got, arrivalAmountIn)
	}
	requireStatus(t, h, id, bridge.StatusCompleted)
}

// --- TestFill_SignedFieldDecidesPath: the SIGNED intent (desired vs source), never the relayer,
// decides whether fill swaps. With the SAME route supplied, a bridge-only intent delivers wrapped
// (no swap, nil delta) and a conversion intent fills via the swap (non-nil delta) — one entry,
// two paths, chosen by the signature.

func TestFill_SignedFieldDecidesPath(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000) // depth for the conversion leg

	// A bridge-only intent (desired == source) delivers wrapped — the route is ignored, no swap.
	gw1, id1, proof1 := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	bo, boSig := h.bridgeOnlyIntent(t, signer, 1)
	res1, _, err1 := fill(gw1, h.state, bo, boSig, proof1, h.swapLeg(), 50_000_000)
	if err1 != nil || !res1.Filled || res1.BalanceDelta != nil {
		t.Fatalf("bridge-only intent must deliver wrapped (nil delta): res=%+v err=%v", res1, err1)
	}
	requireStatus(t, h, id1, bridge.StatusCompleted)

	// A conversion intent (desired != source) fills via the swap with the same route.
	gw2, id2, proof2 := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	conv, convSig := h.conversionIntent(t, signer, 3000, 0, 2)
	res2, _, err2 := fill(gw2, h.state, conv, convSig, proof2, h.swapLeg(), 50_000_000)
	if err2 != nil || !res2.Filled || res2.BalanceDelta == nil {
		t.Fatalf("conversion intent must fill via swap (non-nil delta): res=%+v err=%v", res2, err2)
	}
	requireStatus(t, h, id2, bridge.StatusCompleted)
}

// === CRITICAL-CLOSURE TESTS (A / B / 14) =====================================

// --- A-CLOSURE: TestBridgeInSwap_JunkProofRejected — a junk or sub-⅔ proof can no
// longer mint unbacked wrapped value (the PoC that drained the 0x9999 vault). The
// committee verifier now requires a real ⅔-weight quorum over the completion digest.

func TestBridgeInSwap_JunkProofRejected(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000) // ample depth — the PROOF is the only thing wrong
	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)

	// (a) The exact PoC: a single 1-byte "signature". Under the old stub this passed
	//     (len(sig) > 0, threshold 1) and minted unbacked value. Now it carries zero
	//     valid weight => ErrSignatureThreshold, a hard refusal.
	junk := Proof{RequestID: id, Signers: []bridge.SignerSig{{Index: 0, Sig: []byte{0x01}}}}
	if res, _, err := fill(gw, h.state, in, sig, junk, h.swapLeg(), 50_000_000); err != bridge.ErrSignatureThreshold {
		t.Fatalf("junk proof must reject with ErrSignatureThreshold, got res=%+v err=%v", res, err)
	}

	// (b) A sub-⅔ proof (one valid signature of three) is likewise refused — a real
	//     signature is not enough; the WEIGHT must meet ⅔.
	sub := Proof{RequestID: id, Signers: proof.Signers[:1]}
	if res, _, err := fill(gw, h.state, in, sig, sub, h.swapLeg(), 50_000_000); err != bridge.ErrSignatureThreshold {
		t.Fatalf("sub-⅔ proof must reject with ErrSignatureThreshold, got res=%+v err=%v", res, err)
	}

	// Across BOTH rejected attempts: nothing minted, nothing delivered, object untouched.
	if got := h.nativeBal(signer.addr); got != 0 {
		t.Fatalf("junk/sub-⅔ proof minted %d native (must be 0 — no unbacked mint)", got)
	}
	if got := h.ercBal(h.arrivalTokenOut(), signer.addr); got != 0 {
		t.Fatalf("junk/sub-⅔ proof delivered %d tokenOut (must be 0)", got)
	}
	requireStatus(t, h, id, bridge.StatusPending)

	// And the REAL ⅔ proof DOES settle — the gate is a true quorum check, not a blanket reject.
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil || !res.Filled {
		t.Fatalf("the genuine ⅔ proof must settle: res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusCompleted)
}

// --- B-CLOSURE: TestBridgeInSwap_DeadlineBlockTimeDeterministic — the completion
// deadline outcome is a pure function of BLOCK time, not wall clock. The same block
// time always yields the same outcome (no validator state fork).

func TestBridgeInSwap_DeadlineBlockTimeDeterministic(t *testing.T) {
	deadline := uint64(DexSettleActivationTime) + 1000 // stays >= settlement activation

	// run builds an identical settlement and evaluates it at the given BLOCK time.
	run := func(blockTime uint64) (Result, error) {
		h := arrivalHarness(t)
		h.state.blockTimestamp = blockTime
		signer := newIntentSigner(t)
		gw, _, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, deadline)
		h.restMakerBid(t, arrivalPriceGrid, 100, 5000)
		in, sig := h.conversionIntent(t, signer, 3000, 0 /* no intent deadline */, 1)
		res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
		return res, err
	}

	// bt == deadline (within): settles.
	if res, err := run(deadline); err != nil || !res.Filled {
		t.Fatalf("bt==deadline must settle, got res=%+v err=%v", res, err)
	}
	// bt > deadline (expired): refundable with the bridge-expired reason; nothing minted.
	if res, err := run(deadline + 1); err != nil || !res.Refundable || res.Reason != bridge.ErrRequestExpired {
		t.Fatalf("bt>deadline must be Refundable(ErrRequestExpired), got res=%+v err=%v", res, err)
	}
	// Determinism: identical block time => identical outcome on every evaluation. There is
	// no time.Now() anywhere on the money path, so the result cannot drift with wall clock.
	for i := 0; i < 3; i++ {
		if res, err := run(deadline); err != nil || !res.Filled {
			t.Fatalf("repeat %d at bt==deadline diverged: res=%+v err=%v", i, res, err)
		}
		if res, err := run(deadline + 1); err != nil || !res.Refundable {
			t.Fatalf("repeat %d at bt>deadline diverged: res=%+v err=%v", i, res, err)
		}
	}
}

// --- 14-CLOSURE: TestBridgeInSwap_RevertUnflipsStatus — the status flip lives in
// StateDB, so a RevertToSnapshot of the enclosing frame un-flips Completed back to
// Pending. This closes the consume-iff-swap invariant UNDER REVERTS: the bridge
// object can never be consumed by a transaction that did not commit.

func TestBridgeInSwap_RevertUnflipsStatus(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)
	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)

	cdb := h.state.GetStateDB()
	snap := cdb.Snapshot() // the enclosing transaction boundary
	res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000)
	if err != nil || !res.Filled {
		t.Fatalf("settlement must fill: res=%+v err=%v", res, err)
	}
	requireStatus(t, h, id, bridge.StatusCompleted) // flipped in StateDB

	cdb.RevertToSnapshot(snap)
	// The consume is reverted with the frame — the object is Pending again, NOT stranded
	// as Completed. (Under the old in-memory map the status would have survived the revert.)
	requireStatus(t, h, id, bridge.StatusPending)
}

// --- 14-CLOSURE: TestBridgeInSwap_StateDBRestartDeterministic — the request record
// is StateDB-resident, so a brand-new gateway over the same StateDB ("restart")
// re-reads the committed status deterministically. No in-memory map to strand on
// reorg/restart.

func TestBridgeInSwap_StateDBRestartDeterministic(t *testing.T) {
	h := arrivalHarness(t)
	signer := newIntentSigner(t)
	gw, id, proof := newArrivalGateway(t, h, signer.addr, arrivalAmountIn, 0)
	h.restMakerBid(t, arrivalPriceGrid, 100, 5000)
	in, sig := h.conversionIntent(t, signer, 3000, 0, 1)

	if res, _, err := fill(gw, h.state, in, sig, proof, h.swapLeg(), 50_000_000); err != nil || !res.Filled {
		t.Fatalf("settlement must fill: res=%+v err=%v", res, err)
	}

	// "Restart": a fresh gateway over the SAME StateDB sees the committed Completed status.
	fresh, err := bridge.NewBridgeGateway().GetRequest(h.state.GetStateDB(), bridgeGWAddr, id)
	if err != nil {
		t.Fatalf("fresh gateway GetRequest: %v", err)
	}
	if fresh.Status != bridge.StatusCompleted {
		t.Fatalf("restart status = %d, want Completed (StateDB-resident, not stranded)", fresh.Status)
	}
}
