// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// Adversarial regression suite for the hardened completion primitive. Each test is
// a red-team PoC turned into a permanent guard: findings (6) duplicate-KeyID quorum
// and (9) deadline==0 refund-grief are asserted CLOSED; the confirm-closed cases pin
// cross-network replay, u128 weight bounds, ML-DSA ctx binding, and snapshot atomicity.

package bridge

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// ============================================================================
// CLOSED (9): deadline==0 refund grief. A no-deadline inbound is completable-forever,
// so a permissionless refund would let a third party yank it out from under a
// quorum-valid completion. Refund is caller-authorized: the OWNER (recipient) refunds
// anytime; a THIRD PARTY only after a real deadline. So a deadline==0 inbound is NOT
// third-party refundable (grief closed) while the owner's recovery (N5) stays immediate.
// ============================================================================
func TestRed_Deadline0_RefundIsCallerAuthorized(t *testing.T) {
	st := newMemStateDB()
	gw := NewBridgeGateway()
	thirdParty := common.HexToAddress("0x00000000000000000000000000000000000000ff")

	// Control: a deadline==0 inbound is completable at any block time.
	r := newRequest(80, 0)
	_, signers := recordPending(t, st, r)
	if err := gw.VerifyCompletion(st, gwAddr, testNetworkID, testChainID, 1<<40, r.ID, signers); err != nil {
		t.Fatalf("control: deadline==0 must be completable at any bt, got %v", err)
	}

	// (a) CLOSED: a THIRD PARTY cannot refund the no-deadline inbound — no grief window.
	if err := gw.Refund(st, gwAddr, thirdParty, 1, r.ID); err != ErrRequestNotExpired {
		t.Fatalf("third-party refund of a deadline==0 inbound must be refused, got %v", err)
	}
	// (b) RECOVERY PRESERVED: the OWNER refunds the same inbound immediately.
	if err := gw.Refund(st, gwAddr, r.Recipient, 1, r.ID); err != nil {
		t.Fatalf("owner refund of a deadline==0 inbound must succeed, got %v", err)
	}
	t.Logf("CLOSED(9): deadline==0 third-party refund refused; owner recovery immediate — grief closed, N5 preserved.")

	// (c) deadline>0: a third party still cannot refund before expiry, and a quorum-valid
	//     completion succeeds before the deadline.
	st2 := newMemStateDB()
	r2 := newRequest(80, 500)
	_, signers2 := recordPending(t, st2, r2)
	if err := gw.Refund(st2, gwAddr, thirdParty, 499, r2.ID); err != ErrRequestNotExpired {
		t.Fatalf("deadline>0 pre-expiry third-party refund must be refused, got %v", err)
	}
	if err := gw.CompleteBridge(st2, gwAddr, testNetworkID, testChainID, 400, r2.ID, signers2); err != nil {
		t.Fatalf("quorum-valid completion before deadline must succeed, got %v", err)
	}
	t.Logf("deadline>0: pre-expiry third-party refund refused (bt=499), completion succeeds (bt=400).")
}

// ============================================================================
// CLOSED (6): KeyID uniqueness. SeedCommittee REJECTS a duplicate KeyID, so one
// physical key can never occupy two indices; and VerifyCompletionQuorum counts a
// key once even if a snapshot ever held a dup — ⅔ is of distinct KEYS, not indices.
// One key can no longer reach quorum alone (value fabrication via mis-seed closed).
// ============================================================================
func TestRed_DuplicateKeyID_OneKeyMeetsQuorum(t *testing.T) {
	st := newMemStateDB()

	k, _ := crypto.GenerateKey()
	var keyID [20]byte
	copy(keyID[:], crypto.Keccak256(crypto.FromECDSAPub(&k.PublicKey)[1:])[12:])
	k2, _ := crypto.GenerateKey()
	var keyID2 [20]byte
	copy(keyID2[:], crypto.Keccak256(crypto.FromECDSAPub(&k2.PublicKey)[1:])[12:])

	// A committee with the SAME key at two indices is rejected at construction.
	dup := []CommitteeMember{
		{Scheme: SchemeSecp256k1, Weight: 1, KeyID: keyID},  // idx 0 — key k
		{Scheme: SchemeSecp256k1, Weight: 1, KeyID: keyID},  // idx 1 — SAME key k (dup KeyID!)
		{Scheme: SchemeSecp256k1, Weight: 1, KeyID: keyID2}, // idx 2 — distinct
	}
	if err := SeedCommittee(st, gwAddr, testEpoch, dup, 2, 3); err != ErrInvalidCommittee {
		t.Fatalf("SeedCommittee must REJECT a duplicate KeyID, got %v", err)
	}

	// A well-formed distinct committee is accepted (control), and one key signing at
	// its single index is exactly ½ < ⅔ — one key never reaches quorum.
	ok := []CommitteeMember{
		{Scheme: SchemeSecp256k1, Weight: 1, KeyID: keyID},
		{Scheme: SchemeSecp256k1, Weight: 1, KeyID: keyID2},
	}
	if err := SeedCommittee(st, gwAddr, testEpoch, ok, 2, 3); err != nil {
		t.Fatalf("distinct committee must be accepted, got %v", err)
	}
	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)
	sig, _ := crypto.Sign(d[:], k) // ONE key signs at its one index
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: 0, Sig: sig}}); err != ErrSignatureThreshold {
		t.Fatalf("one key (½ weight) must be sub-⅔, got %v", err)
	}
	t.Logf("CLOSED(6): SeedCommittee enforces KeyID uniqueness; quorum is of distinct keys — one key cannot reach ⅔.")
}

// ============================================================================
// CONFIRM-CLOSED (4): completion sigs are bound to networkID + chainID +
// every value field — no cross-network / cross-chain / cross-destChain replay.
// ============================================================================
func TestRed_CrossNetworkChainDestReplayRejected(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	r := newRequest(80, 0)

	netA, netB := uint32(1), uint32(2)
	chainA, chainB := ids.ID{0xC, 0xC}, ids.ID{0xD, 0xD}

	dA := CompletionDigest(netA, chainA, r)
	sigsA := c.quorum(t, dA, 0, 1)
	if err := VerifyCompletionQuorum(st, gwAddr, dA, sigsA); err != nil {
		t.Fatalf("control: valid on (netA,chainA) must accept, got %v", err)
	}
	if err := VerifyCompletionQuorum(st, gwAddr, CompletionDigest(netB, chainA, r), sigsA); err != ErrSignatureThreshold {
		t.Fatalf("cross-NETWORK replay must reject, got %v", err)
	}
	if err := VerifyCompletionQuorum(st, gwAddr, CompletionDigest(netA, chainB, r), sigsA); err != ErrSignatureThreshold {
		t.Fatalf("cross-CHAIN replay must reject, got %v", err)
	}
	r2 := *r
	r2.DestChain = ChainHanzo
	if err := VerifyCompletionQuorum(st, gwAddr, CompletionDigest(netA, chainA, &r2), sigsA); err != ErrSignatureThreshold {
		t.Fatalf("cross-destChain replay must reject, got %v", err)
	}
	// And amount substitution (value fabrication) — old A-finding — stays closed.
	r3 := *r
	r3.Amount = big.NewInt(1_000_000)
	if err := VerifyCompletionQuorum(st, gwAddr, CompletionDigest(netA, chainA, &r3), sigsA); err != ErrSignatureThreshold {
		t.Fatalf("amount substitution must reject, got %v", err)
	}
	t.Logf("CONFIRMED CLOSED(4): sigs bound to networkID+chainID+destChain+amount; no cross-* replay, no value fabrication.")
}

// ============================================================================
// CONFIRM-CLOSED (7): u128 totalWeight cannot panic FillBytes (bounded by
// maxMembers*maxU64 < 2^128) and the ⅔ test is exact big.Int (no wraparound).
// ============================================================================
func TestRed_U128TotalWeight_NoPanic_OverflowSafe(t *testing.T) {
	st := newMemStateDB()
	const maxU64 = ^uint64(0)

	type wk struct {
		k *ecdsa.PrivateKey
		m CommitteeMember
	}
	var ws []wk
	for i := 0; i < 2; i++ {
		k, _ := crypto.GenerateKey()
		var keyID [20]byte
		copy(keyID[:], crypto.Keccak256(crypto.FromECDSAPub(&k.PublicKey)[1:])[12:])
		ws = append(ws, wk{k: k, m: CommitteeMember{Scheme: SchemeSecp256k1, Weight: maxU64, KeyID: keyID}})
	}
	members := []CommitteeMember{ws[0].m, ws[1].m}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("DoS: FillBytes panicked on total=2*maxU64 (~2^65): %v", rec)
			}
		}()
		if err := SeedCommittee(st, gwAddr, testEpoch, members, 2, 3); err != nil {
			t.Fatalf("SeedCommittee max weights: %v", err)
		}
	}()

	h, err := loadCommitteeHeader(st, gwAddr)
	if err != nil {
		t.Fatalf("loadCommitteeHeader: %v", err)
	}
	want := new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(maxU64))
	if h.totalWeight.Cmp(want) != 0 {
		t.Fatalf("totalWeight = %s, want %s", h.totalWeight, want)
	}

	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)
	sign := func(k *ecdsa.PrivateKey) []byte { s, _ := crypto.Sign(d[:], k); return s }
	// One max member alone is exactly ½ of total < ⅔ => reject (cross-mult: 3*maxU64 < 4*maxU64).
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: 0, Sig: sign(ws[0].k)}}); err != ErrSignatureThreshold {
		t.Fatalf("½ of huge total must be sub-⅔, got %v", err)
	}
	// Both => 6*maxU64 >= 4*maxU64 => accept.
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: 0, Sig: sign(ws[0].k)}, {Index: 1, Sig: sign(ws[1].k)}}); err != nil {
		t.Fatalf("full huge-weight quorum must accept, got %v", err)
	}
	t.Logf("CONFIRMED CLOSED(7): total=2^65 stored w/o panic; ⅔ test exact under huge weights (no overflow/wraparound).")
}

// ============================================================================
// CONFIRM-CLOSED (6b): ML-DSA-65 completion-domain context is BOUND. A sig made
// with the wrong ctx contributes zero weight; the correct ctx counts.
// ============================================================================
func TestRed_MLDSACtxBindingEnforced(t *testing.T) {
	st := newMemStateDB()
	c := &committee{secp: map[uint16]*ecdsa.PrivateKey{}, pq: map[uint16]*mldsa.PrivateKey{}}
	// idx0 secp
	k0, _ := crypto.GenerateKey()
	var id0 [20]byte
	copy(id0[:], crypto.Keccak256(crypto.FromECDSAPub(&k0.PublicKey)[1:])[12:])
	c.secp[0] = k0
	c.members = append(c.members, CommitteeMember{Scheme: SchemeSecp256k1, Weight: 1, KeyID: id0})
	// idx1 mldsa
	pqIdx := c.addMLDSA(t, 1)
	// idx2 secp (so ⅔ needs idx0 + idx1)
	k2, _ := crypto.GenerateKey()
	var id2 [20]byte
	copy(id2[:], crypto.Keccak256(crypto.FromECDSAPub(&k2.PublicKey)[1:])[12:])
	c.secp[2] = k2
	c.members = append(c.members, CommitteeMember{Scheme: SchemeSecp256k1, Weight: 1, KeyID: id2})

	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)

	// Wrong-ctx ML-DSA sig: must NOT count => idx0(1) alone is sub-⅔.
	wrongCtx, err := c.pq[pqIdx].SignCtx(rand.Reader, d[:], []byte("lux.bridge.WRONG"))
	if err != nil {
		t.Fatalf("mldsa SignCtx: %v", err)
	}
	proofBad := []SignerSig{{Index: 0, Sig: c.sign(t, 0, d)}, {Index: pqIdx, Sig: wrongCtx}}
	if err := VerifyCompletionQuorum(st, gwAddr, d, proofBad); err != ErrSignatureThreshold {
		t.Fatalf("wrong-ctx ML-DSA must NOT count (sub-⅔), got %v", err)
	}
	// Correct ctx (helper signs with completionDomain) => counts => quorum met.
	proofGood := []SignerSig{{Index: 0, Sig: c.sign(t, 0, d)}, {Index: pqIdx, Sig: c.sign(t, pqIdx, d)}}
	if err := VerifyCompletionQuorum(st, gwAddr, d, proofGood); err != nil {
		t.Fatalf("correct-ctx ML-DSA must count, got %v", err)
	}
	t.Logf("CONFIRMED CLOSED(6b): ML-DSA-65 completion-domain ctx bound; wrong-ctx sig => 0 weight.")
}

// ============================================================================
// CONFIRM-CLOSED (8/14): status flip is snapshot-atomic at every nesting level;
// no half-Completed strand, and an outer revert un-flips to Pending.
// ============================================================================
func TestRed_NestedSnapshotNoHalfCompletedStrand(t *testing.T) {
	st := newMemStateDB()
	gw := NewBridgeGateway()
	r := newRequest(80, 0)
	_, signers := recordPending(t, st, r)

	outer := st.Snapshot()
	if err := gw.CompleteBridge(st, gwAddr, testNetworkID, testChainID, 1000, r.ID, signers); err != nil {
		t.Fatalf("CompleteBridge: %v", err)
	}
	inner := st.Snapshot()
	// An inner write + inner revert must leave the (already) Completed status untouched.
	st.SetState(gwAddr, addOffset(reqBase(r.ID), 4), common0xFF())
	st.RevertToSnapshot(inner)
	if got, _ := gw.GetRequest(st, gwAddr, r.ID); got.Status != StatusCompleted {
		t.Fatalf("inner revert wrongly changed status to %d", got.Status)
	}
	// Outer revert: the whole unit (including the status flip) rolls back to Pending.
	st.RevertToSnapshot(outer)
	if got, _ := gw.GetRequest(st, gwAddr, r.ID); got.Status != StatusPending {
		t.Fatalf("outer revert must restore Pending, got %d", got.Status)
	}
	t.Logf("CONFIRMED CLOSED(8/14): status flip is snapshot-atomic at both nesting levels; no half-Completed strand.")
}

func common0xFF() (h common.Hash) { // a non-zero 32-byte word for snapshot-revert probing
	for i := range h {
		h[i] = 0xFF
	}
	return h
}
