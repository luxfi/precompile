// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

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

	"github.com/luxfi/precompile/contract"
)

// gateway_test.go is the bridge money-path acceptance gate. It exercises the
// StateDB-resident request FSM and the real ⅔-weight committee verifier directly
// (the DEX composite is tested in dex/intent_settle_test.go). Every test drives
// BLOCK time explicitly — there is no wall clock on the money path. The shared
// snapshot-capable contract.StateDB (memStateDB) lives in registry_test.go.

// --- test committee ----------------------------------------------------------

const (
	testNetworkID uint32 = 1
	testEpoch     uint64 = 7
)

var testChainID = ids.ID{0xC, 0xC}

// committee bundles signing keys with the on-state member set so a test can both
// seed the committee and produce real signatures over a completion digest.
type committee struct {
	secp    map[uint16]*ecdsa.PrivateKey
	pq      map[uint16]*mldsa.PrivateKey
	members []CommitteeMember
}

func newSecpCommittee(t *testing.T, weights ...uint64) *committee {
	t.Helper()
	c := &committee{secp: map[uint16]*ecdsa.PrivateKey{}, pq: map[uint16]*mldsa.PrivateKey{}}
	for i, w := range weights {
		k, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		var keyID [20]byte
		copy(keyID[:], crypto.Keccak256(crypto.FromECDSAPub(&k.PublicKey)[1:])[12:])
		c.secp[uint16(i)] = k
		c.members = append(c.members, CommitteeMember{Scheme: SchemeSecp256k1, Weight: w, KeyID: keyID})
	}
	return c
}

// addMLDSA appends an ML-DSA-65 member and returns its index.
func (c *committee) addMLDSA(t *testing.T, weight uint64) uint16 {
	t.Helper()
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("mldsa GenerateKey: %v", err)
	}
	idx := uint16(len(c.members))
	var keyID [20]byte
	copy(keyID[:], crypto.Keccak256(priv.PublicKey.Bytes())[12:])
	c.pq[idx] = priv
	c.members = append(c.members, CommitteeMember{
		Scheme: SchemeMLDSA65, Weight: weight, KeyID: keyID, PubKey: priv.PublicKey.Bytes(),
	})
	return idx
}

// sign produces a member's signature over d for the given committee index.
func (c *committee) sign(t *testing.T, idx uint16, d [32]byte) []byte {
	t.Helper()
	if k, ok := c.secp[idx]; ok {
		sig, err := crypto.Sign(d[:], k)
		if err != nil {
			t.Fatalf("secp sign: %v", err)
		}
		return sig
	}
	if priv, ok := c.pq[idx]; ok {
		sig, err := priv.SignCtx(rand.Reader, d[:], []byte(completionDomain))
		if err != nil {
			t.Fatalf("mldsa sign: %v", err)
		}
		return sig
	}
	t.Fatalf("no key for index %d", idx)
	return nil
}

// quorum signs d with the given member indices.
func (c *committee) quorum(t *testing.T, d [32]byte, idxs ...uint16) []SignerSig {
	t.Helper()
	out := make([]SignerSig, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, SignerSig{Index: i, Sig: c.sign(t, i, d)})
	}
	return out
}

// gwAddr is where the committee + requests live (the bridge gateway, 0x0440).
var gwAddr = BridgeGatewayCanonicalAddress

// newRequest builds a Pending-shaped request (not yet stored).
func newRequest(amount int64, deadline uint64) *BridgeRequest {
	var id [32]byte
	_, _ = rand.Read(id[:])
	return &BridgeRequest{
		ID:            id,
		SourceNetwork: testNetworkID,
		SourceChain:   ChainEthereum,
		DestNetwork:   testNetworkID,
		DestChain:     ChainLux,
		Nonce:         1,
		Deadline:      deadline,
		Recipient:     common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Token:         common.Address{},
		Amount:        big.NewInt(amount),
	}
}

// recordPending seeds a 2-of-3 secp committee and records r as Pending, returning
// the committee and a valid completion proof (quorum over D).
func recordPending(t *testing.T, st contract.StateDB, r *BridgeRequest) (*committee, []SignerSig) {
	t.Helper()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	d := CompletionDigest(testNetworkID, testChainID, r)
	signers := c.quorum(t, d, 0, 1)
	if err := RecordInbound(st, gwAddr, testNetworkID, testChainID, r, signers); err != nil {
		t.Fatalf("RecordInbound: %v", err)
	}
	return c, signers
}

// --- SeedCommittee validation (acceptance #5) --------------------------------

func TestSeedCommittee_RejectsZeroTotalWeight(t *testing.T) {
	st := newMemStateDB()
	// A single zero-weight member => total weight 0 => rejected.
	c := newSecpCommittee(t, 0)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != ErrInvalidCommittee {
		t.Fatalf("zero-weight committee must reject with ErrInvalidCommittee, got %v", err)
	}
	// Empty committee => rejected.
	if err := SeedCommittee(st, gwAddr, testEpoch, nil, 2, 3); err != ErrInvalidCommittee {
		t.Fatalf("empty committee must reject with ErrInvalidCommittee, got %v", err)
	}
	// Malformed quorum fractions => rejected.
	good := newSecpCommittee(t, 1, 1, 1)
	for _, q := range []struct{ n, d uint16 }{{0, 3}, {3, 0}, {4, 3}} {
		if err := SeedCommittee(st, gwAddr, testEpoch, good.members, q.n, q.d); err != ErrInvalidCommittee {
			t.Fatalf("quorum %d/%d must reject, got %v", q.n, q.d, err)
		}
	}
}

// --- A-CLOSURE: real verify, fail-closed, ⅔ weight ---------------------------

func TestQuorum_UnsetCommitteeFailsClosed(t *testing.T) {
	st := newMemStateDB()
	// No committee seeded — verification must fail closed (NOT a threshold of one).
	if _, err := loadCommitteeHeader(st, gwAddr); err != ErrCommitteeUnset {
		t.Fatalf("loadCommitteeHeader on empty state must be ErrCommitteeUnset, got %v", err)
	}
	var d [32]byte
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: 0, Sig: []byte{0x01}}}); err != ErrCommitteeUnset {
		t.Fatalf("quorum on unset committee must be ErrCommitteeUnset, got %v", err)
	}
}

func TestQuorum_JunkSignatureRejected(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)

	// A 1-byte junk signature contributes zero valid weight => threshold not met.
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: 0, Sig: []byte{0x01}}}); err != ErrSignatureThreshold {
		t.Fatalf("junk proof must reject with ErrSignatureThreshold, got %v", err)
	}
	// Three junk signatures at distinct indices still meet no valid weight.
	junk := []SignerSig{{Index: 0, Sig: []byte{0x01}}, {Index: 1, Sig: []byte{0x02}}, {Index: 2, Sig: []byte{0x03}}}
	if err := VerifyCompletionQuorum(st, gwAddr, d, junk); err != ErrSignatureThreshold {
		t.Fatalf("all-junk proof must reject with ErrSignatureThreshold, got %v", err)
	}
}

func TestQuorum_SubThresholdFails(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)

	// 1 of 3 (weight 1 of total 3): 1*3 = 3 < 3*2 = 6 => below ⅔.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, d, 0)); err != ErrSignatureThreshold {
		t.Fatalf("1-of-3 must reject with ErrSignatureThreshold, got %v", err)
	}
	// 2 of 3: 2*3 = 6 >= 6 => exactly ⅔ => accept.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, d, 0, 1)); err != nil {
		t.Fatalf("2-of-3 must meet ⅔ quorum, got %v", err)
	}
	// 3 of 3 => accept.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, d, 0, 1, 2)); err != nil {
		t.Fatalf("3-of-3 must accept, got %v", err)
	}
}

func TestQuorum_DuplicateIndexRejected(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)
	// The same valid member submitted twice must NOT count as ⅔ — distinct-index only.
	sig0 := c.sign(t, 0, d)
	dup := []SignerSig{{Index: 0, Sig: sig0}, {Index: 0, Sig: sig0}}
	if err := VerifyCompletionQuorum(st, gwAddr, d, dup); err != ErrDuplicateSignerIndex {
		t.Fatalf("duplicate index must reject with ErrDuplicateSignerIndex, got %v", err)
	}
}

func TestQuorum_OutOfRangeIndexRejected(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	r := newRequest(80, 0)
	d := CompletionDigest(testNetworkID, testChainID, r)
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: 99, Sig: c.sign(t, 0, d)}}); err != ErrSignerIndexRange {
		t.Fatalf("out-of-range index must reject with ErrSignerIndexRange, got %v", err)
	}
}

func TestQuorum_WrongDigestRejected(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 1, 1, 1)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	d := CompletionDigest(testNetworkID, testChainID, newRequest(80, 0))
	other := CompletionDigest(testNetworkID, testChainID, newRequest(81, 0))
	// Signatures over `other` do not verify against `d` => no valid weight.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, other, 0, 1)); err != ErrSignatureThreshold {
		t.Fatalf("signatures over a different digest must not count, got %v", err)
	}
}

// ML-DSA-65 (post-quantum) member: the public key is read from STATE and the
// signature verifies with the completion domain bound as the FIPS 204 context.
func TestQuorum_MLDSAMemberVerifies(t *testing.T) {
	st := newMemStateDB()
	c := &committee{secp: map[uint16]*ecdsa.PrivateKey{}, pq: map[uint16]*mldsa.PrivateKey{}}
	// Mixed committee: one secp (idx 0), one ML-DSA-65 (idx 1), one secp (idx 2).
	s0, m0 := func() (*ecdsa.PrivateKey, CommitteeMember) {
		k, _ := crypto.GenerateKey()
		var id [20]byte
		copy(id[:], crypto.Keccak256(crypto.FromECDSAPub(&k.PublicKey)[1:])[12:])
		return k, CommitteeMember{Scheme: SchemeSecp256k1, Weight: 1, KeyID: id}
	}()
	c.secp[0] = s0
	c.members = append(c.members, m0)
	pqIdx := c.addMLDSA(t, 1)
	s2, m2 := func() (*ecdsa.PrivateKey, CommitteeMember) {
		k, _ := crypto.GenerateKey()
		var id [20]byte
		copy(id[:], crypto.Keccak256(crypto.FromECDSAPub(&k.PublicKey)[1:])[12:])
		return k, CommitteeMember{Scheme: SchemeSecp256k1, Weight: 1, KeyID: id}
	}()
	c.secp[2] = s2
	c.members = append(c.members, m2)

	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	d := CompletionDigest(testNetworkID, testChainID, newRequest(80, 0))

	// The ML-DSA-65 member + one secp member make a ⅔ quorum, exercising the PQ path.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, d, pqIdx, 0)); err != nil {
		t.Fatalf("ML-DSA-65 + secp ⅔ quorum must accept, got %v", err)
	}
	// A corrupted ML-DSA signature does not count.
	badSig := c.sign(t, pqIdx, d)
	badSig[0] ^= 0xff
	if err := VerifyCompletionQuorum(st, gwAddr, d, []SignerSig{{Index: pqIdx, Sig: badSig}, {Index: 0, Sig: c.sign(t, 0, d)}}); err != ErrSignatureThreshold {
		t.Fatalf("corrupt ML-DSA sig must not count (sub-⅔), got %v", err)
	}
}

// Weighted committee: a single heavy member can carry ⅔, a light minority cannot.
func TestQuorum_WeightedThreshold(t *testing.T) {
	st := newMemStateDB()
	c := newSecpCommittee(t, 7, 1, 1, 1) // total weight 10; ⅔ => weight*3 >= 20 => weight >= 7 (ceil 6.67)
	if err := SeedCommittee(st, gwAddr, testEpoch, c.members, 2, 3); err != nil {
		t.Fatalf("SeedCommittee: %v", err)
	}
	d := CompletionDigest(testNetworkID, testChainID, newRequest(80, 0))
	// Heavy member alone: 7*3 = 21 >= 20 => accept.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, d, 0)); err != nil {
		t.Fatalf("heavy member alone must meet ⅔, got %v", err)
	}
	// Three light members: 3*3 = 9 < 20 => reject.
	if err := VerifyCompletionQuorum(st, gwAddr, d, c.quorum(t, d, 1, 2, 3)); err != ErrSignatureThreshold {
		t.Fatalf("light minority must fail ⅔, got %v", err)
	}
}

// --- Request lifecycle FSM ---------------------------------------------------

func TestLifecycle_RecordVerifyComplete(t *testing.T) {
	st := newMemStateDB()
	gw := NewBridgeGateway()
	r := newRequest(80, 0)
	_, signers := recordPending(t, st, r)

	got, err := gw.GetRequest(st, gwAddr, r.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("recorded status = %d, want Pending", got.Status)
	}
	// Every digest field round-trips through StateDB (else the proof would fail).
	if got.Amount.Int64() != 80 || got.SourceChain != ChainEthereum || got.DestChain != ChainLux || got.Recipient != r.Recipient {
		t.Fatalf("request did not round-trip: %+v", got)
	}

	if err := gw.VerifyCompletion(st, gwAddr, testNetworkID, testChainID, 1000, r.ID, signers); err != nil {
		t.Fatalf("VerifyCompletion: %v", err)
	}
	if err := gw.CompleteBridge(st, gwAddr, testNetworkID, testChainID, 1000, r.ID, signers); err != nil {
		t.Fatalf("CompleteBridge: %v", err)
	}
	done, _ := gw.GetRequest(st, gwAddr, r.ID)
	if done.Status != StatusCompleted {
		t.Fatalf("status after complete = %d, want Completed", done.Status)
	}
	if done.CompletedAt != 1000 {
		t.Fatalf("completedAt = %d, want 1000 (block time)", done.CompletedAt)
	}
	// Terminal: a second completion and a refund both reject.
	if err := gw.CompleteBridge(st, gwAddr, testNetworkID, testChainID, 1000, r.ID, signers); err != ErrRequestAlreadyDone {
		t.Fatalf("double complete must reject, got %v", err)
	}
	if err := gw.RefundExpired(st, gwAddr, 2000, r.ID); err != ErrRequestAlreadyDone {
		t.Fatalf("refund of consumed request must reject, got %v", err)
	}
}

func TestLifecycle_RefundExpired(t *testing.T) {
	st := newMemStateDB()
	gw := NewBridgeGateway()
	r := newRequest(80, 500) // deadline 500
	recordPending(t, st, r)

	// Before the deadline: refund refused.
	if err := gw.RefundExpired(st, gwAddr, 500, r.ID); err != ErrRequestNotExpired {
		t.Fatalf("refund at bt==deadline must reject with ErrRequestNotExpired, got %v", err)
	}
	// After the deadline: refunded.
	if err := gw.RefundExpired(st, gwAddr, 501, r.ID); err != nil {
		t.Fatalf("refund past deadline: %v", err)
	}
	got, _ := gw.GetRequest(st, gwAddr, r.ID)
	if got.Status != StatusRefunded {
		t.Fatalf("status after refund = %d, want Refunded", got.Status)
	}
}

func TestLifecycle_RecordInboundGuards(t *testing.T) {
	st := newMemStateDB()
	r := newRequest(80, 0)
	c, signers := recordPending(t, st, r)
	// Re-recording the same id is refused (a recorded id is immutable).
	if err := RecordInbound(st, gwAddr, testNetworkID, testChainID, r, signers); err != ErrRequestExists {
		t.Fatalf("re-record must reject with ErrRequestExists, got %v", err)
	}
	// A request whose digest the committee did NOT sign cannot be planted as Pending.
	r2 := newRequest(80, 0)
	dOther := CompletionDigest(testNetworkID, testChainID, newRequest(80, 0))
	if err := RecordInbound(st, gwAddr, testNetworkID, testChainID, r2, c.quorum(t, dOther, 0, 1)); err != ErrSignatureThreshold {
		t.Fatalf("recording with a non-matching quorum must reject, got %v", err)
	}
	if _, err := ReadRequest(st, gwAddr, r2.ID); err != ErrRequestNotFound {
		t.Fatalf("a rejected RecordInbound must NOT plant a Pending record, got %v", err)
	}
	// A non-positive amount is rejected.
	bad := newRequest(0, 0)
	if err := RecordInbound(st, gwAddr, testNetworkID, testChainID, bad, signers); err != ErrInvalidRequest {
		t.Fatalf("non-positive amount must reject with ErrInvalidRequest, got %v", err)
	}
}

func TestLifecycle_UnknownRequest(t *testing.T) {
	st := newMemStateDB()
	gw := NewBridgeGateway()
	var unknown [32]byte
	unknown[0] = 0xFE
	if _, err := gw.GetRequest(st, gwAddr, unknown); err != ErrRequestNotFound {
		t.Fatalf("GetRequest(unknown) must be ErrRequestNotFound, got %v", err)
	}
	if err := gw.VerifyCompletion(st, gwAddr, testNetworkID, testChainID, 1, unknown, nil); err != ErrRequestNotFound {
		t.Fatalf("VerifyCompletion(unknown) must be ErrRequestNotFound, got %v", err)
	}
}

// --- B-CLOSURE: deadline is judged by BLOCK time, deterministically ----------

func TestBlockTime_DeadlineDeterministic(t *testing.T) {
	gw := NewBridgeGateway()
	const deadline = 1000

	// Build the SAME request+committee+state and verify at two block times. The
	// outcome depends ONLY on the block time passed in — never on the wall clock.
	run := func(bt uint64) error {
		st := newMemStateDB()
		r := newRequest(80, deadline)
		_, signers := recordPending(t, st, r)
		return gw.VerifyCompletion(st, gwAddr, testNetworkID, testChainID, bt, r.ID, signers)
	}
	if err := run(deadline); err != nil { // bt == deadline => within deadline
		t.Fatalf("bt==deadline must verify, got %v", err)
	}
	if err := run(deadline + 1); err != ErrRequestExpired { // bt > deadline => expired
		t.Fatalf("bt>deadline must be ErrRequestExpired, got %v", err)
	}
	// Determinism: same block time, same outcome, regardless of when the test runs.
	for i := 0; i < 3; i++ {
		if err := run(deadline); err != nil {
			t.Fatalf("repeat %d at bt==deadline diverged: %v", i, err)
		}
		if err := run(deadline + 1); err != ErrRequestExpired {
			t.Fatalf("repeat %d at bt>deadline diverged: %v", i, err)
		}
	}
}

// --- 14-CLOSURE: StateDB FSM under snapshot + restart ------------------------

func TestStateDB_RevertUnflipsStatus(t *testing.T) {
	st := newMemStateDB()
	gw := NewBridgeGateway()
	r := newRequest(80, 0)
	_, signers := recordPending(t, st, r)

	snap := st.Snapshot()
	if err := gw.CompleteBridge(st, gwAddr, testNetworkID, testChainID, 1000, r.ID, signers); err != nil {
		t.Fatalf("CompleteBridge: %v", err)
	}
	if got, _ := gw.GetRequest(st, gwAddr, r.ID); got.Status != StatusCompleted {
		t.Fatalf("status before revert = %d, want Completed", got.Status)
	}
	// A revert un-flips the status: the consume is atomic with the surrounding tx.
	st.RevertToSnapshot(snap)
	if got, _ := gw.GetRequest(st, gwAddr, r.ID); got.Status != StatusPending {
		t.Fatalf("status after revert = %d, want Pending (un-flipped)", got.Status)
	}
}

func TestStateDB_RestartDeterministic(t *testing.T) {
	st := newMemStateDB()
	r := newRequest(80, 0)
	_, signers := recordPending(t, st, r)

	// "Restart": a brand-new gateway over the SAME StateDB re-reads the committed
	// request deterministically (not Absent) — no in-memory map to strand.
	fresh := NewBridgeGateway()
	got, err := fresh.GetRequest(st, gwAddr, r.ID)
	if err != nil {
		t.Fatalf("fresh gateway GetRequest: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("restart status = %d, want Pending", got.Status)
	}

	// The fresh gateway completes against the SAME state-resident committee, reusing
	// the attestation that recorded the inbound; a THIRD gateway then sees Completed.
	if err := fresh.CompleteBridge(st, gwAddr, testNetworkID, testChainID, 1000, r.ID, signers); err != nil {
		t.Fatalf("CompleteBridge on fresh gateway: %v", err)
	}
	if got, _ := NewBridgeGateway().GetRequest(st, gwAddr, r.ID); got.Status != StatusCompleted {
		t.Fatalf("third gateway status = %d, want Completed", got.Status)
	}
}

// --- registry-driven gateway (retained surface) ------------------------------

func TestNewBridgeGateway_DefaultChains(t *testing.T) {
	gw := NewBridgeGateway()
	for _, id := range []uint32{ChainLux, ChainEthereum, ChainBase, ChainAvalanche} {
		if !gw.Supports(id) {
			t.Fatalf("expected chain %d supported", id)
		}
	}
	if gw.Supports(99999) {
		t.Fatal("chain 99999 must not be supported")
	}
}
