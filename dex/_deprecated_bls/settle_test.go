// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/geth/common"
)

// settle_test.go — the cryptographic + wire-format test suite for the 0x9999
// receipt-settlement money path: BLS cert verify (valid / invalid / quorum-fail /
// replay-of-message), validator-set registry round-trip, receipt + cert wire
// round-trips, and context binding.

// --- BLS test fixtures: a real validator set with real keys.

type testValidator struct {
	sk     *bls.SecretKey
	pk     *bls.PublicKey
	weight uint64
}

func newTestValidators(t testing.TB, weights ...uint64) []testValidator {
	t.Helper()
	vs := make([]testValidator, len(weights))
	for i, w := range weights {
		sk, err := bls.NewSecretKey()
		if err != nil {
			t.Fatalf("bls.NewSecretKey: %v", err)
		}
		vs[i] = testValidator{sk: sk, pk: sk.PublicKey(), weight: w}
	}
	return vs
}

// makePoP builds a valid proof-of-possession for a test validator over its own
// public key (the same message PutValidatorSet verifies against). Centralized here
// so every test set that registers validators carries well-formed PoPs.
func makePoP(t testing.TB, v testValidator) []byte {
	t.Helper()
	sig, err := v.sk.SignProofOfPossession(PoPMessage(v.pk))
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}
	return bls.SignatureToBytes(sig)
}

// makePubkeyBytes returns a validator's 48-byte compressed BLS public key (the wire
// form the registerValidatorSet payload carries).
func makePubkeyBytes(t testing.TB, v testValidator) []byte {
	t.Helper()
	return bls.PublicKeyToCompressedBytes(v.pk)
}

func validatorSetFrom(dChainID, vsID [32]byte, vals []testValidator) *ValidatorSet {
	vs := &ValidatorSet{
		DChainID:         dChainID,
		ValidatorSetID:   vsID,
		CertType:         CertTypeBLSFastPath,
		ActivationHeight: 0,
		Status:           VerifierActive,
		QuorumNum:        2, // 2/3 registry-pinned quorum (matches the BFT floor).
		QuorumDen:        3,
	}
	for _, v := range vals {
		var pop []byte
		if v.sk != nil {
			s, err := v.sk.SignProofOfPossession(PoPMessage(v.pk))
			if err == nil {
				pop = bls.SignatureToBytes(s)
			}
		}
		vs.Validators = append(vs.Validators, Validator{PublicKey: v.pk, Weight: v.weight, PoP: pop})
		vs.TotalWeight += v.weight
	}
	return vs
}

// bitmapForSigners builds a ceil(n/8)-byte bitmap with the given signer indices set.
func bitmapForSigners(n int, signers ...int) []byte {
	bm := make([]byte, (n+7)/8)
	for _, i := range signers {
		bm[i/8] |= 1 << uint(7-(i%8))
	}
	return bm
}

// buildCert aggregates signatures from the given signer indices over the message
// implied by (receipt, receiptRoot) and packs a BLSCert with a 2/3 quorum.
func buildCert(t testing.TB, vsID [32]byte, vals []testValidator, receipt *DFillReceiptV1, receiptRoot [32]byte, signers ...int) *BLSCert {
	t.Helper()
	m := signedMessage(receipt, receiptRoot)
	sigs := make([]*bls.Signature, 0, len(signers))
	for _, i := range signers {
		sig, err := vals[i].sk.Sign(m[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sigs = append(sigs, sig)
	}
	agg, err := bls.AggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	var aggBytes [96]byte
	copy(aggBytes[:], bls.SignatureToBytes(agg))
	return &BLSCert{
		Version:            blsCertVersion,
		CertType:           CertTypeBLSFastPath,
		ValidatorSetID:     vsID,
		SignerBitmap:       bitmapForSigners(len(vals), signers...),
		SignedMessageHash:  m,
		AggregateSignature: aggBytes,
	}
}

// fundClaim seeds a depositor's claim AND the backing settleVault for an asset,
// faithfully modelling what a real deposit does (a claim is always backed by the
// swap-payable vault). Tests use this instead of storeDepositorClaim-alone so the
// conservation invariant settleVault[a] >= Σ unlocked claims[a] holds going in —
// otherwise the maker-lock vault accounting (which moves delta from settleVault to
// makerLockedVault on ADD) would underflow against an unbacked claim.
func fundClaim(stateDB StateDB, account common.Address, assetID [32]byte, amount *big.Int) {
	storeDepositorClaim(stateDB, account, assetID, new(big.Int).Add(loadDepositorClaim(stateDB, account, assetID), amount))
	storeSettleVault(stateDB, assetID, new(big.Int).Add(loadSettleVault(stateDB, assetID), amount))
}

func sampleReceipt() *DFillReceiptV1 {
	return &DFillReceiptV1{
		Version:         1,
		NetworkID:       1,
		DChainID:        [32]byte{0xDD},
		CChainID:        [32]byte{0xCC},
		DHeight:         100,
		DBlockID:        [32]byte{0xB0},
		MarketID:        [32]byte{0x1A},
		FillID:          [32]byte{0xF1},
		ReceiptID:       [32]byte{0x9E},
		PoolKeyHash:     [32]byte{0x90},
		SwapParamsHash:  [32]byte{0x5A},
		Sender:          common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Recipient:       common.HexToAddress("0x1111111111111111111111111111111111111111"),
		TokenInAssetID:  [32]byte{}, // native
		TokenOutAssetID: [32]byte{31: 0x02},
		AmountIn:        big.NewInt(1000),
		AmountOut:       big.NewInt(990),
		FeeAmount:       big.NewInt(10),
		FeeAssetID:      [32]byte{},
		Deadline:        1 << 40,
		Nonce:           7,
		PrecompileAddr:  poolManagerAddr9999,
		DStateRoot:      [32]byte{0x57},
		BookRoot:        [32]byte{0xB0, 0x0C},
		FillRoot:        [32]byte{0xF0},
		CertType:        CertTypeBLSFastPath,
	}
}

// TestBLSCert_ValidQuorum: a cert by a >=2/3 weight subset verifies.
func TestBLSCert_ValidQuorum(t *testing.T) {
	vsID := [32]byte{0x01}
	vals := newTestValidators(t, 1, 1, 1) // total 3, quorum 2/3 => need >=2
	r := sampleReceipt()
	receiptRoot := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	cert := buildCert(t, vsID, vals, r, receiptRoot, 0, 1) // 2 of 3 weight
	if err := VerifyBLSCert(cert, r, receiptRoot, vset); err != nil {
		t.Fatalf("valid 2/3 quorum cert must verify, got: %v", err)
	}

	// All three signers also verify.
	certAll := buildCert(t, vsID, vals, r, receiptRoot, 0, 1, 2)
	if err := VerifyBLSCert(certAll, r, receiptRoot, vset); err != nil {
		t.Fatalf("full-set cert must verify, got: %v", err)
	}
}

// TestBLSCert_QuorumNotMet: a cert by < quorum weight is refused even with valid sigs.
func TestBLSCert_QuorumNotMet(t *testing.T) {
	vsID := [32]byte{0x02}
	vals := newTestValidators(t, 1, 1, 1) // total 3, need >=2
	r := sampleReceipt()
	receiptRoot := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	cert := buildCert(t, vsID, vals, r, receiptRoot, 0) // 1 of 3 weight < 2/3
	if err := VerifyBLSCert(cert, r, receiptRoot, vset); err != ErrCertQuorumNotMet {
		t.Fatalf("sub-quorum cert must fail with ErrCertQuorumNotMet, got: %v", err)
	}
}

// TestBLSCert_InvalidSignature: a tampered aggregate signature is refused.
func TestBLSCert_InvalidSignature(t *testing.T) {
	vsID := [32]byte{0x03}
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	receiptRoot := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	cert := buildCert(t, vsID, vals, r, receiptRoot, 0, 1)
	// Flip a byte in the aggregate signature.
	cert.AggregateSignature[10] ^= 0xFF
	if err := VerifyBLSCert(cert, r, receiptRoot, vset); err == nil {
		t.Fatal("tampered signature must be refused")
	}
}

// TestBLSCert_MessageConfusion: a cert signed over receiptRoot A is refused when
// presented against a receipt whose context implies a DIFFERENT message. This is
// the contextual-binding defense (the cert binds to exactly one receipt context).
func TestBLSCert_MessageConfusion(t *testing.T) {
	vsID := [32]byte{0x04}
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	receiptRoot := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	cert := buildCert(t, vsID, vals, r, receiptRoot, 0, 1)
	// Now mutate the receipt's dHeight: the recomputed message no longer matches
	// the cert's SignedMessageHash, so verification must refuse before pairing.
	r2 := sampleReceipt()
	r2.DHeight = 101
	if err := VerifyBLSCert(cert, r2, r2.ReceiptID, vset); err != ErrCertMsgMismatch {
		t.Fatalf("message confusion must fail with ErrCertMsgMismatch, got: %v", err)
	}
}

// TestBLSCert_WrongKeyDoesNotVerify: a cert aggregated from keys NOT in the set
// (or a single honest signer's sig presented as if from another) fails. We model
// this by signing with a fresh key not in the set and claiming an in-set bit.
func TestBLSCert_WrongKeyDoesNotVerify(t *testing.T) {
	vsID := [32]byte{0x05}
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	receiptRoot := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	// Build a cert whose bitmap claims signers {0,1} but whose aggregate is signed
	// by a foreign key — the aggregate public key (vals[0]+vals[1]) won't match.
	m := signedMessage(r, receiptRoot)
	foreign, _ := bls.NewSecretKey()
	fsig, _ := foreign.Sign(m[:])
	hsig, _ := vals[0].sk.Sign(m[:])
	agg, _ := bls.AggregateSignatures([]*bls.Signature{hsig, fsig})
	var aggBytes [96]byte
	copy(aggBytes[:], bls.SignatureToBytes(agg))
	cert := &BLSCert{
		Version:            blsCertVersion,
		CertType:           CertTypeBLSFastPath,
		ValidatorSetID:     vsID,
		SignerBitmap:       bitmapForSigners(3, 0, 1),
		SignedMessageHash:  m,
		AggregateSignature: aggBytes,
	}
	if err := VerifyBLSCert(cert, r, receiptRoot, vset); err != ErrCertVerifyFailed {
		t.Fatalf("foreign-key aggregate must fail verification, got: %v", err)
	}
}

// TestBLSCert_PhantomSignerBit: a bitmap with a bit set past the set size is
// refused (anti phantom-signer / over-long bitmap).
func TestBLSCert_PhantomSignerBit(t *testing.T) {
	vsID := [32]byte{0x06}
	vals := newTestValidators(t, 1, 1, 1) // n=3 => 1-byte bitmap, bits 0..2 valid
	r := sampleReceipt()
	receiptRoot := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	cert := buildCert(t, vsID, vals, r, receiptRoot, 0, 1)
	// Set bit 5 (past n=3) in the single bitmap byte.
	cert.SignerBitmap[0] |= 1 << uint(7-5)
	if err := VerifyBLSCert(cert, r, receiptRoot, vset); err != ErrCertUnknownBit {
		t.Fatalf("phantom signer bit must fail with ErrCertUnknownBit, got: %v", err)
	}
}

// TestVerifierRegistry_RoundTrip: a validator set written to StateDB resolves
// back identically (keys, weights, total) and enforces certType + activation.
func TestVerifierRegistry_RoundTrip(t *testing.T) {
	db := NewMockStateDB()
	vals := newTestValidators(t, 5, 3, 2) // total 10
	dChainID := [32]byte{0xDD}
	vsID := [32]byte{0xAA}
	vs := validatorSetFrom(dChainID, vsID, vals)
	vs.ActivationHeight = 50

	if err := PutValidatorSet(db, vs); err != nil {
		t.Fatalf("PutValidatorSet: %v", err)
	}
	got, err := ResolveValidatorSet(db, dChainID, vsID, CertTypeBLSFastPath, 60)
	if err != nil {
		t.Fatalf("ResolveValidatorSet: %v", err)
	}
	if got.TotalWeight != 10 || len(got.Validators) != 3 {
		t.Fatalf("resolved set wrong: total=%d n=%d", got.TotalWeight, len(got.Validators))
	}
	for i := range vals {
		want := bls.PublicKeyToCompressedBytes(vals[i].pk)
		gotPk := bls.PublicKeyToCompressedBytes(got.Validators[i].PublicKey)
		if string(want) != string(gotPk) {
			t.Fatalf("validator %d pubkey mismatch", i)
		}
		if got.Validators[i].Weight != vals[i].weight {
			t.Fatalf("validator %d weight mismatch", i)
		}
	}

	// certType mismatch is refused.
	if _, err := ResolveValidatorSet(db, dChainID, vsID, CertTypeQ, 60); err != ErrVerifierCertType {
		t.Fatalf("wrong certType must fail, got: %v", err)
	}
	// dHeight before activation is refused.
	if _, err := ResolveValidatorSet(db, dChainID, vsID, CertTypeBLSFastPath, 49); err != ErrVerifierTooEarly {
		t.Fatalf("pre-activation height must fail, got: %v", err)
	}
	// Unknown set is not found.
	if _, err := ResolveValidatorSet(db, dChainID, [32]byte{0xBB}, CertTypeBLSFastPath, 60); err != ErrVerifierNotFound {
		t.Fatalf("unknown set must be not-found, got: %v", err)
	}
}

// TestReceiptWireRoundTrip: a receipt encodes and decodes byte-identically.
func TestReceiptWireRoundTrip(t *testing.T) {
	r := sampleReceipt()
	b := r.Encode()
	if len(b) != receiptFixedLen {
		t.Fatalf("encoded receipt len %d != %d", len(b), receiptFixedLen)
	}
	got, err := DecodeFillReceipt(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.NetworkID != r.NetworkID || got.DHeight != r.DHeight ||
		got.ReceiptID != r.ReceiptID || got.AmountIn.Cmp(r.AmountIn) != 0 ||
		got.AmountOut.Cmp(r.AmountOut) != 0 || got.PrecompileAddr != r.PrecompileAddr ||
		got.CertType != r.CertType || got.Sender != r.Sender {
		t.Fatal("receipt round-trip mismatch")
	}
}

// TestCertWireRoundTrip: a cert encodes and decodes byte-identically.
func TestCertWireRoundTrip(t *testing.T) {
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	cert := buildCert(t, [32]byte{0x01}, vals, r, r.ReceiptID, 0, 1)
	b := cert.Encode()
	got, err := DecodeBLSCert(b)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if got.Version != cert.Version || got.CertType != cert.CertType ||
		got.ValidatorSetID != cert.ValidatorSetID ||
		got.SignedMessageHash != cert.SignedMessageHash ||
		got.AggregateSignature != cert.AggregateSignature ||
		string(got.SignerBitmap) != string(cert.SignerBitmap) {
		t.Fatal("cert round-trip mismatch")
	}
}

// TestHookDataEnvelopeRoundTrip: the settlement envelope round-trips and rejects
// non-tagged / malformed hookData.
func TestHookDataEnvelopeRoundTrip(t *testing.T) {
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	cert := buildCert(t, [32]byte{0x01}, vals, r, r.ReceiptID, 0, 1)
	hd := EncodeSettlementHookData(r, cert, nil)

	gotR, gotC, proof, err := DecodeSettlementHookData(hd)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if gotR.ReceiptID != r.ReceiptID || gotC.SignedMessageHash != cert.SignedMessageHash || len(proof) != 0 {
		t.Fatal("envelope round-trip mismatch")
	}

	// Non-tagged hookData => MISSING_RECEIPT.
	if _, _, _, err := DecodeSettlementHookData([]byte("not a receipt envelope at all")); err != ErrNoSettlementEnvelope {
		t.Fatalf("non-tagged hookData must be ErrNoSettlementEnvelope, got: %v", err)
	}
	// Truncated envelope => malformed.
	if _, _, _, err := DecodeSettlementHookData(hd[:len(hd)-5]); err == nil {
		t.Fatal("truncated envelope must be refused")
	}
	// Trailing garbage => malformed.
	if _, _, _, err := DecodeSettlementHookData(append(hd, 0xFF)); err != ErrEnvelopeMalformed {
		t.Fatalf("trailing garbage must be ErrEnvelopeMalformed, got: %v", err)
	}
}
