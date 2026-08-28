// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// wire_test.go — the SHARED WIRE SPEC cross-check. It pins intent_id and receipt_hash
// to GOLDEN VECTORS computed from a fixed fixture. Blue-B's chains/aivm importer MUST
// reproduce these EXACT bytes; a divergence here is a cross-chain wire break (an A
// receipt C cannot verify, or an intent A imports under the wrong id). These vectors
// ARE the contract between the C precompile and the A importer.

package aivmbridge

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
)

// fixtureIntent is the canonical wire-spec fixture (every field set to a distinct,
// recognizable pattern so a mis-ordered preimage is obvious).
func fixtureIntent() InferenceIntent {
	return InferenceIntent{
		CChainID:        h32(0xC0),
		AChainID:        h32(0xA0),
		CTxHash:         h32(0x77),
		CallIndex:       0x01020304,
		Caller:          common.HexToAddress("0x1111111111111111111111111111111111111111"),
		ModelSpecHash:   h32(0x5E),
		ModelPromptHash: h32(0x9D),
		N:               3,
		Threshold:       2,
		Fee:             feeWord(1_000_000),
	}
}

// fixtureReceipt is the canonical receipt wire-spec fixture (bound to fixtureIntent).
func fixtureReceipt() AInferenceReceipt {
	intentID := DeriveIntentID(fixtureIntent())
	return AInferenceReceipt{
		Version:             ReceiptVersion,
		IntentID:            intentID,
		TaskID:              h32(0x7A),
		CChainID:            h32(0xC0),
		AChainID:            h32(0xA0),
		Requester:           common.HexToAddress("0x1111111111111111111111111111111111111111"),
		ModelSpecHash:       h32(0x5E),
		PromptHash:          h32(0x9D),
		CanonicalOutputHash: h32(0x0F),
		Status:              StatusCompleted,
		N:                   3,
		Threshold:           2,
		WinnersRoot:         h32(0x44),
		OperatorsRoot:       h32(0x55),
		FeePaid:             feeWord(1_000_000),
		SettledAtHeight:     0x0102030405060708,
	}
}

// GOLDEN VECTORS — these are the pinned wire-spec outputs. Blue-B's chains/aivm MUST
// match them. (Computed by this package's own DeriveIntentID / ReceiptHash; locked in
// so a future refactor that changes the byte layout fails loudly.)
const (
	goldenIntentID    = "13346f5fe5f8feda7fec68968366fb397cf3854096a07a1528ada9a0c910d758"
	goldenReceiptHash = "c6e07d2b28f8cafa0ccf12a540379eb37afe50cf48567e59d96e386a73ca5b5b"
)

// TestWireSpecGoldenIntentID asserts intent_id matches the pinned golden vector AND
// the documented keccak preimage layout exactly.
func TestWireSpecGoldenIntentID(t *testing.T) {
	got := DeriveIntentID(fixtureIntent())
	gotHex := hex.EncodeToString(got[:])

	// Reconstruct the preimage by hand per the spec and assert DeriveIntentID equals
	// keccak of it (proves the function follows the documented layout, not just itself).
	want := manualIntentID(fixtureIntent())
	wantHex := hex.EncodeToString(want[:])
	if gotHex != wantHex {
		t.Fatalf("intent_id != manual preimage keccak:\n  got  %s\n  want %s", gotHex, wantHex)
	}
	t.Logf("GOLDEN intent_id = %s", gotHex)

	if goldenIntentID != "" && goldenIntentID != "PLACEHOLDER_INTENT_ID" && gotHex != goldenIntentID {
		t.Fatalf("intent_id golden vector drift:\n  got    %s\n  golden %s", gotHex, goldenIntentID)
	}
}

// TestWireSpecGoldenReceiptHash asserts receipt_hash matches the documented domain +
// canonical encoding, and round-trips encode/decode.
func TestWireSpecGoldenReceiptHash(t *testing.T) {
	r := fixtureReceipt()

	// Round-trip the canonical encoding.
	enc := EncodeReceipt(r)
	if len(enc) != receiptEncodedLen {
		t.Fatalf("receipt encoding length = %d, want %d", len(enc), receiptEncodedLen)
	}
	dec, err := DecodeReceipt(enc)
	if err != nil {
		t.Fatalf("DecodeReceipt: %v", err)
	}
	if dec != r {
		t.Fatalf("receipt round-trip mismatch:\n  got  %+v\n  want %+v", dec, r)
	}

	got := ReceiptHash(r)
	gotHex := hex.EncodeToString(got[:])
	t.Logf("GOLDEN receipt_hash = %s", gotHex)

	// Manual recompute: keccak(DOMAIN_RECEIPT || canonical_encoding).
	want := manualReceiptHash(r)
	if got != want {
		t.Fatalf("receipt_hash != manual domain||encoding keccak:\n  got  %s\n  want %s",
			gotHex, hex.EncodeToString(want[:]))
	}

	if goldenReceiptHash != "" && goldenReceiptHash != "PLACEHOLDER_RECEIPT_HASH" && gotHex != goldenReceiptHash {
		t.Fatalf("receipt_hash golden vector drift:\n  got    %s\n  golden %s", gotHex, goldenReceiptHash)
	}
}

// TestDomainSeparators pins the exact domain strings (a typo here is a wire break).
func TestDomainSeparators(t *testing.T) {
	if DomainIntent != "lux/aivmbridge/intent/v1" {
		t.Fatalf("DomainIntent = %q", DomainIntent)
	}
	if DomainReceipt != "lux/aivmbridge/receipt/v1" {
		t.Fatalf("DomainReceipt = %q", DomainReceipt)
	}
}

// manualIntentID is an INDEPENDENT re-implementation of the intent_id preimage from
// the spec text, used to prove DeriveIntentID follows the documented layout (a tautology
// is avoided: this assembles the bytes by hand in spec order).
func manualIntentID(in InferenceIntent) [32]byte {
	var buf []byte
	buf = append(buf, []byte("lux/aivmbridge/intent/v1")...)
	buf = append(buf, in.CChainID[:]...)
	buf = append(buf, in.AChainID[:]...)
	buf = append(buf, in.CTxHash[:]...)
	buf = append(buf, byte(in.CallIndex>>24), byte(in.CallIndex>>16), byte(in.CallIndex>>8), byte(in.CallIndex))
	buf = append(buf, in.Caller.Bytes()...)
	buf = append(buf, in.ModelSpecHash[:]...)
	buf = append(buf, in.ModelPromptHash[:]...)
	buf = append(buf, byte(in.N>>8), byte(in.N))
	buf = append(buf, byte(in.Threshold>>8), byte(in.Threshold))
	buf = append(buf, in.Fee[:]...)
	return keccak(buf)
}

// manualReceiptHash independently recomputes keccak(DOMAIN_RECEIPT || canonical) by
// assembling the canonical encoding by hand in spec order.
func manualReceiptHash(r AInferenceReceipt) [32]byte {
	var e []byte
	e = append(e, byte(r.Version>>8), byte(r.Version))
	e = append(e, r.IntentID[:]...)
	e = append(e, r.TaskID[:]...)
	e = append(e, r.CChainID[:]...)
	e = append(e, r.AChainID[:]...)
	e = append(e, r.Requester.Bytes()...)
	e = append(e, r.ModelSpecHash[:]...)
	e = append(e, r.PromptHash[:]...)
	e = append(e, r.CanonicalOutputHash[:]...)
	e = append(e, byte(r.Status))
	e = append(e, byte(r.N>>8), byte(r.N))
	e = append(e, byte(r.Threshold>>8), byte(r.Threshold))
	e = append(e, r.WinnersRoot[:]...)
	e = append(e, r.OperatorsRoot[:]...)
	e = append(e, r.FeePaid[:]...)
	h := r.SettledAtHeight
	e = append(e, byte(h>>56), byte(h>>48), byte(h>>40), byte(h>>32), byte(h>>24), byte(h>>16), byte(h>>8), byte(h))

	var buf []byte
	buf = append(buf, []byte("lux/aivmbridge/receipt/v1")...)
	buf = append(buf, e...)
	return keccak(buf)
}
