// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// receipt.go — the A-Chain inference RECEIPT, its canonical encoding, and its hash.
//
// THE SHARED WIRE SPEC (pinned byte-for-byte; Blue-B's chains/aivm importer MUST
// produce this exact encoding; aivmbridge_wire_test.go asserts the golden vectors).
//
//	AInferenceReceipt canonical encoding (fixed-width, THIS order):
//	  u16be(Version)            // 2
//	  IntentID(32)              // the C intent this receipt settles
//	  TaskID(32)                // the A-Chain task id
//	  CChainID(32) AChainID(32) // the C<->A rail binding (mirrors the intent)
//	  Requester(20)             // the C caller the intent bound
//	  ModelSpecHash(32) PromptHash(32)
//	  CanonicalOutputHash(32)   // the agreed output digest (zero unless Completed)
//	  u8(Status)
//	  u16be(N) u16be(Threshold)
//	  WinnersRoot(32) OperatorsRoot(32)
//	  u256be(FeePaid, 32)
//	  u64be(SettledAtHeight)
//
//	DOMAIN_RECEIPT = "lux/aivmbridge/receipt/v1"   (raw utf8, no length prefix)
//	receipt_hash   = keccak256( DOMAIN_RECEIPT || <that encoding> )
//
// ONLY a receipt with Status == StatusCompleted AND a non-zero CanonicalOutputHash
// is actionable on C. Every other status carries no actionable output (fail-secure).

package aivmbridge

import (
	"encoding/binary"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// DomainReceipt is the keccak domain separator for receipt-hash derivation. Raw
// utf8 bytes (no length prefix) — pinned by the shared wire spec.
const DomainReceipt = "lux/aivmbridge/receipt/v1"

// ReceiptVersion is the only canonical receipt version this package encodes/accepts.
// A receipt declaring any other version fails decode (an unknown layout must never be
// mis-read into a value).
const ReceiptVersion uint16 = 1

// receiptEncodedLen is the fixed byte length of the canonical receipt encoding.
//
//	2 + 32 + 32 + 32 + 32 + 20 + 32 + 32 + 32 + 1 + 2 + 2 + 32 + 32 + 32 + 8
const receiptEncodedLen = 2 + 32 + 32 + 32 + 32 + 20 + 32 + 32 + 32 + 1 + 2 + 2 + 32 + 32 + 32 + 8

// ReceiptStatus is the lifecycle of an A-Chain inference job, as the C side sees it
// through a committed receipt. Only StatusCompleted (2) with a non-zero output is
// actionable; every other value carries no actionable output (fail-secure).
type ReceiptStatus uint8

const (
	StatusUnknown    ReceiptStatus = 0
	StatusPending    ReceiptStatus = 1
	StatusCompleted  ReceiptStatus = 2
	StatusFailed     ReceiptStatus = 3
	StatusChallenged ReceiptStatus = 4
)

// AInferenceReceipt is a COMMITTED A-Chain receipt for a C intent (the Pattern-B
// verification target). The C side verifies it against a committed receipt root and
// applies an effect ONLY when Status == StatusCompleted with a non-zero
// CanonicalOutputHash. A non-final receipt is inert.
type AInferenceReceipt struct {
	Version             uint16
	IntentID            [32]byte
	TaskID              [32]byte
	CChainID            [32]byte
	AChainID            [32]byte
	Requester           common.Address
	ModelSpecHash       [32]byte
	PromptHash          [32]byte
	CanonicalOutputHash [32]byte
	Status              ReceiptStatus
	N                   uint16
	Threshold           uint16
	WinnersRoot         [32]byte
	OperatorsRoot       [32]byte
	FeePaid             [32]byte
	SettledAtHeight     uint64
}

// EncodeReceipt serializes the receipt into its canonical fixed-width encoding (the
// exact byte order pinned by the shared wire spec).
func EncodeReceipt(r AInferenceReceipt) []byte {
	b := make([]byte, receiptEncodedLen)
	o := 0
	binary.BigEndian.PutUint16(b[o:o+2], r.Version)
	o += 2
	o += copy(b[o:], r.IntentID[:])
	o += copy(b[o:], r.TaskID[:])
	o += copy(b[o:], r.CChainID[:])
	o += copy(b[o:], r.AChainID[:])
	o += copy(b[o:], r.Requester.Bytes()) // exactly 20 bytes
	o += copy(b[o:], r.ModelSpecHash[:])
	o += copy(b[o:], r.PromptHash[:])
	o += copy(b[o:], r.CanonicalOutputHash[:])
	b[o] = byte(r.Status)
	o++
	binary.BigEndian.PutUint16(b[o:o+2], r.N)
	o += 2
	binary.BigEndian.PutUint16(b[o:o+2], r.Threshold)
	o += 2
	o += copy(b[o:], r.WinnersRoot[:])
	o += copy(b[o:], r.OperatorsRoot[:])
	o += copy(b[o:], r.FeePaid[:])
	binary.BigEndian.PutUint64(b[o:o+8], r.SettledAtHeight)
	o += 8
	// o == receiptEncodedLen by construction.
	return b
}

// DecodeReceipt parses the canonical fixed-width receipt encoding. It REJECTS any
// input that is not exactly receiptEncodedLen bytes or declares a version other than
// ReceiptVersion — an unknown layout must never be mis-decoded into a value.
func DecodeReceipt(b []byte) (AInferenceReceipt, error) {
	if len(b) != receiptEncodedLen {
		return AInferenceReceipt{}, ErrReceiptDecode
	}
	var r AInferenceReceipt
	o := 0
	r.Version = binary.BigEndian.Uint16(b[o : o+2])
	o += 2
	if r.Version != ReceiptVersion {
		return AInferenceReceipt{}, ErrReceiptDecode
	}
	copy(r.IntentID[:], b[o:o+32])
	o += 32
	copy(r.TaskID[:], b[o:o+32])
	o += 32
	copy(r.CChainID[:], b[o:o+32])
	o += 32
	copy(r.AChainID[:], b[o:o+32])
	o += 32
	r.Requester = common.BytesToAddress(b[o : o+20])
	o += 20
	copy(r.ModelSpecHash[:], b[o:o+32])
	o += 32
	copy(r.PromptHash[:], b[o:o+32])
	o += 32
	copy(r.CanonicalOutputHash[:], b[o:o+32])
	o += 32
	r.Status = ReceiptStatus(b[o])
	o++
	r.N = binary.BigEndian.Uint16(b[o : o+2])
	o += 2
	r.Threshold = binary.BigEndian.Uint16(b[o : o+2])
	o += 2
	copy(r.WinnersRoot[:], b[o:o+32])
	o += 32
	copy(r.OperatorsRoot[:], b[o:o+32])
	o += 32
	copy(r.FeePaid[:], b[o:o+32])
	o += 32
	r.SettledAtHeight = binary.BigEndian.Uint64(b[o : o+8])
	o += 8
	return r, nil
}

// ReceiptHash computes keccak256(DOMAIN_RECEIPT || canonical_encoding(r)) — the leaf
// digest a merkle proof must include under the committed receipt root.
func ReceiptHash(r AInferenceReceipt) [32]byte {
	enc := EncodeReceipt(r)
	buf := make([]byte, 0, len(DomainReceipt)+len(enc))
	buf = append(buf, []byte(DomainReceipt)...)
	buf = append(buf, enc...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out
}

// isZero32 reports whether a 32-byte value is all zero.
func isZero32(b [32]byte) bool {
	return b == [32]byte{}
}
