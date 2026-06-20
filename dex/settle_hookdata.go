// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// settle_hookdata.go parses the SETTLEMENT ENVELOPE carried in the V4 swap
// hookData. The V4 ABI is UNCHANGED — `swap(PoolKey, SwapParams, bytes hookData)`
// already passes a `bytes hookData` argument that web/mobile populate. The
// settlement model puts the certified D-Chain fill receipt + BLS cert (+ optional
// Merkle inclusion proof, P3) INSIDE that existing argument. No selector change,
// no tuple change — only the CONTENTS of hookData.
//
// Envelope layout (deterministic, bounds-checked, length-prefixed):
//
//	tag[4] = "D991"
//	receiptLen[4] | receipt[receiptLen]
//	certLen[4]    | cert[certLen]
//	proofLen[4]   | proof[proofLen]   // 0-length day-1; the P3 inclusion proof
//
// A hookData that does NOT begin with the tag is treated as "no settlement
// instruction": a value-moving swap then reverts MISSING_RECEIPT (there is no
// embedded matcher to fall back to — settlement REQUIRES a certified fill). This
// is unambiguous: a hook contract's own opaque bytes will not collide with the
// 4-byte tag, and even if they did, the inner length-prefixed decode would reject
// a non-conforming body.

// SettlementEnvelopeTag marks a hookData blob as carrying a settlement receipt.
var SettlementEnvelopeTag = [4]byte{'D', '9', '9', '1'}

var (
	ErrNoSettlementEnvelope = errors.New("dex: swap hookData carries no settlement receipt (MISSING_RECEIPT)")
	ErrEnvelopeMalformed    = errors.New("dex: settlement envelope is malformed")
)

// maxEnvelopeField bounds each length-prefixed field so a malformed length cannot
// over-read or allocate unboundedly. Receipt and cert are small (hundreds of
// bytes); 1<<20 is a generous ceiling that still rejects garbage lengths.
const maxEnvelopeField = 1 << 20

// HasSettlementEnvelope reports whether hookData begins with the settlement tag.
// Used to distinguish a settlement swap from a hook-only swap before decoding.
func HasSettlementEnvelope(hookData []byte) bool {
	return len(hookData) >= 4 && bytes.Equal(hookData[:4], SettlementEnvelopeTag[:])
}

// DecodeSettlementHookData parses the tagged envelope into a decoded receipt, a
// decoded cert, and the raw inclusion proof (nil/empty day-1). It bounds-checks
// every length and rejects trailing garbage. It performs NO binding and NO crypto.
func DecodeSettlementHookData(hookData []byte) (*DFillReceiptV1, *BLSCert, []byte, error) {
	if !HasSettlementEnvelope(hookData) {
		return nil, nil, nil, ErrNoSettlementEnvelope
	}
	off := 4
	readField := func() ([]byte, error) {
		if off+4 > len(hookData) {
			return nil, ErrEnvelopeMalformed
		}
		n := binary.BigEndian.Uint32(hookData[off : off+4])
		off += 4
		if n > maxEnvelopeField {
			return nil, ErrEnvelopeMalformed
		}
		if uint64(off)+uint64(n) > uint64(len(hookData)) {
			return nil, ErrEnvelopeMalformed
		}
		b := hookData[off : off+int(n)]
		off += int(n)
		return b, nil
	}

	receiptBytes, err := readField()
	if err != nil {
		return nil, nil, nil, err
	}
	certBytes, err := readField()
	if err != nil {
		return nil, nil, nil, err
	}
	proofBytes, err := readField()
	if err != nil {
		return nil, nil, nil, err
	}
	// Reject trailing garbage: the envelope must consume exactly hookData.
	if off != len(hookData) {
		return nil, nil, nil, ErrEnvelopeMalformed
	}

	receipt, err := DecodeFillReceipt(receiptBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := DecodeBLSCert(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	// The receipt's certType and the cert's certType MUST agree (the receipt names
	// the scheme; the cert is that scheme's proof). A mismatch is malformed.
	if receipt.CertType != cert.CertType {
		return nil, nil, nil, ErrCertType
	}
	return receipt, cert, proofBytes, nil
}

// EncodeSettlementHookData builds the tagged envelope from a receipt + cert (+
// optional proof). Used by tests and the P4 builder/RPC automation. The encoding
// is the exact inverse of DecodeSettlementHookData.
func EncodeSettlementHookData(receipt *DFillReceiptV1, cert *BLSCert, proof []byte) []byte {
	rb := receipt.Encode()
	cb := cert.Encode()
	out := make([]byte, 0, 4+4+len(rb)+4+len(cb)+4+len(proof))
	out = append(out, SettlementEnvelopeTag[:]...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(rb)))
	out = append(out, l[:]...)
	out = append(out, rb...)
	binary.BigEndian.PutUint32(l[:], uint32(len(cb)))
	out = append(out, l[:]...)
	out = append(out, cb...)
	binary.BigEndian.PutUint32(l[:], uint32(len(proof)))
	out = append(out, l[:]...)
	out = append(out, proof...)
	return out
}
