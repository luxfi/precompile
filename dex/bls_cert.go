// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/luxfi/crypto/bls"
)

// bls_cert.go is the day-1 CERTIFICATE: a BLS12-381 aggregate signature by a
// >= quorum subset of the D-validator set active at the receipt's dHeight.
//
// WHY THIS IS FORK-SAFE (the cryptographic crux of the whole design): BLS
// aggregate verify is e(sigma, g2) == e(H(m), aggPubKey) — a FIXED pairing check
// over fixed byte inputs. It reads no clock, no network, no per-validator mutable
// state, uses no RNG, and (in blst, the luxfi/crypto backend) is field-exact with
// no floating point. Every honest validator re-executing the C block computes the
// IDENTICAL boolean. This is the categorical difference from the deprecated 0x9010
// live-matcher query, which observed a moving order book at per-validator wall-
// clock instants and therefore forked the StateRoot (proven by chains/dexvm
// TestRED_PerValidatorRelay_SplitsConsensus). Verifying an already-committed,
// already-certified result is consensus-safe; producing it inline is not.
//
// SECURITY (EUF-CMA over the validator set): forging a cert that 0x9999 accepts
// reduces to forging a BLS aggregate over the active D-validator set. Under the
// AGM/ROM for BLS12-381 this is co-CDH-hard (Boneh-Lynn-Shacham). Rogue-key
// attacks (Ristenpart-Yilek) are precluded because validator keys are registered
// with proof-of-possession (luxfi/crypto bls.VerifyProofOfPossession at
// registration time, NOT here — here the keys are already trusted set members).

// BLSCertDomain is the domain-separation tag prepended to the signed message. It
// scopes a D fill attestation so a signature over a fill root can NEVER be replayed
// as a signature in any other Lux BLS context (warp, Quasar, staking). This is the
// contextual-binding defense against cross-protocol signature reuse.
const BLSCertDomain = "lux.dex.bls.fill.v1"

const blsCertVersion uint8 = 1

// BLSCert is the aggregate-signature certificate carried in the V4 swap hookData.
type BLSCert struct {
	Version           uint8
	CertType          CertType
	ValidatorSetID    [32]byte // selects the VerifierRegistry entry / pubkey ordering
	QuorumNumerator   uint32
	QuorumDenominator uint32
	SignerBitmap      []byte    // bit i set => validator i (canonical order) signed
	SignedMessageHash [32]byte  // == signedMessage(...); C recomputes and equality-checks
	AggregateSignature [96]byte // BLS12-381 G2 compressed aggregate signature
}

var (
	ErrCertTooShort       = errors.New("dex: BLS cert too short")
	ErrCertVersion        = errors.New("dex: unsupported BLS cert version")
	ErrCertType           = errors.New("dex: BLS cert type mismatch")
	ErrCertMsgMismatch    = errors.New("dex: BLS cert signed-message hash does not bind this receipt")
	ErrCertBadQuorum      = errors.New("dex: BLS cert has invalid quorum fraction")
	ErrCertQuorumNotMet   = errors.New("dex: BLS cert signer weight below quorum")
	ErrCertBitmapLen      = errors.New("dex: BLS cert signer bitmap length does not match validator set")
	ErrCertNoSigners      = errors.New("dex: BLS cert has no signers")
	ErrCertBadAggregate   = errors.New("dex: BLS cert aggregate public key invalid")
	ErrCertVerifyFailed   = errors.New("dex: BLS cert aggregate signature verification failed")
	ErrCertUnknownBit     = errors.New("dex: BLS cert signer bitmap references an absent validator")
)

// signedMessage builds the 32-byte message the D validators signed. It is
// DOMAIN-SEPARATED and binds the chain identity, the D block, and the three roots
// (receiptRoot, dStateRoot, fillRoot). Day-1 receiptRoot == receiptID (one cert
// per receipt); P3 makes receiptRoot a Merkle root over all the block's fills and
// each swap carries an inclusion proof — the message construction is IDENTICAL in
// both modes (only whether receiptRoot is a leaf or a tree root changes), so the
// batch upgrade needs no re-sign semantics and no ABI change.
//
// SHA-256 (not keccak) is used here because this is a fresh attestation domain
// the D-Chain signer and this verifier define together; the choice is internal
// and consistent on both ends. The domain tag makes it unambiguous regardless.
func signedMessage(r *DFillReceiptV1, receiptRoot [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(BLSCertDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], r.NetworkID)
	h.Write(u4[:])
	h.Write(r.DChainID[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], r.DHeight)
	h.Write(u8[:])
	h.Write(r.DBlockID[:])
	h.Write(receiptRoot[:])
	h.Write(r.DStateRoot[:])
	h.Write(r.FillRoot[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// blsCertFixedHeaderLen is the fixed prefix before the variable-length bitmap.
//
//	version(1) certType(1) validatorSetID(32) quorumNum(4) quorumDen(4)
//	signedMessageHash(32) aggregateSignature(96) bitmapLen(4)
const blsCertFixedHeaderLen = 1 + 1 + 32 + 4 + 4 + 32 + 96 + 4

// DecodeBLSCert parses a BLSCert frame: fixed header then a 4-byte bitmap length
// then the bitmap bytes. Bounds-checked; no crypto here.
func DecodeBLSCert(b []byte) (*BLSCert, error) {
	if len(b) < blsCertFixedHeaderLen {
		return nil, ErrCertTooShort
	}
	if b[0] != blsCertVersion {
		return nil, ErrCertVersion
	}
	c := &BLSCert{}
	off := 0
	c.Version = b[off]
	off++
	c.CertType = CertType(b[off])
	off++
	copy(c.ValidatorSetID[:], b[off:off+32])
	off += 32
	c.QuorumNumerator = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	c.QuorumDenominator = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	copy(c.SignedMessageHash[:], b[off:off+32])
	off += 32
	copy(c.AggregateSignature[:], b[off:off+96])
	off += 96
	bitmapLen := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if uint64(off)+uint64(bitmapLen) > uint64(len(b)) {
		return nil, ErrCertTooShort
	}
	c.SignerBitmap = make([]byte, bitmapLen)
	copy(c.SignerBitmap, b[off:off+int(bitmapLen)])
	return c, nil
}

// Encode serializes the cert (exact inverse of DecodeBLSCert; used by tests and
// the D-Chain cert builder).
func (c *BLSCert) Encode() []byte {
	b := make([]byte, blsCertFixedHeaderLen+len(c.SignerBitmap))
	off := 0
	b[off] = c.Version
	off++
	b[off] = byte(c.CertType)
	off++
	copy(b[off:off+32], c.ValidatorSetID[:])
	off += 32
	binary.BigEndian.PutUint32(b[off:off+4], c.QuorumNumerator)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], c.QuorumDenominator)
	off += 4
	copy(b[off:off+32], c.SignedMessageHash[:])
	off += 32
	copy(b[off:off+96], c.AggregateSignature[:])
	off += 96
	binary.BigEndian.PutUint32(b[off:off+4], uint32(len(c.SignerBitmap)))
	off += 4
	copy(b[off:], c.SignerBitmap)
	return b
}

// bitmapPopcount counts set bits (number of declared signers).
func bitmapPopcount(bm []byte) int {
	n := 0
	for _, x := range bm {
		n += bits.OnesCount8(x)
	}
	return n
}

// bitSet reports whether validator index i is marked in the bitmap. Bit i lives
// in byte i/8 at position i%8 (MSB-first within the byte, the canonical Lux warp
// bitmap convention).
func bitSet(bm []byte, i int) bool {
	byteIdx := i / 8
	if byteIdx >= len(bm) {
		return false
	}
	return bm[byteIdx]&(1<<uint(7-(i%8))) != 0
}

// VerifyBLSCert performs the DETERMINISTIC quorum-aggregate verification:
//
//  1. cert version/type sanity;
//  2. the cert's signed-message hash equals the message THIS receipt+root implies
//     (anti message-confusion — a cert is bound to exactly one receipt context);
//  3. the bitmap selects a >= quorum subset by stake weight of the registered set;
//  4. the selected validators' public keys aggregate and the aggregate signature
//     verifies over the message.
//
// vset is the validator set active at the receipt's dHeight, resolved by the
// caller from the VerifierRegistry. This function makes C-Chain consensus state
// depend ONLY on a fixed pairing check over already-committed bytes — never on a
// live query — so it is safe to call inside Run().
func VerifyBLSCert(c *BLSCert, r *DFillReceiptV1, receiptRoot [32]byte, vset *ValidatorSet) error {
	if c.Version != blsCertVersion {
		return ErrCertVersion
	}
	if c.CertType != CertTypeBLSFastPath {
		return ErrCertType
	}
	// (2) bind the cert's declared message to THIS receipt context.
	m := signedMessage(r, receiptRoot)
	if c.SignedMessageHash != m {
		return ErrCertMsgMismatch
	}
	if c.QuorumDenominator == 0 || c.QuorumNumerator == 0 || c.QuorumNumerator > c.QuorumDenominator {
		return ErrCertBadQuorum
	}
	if bitmapPopcount(c.SignerBitmap) == 0 {
		return ErrCertNoSigners
	}
	// The bitmap must be sized for exactly this set (ceil(n/8) bytes) so an
	// over-long bitmap cannot smuggle phantom signer bits past the loop bound.
	wantBytes := (len(vset.Validators) + 7) / 8
	if len(c.SignerBitmap) != wantBytes {
		return ErrCertBitmapLen
	}

	// (3)+(4) walk the set in canonical order, accumulate signer weight and the
	// public keys to aggregate. A bit set beyond the set size is a malformed cert.
	pubkeys := make([]*bls.PublicKey, 0, len(vset.Validators))
	var signerWeight uint64
	for i := range vset.Validators {
		if !bitSet(c.SignerBitmap, i) {
			continue
		}
		v := vset.Validators[i]
		pubkeys = append(pubkeys, v.PublicKey)
		signerWeight += v.Weight
	}
	// Any high bits beyond the set must be zero (already guaranteed by length, but
	// the final partial byte can hold bits past n).
	if extra := (wantBytes * 8) - len(vset.Validators); extra > 0 {
		last := c.SignerBitmap[wantBytes-1]
		mask := byte((1 << uint(extra)) - 1) // low `extra` bits = positions past n
		if last&mask != 0 {
			return ErrCertUnknownBit
		}
	}
	if len(pubkeys) == 0 {
		return ErrCertNoSigners
	}

	// Quorum by stake weight: signerWeight / totalWeight >= num / den.
	// Cross-multiply to avoid division (exact, no rounding): signerWeight * den
	// >= totalWeight * num. Guard the multiply against overflow with big-free
	// 128-bit comparison via bits.Mul64.
	if !weightMeetsQuorum(signerWeight, vset.TotalWeight, c.QuorumNumerator, c.QuorumDenominator) {
		return ErrCertQuorumNotMet
	}

	apk, err := bls.AggregatePublicKeys(pubkeys)
	if err != nil || apk == nil {
		return ErrCertBadAggregate
	}
	if !bls.Verify(apk, sigFrom(c.AggregateSignature), m[:]) {
		return ErrCertVerifyFailed
	}
	return nil
}

// weightMeetsQuorum returns signerWeight * den >= totalWeight * num without
// overflow (128-bit cross-multiply via bits.Mul64). Pure, deterministic.
func weightMeetsQuorum(signerWeight, totalWeight uint64, num, den uint32) bool {
	lhsHi, lhsLo := bits.Mul64(signerWeight, uint64(den))
	rhsHi, rhsLo := bits.Mul64(totalWeight, uint64(num))
	if lhsHi != rhsHi {
		return lhsHi > rhsHi
	}
	return lhsLo >= rhsLo
}

// sigFrom reconstructs a *bls.Signature from its 96-byte compressed form. A
// malformed signature deserializes to a value that fails Verify; we return a
// best-effort handle and let Verify reject it (Verify is the authority on
// validity, and an invalid point cannot pass the pairing check).
func sigFrom(b [96]byte) *bls.Signature {
	sig, err := bls.SignatureFromBytes(b[:])
	if err != nil {
		return nil
	}
	return sig
}
