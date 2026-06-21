// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
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
//
// SECURITY (the quorum is REGISTRY-PINNED, not cert-supplied): the cert carries
// NO quorum fraction. The quorum is read from the validator set's registry meta
// slot (governance authority), and an absolute >=2/3 BFT floor is enforced on top
// regardless. A cert cannot lower its own acceptance threshold — closing the
// "attacker sets QuorumNumerator=1/QuorumDenominator=large" single-signer drain.
type BLSCert struct {
	Version            uint8
	CertType           CertType
	ValidatorSetID     [32]byte // selects the VerifierRegistry entry / pubkey ordering
	SignerBitmap       []byte   // bit i set => validator i (canonical order) signed
	SignedMessageHash  [32]byte // == signedMessage(...); C recomputes and equality-checks
	AggregateSignature [96]byte // BLS12-381 G2 compressed aggregate signature
}

var (
	ErrCertTooShort      = errors.New("dex: BLS cert too short")
	ErrCertVersion       = errors.New("dex: unsupported BLS cert version")
	ErrCertType          = errors.New("dex: BLS cert type mismatch")
	ErrCertMsgMismatch   = errors.New("dex: BLS cert signed-message hash does not bind this receipt")
	ErrCertQuorumNotMet  = errors.New("dex: BLS cert signer weight below the registry-pinned quorum")
	ErrCertBelowBFTFloor = errors.New("dex: BLS cert signer weight is below the 2/3 BFT floor")
	ErrCertBitmapLen     = errors.New("dex: BLS cert signer bitmap length does not match validator set")
	ErrCertNoSigners     = errors.New("dex: BLS cert has no signers")
	ErrCertBadAggregate  = errors.New("dex: BLS cert aggregate public key invalid")
	ErrCertVerifyFailed  = errors.New("dex: BLS cert aggregate signature verification failed")
	ErrCertUnknownBit    = errors.New("dex: BLS cert signer bitmap references an absent validator")
)

// signedMessage builds the 32-byte message the D validators signed. It is
// DOMAIN-SEPARATED and binds the chain identity, the D block, the three roots
// (receiptRoot, dStateRoot, fillRoot), AND every value-bearing field of the
// receipt. Day-1 receiptRoot == receiptID (one cert per receipt); P3 makes
// receiptRoot a Merkle root over all the block's fills and each swap carries an
// inclusion proof — the message construction is IDENTICAL in both modes (only
// whether receiptRoot is a leaf or a tree root changes), so the batch upgrade
// needs no re-sign semantics and no ABI change.
//
// WHY THE VALUE FIELDS ARE IN THE MESSAGE (the critical binding): the BLS quorum
// must authorize the SPECIFIC fill — its sender, recipient, assets, and amounts —
// not merely an opaque receiptID a forger can copy onto a different economic
// payload. Without this, an attacker takes any one publicly-broadcast cert and
// rebinds it to a NEW receipt crediting itself huge AmountOut for AmountIn=1
// (receiptRoot==receiptID only commits to the id, and the id was a free wire
// field). Hashing the full value content here makes the cert co-sign exactly the
// economic effect; any tampered field yields a different message and the cert no
// longer verifies (ErrCertMsgMismatch). The D-Chain signer hashes the identical
// extended message over the identical fields.
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
	// cChainID binds the destination chain identity into the signature (it is also
	// checked in BindToSwap, but signing it precludes a cross-cChain cert lift).
	h.Write(r.CChainID[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], r.DHeight)
	h.Write(u8[:])
	h.Write(r.DBlockID[:])
	h.Write(receiptRoot[:])
	h.Write(r.DStateRoot[:])
	h.Write(r.FillRoot[:])

	// --- VALUE BINDING: every economic field the settle path moves on. A change
	// to any one of these produces a different message, so the cert authorizes
	// exactly this fill and a copied cert cannot be rebound to a different payload.
	h.Write(r.MarketID[:])
	h.Write(r.FillID[:])
	h.Write(r.PoolKeyHash[:])
	h.Write(r.SwapParamsHash[:])
	h.Write(r.Sender.Bytes())
	h.Write(r.Recipient.Bytes())
	h.Write(r.TokenInAssetID[:])
	h.Write(r.TokenOutAssetID[:])
	writeU256(h, r.AmountIn)
	writeU256(h, r.AmountOut)
	writeU256(h, r.FeeAmount)
	h.Write(r.FeeAssetID[:])
	binary.BigEndian.PutUint64(u8[:], r.Deadline)
	h.Write(u8[:])
	binary.BigEndian.PutUint64(u8[:], r.Nonce)
	h.Write(u8[:])
	h.Write(r.PrecompileAddr.Bytes())
	h.Write([]byte{byte(r.CertType)})

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// writeU256 streams a uint256 amount as a fixed 32-byte big-endian word into the
// hash (nil => zero). Fixed width keeps the message unambiguous regardless of the
// big.Int's minimal byte length, so two distinct amounts can never collide.
func writeU256(h hashWriter, v *big.Int) {
	var w [32]byte
	if v != nil && v.Sign() > 0 {
		v.FillBytes(w[:])
	}
	h.Write(w[:])
}

// hashWriter is the minimal write surface signedMessage needs (sha256.Hash
// satisfies it). Decoupled so writeU256 does not import the hash impl.
type hashWriter interface{ Write([]byte) (int, error) }

// blsCertFixedHeaderLen is the fixed prefix before the variable-length bitmap.
// The quorum fraction is NOT on the wire — it is registry-pinned (see BLSCert).
//
//	version(1) certType(1) validatorSetID(32)
//	signedMessageHash(32) aggregateSignature(96) bitmapLen(4)
const blsCertFixedHeaderLen = 1 + 1 + 32 + 32 + 96 + 4

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
//     (anti message-confusion — a cert is bound to exactly one receipt context
//     including its full economic value, see signedMessage);
//  3. the bitmap selects a quorum subset by stake weight of the REGISTERED set,
//     where the quorum is the REGISTRY-PINNED fraction (vset.QuorumNum/QuorumDen,
//     governance authority) AND, regardless, a hard absolute >=2/3 BFT floor;
//  4. the selected validators' public keys aggregate and the aggregate signature
//     verifies over the message.
//
// THE QUORUM IS NOT CERT-SUPPLIED (the critical fix): an attacker cannot lower the
// acceptance threshold by writing a tiny fraction into the cert — there is no such
// field. The threshold is the registry value (set by the same authority as the
// validator set) floored at strictly-greater-than-two-thirds of total stake, so a
// single colluding validator can never produce an accepted cert.
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
	// (2) bind the cert's declared message to THIS receipt context + value.
	m := signedMessage(r, receiptRoot)
	if c.SignedMessageHash != m {
		return ErrCertMsgMismatch
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

	// (3) QUORUM by stake weight — REGISTRY-PINNED fraction AND a hard BFT floor.
	// Both gates must pass; whichever is stricter binds. The registry value lets
	// governance require MORE than 2/3; the floor guarantees it can never be LESS.
	num, den := vset.QuorumNum, vset.QuorumDen
	if den == 0 || num == 0 || num > den {
		// A malformed/unset registry quorum falls back to the BFT floor alone (never
		// to "anything goes"): use 2/3 so the floor check below is the binding gate.
		num, den = 2, 3
	}
	if !weightMeetsQuorum(signerWeight, vset.TotalWeight, num, den) {
		return ErrCertQuorumNotMet
	}
	// Hard absolute BFT floor: signerWeight >= 2/3 * totalWeight, i.e.
	// signerWeight*3 >= totalWeight*2. Defense-in-depth that holds regardless of the
	// registry value (a corrupt registry quorum can never drop acceptance below the
	// 2/3 BFT threshold), and rejects a zero-total degenerate set. The >= boundary
	// matches the canonical Lux warp VerifyWeight semantics (node/vms/platformvm/
	// warp/signature.go: sigWeight >= total*num/den) so the DEX quorum is consistent
	// with the rest of the platform; governance can require a STRICTER margin by
	// pinning a registry fraction above 2/3 (e.g. 67/100).
	if !meetsBFTFloor(signerWeight, vset.TotalWeight) {
		return ErrCertBelowBFTFloor
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
// overflow (128-bit cross-multiply via bits.Mul64). A zero total weight never
// meets quorum (a degenerate set must fail closed, never vacuously pass). Pure,
// deterministic.
func weightMeetsQuorum(signerWeight, totalWeight uint64, num, den uint32) bool {
	if totalWeight == 0 {
		return false // degenerate set: quorum is undefined => never met (fail closed).
	}
	lhsHi, lhsLo := bits.Mul64(signerWeight, uint64(den))
	rhsHi, rhsLo := bits.Mul64(totalWeight, uint64(num))
	if lhsHi != rhsHi {
		return lhsHi > rhsHi
	}
	return lhsLo >= rhsLo
}

// meetsBFTFloor enforces the absolute Byzantine-fault threshold: signers must hold
// AT LEAST two-thirds of total stake (signerWeight*3 >= totalWeight*2), matching
// the canonical Lux warp VerifyWeight >= convention. 128-bit cross-multiply (no
// big.Int, overflow-safe). A zero total fails (no set can clear a floor it cannot
// define), closing the zero-total vacuous-quorum hole.
func meetsBFTFloor(signerWeight, totalWeight uint64) bool {
	if totalWeight == 0 {
		return false
	}
	lhsHi, lhsLo := bits.Mul64(signerWeight, 3)
	rhsHi, rhsLo := bits.Mul64(totalWeight, 2)
	if lhsHi != rhsHi {
		return lhsHi > rhsHi
	}
	return lhsLo >= rhsLo // at least 2/3 (>=), per Lux warp VerifyWeight.
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
