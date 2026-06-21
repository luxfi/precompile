// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
)

// receipt.go is the WIRE FORMAT and CONTEXT BINDING for the 0x9999 receipt-
// settlement model (decomplected — this file knows nothing about signatures,
// replay, halt, or value movement; it only parses a DFillReceiptV1 and answers
// "does this receipt bind to THIS swap on THIS chain at THIS precompile").
//
// THE MODEL (settled): D-Chain (dexvm) MATCHES (CLOB) and emits a DFillReceipt;
// the D-validator quorum BLS-signs the receipt root; C-Chain (cevm) SETTLES the
// fill via the 0x9999 precompile by VERIFYING the receipt + cert and moving value
// accordingly. C NEVER matches. The verify is a PURE DETERMINISTIC function of
// public on-chain bytes — every validator re-executing the C block computes the
// identical accept/reject — which is exactly why it is fork-safe where a live
// matcher query (the deprecated 0x9010 path) is not.

// DFillReceiptDomain is the domain-separation tag the D-Chain uses when it
// constructs a receipt id. It is NOT signed directly (the BLS message is the
// receipt root, see bls_cert.go); it scopes the receiptID derivation so a fill
// id from one chain can never be confused with another context.
const DFillReceiptDomain = "lux.dex.fill.v1"

// CertType selects the verification scheme for a receipt's certificate. The enum
// is the UPGRADE SEAM: the on-chain V4 ABI never changes; 0x9999 dispatches
// verification by certType through the VerifierRegistry, so the cert scheme can
// move BLS -> Quasar -> post-quantum -> ZK with no ABI change and no new address.
type CertType uint8

const (
	// CertTypeBLSFastPath is the day-1 certificate: a BLS12-381 aggregate
	// signature by a >= quorum subset of the D-validator set active at dHeight.
	// Deterministic to verify (a fixed pairing check), hence fork-safe inline.
	CertTypeBLSFastPath CertType = 1
	// CertTypeQ is a Quasar quorum certificate (staged P5).
	CertTypeQ CertType = 2
	// CertTypeQPQ is a post-quantum Quasar certificate (ML-DSA aggregate, staged P5).
	CertTypeQPQ CertType = 3
	// CertTypeZK is a succinct proof (starkfri, staged P5).
	CertTypeZK CertType = 4
)

// receiptVersion is the only DFillReceipt version this precompile accepts. A
// receipt with any other version is refused (no silent forward-compat — a new
// layout is a new version with explicit handling).
const receiptVersion uint8 = 1

// receiptFixedLen is the byte length of the fixed-width DFillReceiptV1 frame.
// Every field is fixed width (no length-prefixed sub-fields) so the frame is
// unambiguous and the decode is bounds-checked against exactly this length.
//
//	version(1) networkID(4) dChainID(32) cChainID(32) dHeight(8) dBlockID(32)
//	marketID(32) fillID(32) receiptID(32) poolKeyHash(32) swapParamsHash(32)
//	sender(20) recipient(20) tokenInAssetID(32) tokenOutAssetID(32)
//	amountIn(32) amountOut(32) feeAmount(32) feeAssetID(32) deadline(8)
//	nonce(8) precompileAddr(20) dStateRoot(32) bookRoot(32) fillRoot(32) certType(1)
const receiptFixedLen = 1 + 4 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 32 + 32 +
	20 + 20 + 32 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 20 + 32 + 32 + 32 + 1

// DFillReceiptV1 is the D-Chain's committed, certified record of a single fill.
// It rides in the V4 swap hookData (see settle9999.go). Every identity field is
// FULL WIDTH (AccountID/AssetID never a truncated handle) — the security
// invariant the deprecated path also held.
type DFillReceiptV1 struct {
	Version         uint8
	NetworkID       uint32
	DChainID        [32]byte
	CChainID        [32]byte
	DHeight         uint64
	DBlockID        [32]byte
	MarketID        [32]byte
	FillID          [32]byte
	ReceiptID       [32]byte // the REPLAY KEY; consumedReceipt is keyed on this
	PoolKeyHash     [32]byte // == PoolKey.ID() of the swap's pool
	SwapParamsHash  [32]byte // == keccak(swapParamsDigest(params)) of the swap
	Sender          common.Address
	Recipient       common.Address
	TokenInAssetID  [32]byte // full injective AssetID (assetID(Currency); native=0)
	TokenOutAssetID [32]byte
	AmountIn        *big.Int
	AmountOut       *big.Int
	FeeAmount       *big.Int
	FeeAssetID      [32]byte
	Deadline        uint64
	Nonce           uint64
	PrecompileAddr  common.Address // MUST be 0x9999 — binds to the sole money path
	DStateRoot      [32]byte
	BookRoot        [32]byte
	FillRoot        [32]byte
	CertType        CertType
}

// receipt-settlement errors. Each maps to a clean revert; no error leaks partial
// state (EVM revert rolls back every SetState/balance change made before it).
var (
	ErrReceiptTooShort     = errors.New("dex: fill receipt too short")
	ErrReceiptVersion      = errors.New("dex: unsupported fill receipt version")
	ErrReceiptWrongNetwork = errors.New("dex: fill receipt networkID mismatch")
	ErrReceiptWrongCChain  = errors.New("dex: fill receipt cChainID mismatch")
	ErrReceiptWrongAddr    = errors.New("dex: fill receipt precompile address mismatch")
	ErrReceiptWrongPool    = errors.New("dex: fill receipt poolKeyHash does not match swap")
	ErrReceiptWrongParams  = errors.New("dex: fill receipt swapParamsHash does not match swap")
	ErrReceiptWrongSender  = errors.New("dex: fill receipt sender is not the caller")
	ErrReceiptWrongRecip   = errors.New("dex: fill receipt recipient does not match swap recipient")
	ErrReceiptWrongAssets  = errors.New("dex: fill receipt assets do not match swap direction")
	ErrReceiptBelowMin     = errors.New("dex: fill receipt amountOut below requested minimum")
	ErrReceiptExpired      = errors.New("dex: fill receipt deadline has passed")
	ErrReceiptBadAmounts   = errors.New("dex: fill receipt has negative or nil amounts")
)

// DecodeFillReceipt parses a fixed-width DFillReceiptV1 frame. It bounds-checks
// the exact length, rejects unsupported versions, and reads big-endian. It does
// NO binding and NO crypto — those are separate concerns (BindToSwap, verifyCert).
func DecodeFillReceipt(b []byte) (*DFillReceiptV1, error) {
	if len(b) < receiptFixedLen {
		return nil, ErrReceiptTooShort
	}
	if b[0] != receiptVersion {
		return nil, ErrReceiptVersion
	}
	r := &DFillReceiptV1{}
	off := 0
	rd8 := func() uint64 { v := binary.BigEndian.Uint64(b[off : off+8]); off += 8; return v }
	rd4 := func() uint32 { v := binary.BigEndian.Uint32(b[off : off+4]); off += 4; return v }
	rd32 := func() (x [32]byte) { copy(x[:], b[off:off+32]); off += 32; return x }
	rd20 := func() (a common.Address) { copy(a[:], b[off:off+20]); off += 20; return a }
	rdU256 := func() *big.Int { v := new(big.Int).SetBytes(b[off : off+32]); off += 32; return v }

	r.Version = b[off]
	off++
	r.NetworkID = rd4()
	r.DChainID = rd32()
	r.CChainID = rd32()
	r.DHeight = rd8()
	r.DBlockID = rd32()
	r.MarketID = rd32()
	r.FillID = rd32()
	r.ReceiptID = rd32()
	r.PoolKeyHash = rd32()
	r.SwapParamsHash = rd32()
	r.Sender = rd20()
	r.Recipient = rd20()
	r.TokenInAssetID = rd32()
	r.TokenOutAssetID = rd32()
	r.AmountIn = rdU256()
	r.AmountOut = rdU256()
	r.FeeAmount = rdU256()
	r.FeeAssetID = rd32()
	r.Deadline = rd8()
	r.Nonce = rd8()
	r.PrecompileAddr = rd20()
	r.DStateRoot = rd32()
	r.BookRoot = rd32()
	r.FillRoot = rd32()
	r.CertType = CertType(b[off])
	return r, nil
}

// Encode serializes the receipt to its fixed-width frame. Used by tests and by
// the D-Chain receipt builder (P4); the encoding is the EXACT inverse of
// DecodeFillReceipt so a round-trip is byte-identical.
func (r *DFillReceiptV1) Encode() []byte {
	b := make([]byte, receiptFixedLen)
	off := 0
	wr8 := func(v uint64) { binary.BigEndian.PutUint64(b[off:off+8], v); off += 8 }
	wr4 := func(v uint32) { binary.BigEndian.PutUint32(b[off:off+4], v); off += 4 }
	wr32 := func(x [32]byte) { copy(b[off:off+32], x[:]); off += 32 }
	wr20 := func(a common.Address) { copy(b[off:off+20], a[:]); off += 20 }
	wrU256 := func(v *big.Int) {
		if v != nil {
			v.FillBytes(b[off : off+32])
		}
		off += 32
	}
	b[off] = r.Version
	off++
	wr4(r.NetworkID)
	wr32(r.DChainID)
	wr32(r.CChainID)
	wr8(r.DHeight)
	wr32(r.DBlockID)
	wr32(r.MarketID)
	wr32(r.FillID)
	wr32(r.ReceiptID)
	wr32(r.PoolKeyHash)
	wr32(r.SwapParamsHash)
	wr20(r.Sender)
	wr20(r.Recipient)
	wr32(r.TokenInAssetID)
	wr32(r.TokenOutAssetID)
	wrU256(r.AmountIn)
	wrU256(r.AmountOut)
	wrU256(r.FeeAmount)
	wr32(r.FeeAssetID)
	wr8(r.Deadline)
	wr8(r.Nonce)
	wr20(r.PrecompileAddr)
	wr32(r.DStateRoot)
	wr32(r.BookRoot)
	wr32(r.FillRoot)
	b[off] = byte(r.CertType)
	return b
}

// minAmountOut derives the swap's slippage floor from V4 SwapParams. The receipt's
// AmountOut must be >= this. V4 exact-output (AmountSpecified > 0) names the exact
// output desired; exact-input (AmountSpecified < 0) leaves the floor to the price
// limit, which the D-Chain enforced at match time and the cert attests — so for
// exact-input the floor is the magnitude only when it is an exact-output request.
//
// Conservative rule (the SAFE direction — never credits MORE than the user asked
// to receive for an exact-output, never under-credits below an exact-output ask):
//   - exact-output (AmountSpecified > 0): floor = AmountSpecified (must receive at
//     least the exact output requested).
//   - exact-input (AmountSpecified <= 0): floor = 0 here; the realized output is
//     whatever the D-Chain matched within the price limit, which the cert binds.
//     (A nonzero exact-input floor is a P4 router concern carried in params; the
//     CLOB price limit already bounds it on the D side.)
func minAmountOut(params SwapParams) *big.Int {
	if params.AmountSpecified != nil && params.AmountSpecified.Sign() > 0 {
		return new(big.Int).Set(params.AmountSpecified)
	}
	return big.NewInt(0)
}

// swapAssetDirection returns the (tokenIn, tokenOut) injective AssetIDs implied by
// the pool key and swap direction. ZeroForOne true => in=currency0, out=currency1.
// The receipt's TokenIn/TokenOut AssetIDs MUST equal these (anti asset-swap).
func swapAssetDirection(key PoolKey, params SwapParams) (in, out [32]byte) {
	c0 := assetID(key.Currency0)
	c1 := assetID(key.Currency1)
	if params.ZeroForOne {
		return c0, c1
	}
	return c1, c0
}

// BindToSwap checks every CONTEXT binding between a decoded receipt and the swap
// the C-Chain is executing. It is cheap (hashes + comparisons), runs BEFORE the
// crypto, and refuses any cross-pool / cross-chain / cross-precompile / asset-swap
// / stale-deadline / under-min / wrong-sender / wrong-recipient replay. It does
// NOT check the signature (verifyCert) nor replay consumption (consumedReceipt) —
// those are separate, single-concern checks composed by the 0x9999 handler.
//
// networkID and cChainID are the precompile's CONFIGURED chain identity (written
// to StateDB at Configure, read by the handler) — the receipt must name THIS
// chain. callerAuthorized lets an operator settle on a sender's behalf when the
// sender explicitly authorized that operator (default: sender == caller).
func (r *DFillReceiptV1) BindToSwap(
	key PoolKey,
	params SwapParams,
	caller common.Address,
	recipient common.Address,
	networkID uint32,
	cChainID [32]byte,
	blockTime uint64,
	callerAuthorized bool,
) error {
	if r.AmountIn == nil || r.AmountIn.Sign() < 0 ||
		r.AmountOut == nil || r.AmountOut.Sign() < 0 ||
		(r.FeeAmount != nil && r.FeeAmount.Sign() < 0) {
		return ErrReceiptBadAmounts
	}
	if r.NetworkID != networkID {
		return ErrReceiptWrongNetwork
	}
	if r.CChainID != cChainID {
		return ErrReceiptWrongCChain
	}
	if r.PrecompileAddr != poolManagerAddr9999 {
		return ErrReceiptWrongAddr
	}
	if r.PoolKeyHash != key.ID() {
		return ErrReceiptWrongPool
	}
	if r.SwapParamsHash != swapParamsHash(params) {
		return ErrReceiptWrongParams
	}
	// sender == caller, unless the caller is an authorized operator for sender.
	if r.Sender != caller && !callerAuthorized {
		return ErrReceiptWrongSender
	}
	if r.Recipient != recipient {
		return ErrReceiptWrongRecip
	}
	wantIn, wantOut := swapAssetDirection(key, params)
	if r.TokenInAssetID != wantIn || r.TokenOutAssetID != wantOut {
		return ErrReceiptWrongAssets
	}
	if r.AmountOut.Cmp(minAmountOut(params)) < 0 {
		return ErrReceiptBelowMin
	}
	if r.Deadline < blockTime {
		return ErrReceiptExpired
	}
	return nil
}

// swapParamsHash is the 32-byte commitment to a swap's parameters. It reuses the
// canonical swapParamsDigest encoding (direction + |amount| + sign + price limit)
// so the C-side binding names the EXACT same swap the D-Chain matched. The
// D-Chain receipt builder computes the identical hash over the identical fields.
func swapParamsHash(params SwapParams) [32]byte {
	return keccak32([]byte(swapParamsDigest(params)))
}
