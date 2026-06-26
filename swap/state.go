// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// State layout under swapAddr, using the mapping-slot idiom slot(id,f) =
// keccak256(id ‖ f). Per-swap fields are keyed by (swapId, fieldByte); the
// singletons are keyed by fixed string prefixes.
const (
	fStatus    byte = 0 // 0 None / 1 Locked / 2 Claimed / 3 Refunded
	fHashlock  byte = 1
	fRecipient byte = 2
	fRefund    byte = 3
	fAsset     byte = 4
	fAmount    byte = 5
	fTimeout   byte = 6
	fPreimage  byte = 7
)

var (
	prefixPreimage = []byte("pre")   // preimageIdx[hashlock] = s
	prefixReserve  = []byte("res")   // reserve[asset] = Σ live locked amount
	prefixNonce    = []byte("nonce") // monotonic lock counter
	prefixGuard    = []byte("guard") // global non-reentrant entry guard
)

// swapFieldSlot = keccak256(swapId ‖ field).
func swapFieldSlot(swapId common.Hash, field byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(swapId[:], []byte{field}))
}

// preimageIdxSlot = keccak256("pre" ‖ hashlock).
func preimageIdxSlot(hashlock common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixPreimage, hashlock[:]))
}

// reserveSlot = keccak256("res" ‖ asset).
func reserveSlot(asset common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prefixReserve, asset.Bytes()))
}

// nonceSlot = keccak256("nonce"); guardSlot = keccak256("guard").
func nonceSlot() common.Hash { return common.BytesToHash(crypto.Keccak256(prefixNonce)) }
func guardSlot() common.Hash { return common.BytesToHash(crypto.Keccak256(prefixGuard)) }

// computeSwapID = keccak256(h ‖ recipient ‖ refund ‖ asset ‖ amount ‖ timeout ‖
// caller ‖ nonce) with amount and nonce as 32-byte big-endian words and timeout
// as an 8-byte big-endian word.
func computeSwapID(
	hashlock common.Hash,
	recipient, refund, asset common.Address,
	amount *big.Int,
	timeout uint64,
	caller common.Address,
	nonce uint64,
) common.Hash {
	var amountW [32]byte
	amount.FillBytes(amountW[:])
	var timeoutW [8]byte
	binary.BigEndian.PutUint64(timeoutW[:], timeout)
	var nonceW [32]byte
	binary.BigEndian.PutUint64(nonceW[24:], nonce)

	return common.BytesToHash(crypto.Keccak256(
		hashlock[:],
		recipient.Bytes(),
		refund.Bytes(),
		asset.Bytes(),
		amountW[:],
		timeoutW[:],
		caller.Bytes(),
		nonceW[:],
	))
}

// preimageMatches reports whether SHA256(preimage) == hashlock. The preimage is
// public once revealed, so a plain comparison is correct here — there is no secret
// to leak via timing.
func preimageMatches(preimage [preimageLen]byte, hashlock common.Hash) bool {
	sum := sha256.Sum256(preimage[:])
	return common.BytesToHash(sum[:]) == hashlock
}

// ---------------------------------------------------------------------------
// stateRW is the minimal StateDB surface this precompile touches: word-addressed
// storage plus the event log. contract.StateDB satisfies it.
// ---------------------------------------------------------------------------

type stateRW interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash) common.Hash
}

// ---------------------------------------------------------------------------
// Per-swap field accessors
// ---------------------------------------------------------------------------

func loadStatus(db stateRW, swapId common.Hash) uint8 {
	return db.GetState(swapAddr, swapFieldSlot(swapId, fStatus))[31]
}

func storeStatus(db stateRW, swapId common.Hash, status uint8) {
	var w common.Hash
	w[31] = status
	db.SetState(swapAddr, swapFieldSlot(swapId, fStatus), w)
}

func loadHash(db stateRW, swapId common.Hash, field byte) common.Hash {
	return db.GetState(swapAddr, swapFieldSlot(swapId, field))
}

func storeHash(db stateRW, swapId common.Hash, field byte, v common.Hash) {
	db.SetState(swapAddr, swapFieldSlot(swapId, field), v)
}

func loadAddress(db stateRW, swapId common.Hash, field byte) common.Address {
	return common.BytesToAddress(db.GetState(swapAddr, swapFieldSlot(swapId, field)).Bytes())
}

func storeAddress(db stateRW, swapId common.Hash, field byte, a common.Address) {
	db.SetState(swapAddr, swapFieldSlot(swapId, field), common.BytesToHash(a.Bytes()))
}

func loadAmount(db stateRW, swapId common.Hash, field byte) *big.Int {
	return new(big.Int).SetBytes(db.GetState(swapAddr, swapFieldSlot(swapId, field)).Bytes())
}

func storeAmount(db stateRW, swapId common.Hash, field byte, amount *big.Int) {
	db.SetState(swapAddr, swapFieldSlot(swapId, field), common.BigToHash(amount))
}

func loadTimeout(db stateRW, swapId common.Hash) uint64 {
	w := db.GetState(swapAddr, swapFieldSlot(swapId, fTimeout))
	return binary.BigEndian.Uint64(w[24:])
}

func storeTimeout(db stateRW, swapId common.Hash, timeout uint64) {
	var w common.Hash
	binary.BigEndian.PutUint64(w[24:], timeout)
	db.SetState(swapAddr, swapFieldSlot(swapId, fTimeout), w)
}

// ---------------------------------------------------------------------------
// preimageIdx[hashlock]
// ---------------------------------------------------------------------------

func loadPreimageIdx(db stateRW, hashlock common.Hash) [preimageLen]byte {
	var p [preimageLen]byte
	copy(p[:], db.GetState(swapAddr, preimageIdxSlot(hashlock)).Bytes())
	return p
}

func storePreimageIdx(db stateRW, hashlock common.Hash, preimage [preimageLen]byte) {
	db.SetState(swapAddr, preimageIdxSlot(hashlock), common.BytesToHash(preimage[:]))
}

// ---------------------------------------------------------------------------
// reserve[asset] — the per-asset conservation accumulator.
// ---------------------------------------------------------------------------

func loadReserve(db stateRW, asset common.Address) *big.Int {
	return new(big.Int).SetBytes(db.GetState(swapAddr, reserveSlot(asset)).Bytes())
}

func storeReserve(db stateRW, asset common.Address, v *big.Int) {
	db.SetState(swapAddr, reserveSlot(asset), common.BigToHash(v))
}

func addReserve(db stateRW, asset common.Address, delta *big.Int) {
	storeReserve(db, asset, new(big.Int).Add(loadReserve(db, asset), delta))
}

// subReserve debits the per-asset reserve, refusing (false) on underflow. Under
// the conservation invariant the reserve always covers a Locked swap's amount, so
// false signals a state-corruption bug, never a normal path.
func subReserve(db stateRW, asset common.Address, amount *big.Int) bool {
	cur := loadReserve(db, asset)
	if cur.Cmp(amount) < 0 {
		return false
	}
	storeReserve(db, asset, new(big.Int).Sub(cur, amount))
	return true
}

// ---------------------------------------------------------------------------
// nonce + reentrancy guard
// ---------------------------------------------------------------------------

func loadNonce(db stateRW) uint64 {
	w := db.GetState(swapAddr, nonceSlot())
	return binary.BigEndian.Uint64(w[24:])
}

func storeNonce(db stateRW, nonce uint64) {
	var w common.Hash
	binary.BigEndian.PutUint64(w[24:], nonce)
	db.SetState(swapAddr, nonceSlot(), w)
}

// enterGuard sets the global guard, returning false if it was already set (a
// reentrant entry). exitGuard clears it. Together they make the transferFrom-delta
// measurement and the status flip atomic against a token's reentrant callback.
func enterGuard(db stateRW) bool {
	slot := guardSlot()
	if db.GetState(swapAddr, slot)[31] != 0 {
		return false
	}
	var w common.Hash
	w[31] = 1
	db.SetState(swapAddr, slot, w)
	return true
}

func exitGuard(db stateRW) {
	db.SetState(swapAddr, guardSlot(), common.Hash{})
}

// ---------------------------------------------------------------------------
// ABI word helpers
// ---------------------------------------------------------------------------

// wordAddress reads an address from a right-aligned 32-byte ABI word.
func wordAddress(word []byte) common.Address {
	return common.BytesToAddress(word[12:32])
}

// wordUint64 reads a uint64 from a right-aligned 32-byte ABI word, rejecting any
// value that does not fit in 64 bits (high 24 bytes must be zero).
func wordUint64(word []byte) (uint64, bool) {
	for _, b := range word[:24] {
		if b != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint64(word[24:32]), true
}

func addressWord(a common.Address) []byte { return common.BytesToHash(a.Bytes()).Bytes() }

func uint64Word(v uint64) []byte {
	var w common.Hash
	binary.BigEndian.PutUint64(w[24:], v)
	return w.Bytes()
}

func uint8Word(v uint8) []byte {
	var w common.Hash
	w[31] = v
	return w.Bytes()
}

func boolWord(b bool) []byte {
	var w common.Hash
	if b {
		w[31] = 1
	}
	return w.Bytes()
}
