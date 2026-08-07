// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_wire.go is the C<->D ATOMIC OBJECT wire format for the 0x9999 native
// settlement seam. It is byte-for-byte the same shared-memory UTXO value the
// dexvm side reads/writes (chains/dexvm/atomic.go encodeExportedOutput /
// decodeExportedOutput): rail(1) | owner(20) | asset(32) | amount(8) | spent(8) =
// 69 bytes, fixed width, deterministic. Keeping the wire identical is what lets the
// D side import a C->D object NATIVELY (its executeImport binds the recorded rail/
// owner/asset/amount) and lets C consume a D->C object the same way.
//
// THE SPENT WITNESS (trailing 8 bytes): on a D->C swap PROCEEDS leg, spent carries
// the matched INPUT amount (in the locked/input-asset units) that produced this
// output. It is 0 on every other leg (C->D orders/commits, same-asset refunds, LP
// collects). ImportSettlement reads it to enforce the TAKER's OWN recorded slippage
// limit on the proceeds leg — realized price = out/spent (SELL) or spent/out (BUY) —
// INDEPENDENTLY of the keeper-relayed RelayOrderTx.PriceLimit. So a keeper that
// zeroes the relay limit to let a sandwiched fill through still produces a proceeds
// object whose realized price C refuses to credit (taker-authenticated MEV floor).
// The two repos extend this width in LOCKSTEP; native_seam_parity_test pins the
// golden bytes so a one-sided change is caught at test time, never in consensus.
//
// THE RAIL TAG (the H1 fix): the object's FIRST byte is the RAIL discriminator —
// the lane the value travels on, a property of the OBJECT, not of the C-side
// selector that consumes it. A swap-fill object is railSwap; an LP-collect object
// is railLP. Each C-side consume path accepts ONLY its own rail (ImportSettlement
// => railSwap, ImportPositionCollect => railLP) and debits ONLY its own pot
// (seamReserve vs committedPositions). Before the tag, a D->C object was rail-
// agnostic and the DEBITED pot was chosen by which selector the caller invoked —
// so an LP-collect object could drain the swap pot (H1-A) and a swap-fill object
// could drain the LP pot (H1-B). With the tag the object is UNAMBIGUOUSLY one rail
// and a cross-rail consume is rejected at decode-bind. A unit is CSpendable XOR
// DCommitted across BOTH rails because a D->C object carries exactly one rail and
// only the matching consume path (drawing only the matching pot) accepts it.
//
// THE TWO LEGS (the ship rule made concrete):
//   - C->D ORDER/COMMIT: C writes one of these into shared memory keyed by the D
//     chain. D's executeImport consumes it and credits a funded D order/position.
//     D is funded ONLY by consuming a C->D object. The C->D object is stamped with
//     the lane that wrote it (SubmitSwapOrder => railSwap, SubmitPositionCommit
//     => railLP) so the rail round-trips: a swap lives on railSwap for BOTH legs,
//     an LP on railLP for BOTH legs.
//   - D->C SETTLEMENT/COLLECT: D writes one of these into shared memory keyed by
//     the C chain (its executeExport). C's ImportSettlement (railSwap) /
//     ImportPositionCollect (railLP) consumes it ONCE and credits C value. C is
//     credited ONLY by consuming a D->C object OF THE MATCHING RAIL.
//
// THE OPERATION SEGMENT (the seam's missing half). The 69 bytes above are a VALUE:
// "this much of this asset belongs to this owner on this rail". A value says what
// moves; it does not say what to DO with it. That is why the D side could consume a
// C->D order, credit the taker's D account, and stop: it had been told nothing else.
// Nothing placed an order, so nothing crossed, so no proceeds existed, so no D->C
// settlement object was ever produced and the whole seam was unreachable by
// construction.
//
// A C->D SWAP ORDER therefore carries a second, orthogonal segment — the OPERATION
// the taker authorized on C:
//
//	market(32) | side(1) | limitPrice(8) | size(8)  = 49 bytes
//
// appended to the value, giving a 118-byte order object. The two segments are
// composed, not braided: the value head is byte-for-byte the same 69 bytes every
// other consumer already reads (the golden vectors that pin it stay valid), and the
// op tail is a separate value qualified by its own accessor. WIDTH IS THE
// DISCRIMINATOR — 69 and 118 are distinct fixed widths, so a decode can never be
// steered between the two readings:
//
//	69 bytes  -> a VALUE object: D->C settlements, D->C LP collects, C->D LP commits.
//	            Those legs instruct nothing; they only move value. decodeAtomicObject.
//	118 bytes -> a C->D SWAP ORDER: value + the CLOB operation. decodeOrderObject.
//
// WHY THE OPERATION MUST BE IN THE OBJECT AND NOWHERE ELSE. The atomic object is the
// only authenticated C->D channel. D cannot read C's logs, so the routing EVENT is
// not a source D may bind to; anything D is not handed in the object, D would have to
// invent — and an invented market/side/limit is an order the taker never authorized.
// Carrying it here makes the operation as strongly bound as the value: one object,
// one atomic consumption, one authorization.
//
// isMarket and limitIsUpper are NOT carried, because they are not independent facts:
// every seam order is a LIMIT order (the limit is required, see SeamOp), and a BUY's
// limit is by definition its ceiling while a SELL's is its floor. Deriving them keeps
// one declaration of each fact instead of two to cross-check.
//
// The remaining order metadata (minAmountOut, recipient, deadline, nonce) is neither
// value-bearing nor an instruction to the matcher; it rides in the C->D routing EVENT
// (events.go) and is enforced on C at settlement.

// Rail is the cross-chain object's lane discriminator (wire byte 0). It is the
// H1-closing property that makes a D->C object UNAMBIGUOUSLY one rail, so a C-side
// consume path can refuse an object from the other rail before it touches a pot.
type Rail uint8

const (
	// railSwap is the swap-fill / refund lane: SubmitSwapOrder writes it on C->D,
	// the dexvm's fill-settlement export (settleFromFills) writes it on D->C, and
	// ImportSettlement is the ONLY C-side path that consumes it — debiting ONLY
	// seamReserve. It is the ZERO value so an object whose lane is unstated defaults
	// to the swap rail (the dexvm's swap-fill exports omit the field), keeping the
	// non-LP call sites untouched.
	railSwap Rail = 0
	// railLP is the LP position-commit / collect lane: SubmitPositionCommit writes
	// it on C->D, the dexvm's executeWithdraw writes it on D->C, and
	// ImportPositionCollect is the ONLY C-side path that consumes it — debiting ONLY
	// committedPositions. A non-zero tag, so an LP object is never mistaken for the
	// zero-valued swap rail.
	railLP Rail = 1
)

// exportedOutputSize is the fixed shared-memory object width: rail(1) | owner(20) |
// asset(32) | amount(8) | spent(8). IDENTICAL to chains/dexvm/atomic.go
// exportedOutputSize. The trailing spent(8) is the matched-input witness on a swap
// proceeds leg (0 elsewhere); both repos carry it in lockstep.
const exportedOutputSize9999 = 1 + 20 + 32 + 8 + 8

// encodeAtomicObject serializes a cross-chain value object as the shared-memory
// value, byte-identical with the dexvm side: rail(1) | owner(20) | asset(32) |
// amount(8) | spent(8). rail is the lane the value travels (railSwap / railLP);
// owner is the account (EVM address / dexvm ShortID — both 20 bytes); asset is the
// full injective AssetID (assetID(Currency); native = all-zero); amount is the
// integer asset unit count.
//
// The precompile only ever writes C->D ORDER/COMMIT objects, which carry NO matched
// input (the match happens later on D), so spent is ALWAYS 0 here — written as the
// trailing zero word. The D side fills spent on the D->C proceeds leg (settleFromFills);
// the precompile DECODES it in ImportSettlement. Keeping spent=0 on the C->D leg makes
// the C->D object byte-identical with what the dexvm's executeImport expects (its
// decodeExportedOutput requires exactly this width and ignores spent on an import).
func encodeAtomicObject(rail Rail, owner common.Address, asset [32]byte, amount uint64) []byte {
	// A C->D order/commit object carries no matched input, so spent is always 0 here.
	return encodeAtomicObjectSpent(rail, owner, asset, amount, 0)
}

// encodeAtomicObjectSpent is the full encoder including the trailing spent witness. The
// production C->D path uses spent=0 (encodeAtomicObject); the D side (chains
// settleFromFills) sets spent>0 on a D->C PROCEEDS leg. This variant exists so the seam
// surface (and the parity/redteam tests) can construct the EXACT bytes the dexvm exports,
// byte-identical with chains/dexvm/atomic.go encodeExportedOutput.
func encodeAtomicObjectSpent(rail Rail, owner common.Address, asset [32]byte, amount, spent uint64) []byte {
	v := make([]byte, exportedOutputSize9999)
	v[0] = byte(rail)
	copy(v[1:21], owner[:])
	copy(v[21:53], asset[:])
	binary.BigEndian.PutUint64(v[53:61], amount)
	binary.BigEndian.PutUint64(v[61:69], spent)
	return v
}

// --- the OPERATION segment (C->D swap orders only) -----------------------------

// Side is the CLOB side the taker's operation takes. The wire bytes are pinned to
// the matcher's own constants (dex/pkg/zapwire, dex/pkg/dchain sideBuy/sideSell), so
// the byte D reads out of the object is the byte D's order book consumes.
const (
	seamSideBuy  uint8 = 0
	seamSideSell uint8 = 1
)

// seamOpSize is the fixed OPERATION segment width: market(32) | side(1) |
// limitPrice(8) | size(8) = 49 bytes. IDENTICAL to dex/pkg/dchain seamOpSize.
const seamOpSize = 32 + 1 + 8 + 8

// orderObjectSize9999 is the fixed C->D SWAP ORDER object width: the 69-byte value
// head plus the 49-byte operation tail = 118 bytes. IDENTICAL to dex/pkg/dchain
// seamOrderObjectSize. A width that is neither 69 nor 118 is not an object of ours.
const orderObjectSize9999 = exportedOutputSize9999 + seamOpSize

// SeamOp is the CLOB operation a C->D swap order instructs. Every field is a value
// the taker fixed on C when they signed the swap:
//
//   - Market     : the D market (poolId) the order targets.
//   - Side       : seamSideBuy / seamSideSell.
//   - LimitPrice : the worst acceptable price on the PriceInt grid (quote-per-base
//     x 1e8). REQUIRED, non-zero. Every seam order is a LIMIT IOC order:
//     a cross-chain taker cannot re-price mid-flight and their order
//     executes in a block they do not control, so an unbounded market
//     order across the seam is exactly the unbounded-MEV case the spent
//     witness exists to prevent. C refuses a zero limit at submission and
//     D refuses a zero-limit op at import — the same rule, both ends.
//   - Size       : the base-unit quantity to trade.
type SeamOp struct {
	Market     [32]byte
	Side       uint8
	LimitPrice uint64
	Size       uint64
}

// limitIsUpper reports which end of the price range the taker's limit bounds: a BUY's
// limit is a CEILING (reject a realized price above it), a SELL's is a FLOOR. It is a
// pure function of Side, so the bound is never stored alongside the side as a second
// copy of one fact.
func limitIsUpper(side uint8) bool { return side == seamSideBuy }

// encodeSeamOp serializes the operation segment. Fixed width, big-endian, no padding
// — the same discipline as the value head.
func encodeSeamOp(op SeamOp) []byte {
	b := make([]byte, seamOpSize)
	copy(b[0:32], op.Market[:])
	b[32] = op.Side
	binary.BigEndian.PutUint64(b[33:41], op.LimitPrice)
	binary.BigEndian.PutUint64(b[41:49], op.Size)
	return b
}

// decodeSeamOp is the inverse over an EXACTLY seamOpSize-wide tail.
func decodeSeamOp(b []byte) (SeamOp, bool) {
	if len(b) != seamOpSize {
		return SeamOp{}, false
	}
	var op SeamOp
	copy(op.Market[:], b[0:32])
	op.Side = b[32]
	op.LimitPrice = binary.BigEndian.Uint64(b[33:41])
	op.Size = binary.BigEndian.Uint64(b[41:49])
	return op, true
}

// encodeOrderObject serializes a C->D SWAP ORDER: the canonical value head with
// spent=0 (a C->D leg has matched nothing yet), followed by the operation tail. This
// is the ONLY object the swap rail writes C->D, and the ONLY one D's import consumes.
func encodeOrderObject(owner common.Address, asset [32]byte, amount uint64, op SeamOp) []byte {
	v := make([]byte, 0, orderObjectSize9999)
	v = append(v, encodeAtomicObjectSpent(railSwap, owner, asset, amount, 0)...)
	return append(v, encodeSeamOp(op)...)
}

// decodeOrderObject reads back a C->D swap order. ok=false for any width other than
// the canonical 118 — so a 69-byte VALUE object (an old, op-less order, or a
// settlement object misrouted here) is REFUSED rather than imported with an invented
// operation. Fail closed: no operation, no import.
func decodeOrderObject(v []byte) (owner common.Address, asset [32]byte, amount uint64, op SeamOp, ok bool) {
	if len(v) != orderObjectSize9999 {
		return common.Address{}, [32]byte{}, 0, SeamOp{}, false
	}
	rail, owner, asset, amount, _, headOK := decodeObjectHead(v[:exportedOutputSize9999])
	if !headOK || rail != railSwap {
		return common.Address{}, [32]byte{}, 0, SeamOp{}, false
	}
	op, opOK := decodeSeamOp(v[exportedOutputSize9999:])
	if !opOK {
		return common.Address{}, [32]byte{}, 0, SeamOp{}, false
	}
	return owner, asset, amount, op, true
}

// decodeObjectHead reads the 69-byte VALUE head. It is the single definition of the
// head field offsets, shared by the value-object decoder and the order decoder, so
// the two readings of those bytes can never drift apart.
func decodeObjectHead(v []byte) (rail Rail, owner common.Address, asset [32]byte, amount, spent uint64, ok bool) {
	if len(v) != exportedOutputSize9999 {
		return 0, common.Address{}, [32]byte{}, 0, 0, false
	}
	rail = Rail(v[0])
	copy(owner[:], v[1:21])
	copy(asset[:], v[21:53])
	amount = binary.BigEndian.Uint64(v[53:61])
	spent = binary.BigEndian.Uint64(v[61:69])
	return rail, owner, asset, amount, spent, true
}

// decodeAtomicObject is the inverse: it reads back the (rail, owner, asset, amount,
// spent) a consumed cross-chain object RECORDED in shared memory. ok=false for any
// value that is not EXACTLY the canonical width, so a corrupt/garbage record is never
// reinterpreted into a credit — the same defense the dexvm decodeExportedOutput
// applies. The consumer binds the credited rail/owner/asset/amount to THIS recorded
// value, never to what the calling tx merely declares — so the rail (and therefore
// which pot may be debited) is the OBJECT's, not the caller's. spent is meaningful
// ONLY on a D->C swap proceeds leg (the MEV-floor witness ImportSettlement checks);
// the LP-collect and staging consumers ignore it.
func decodeAtomicObject(v []byte) (rail Rail, owner common.Address, asset [32]byte, amount, spent uint64, ok bool) {
	return decodeObjectHead(v)
}

// DeriveOrderID computes the deterministic id of a C->D atomic order object.
// It is the shared-memory UTXO key the object is PUT under (and that D's import
// consumes), and it is INJECTIVE over the full identity so two distinct orders
// never collide:
//
//	SHA-256( domain | networkID | cChainID | dChainID |
//	         account | assetIn | amountIn | marketID | nonce )
//
// Every component is fixed width and length-stable (no concatenation ambiguity).
// (networkID, cChainID, dChainID) scope the object to exactly one rail;
// account/asset/amount/market bind the economic payload; nonce is the taker's
// own disambiguator so two otherwise-identical swaps get distinct ids.
//
// CHAIN-OBSERVABLE BY CONSTRUCTION (the watch-correlation fix). The id derives ONLY
// from values the off-chain client knows BEFORE it signs — there is NO txID here. The
// nonce is carried in the swap's own DI01 hookData, so the precompile (on-chain) and the
// keeper/SDK (off-chain) read the IDENTICAL nonce from the IDENTICAL calldata and derive
// the IDENTICAL id. Previously the off-chain side substituted a ZERO txID (the real txID
// is unknown pre-landing) while the chain used the REAL txID, so the two ids never
// matched and the keeper's watch could not correlate against a live chain. Binding the id
// to a chain-observable nonce (not the post-landing txID) closes that.
//
// REPLAY/INJECTIVITY. Two distinct takers differ by account; the same taker's two
// DIFFERENT swaps differ by asset/amount/market; the same taker's two IDENTICAL swaps
// must use DISTINCT nonces (a reused tuple derives the same id and the second submit is
// replay-rejected by the on-chain isOrderSubmitted guard — idempotent, never a second
// debit). The nonce is the user's order-nonce: it disambiguates repeats AND two swaps in
// one tx (the caller supplies distinct nonces), replacing the former callIndex axis.
func DeriveOrderID(
	networkID uint32,
	cChainID, dChainID ids.ID,
	account common.Address,
	assetIn [32]byte,
	amountIn uint64,
	marketID [32]byte,
	nonce uint64,
) ids.ID {
	h := sha256.New()
	h.Write([]byte(nativeOrderDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], networkID)
	h.Write(u4[:])
	h.Write(cChainID[:])
	h.Write(dChainID[:])
	h.Write(account[:])
	h.Write(assetIn[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], amountIn)
	h.Write(u8[:])
	h.Write(marketID[:])
	binary.BigEndian.PutUint64(u8[:], nonce)
	h.Write(u8[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return ids.ID(out)
}

// nativeOrderDomain scopes the order-id derivation so an id minted for the DEX
// C->D atomic seam can never be confused with any other shared-memory object id.
//
// The literal is the hash input, not a label, so it does not track this identifier:
// changing a byte of it moves every order id the seam has ever derived.
const nativeOrderDomain = "lux.dex.native.intent.v1"

// DerivePositionCommitID computes the deterministic id of a C->D LP POSITION-COMMIT
// atomic object (order kind DL01) — the C->D leg that FUNDS a D position. It is the
// shared-memory UTXO key the commit object is PUT under (and that D's import
// consumes). It is derived with its OWN domain (positionCommitDomain) so a
// position-commit id and a swap-order id (DeriveOrderID, nativeOrderDomain) live
// in DISJOINT id spaces — a swap order object can NEVER be consumed as a position
// commit, nor vice-versa, even with the same (account, asset, amount, market). The
// 69-byte object wire (rail|owner|asset|amount|spent) is IDENTICAL so D imports both
// natively; only the id DOMAIN (and the routing event KIND) distinguish the two rails.
//
//	SHA-256( positionCommitDomain | networkID | cChainID | dChainID | txID |
//	         callIndex | account | assetIn | amountIn | poolID )
//
// Every component is fixed width and length-stable; callIndex disambiguates two
// commits in one tx; (networkID, cChainID, dChainID) scope the object to one rail;
// account/asset/amount/pool bind the economic payload so the id cannot be reused.
//
// DELIBERATE ASYMMETRY vs DeriveOrderID (txID+callIndex here, user NONCE there — do NOT
// "align" them into a consensus break). The SWAP id is chain-observable (derived from the
// taker's DI01 nonce, no txID) because an OFF-CHAIN keeper must re-derive it from calldata
// to correlate its fill watch. The LP commit id has NO such off-chain re-derivation: it is
// only ever READ from shared memory by the dexvm's executeImport (the keeper opens the D
// position from the routing EVENT, which already carries the id), so it does not need to be
// computable from calldata alone. txID+callIndex is therefore the right choice for the LP
// rail — injective, and callIndex (not a user-supplied nonce the LP path doesn't carry)
// disambiguates two commits in one tx. Switching the LP rail to a nonce would add a
// user-managed field the modifyLiquidity ABI doesn't have and change a consensus-shared key
// for no correlation benefit.
func DerivePositionCommitID(
	networkID uint32,
	cChainID, dChainID ids.ID,
	txID ids.ID,
	callIndex uint32,
	account common.Address,
	assetIn [32]byte,
	amountIn uint64,
	poolID [32]byte,
) ids.ID {
	h := sha256.New()
	h.Write([]byte(positionCommitDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], networkID)
	h.Write(u4[:])
	h.Write(cChainID[:])
	h.Write(dChainID[:])
	h.Write(txID[:])
	binary.BigEndian.PutUint32(u4[:], callIndex)
	h.Write(u4[:])
	h.Write(account[:])
	h.Write(assetIn[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], amountIn)
	h.Write(u8[:])
	h.Write(poolID[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return ids.ID(out)
}

// positionCommitDomain scopes the position-commit-id derivation so a DL01 LP commit
// object id can never collide with a DI01 swap-order object id (nativeOrderDomain)
// or any other shared-memory object id. This is the id-space half of the rail
// separation (the routing-event KIND is the other half).
const positionCommitDomain = "lux.dex.native.poscommit.v1"
