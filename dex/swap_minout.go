// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
)

// swap_minout.go carries the V4 slippage FLOOR (min-out) for the SYNCHRONOUS 0x9999
// smart-order-router. The V4 swap ABI is UNCHANGED — `swap(PoolKey, SwapParams, bytes
// hookData)` already passes `bytes hookData`; an exact-input swap's min-amount-out is
// not in the SwapParams tuple, so (exactly as the async intent/settlement phases do) it
// rides in hookData behind a small tag. This is the source the H3 fix wires into
// req.MinOut so dexcore's enforceProceedsPriceFloor / the MinOut floor BITES on the sync
// SELL path.
//
// WHY A FLOOR IS REQUIRED ON THIS SURFACE. The 0x9999 sync swap is a PUBLIC, adversarial,
// real-money entrypoint. An exact-input MARKET order (no price limit) sweeps the resting
// book at whatever price exists — so a sandwich attacker who brackets the taker's tx
// extracts the spread. The async BUY path is already guarded (dexcore ErrBuyRequiresLimit
// refuses an unbounded-slippage market BUY). The symmetric SELL hazard is closed HERE:
// on the value path a market SELL (no price limit) MUST declare a min-out, so the taker's
// realized proceeds are floored. A SELL that carries a price LIMIT is already protected
// (the limit floors the price); a SELL with NEITHER a limit nor a min-out is refused
// (ErrSellRequiresProtection) — the precompile-side mirror of the BUY guard, scoped to
// the hostile cEVM surface so the internal dchain matcher path (shared dexcore) is
// unaffected.
//
// The min-out tag (DM01) is "untagged" for ROUTING purposes (isUntaggedSwap only routes
// DI01/DS01 to the async cross-chain handler), so a DM01 swap reaches the synchronous
// router, which then reads the floor from it. A DM01 body of the wrong width, or a value
// that does not fit uint64, is malformed and reverts (a swap that carries garbage where a
// min-out should be never silently drops the taker's floor).

// minOutPhaseTag marks a sync-swap hookData as carrying a min-out floor. It is distinct
// from the async DI01/DS01 tags and from the maker M999 tag, so the four hookData kinds
// never collide. ("DEX Min-out 01".)
var minOutPhaseTag = [4]byte{'D', 'M', '0', '1'}

// minOutBodyLen is the fixed DM01 body width: minOut(32) as a uint256 (must fit uint64).
const minOutBodyLen = 32

var (
	// ErrMinOutMalformed is returned when a DM01 hookData body is not exactly the fixed
	// width or carries a value that does not fit uint64.
	ErrMinOutMalformed = errors.New("dex: min-out hookData body is malformed")
	// ErrSellRequiresProtection is returned on the value path when an exact-input market
	// SELL (no price limit) carries NO min-out floor — an unbounded-slippage market SELL
	// on the public 0x9999 surface is refused (the SELL-side mirror of ErrBuyRequiresLimit).
	ErrSellRequiresProtection = errors.New("dex: exact-input market SELL on the 0x9999 value path requires a price limit or a min-out floor (unbounded-slippage market sell refused)")

	// ErrExactOutputNotSupported is returned when a swap on the synchronous value router
	// carries a POSITIVE AmountSpecified (V4 exact-output). The sync router is exact-input
	// only — its protection is the MinOut floor on the realized output — so an exact-output
	// swap (maxAmountIn semantics) is refused rather than mis-routed as exact-input with no
	// floor. (Exact-output is a P4/async concern; the sync path never routes it unprotected.)
	ErrExactOutputNotSupported = errors.New("dex: the synchronous 0x9999 router is exact-input only; an exact-output swap (positive amountSpecified) is not supported on this path")
)

// decodeMinOut extracts the taker's min-out floor from a sync-swap hookData. It returns
// (0, false, nil) for any hookData that does not carry the DM01 tag (a plain swap with no
// declared floor — the floor then comes from the price limit, or the SELL policy guard
// refuses an unprotected market SELL). A DM01 tag with a well-formed body returns
// (minOut, true, nil); a malformed DM01 body returns an error so the swap reverts rather
// than silently dropping the floor.
func decodeMinOut(hookData []byte) (minOut uint64, present bool, err error) {
	if len(hookData) < 4 || !bytes.Equal(hookData[:4], minOutPhaseTag[:]) {
		return 0, false, nil
	}
	body := hookData[4:]
	if len(body) != minOutBodyLen {
		return 0, false, ErrMinOutMalformed
	}
	v := new(big.Int).SetBytes(body[0:32])
	if !v.IsUint64() {
		return 0, false, ErrMinOutMalformed
	}
	return v.Uint64(), true, nil
}

// EncodeMinOutHookData builds a DM01 sync-swap hookData carrying the taker's min-out
// floor: the tag + minOut[32]. It is the inverse of decodeMinOut, used by the on-chain
// router clients and by tests so the off-chain and on-chain encoders produce
// byte-identical calldata for the same floor.
func EncodeMinOutHookData(minOut uint64) []byte {
	out := make([]byte, 0, 4+minOutBodyLen)
	out = append(out, minOutPhaseTag[:]...)
	var m [32]byte
	binary.BigEndian.PutUint64(m[24:32], minOut)
	out = append(out, m[:]...)
	return out
}
