// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle_views9999.go ports the residual V4 PoolManager methods donate / extsload /
// extsloadArray onto 0x9999.
//
//   - extsload / extsloadArray are RAW SLOT READS of 0x9999's own storage. They are
//     read-only and harmless: a client (or an off-chain indexer that does not want
//     to model the registry layout) can read any 0x9999 slot directly. They never
//     write and never move value.
//
//   - donate is EXPLICITLY UNSUPPORTED at 0x9999 (it reverts ErrUnsupported). This
//     is the design's sanctioned fallback, NOT a stub: in the receipt-settlement
//     model the C-Chain holds NO V4 LP fee-growth accumulator (LP positions, fee
//     growth, and the donate→feeGrowth distribution all live on the D-Chain CLOB
//     that MATCHES). A C-side donate could only PRETEND to distribute to LPs it
//     does not track — that would be faking a distribution, which we refuse. A
//     genuine donation routes through the D-Chain (which then certifies the
//     resulting fills/positions); there is no safe C-only donate to implement.

var (
	// ErrUnsupported is returned by a 0x9999 selector that is deliberately not
	// implementable in the receipt-settlement model (donate). It is a CLEAN revert
	// that names the boundary, never a silent no-op or a faked success.
	ErrUnsupported = errors.New("dex: 0x9999 donate is unsupported in the receipt-settlement model — donations route through the D-Chain CLOB (LP fee growth is D-authoritative)")
)

// runSettleDonate reverts ErrUnsupported. See file header: there is no C-side LP
// fee-growth ledger to distribute into, so a safe donate cannot exist at 0x9999.
func (s *SettleContract) runSettleDonate(
	_ contract.AccessibleState, _ common.Address, _ []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, ErrUnsupported
	}
	// Charge nothing beyond the base lookup so the explicit-unsupported revert is
	// cheap and unambiguous to callers probing the surface.
	if gas < GasPoolLookup {
		return nil, 0, errors.New("dex: out of gas")
	}
	return nil, gas - GasPoolLookup, ErrUnsupported
}

// runSettleExtsload reads a single raw 0x9999 storage slot: extsload(bytes32 slot)
// -> bytes32. Read-only.
func (s *SettleContract) runSettleExtsload(
	state contract.AccessibleState, input []byte, gas uint64,
) ([]byte, uint64, error) {
	if gas < GasPoolLookup {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasPoolLookup
	if len(input) < 32 {
		return nil, gasLeft, errors.New("dex: extsload needs a bytes32 slot")
	}
	var slot common.Hash
	copy(slot[:], input[:32])
	v := newPoolStateAdapter(state).GetState(poolManagerAddr9999, slot)
	out := make([]byte, 32)
	copy(out, v[:])
	return out, gasLeft, nil
}

// runSettleExtsloadArray reads many raw 0x9999 slots: extsload(bytes32[] slots) ->
// bytes32[]. ABI: offset word, length word, then `length` slot words. Read-only.
// Bounds-checked; a malformed array reverts.
func (s *SettleContract) runSettleExtsloadArray(
	state contract.AccessibleState, input []byte, gas uint64,
) ([]byte, uint64, error) {
	if gas < GasPoolLookup {
		return nil, 0, errors.New("dex: out of gas")
	}
	if len(input) < 64 {
		return nil, gas - GasPoolLookup, errors.New("dex: extsload(bytes32[]) needs offset+length")
	}
	// input[0:32] is the ABI offset (always 0x20 for a single dynamic arg); read the
	// length at that offset to be tolerant of the standard encoding.
	//
	// OVERFLOW-SAFE BOUNDS: do all offset math in uint64 and compare via subtraction
	// (the canonical EVM-safe idiom) — NEVER cast to int before checking. The prior
	// `int(readLowU64(...)) ; off+32 > len(input)` form was a liveness DoS: an offset
	// of 0x7FFFFFFFFFFFFFFF made off+32 overflow signed int to a large NEGATIVE, so
	// the guard read false and input[off:off+32] PANICKED (no recover() on the
	// block-execution path => validator crash). readLowU64 caps the value at 2^64-1,
	// so a high-bit-set offset is rejected here rather than truncated.
	offU := readLowU64(input[0:32])
	inLen := uint64(len(input))
	if offU > inLen || inLen-offU < 32 {
		return nil, gas - GasPoolLookup, errors.New("dex: extsload array offset out of bounds")
	}
	off := int(offU) // provably < inLen (<= MaxInt for any real calldata), safe to index.
	nU := readLowU64(input[off : off+32])
	dataStart := off + 32
	// Bound n by the remaining input BEFORE any multiply, so a huge length cannot
	// overflow int in n*32. maxN = floor((len-dataStart)/32); reject n > maxN.
	maxN := uint64(len(input)-dataStart) / 32
	if nU > maxN {
		return nil, gas - GasPoolLookup, errors.New("dex: extsload array length out of bounds")
	}
	n := int(nU)
	// Gas scales with the number of slots read (each is a real SLOAD-equivalent).
	cost := GasPoolLookup * uint64(n+1)
	if gas < cost {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - cost

	state2 := newPoolStateAdapter(state)
	// ABI-encode the returned bytes32[]: offset(0x20) | length(n) | n words.
	out := make([]byte, 64+n*32)
	out[31] = 0x20 // offset to the array data
	putWordUint64(out[32:64], uint64(n))
	for i := 0; i < n; i++ {
		var slot common.Hash
		copy(slot[:], input[dataStart+i*32:dataStart+i*32+32])
		v := state2.GetState(poolManagerAddr9999, slot)
		copy(out[64+i*32:64+i*32+32], v[:])
	}
	return out, gasLeft, nil
}

// readLowU64 reads the low 8 bytes of a 32-byte big-endian word into a uint64 (the
// high 24 bytes of an ABI length/offset are zero in any valid encoding). A value
// wider than 8 bytes would have non-zero high bytes; we treat the low 8 bytes as
// the count, and the subsequent bounds check rejects any count that overruns input,
// so an oversized length cannot over-read.
func readLowU64(b []byte) uint64 {
	if len(b) < 32 {
		return 0
	}
	var v uint64
	for i := 24; i < 32; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// putWordUint64 writes v into the low 8 bytes of a 32-byte big-endian word.
func putWordUint64(b []byte, v uint64) {
	if len(b) < 32 {
		return
	}
	putU64(b[24:32], v)
}
