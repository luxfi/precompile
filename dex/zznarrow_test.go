// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/precompile/contract"
)

// zznarrow_test.go covers the decode boundary where a 256-bit calldata word
// becomes a field narrower than 256 bits.
//
// The EVM word is 256 bits and PoolKey.Fee / PoolKey.TickSpacing are 24. Between
// those two widths sat two independent substitutions, in series:
//
//	uint24(new(big.Int).SetBytes(input[64:96]).Uint64())
//	     ^ drops bits 32..63                  ^ drops bits 64..255
//
// Neither reports anything. A word of 2^32+6 arrived as 6, and a word of
// 2^24+3000 arrived as 2^24+3000 — faithful in the struct, but EncodePoolKeyABI
// writes three bytes, so it hashed to the pool id of fee 3000 while the field
// carried 16780216: 5593 times the fee the pool was created with.
//
// The refusal is at the decode, not at each use, so every consumer inherits it —
// settle_market's FeeMax check on the dispatched path, and calculateFlashFee /
// getPoolState on the PoolManager lineage that is not dispatched today and does
// spend the calldata value directly.

// zznWord renders v as a 32-byte big-endian ABI slot, two's complement for
// negatives — the encoding a caller actually puts on the wire.
func zznWord(v *big.Int) []byte {
	var b [32]byte
	m := new(big.Int).Mod(v, new(big.Int).Lsh(big.NewInt(1), 256))
	m.FillBytes(b[:])
	return b[:]
}

// zznKey builds the 160-byte PoolKey calldata with fee and tickSpacing set to
// arbitrary 256-bit words, which is what a caller can send regardless of what
// the Go types can hold.
func zznKey(fee, tickSpacing *big.Int) []byte {
	out := make([]byte, 0, 160)
	out = append(out, zznWord(big.NewInt(0))...) // currency0
	out = append(out, zznWord(big.NewInt(1))...) // currency1
	out = append(out, zznWord(fee)...)
	out = append(out, zznWord(tickSpacing)...)
	out = append(out, zznWord(big.NewInt(0))...) // hooks
	return contract.Poisoned(out, 1024)
}

func zznPow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

// TestZznDecodePoolKeyBoundsFeeAtItsDeclaredWidth walks the fee boundary from
// both sides. 2^24-1 is the largest uint24 and must decode; 2^24 is the smallest
// value that cannot and must be refused.
func TestZznDecodePoolKeyBoundsFeeAtItsDeclaredWidth(t *testing.T) {
	max := new(big.Int).Sub(zznPow2(24), big.NewInt(1))
	got, err := DecodePoolKey(zznKey(max, big.NewInt(60)))
	if err != nil {
		t.Fatalf("the largest uint24 fee was refused: %v", err)
	}
	if got.Fee != 1<<24-1 {
		t.Fatalf("Fee = %d, want 2^24-1", got.Fee)
	}

	for _, wide := range []*big.Int{
		zznPow2(24), // one past the width
		new(big.Int).Add(zznPow2(24), big.NewInt(3000)), // the pool-id collision
		zznPow2(32), // one past uint32, where uint24() starts lying
		new(big.Int).Add(zznPow2(32), big.NewInt(3000)),
		zznPow2(64),  // one past uint64, where Uint64 starts lying
		zznPow2(255), // low word zero
		new(big.Int).Sub(zznPow2(256), big.NewInt(1)), // all ones
		new(big.Int).Neg(big.NewInt(1)),               // 2^256-1 on the wire; no unsigned reading
	} {
		if got, err := DecodePoolKey(zznKey(wide, big.NewInt(60))); !errors.Is(err, ErrInvalidFee) {
			t.Fatalf("fee %s admitted as %d: %v", wide, got.Fee, err)
		}
	}
}

// TestZznDecodePoolKeyBoundsTickSpacingAtItsDeclaredWidth does the same for the
// signed field. The span is asymmetric — -2^23 is representable and +2^23 is not
// — and both ends are pinned, because a check written on bit length alone admits
// exactly one of them wrongly.
func TestZznDecodePoolKeyBoundsTickSpacingAtItsDeclaredWidth(t *testing.T) {
	for _, ok := range []int64{0, 1, 60, -1, -60, 1<<23 - 1, -(1 << 23)} {
		got, err := DecodePoolKey(zznKey(big.NewInt(3000), big.NewInt(ok)))
		if err != nil {
			t.Fatalf("tick spacing %d is a valid int24 and was refused: %v", ok, err)
		}
		if int64(got.TickSpacing) != ok {
			t.Fatalf("TickSpacing = %d, want %d", got.TickSpacing, ok)
		}
	}

	for _, wide := range []*big.Int{
		zznPow2(23), // one past the top
		new(big.Int).Neg(new(big.Int).Add(zznPow2(23), big.NewInt(1))), // one past the bottom
		new(big.Int).Add(zznPow2(24), big.NewInt(60)),                  // same pool id, foreign tick grid
		new(big.Int).Add(zznPow2(32), big.NewInt(6)),                   // used to arrive as 6
		new(big.Int).Add(zznPow2(32), big.NewInt(60)),                  // used to arrive as 60
		new(big.Int).Add(zznPow2(64), big.NewInt(60)),
		zznPow2(200),
	} {
		if got, err := DecodePoolKey(zznKey(big.NewInt(3000), wide)); !errors.Is(err, ErrInvalidTickSpacing) {
			t.Fatalf("tick spacing %s admitted as %d: %v", wide, got.TickSpacing, err)
		}
	}
}

// TestZznPoolIDIsInjectiveOverEveryDecodableKey is the property the refusal
// exists to restore, stated directly: over the keys DecodePoolKey can produce,
// EncodePoolKeyABI loses nothing, so PoolKey.ID is injective.
//
// It is a sweep rather than a table because the failing pairs are the ones
// nobody thinks to tabulate — the collision that started this was fee 3000
// against fee 2^24+3000, which no hand-written matrix contains.
func TestZznPoolIDIsInjectiveOverEveryDecodableKey(t *testing.T) {
	rng := rand.New(rand.NewSource(0x9999))
	seen := map[[32]byte][2]int64{}
	decoded := 0

	for i := 0; i < 40_000; i++ {
		// Draw words spanning the whole 256-bit space. Half land inside the
		// declared widths so the injectivity claim has material to test; the rest
		// sit on the boundaries where the substitutions used to live, so the
		// refusal is exercised at the same time.
		draw := func() *big.Int {
			switch rng.Intn(8) {
			case 0, 1, 2:
				return big.NewInt(rng.Int63n(1 << 23)) // in range for both fields
			case 3:
				return new(big.Int).Neg(big.NewInt(rng.Int63n(1 << 23)))
			case 4:
				return new(big.Int).Add(zznPow2(23), big.NewInt(rng.Int63n(64)))
			case 5:
				return new(big.Int).Add(zznPow2(24), big.NewInt(rng.Int63n(64)))
			case 6:
				return new(big.Int).Add(zznPow2(32), big.NewInt(rng.Int63n(64)))
			default:
				return new(big.Int).Rand(rng, zznPow2(256))
			}
		}
		key, err := DecodePoolKey(zznKey(draw(), draw()))
		if err != nil {
			continue
		}
		decoded++

		// Anything the decoder admits must survive its own encoding, or the id
		// is derived from a value the caller did not send.
		back, err := DecodePoolKey(contract.Poisoned(EncodePoolKeyABI(key), 512))
		if err != nil || back != key {
			t.Fatalf("decoded key %+v did not survive re-encoding: (%+v, %v)", key, back, err)
		}

		// Currencies and hooks are fixed by zznKey, so the id is a function of
		// exactly (Fee, TickSpacing) here. Two of those must never share one id.
		id := key.ID()
		pair := [2]int64{int64(key.Fee), int64(key.TickSpacing)}
		if prev, ok := seen[id]; ok && prev != pair {
			t.Fatalf("pool id collision: (fee %d, spacing %d) and (fee %d, spacing %d)",
				prev[0], prev[1], pair[0], pair[1])
		}
		seen[id] = pair
	}

	if decoded < 1000 {
		t.Fatalf("only %d of 40000 draws decoded — the sweep is refusing almost everything "+
			"and would pass against a decoder that refused all input", decoded)
	}
}

// TestZznLifecycleTicksAreBoundedAtTheirWidth covers the second decoder, which
// had the same shape at data[160:192] and data[192:224]: int24(x.Int64()) with no
// bound, so a tick of 2^32+6 opened a position at tick 6.
func TestZznLifecycleTicksAreBoundedAtTheirWidth(t *testing.T) {
	build := func(lower, upper *big.Int) []byte {
		data := make([]byte, 0, 320)
		data = append(data, zznKey(big.NewInt(3000), big.NewInt(60))[:160]...)
		data = append(data, zznWord(lower)...)
		data = append(data, zznWord(upper)...)
		data = append(data, zznWord(big.NewInt(1))...) // delta
		data = append(data, zznWord(big.NewInt(0))...) // salt
		data = append(data, zznWord(big.NewInt(0))...) // side
		return contract.Poisoned(data, 1024)
	}

	// Both int24 extremes decode, and they decode as themselves.
	a, err := decodePMLifecycle(build(big.NewInt(-(1 << 23)), big.NewInt(1<<23-1)))
	if err != nil {
		t.Fatalf("the int24 extremes were refused: %v", err)
	}
	if a.tickLower != -(1<<23) || a.tickUpper != 1<<23-1 {
		t.Fatalf("ticks = (%d, %d), want the int24 extremes", a.tickLower, a.tickUpper)
	}

	for _, wide := range []*big.Int{
		zznPow2(23),
		new(big.Int).Add(zznPow2(24), big.NewInt(6)),
		new(big.Int).Add(zznPow2(32), big.NewInt(6)),
		new(big.Int).Neg(new(big.Int).Add(zznPow2(23), big.NewInt(1))),
		zznPow2(200),
	} {
		if got, err := decodePMLifecycle(build(wide, big.NewInt(60))); !errors.Is(err, ErrInvalidTick) {
			t.Fatalf("tickLower %s admitted as %d: %v", wide, got.tickLower, err)
		}
		if got, err := decodePMLifecycle(build(big.NewInt(-60), wide)); !errors.Is(err, ErrInvalidTick) {
			t.Fatalf("tickUpper %s admitted as %d: %v", wide, got.tickUpper, err)
		}
	}
}

// TestZznEntryDecodersSurfaceThePoolKeyRefusal covers three arms that USED TO BE
// DEAD. Each entry decoder checks its own total length and then hands
// DecodePoolKey a 160-byte prefix, so while DecodePoolKey refused only on length
// its error could not fire — the caller had already guaranteed the bytes were
// there. Bounding the fields made all three live, and an arm that is live and
// untested is the arm that returns a zero PoolKey to a caller reading err.
func TestZznEntryDecodersSurfaceThePoolKeyRefusal(t *testing.T) {
	wideFee := new(big.Int).Add(zznPow2(24), big.NewInt(3000))
	pad := func(prefix []byte, n int) []byte {
		out := make([]byte, n)
		copy(out, prefix)
		return contract.Poisoned(out, 1024)
	}
	good := zznKey(big.NewInt(3000), big.NewInt(60))[:160]
	bad := zznKey(wideFee, big.NewInt(60))[:160]

	if _, _, _, err := DecodeSwapInput(pad(bad, 256)); !errors.Is(err, ErrInvalidFee) {
		t.Fatalf("DecodeSwapInput admitted a wide fee: %v", err)
	}
	if _, _, _, err := DecodeModifyLiquidityInput(pad(bad, 288)); !errors.Is(err, ErrInvalidFee) {
		t.Fatalf("DecodeModifyLiquidityInput admitted a wide fee: %v", err)
	}
	if _, err := decodePMLifecycle(pad(bad, 320)); !errors.Is(err, ErrInvalidFee) {
		t.Fatalf("decodePMLifecycle admitted a wide fee: %v", err)
	}

	// The same three, with an in-range key, must get past the decode — otherwise
	// the assertions above would hold against a decoder that refused everything.
	if _, _, _, err := DecodeSwapInput(pad(good, 256)); err != nil {
		t.Fatalf("DecodeSwapInput refused a valid key: %v", err)
	}
	if _, _, _, err := DecodeModifyLiquidityInput(pad(good, 288)); err != nil {
		t.Fatalf("DecodeModifyLiquidityInput refused a valid key: %v", err)
	}
	if _, err := decodePMLifecycle(pad(good, 320)); err != nil {
		t.Fatalf("decodePMLifecycle refused a valid key: %v", err)
	}
}

// The refusal must not depend on how the fixture was built. A precompile's input
// carries attacker-chosen spare capacity, so a decoder that reads past its
// declared length reads those bytes rather than panicking. Every fixture above is
// poisoned; this asserts the poison is actually visible, so those fixtures are
// testing the bound rather than the allocator.
func TestZznPoisonedInputIsNotZeroFilled(t *testing.T) {
	b := contract.Poisoned(make([]byte, 160), 64)
	if len(b) != 160 {
		t.Fatalf("len = %d, want 160", len(b))
	}
	if cap(b) < 224 {
		t.Fatalf("cap = %d, want at least 224 — the fixture carries no spare capacity "+
			"and an over-read would panic instead of succeeding", cap(b))
	}
	if spare := b[:cap(b)][160:]; spare[0] != 0xA5 {
		t.Fatalf("spare capacity begins %#x, want 0xA5", spare[0])
	}
	// 159 bytes plus poison must refuse, not complete itself from the spare.
	if _, err := DecodePoolKey(contract.Poisoned(make([]byte, 159), 512)); err == nil {
		t.Fatal("a 159-byte PoolKey decoded from spare capacity")
	}
}
