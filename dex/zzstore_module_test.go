// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// zzstore_module_test.go covers module.go — the shared decode surface every 0x9999
// selector calls before it touches money, plus the state adapter the handlers run
// over.
//
// The load-bearing property is that PoolKey.ID() is INJECTIVE over the keys the
// chain can hold: two markets that differ in any field must land on two pool ids,
// because a shared id is two markets sharing one pool's state. ID() is derived
// from EncodePoolKeyABI, so this file tests the encoder field by field and byte by
// byte, and then tests the decoder's refusal of everything shorter than a key.

// =========================================================================
// 1. PoolKey — round trip, injectivity, refusal
// =========================================================================

// zzstPoolKeys is the matrix a pool key has to survive: zero and maximal
// addresses, the fee bounds, and BOTH signs of tick spacing including the int24
// extremes where the sign extension lives.
func zzstPoolKeys() []PoolKey {
	addr := func(b byte) common.Address {
		var a common.Address
		for i := range a {
			a[i] = b
		}
		return a
	}
	var keys []PoolKey
	for _, c0 := range []common.Address{{}, addr(0x01), addr(0xff)} {
		for _, c1 := range []common.Address{{}, addr(0x02), addr(0xfe)} {
			for _, fee := range []uint24{0, 1, 500, 3000, FeeMax, 1<<24 - 1} {
				for _, ts := range []int24{0, 1, 60, -1, -60, 1<<23 - 1, -(1 << 23), 1<<24 - 1, -(1 << 24)} {
					for _, hooks := range []common.Address{{}, addr(0x03)} {
						keys = append(keys, PoolKey{
							Currency0:   Currency{Address: c0},
							Currency1:   Currency{Address: c1},
							Fee:         fee,
							TickSpacing: ts,
							Hooks:       hooks,
						})
					}
				}
			}
		}
	}
	return keys
}

func TestZzstPoolKeyABIRoundTripIsExact(t *testing.T) {
	for _, want := range zzstPoolKeys() {
		enc := EncodePoolKeyABI(want)
		if len(enc) != 160 {
			t.Fatalf("EncodePoolKeyABI produced %d bytes, want 160", len(enc))
		}
		got, err := DecodePoolKey(enc)
		if err != nil {
			t.Fatalf("DecodePoolKey(%+v): %v", want, err)
		}
		if got.Currency0.Address != want.Currency0.Address {
			t.Fatalf("Currency0 = %s, want %s", got.Currency0.Address.Hex(), want.Currency0.Address.Hex())
		}
		if got.Currency1.Address != want.Currency1.Address {
			t.Fatalf("Currency1 = %s, want %s", got.Currency1.Address.Hex(), want.Currency1.Address.Hex())
		}
		if got.Fee != want.Fee {
			t.Fatalf("Fee = %d, want %d", got.Fee, want.Fee)
		}
		if got.TickSpacing != want.TickSpacing {
			t.Fatalf("TickSpacing = %d, want %d (sign extension)", got.TickSpacing, want.TickSpacing)
		}
		if got.Hooks != want.Hooks {
			t.Fatalf("Hooks = %s, want %s", got.Hooks.Hex(), want.Hooks.Hex())
		}
		// Encoding is a function of the value alone, so it repeats byte for byte.
		for i := 0; i < 8; i++ {
			if !bytes.Equal(EncodePoolKeyABI(want), enc) {
				t.Fatalf("EncodePoolKeyABI is not deterministic for %+v", want)
			}
		}
		// Trailing calldata past the 5 slots is ignored, not misread.
		long := append(append([]byte(nil), enc...), bytes.Repeat([]byte{0xAA}, 96)...)
		got2, err := DecodePoolKey(long)
		if err != nil || got2 != got {
			t.Fatalf("trailing bytes changed the decode: (%+v, %v)", got2, err)
		}
	}
}

// The ABI slot layout, asserted directly. A field that moves slot silently reads
// another field's bytes, and every caller downstream inherits the swap.
func TestZzstPoolKeyABISlotLayout(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Currency1:   Currency{Address: common.HexToAddress("0x2222222222222222222222222222222222222222")},
		Fee:         0xABCDEF,
		TickSpacing: 0x123456,
		Hooks:       common.HexToAddress("0x3333333333333333333333333333333333333333"),
	}
	d := EncodePoolKeyABI(key)

	if !bytes.Equal(d[0:12], make([]byte, 12)) || !bytes.Equal(d[12:32], key.Currency0.Address.Bytes()) {
		t.Fatalf("slot 0 is not a left-padded currency0: %x", d[0:32])
	}
	if !bytes.Equal(d[32:44], make([]byte, 12)) || !bytes.Equal(d[44:64], key.Currency1.Address.Bytes()) {
		t.Fatalf("slot 1 is not a left-padded currency1: %x", d[32:64])
	}
	if !bytes.Equal(d[64:93], make([]byte, 29)) || !bytes.Equal(d[93:96], []byte{0xAB, 0xCD, 0xEF}) {
		t.Fatalf("slot 2 is not a right-aligned uint24 fee: %x", d[64:96])
	}
	if !bytes.Equal(d[96:125], make([]byte, 29)) || !bytes.Equal(d[125:128], []byte{0x12, 0x34, 0x56}) {
		t.Fatalf("slot 3 is not a right-aligned int24 tick spacing: %x", d[96:128])
	}
	if !bytes.Equal(d[128:140], make([]byte, 12)) || !bytes.Equal(d[140:160], key.Hooks.Bytes()) {
		t.Fatalf("slot 4 is not a left-padded hooks address: %x", d[128:160])
	}

	// A negative tick spacing sign-extends across the whole word, so an int256
	// reader sees the right number.
	key.TickSpacing = -2
	d = EncodePoolKeyABI(key)
	for i := 96; i < 125; i++ {
		if d[i] != 0xff {
			t.Fatalf("negative tick spacing is not sign-extended at byte %d: %x", i, d[96:128])
		}
	}
	if !bytes.Equal(d[125:128], []byte{0xff, 0xff, 0xfe}) {
		t.Fatalf("negative tick spacing low bytes = %x, want fffffe", d[125:128])
	}
}

// Two markets that differ ANYWHERE must get two pool ids. Tested per field, and
// per BYTE inside each field, so a derivation that drops part of a field is
// caught rather than averaged away.
func TestZzstPoolKeyIDDependsOnEveryField(t *testing.T) {
	base := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000A1")},
		Currency1:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000B2")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.HexToAddress("0x00000000000000000000000000000000000000C3"),
	}
	baseID := base.ID()

	seen := map[[32]byte]string{baseID: "base"}
	note := func(name string, k PoolKey) {
		id := k.ID()
		if id == baseID {
			t.Fatalf("changing %s did NOT change the pool id — %s is not part of the derivation, "+
				"so two different markets share one pool's state", name, name)
		}
		if prev, dup := seen[id]; dup {
			t.Fatalf("POOL ID COLLISION between %q and %q", name, prev)
		}
		seen[id] = name
	}

	// Every byte of every address, one at a time.
	for i := 0; i < common.AddressLength; i++ {
		k := base
		k.Currency0.Address[i] ^= 0xff
		note("currency0 byte "+string(rune('0'+i%10)), k)

		k = base
		k.Currency1.Address[i] ^= 0xff
		note("currency1 byte "+string(rune('0'+i%10)), k)

		k = base
		k.Hooks[i] ^= 0xff
		note("hooks byte "+string(rune('0'+i%10)), k)
	}

	// Every bit of the fee that the 24-bit field can hold.
	for b := 0; b < 24; b++ {
		k := base
		k.Fee = base.Fee ^ (1 << b)
		note("fee bit "+string(rune('0'+b%10)), k)
	}
	// Every bit of the tick spacing the int24 field can hold, both signs.
	for b := 0; b < 24; b++ {
		k := base
		k.TickSpacing = base.TickSpacing ^ (1 << b)
		if k.TickSpacing >= 1<<23 {
			k.TickSpacing -= 1 << 24 // stay inside the int24 domain
		}
		if k.TickSpacing == base.TickSpacing {
			continue
		}
		note("tickSpacing bit "+string(rune('0'+b%10)), k)
	}

	// And a broad sweep: every key in the matrix is distinct from every other.
	ids := map[[32]byte]PoolKey{}
	for _, k := range zzstPoolKeys() {
		if prev, dup := ids[k.ID()]; dup && prev != k {
			// Fee and tick spacing above 24 bits are a KNOWN collision — see
			// TestZzstPoolKeyIDIgnoresBitsAbove24DEFECT. Everything else must be distinct.
			if prev.Fee&0xFFFFFF == k.Fee&0xFFFFFF &&
				prev.TickSpacing&0xFFFFFF == k.TickSpacing&0xFFFFFF &&
				prev.Currency0 == k.Currency0 && prev.Currency1 == k.Currency1 && prev.Hooks == k.Hooks {
				continue
			}
			t.Fatalf("POOL ID COLLISION between %+v and %+v", prev, k)
		}
		ids[k.ID()] = k
	}
}

// A pool id must be a pure function of the key: same key, same id, forever.
func TestZzstPoolKeyIDIsStable(t *testing.T) {
	for _, k := range zzstPoolKeys() {
		want := k.ID()
		for i := 0; i < 8; i++ {
			if k.ID() != want {
				t.Fatalf("PoolKey.ID() is not stable for %+v", k)
			}
		}
	}
	// Known answers, written out rather than recomputed, so a change to the
	// derivation (a reordered field, a dropped field, a different hash) cannot slip
	// through as "all the relative tests still pass". Both signs of tick spacing are
	// pinned because the sign extension is its own branch.
	k := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
	}
	if got := k.ID(); got != zzstKnownPoolID {
		t.Fatalf("the pool id derivation changed: got %x, want %x", got, zzstKnownPoolID)
	}
	k.TickSpacing = -60
	if got := k.ID(); got != zzstKnownNegPoolID {
		t.Fatalf("the pool id derivation for a negative tick spacing changed: got %x, want %x",
			got, zzstKnownNegPoolID)
	}
}

// zzstKnownPoolID and zzstKnownNegPoolID are keccak256(EncodePoolKeyABI) of the
// (0x01, 0x02, fee 3000, spacing ±60, no hooks) market. Fixtures, not constants of
// the protocol — but they must not move by accident.
var (
	zzstKnownPoolID = [32]byte{
		0xf6, 0xa1, 0x17, 0x50, 0x1d, 0x7c, 0x06, 0xf9, 0x88, 0xe5, 0xcb, 0x96, 0x44, 0x1d, 0xff, 0x2b,
		0x3b, 0xc2, 0x0b, 0xc7, 0xc5, 0x2b, 0xc9, 0x43, 0xe6, 0x6d, 0xa6, 0xe6, 0x3b, 0x93, 0xc9, 0x7c,
	}
	zzstKnownNegPoolID = [32]byte{
		0x4a, 0x3c, 0x0d, 0x30, 0xdc, 0xb6, 0x22, 0xed, 0x30, 0x8c, 0xa7, 0xef, 0x05, 0x27, 0x06, 0x69,
		0x87, 0x6d, 0x8b, 0x2b, 0x08, 0xc9, 0xe2, 0xfe, 0xd9, 0xf1, 0x1d, 0x1d, 0xa3, 0xcb, 0xd0, 0x36,
	}
)

// DEFECT characterisation. EncodePoolKeyABI writes fee and tick spacing as THREE
// bytes (module.go:621 and :630) but the fields are 32 bits wide and DecodePoolKey
// (module.go:344 and :350) applies no bound, so anything above bit 23 is dropped
// on the way into the hash. Two PoolKey values that differ only above bit 23 get
// the SAME pool id.
//
// Initialize refuses fee > FeeMax and tick spacing outside [1, MaxTickSpacing], so
// no such market can be created today — the exposure is that DecodePoolKey hands
// callers a PoolKey whose Fee/TickSpacing are not the ones the id was derived from.
// The bound belongs on the decoder. Until then, this pins the boundary exactly.
func TestZzstPoolKeyIDIgnoresBitsAbove24DEFECT(t *testing.T) {
	base := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x01")},
		Currency1:   Currency{Address: common.HexToAddress("0x02")},
		Fee:         3000,
		TickSpacing: 60,
	}

	// Inside 24 bits, every value is faithful.
	inRange := base
	inRange.Fee = 1<<24 - 1
	if got, err := DecodePoolKey(EncodePoolKeyABI(inRange)); err != nil || got.Fee != inRange.Fee {
		t.Fatalf("fee %d did not round-trip: (%d, %v)", inRange.Fee, got.Fee, err)
	}
	inRange = base
	inRange.TickSpacing = -(1 << 24)
	if got, err := DecodePoolKey(EncodePoolKeyABI(inRange)); err != nil || got.TickSpacing != inRange.TickSpacing {
		t.Fatalf("tick spacing %d did not round-trip: (%d, %v)", inRange.TickSpacing, got.TickSpacing, err)
	}

	// Above it, the id collides.
	wideFee := base
	wideFee.Fee = base.Fee + 1<<24
	if wideFee.ID() != base.ID() {
		t.Fatalf("module.go:621 now carries fee bits above 23 into the pool id — the bound was "+
			"added; update this characterisation test (fee %d vs %d)", wideFee.Fee, base.Fee)
	}
	wideTick := base
	wideTick.TickSpacing = base.TickSpacing + 1<<24
	if wideTick.ID() != base.ID() {
		t.Fatalf("module.go:630 now carries tick-spacing bits above 23 into the pool id — the " +
			"bound was added; update this characterisation test")
	}

	// And the decoder accepts calldata carrying those bits rather than refusing it.
	wide := make([]byte, 160)
	copy(wide, EncodePoolKeyABI(base))
	wide[92] = 0x01 // fee bit 24
	got, err := DecodePoolKey(wide)
	if err != nil {
		t.Fatalf("module.go:344 now bounds the fee — update this characterisation test")
	}
	if got.Fee != base.Fee+1<<24 {
		t.Fatalf("fee decoded as %d, want %d", got.Fee, base.Fee+1<<24)
	}
	if got.ID() != base.ID() {
		t.Fatalf("the wide-fee key no longer shares the base pool id — the defect is fixed; " +
			"update this characterisation test")
	}
}

func TestZzstDecodePoolKeyRefusesEveryTruncation(t *testing.T) {
	full := EncodePoolKeyABI(PoolKey{Fee: 3000, TickSpacing: 60})
	for n := 0; n < 160; n++ {
		got, err := DecodePoolKey(full[:n])
		if err == nil {
			t.Fatalf("DecodePoolKey accepted %d bytes (needs 160)", n)
		}
		if got != (PoolKey{}) {
			t.Fatalf("DecodePoolKey returned a partially-populated key for %d bytes: %+v", n, got)
		}
	}
	if _, err := DecodePoolKey(nil); err == nil {
		t.Fatalf("DecodePoolKey(nil) succeeded")
	}
	if _, err := DecodePoolKey(full); err != nil {
		t.Fatalf("DecodePoolKey(160 bytes): %v", err)
	}
}

// =========================================================================
// 2. Swap and modifyLiquidity calldata
// =========================================================================

func TestZzstDecodeSwapInputRoundTripAndRefusal(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0xA1")},
		Currency1:   Currency{Address: common.HexToAddress("0xB2")},
		Fee:         500,
		TickSpacing: -10,
	}
	for _, tc := range []struct {
		name   string
		params SwapParams
		hook   []byte
	}{
		{"exact input (negative)", SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-1_000_000), SqrtPriceLimitX96: big.NewInt(4295128740)}, nil},
		{"exact output (positive)", SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(1_000_000), SqrtPriceLimitX96: big.NewInt(1 << 60)}, []byte("hook")},
		{"zero amount", SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(0), SqrtPriceLimitX96: big.NewInt(1)}, nil},
		{"min int128 amount", SwapParams{ZeroForOne: true, AmountSpecified: minInt128, SqrtPriceLimitX96: big.NewInt(1)}, bytes.Repeat([]byte{0xEE}, 64)},
		{"max int128 amount", SwapParams{ZeroForOne: false, AmountSpecified: maxInt128, SqrtPriceLimitX96: big.NewInt(1)}, []byte{0x01}},
	} {
		args := buildSwapCalldata(key, tc.params, tc.hook)
		gotKey, gotParams, gotHook, err := DecodeSwapInput(args)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if gotKey != key {
			t.Fatalf("%s: pool key moved: %+v", tc.name, gotKey)
		}
		if gotParams.ZeroForOne != tc.params.ZeroForOne {
			t.Fatalf("%s: zeroForOne = %v", tc.name, gotParams.ZeroForOne)
		}
		if gotParams.AmountSpecified.Cmp(tc.params.AmountSpecified) != 0 {
			t.Fatalf("%s: amountSpecified = %s, want %s", tc.name, gotParams.AmountSpecified, tc.params.AmountSpecified)
		}
		if gotParams.SqrtPriceLimitX96.Cmp(tc.params.SqrtPriceLimitX96) != 0 {
			t.Fatalf("%s: sqrtPriceLimit = %s, want %s", tc.name, gotParams.SqrtPriceLimitX96, tc.params.SqrtPriceLimitX96)
		}
		if len(tc.hook) == 0 {
			if len(gotHook) != 0 {
				t.Fatalf("%s: hookData = %x, want empty", tc.name, gotHook)
			}
		} else if !bytes.Equal(gotHook, tc.hook) {
			t.Fatalf("%s: hookData = %x, want %x", tc.name, gotHook, tc.hook)
		}

		// Every truncation is refused; none returns a half-built SwapParams.
		for n := 0; n < 256; n++ {
			k, p, h, err := DecodeSwapInput(args[:n])
			if err == nil {
				t.Fatalf("%s: DecodeSwapInput accepted %d bytes (needs 256)", tc.name, n)
			}
			if k != (PoolKey{}) || p.AmountSpecified != nil || p.SqrtPriceLimitX96 != nil || h != nil {
				t.Fatalf("%s: DecodeSwapInput(%d bytes) returned partial data", tc.name, n)
			}
		}
		// Prefixes at or past the header decode a key and params without panicking;
		// a truncated hookData tail simply yields no hook data.
		for n := 256; n < len(args); n++ {
			if _, _, _, err := DecodeSwapInput(args[:n]); err != nil {
				t.Fatalf("%s: DecodeSwapInput(%d bytes) errored: %v", tc.name, n, err)
			}
		}
	}
}

// zzstBuildModifyLiquidityInput lays out the modifyLiquidity args the decoder
// expects: pool key, tickLower, tickUpper, liquidityDelta, salt, hookData.
func zzstBuildModifyLiquidityInput(key PoolKey, p ModifyLiquidityParams, hook []byte) []byte {
	args := make([]byte, 320)
	copy(args[0:160], EncodePoolKeyABI(key))
	zzstPutSigned256(args[160:192], big.NewInt(int64(p.TickLower)))
	zzstPutSigned256(args[192:224], big.NewInt(int64(p.TickUpper)))
	zzstPutSigned256(args[224:256], p.LiquidityDelta)
	copy(args[256:288], p.Salt[:])
	binary.BigEndian.PutUint64(args[312:320], 320) // hookData offset
	lenWord := make([]byte, 32)
	binary.BigEndian.PutUint64(lenWord[24:32], uint64(len(hook)))
	padded := make([]byte, (len(hook)+31)/32*32)
	copy(padded, hook)
	return append(append(args, lenWord...), padded...)
}

// zzstPutSigned256 writes v into a 32-byte two's-complement word.
func zzstPutSigned256(dst []byte, v *big.Int) {
	if v == nil {
		return
	}
	if v.Sign() < 0 {
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), v).FillBytes(dst)
		return
	}
	v.FillBytes(dst)
}

func TestZzstDecodeModifyLiquidityRoundTripAndRefusal(t *testing.T) {
	key := PoolKey{Fee: 3000, TickSpacing: 60}
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	for _, p := range []ModifyLiquidityParams{
		{TickLower: -887272, TickUpper: 887272, LiquidityDelta: big.NewInt(1_000_000), Salt: salt},
		{TickLower: 0, TickUpper: 0, LiquidityDelta: big.NewInt(0)},
		{TickLower: -1, TickUpper: 1, LiquidityDelta: big.NewInt(-1)},
		{TickLower: -60, TickUpper: 60, LiquidityDelta: new(big.Int).Neg(maxInt128), Salt: salt},
	} {
		args := zzstBuildModifyLiquidityInput(key, p, []byte("hd"))
		gotKey, got, hook, err := DecodeModifyLiquidityInput(args)
		if err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
		if gotKey != key {
			t.Fatalf("%+v: pool key moved", p)
		}
		if got.TickLower != p.TickLower || got.TickUpper != p.TickUpper {
			t.Fatalf("ticks = (%d, %d), want (%d, %d)", got.TickLower, got.TickUpper, p.TickLower, p.TickUpper)
		}
		if got.LiquidityDelta.Cmp(p.LiquidityDelta) != 0 {
			t.Fatalf("liquidityDelta = %s, want %s", got.LiquidityDelta, p.LiquidityDelta)
		}
		if got.Salt != p.Salt {
			t.Fatalf("salt = %x, want %x", got.Salt, p.Salt)
		}
		if !bytes.Equal(hook, []byte("hd")) {
			t.Fatalf("hookData = %x", hook)
		}

		for n := 0; n < 288; n++ {
			k, gp, h, err := DecodeModifyLiquidityInput(args[:n])
			if err == nil {
				t.Fatalf("DecodeModifyLiquidityInput accepted %d bytes (needs 288)", n)
			}
			if k != (PoolKey{}) || gp.LiquidityDelta != nil || h != nil {
				t.Fatalf("DecodeModifyLiquidityInput(%d bytes) returned partial data", n)
			}
		}
		for n := 288; n < len(args); n++ {
			if _, _, _, err := DecodeModifyLiquidityInput(args[:n]); err != nil {
				t.Fatalf("DecodeModifyLiquidityInput(%d bytes) errored: %v", n, err)
			}
		}
	}
}

// =========================================================================
// 3. decodeABIBytes — the dynamic-bytes reader every hookData rides on
// =========================================================================

func TestZzstDecodeABIBytesRefusesMalformedOffsets(t *testing.T) {
	// A well-formed buffer: offset word at 0 pointing at 32, then length 3, then data.
	good := make([]byte, 32+32+32)
	binary.BigEndian.PutUint64(good[24:32], 32)
	binary.BigEndian.PutUint64(good[56:64], 3)
	copy(good[64:], []byte{0xAA, 0xBB, 0xCC})
	if got := decodeABIBytes(good, 0); !bytes.Equal(got, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("well-formed decode = %x", got)
	}

	word := func(v uint64) []byte {
		b := make([]byte, 32)
		binary.BigEndian.PutUint64(b[24:32], v)
		return b
	}
	huge := bytes.Repeat([]byte{0xff}, 32)

	for name, tc := range map[string]struct {
		args      []byte
		offsetPos uint64
	}{
		"offset word runs off the end":  {make([]byte, 16), 0},
		"offset word starts past":       {good, 1024},
		"offset exceeds int64":          {append(huge, make([]byte, 64)...), 0},
		"offset points back at itself":  {append(word(0), make([]byte, 64)...), 0},
		"offset points inside its word": {append(word(31), make([]byte, 64)...), 0},
		"offset past the buffer":        {append(word(4096), make([]byte, 64)...), 0},
		"no room for a length word":     {append(word(32), make([]byte, 16)...), 0},
		"length exceeds int64":          {append(append(word(32), huge...), make([]byte, 32)...), 0},
		"zero length":                   {append(append(word(32), word(0)...), make([]byte, 32)...), 0},
		"length past the buffer":        {append(append(word(32), word(4096)...), make([]byte, 32)...), 0},
		"length one byte too long":      {append(append(word(32), word(33)...), make([]byte, 32)...), 0},
	} {
		if got := decodeABIBytes(tc.args, tc.offsetPos); got != nil {
			t.Fatalf("%s: decodeABIBytes returned %x, want nil", name, got)
		}
	}

	// Exactly-fitting data is accepted (the boundary the "one byte too long" case
	// sits next to).
	exact := append(append(word(32), word(32)...), bytes.Repeat([]byte{0x5A}, 32)...)
	if got := decodeABIBytes(exact, 0); len(got) != 32 {
		t.Fatalf("exactly-fitting data decoded as %d bytes", len(got))
	}

	// The three cases below are built with make() at their exact size, NOT with
	// append: a slice carrying spare capacity can be re-sliced PAST its length
	// without panicking, so a buffer built by append lets a missing bound read into
	// the spare bytes and look harmless. Sized exactly, the bound is load-bearing.

	// An offset whose value overflows uint64 must be refused on its WIDTH. It
	// truncates to a perfectly usable 1000, so a decoder that skips the width check
	// follows a bogus pointer to real bytes and hands them back as hook data.
	wide := make([]byte, 1064)
	wide[23] = 0x01                                // bit 64 of the offset word
	binary.BigEndian.PutUint64(wide[24:32], 1000)  // ...over a usable low half
	binary.BigEndian.PutUint64(wide[1024:1032], 8) // a length word at 1000
	copy(wide[1032:1040], []byte("12345678"))
	if got := decodeABIBytes(wide, 0); got != nil {
		t.Fatalf("an offset wider than uint64 was accepted, reading %q", got)
	}

	// An offset that points BACKWARDS, at or before its own word, is refused —
	// otherwise the length word can be made to overlap the arguments themselves and
	// an argument becomes its own length prefix.
	back := make([]byte, 96)
	binary.BigEndian.PutUint64(back[24:32], 3) // a length word sitting at 0
	// the offset word at 32 is left zero, i.e. it points back at 0
	if got := decodeABIBytes(back, 32); got != nil {
		t.Fatalf("a backwards offset was accepted, reading %x", got)
	}

	// An offset inside the buffer but with fewer than 32 bytes behind it has no
	// room for a length word. Without that bound the read runs past the end.
	tight := make([]byte, 48)
	binary.BigEndian.PutUint64(tight[24:32], 32)
	if got := decodeABIBytes(tight, 0); got != nil {
		t.Fatalf("an offset with no room for a length word was accepted, reading %x", got)
	}

	// Feeding every prefix of a well-formed buffer must never panic and must never
	// invent data beyond the buffer.
	for n := 0; n <= len(good); n++ {
		got := decodeABIBytes(good[:n], 0)
		if len(got) > n {
			t.Fatalf("decodeABIBytes(%d bytes) returned %d bytes", n, len(got))
		}
	}
}

// =========================================================================
// 4. BalanceDelta packing
// =========================================================================

func TestZzstBalanceDeltaRoundTripAndBounds(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 30))

	vals := []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(-1),
		new(big.Int).Set(maxInt128), new(big.Int).Set(minInt128),
		new(big.Int).Sub(maxInt128, big.NewInt(1)),
		new(big.Int).Add(minInt128, big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 100),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 100)),
	}
	for i := 0; i < 32; i++ {
		v := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), 127))
		if i%2 == 0 {
			v.Neg(v)
		}
		vals = append(vals, v)
	}

	for _, a0 := range vals {
		for _, a1 := range vals {
			packed := PackBalanceDelta(a0, a1)
			if len(packed) != 32 {
				t.Fatalf("PackBalanceDelta produced %d bytes", len(packed))
			}
			g0, g1 := UnpackBalanceDelta(packed)
			if g0.Cmp(a0) != 0 || g1.Cmp(a1) != 0 {
				t.Fatalf("BalanceDelta round trip lost data: (%s, %s) -> (%s, %s)", a0, a1, g0, g1)
			}
			// The two legs are independent: leg 0 lives in the high 16 bytes.
			if !bytes.Equal(packed[0:16], bigIntTo16Bytes(a0)) || !bytes.Equal(packed[16:32], bigIntTo16Bytes(a1)) {
				t.Fatalf("BalanceDelta legs are not at their slots for (%s, %s)", a0, a1)
			}
		}
	}

	// nil encodes as zero on both legs.
	g0, g1 := UnpackBalanceDelta(PackBalanceDelta(nil, nil))
	if g0.Sign() != 0 || g1.Sign() != 0 {
		t.Fatalf("nil legs decoded as (%s, %s)", g0, g1)
	}

	// The lenient packer keeps only the low 16 bytes of a leg that does not fit —
	// documented behaviour, and the reason the money path must call
	// FitsSignedInt128 BEFORE packing. Assert the truncation is exactly a low-16
	// mask (positive) and a low-16 mask of the two's complement (negative), so a
	// change in the truncation rule shows up here rather than in a settled trade.
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	for _, v := range []*big.Int{
		new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Lsh(big.NewInt(1), 200),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(7)),
	} {
		if FitsSignedInt128(v) {
			t.Fatalf("%s should not fit an int128 leg", v)
		}
		got := new(big.Int).SetBytes(bigIntTo16Bytes(v))
		if got.Cmp(new(big.Int).And(v, mask)) != 0 {
			t.Fatalf("bigIntTo16Bytes(%s) = %s, want the low 128 bits %s", v, got, new(big.Int).And(v, mask))
		}
		neg := new(big.Int).Neg(v)
		if FitsSignedInt128(neg) {
			t.Fatalf("%s should not fit an int128 leg", neg)
		}
		gotNeg := new(big.Int).SetBytes(bigIntTo16Bytes(neg))
		wantNeg := new(big.Int).And(new(big.Int).Abs(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), neg)), mask)
		if gotNeg.Cmp(wantNeg) != 0 {
			t.Fatalf("bigIntTo16Bytes(%s) = %s, want %s", neg, gotNeg, wantNeg)
		}
	}

	// A short buffer yields zeros rather than reading past the end.
	for n := 0; n < 32; n++ {
		g0, g1 := UnpackBalanceDelta(make([]byte, n))
		if g0 == nil || g1 == nil || g0.Sign() != 0 || g1.Sign() != 0 {
			t.Fatalf("UnpackBalanceDelta(%d bytes) = (%v, %v)", n, g0, g1)
		}
	}
}

func TestZzstFitsSignedInt128Boundaries(t *testing.T) {
	one := big.NewInt(1)
	for _, tc := range []struct {
		v    *big.Int
		want bool
	}{
		{nil, true},
		{big.NewInt(0), true},
		{new(big.Int).Set(maxInt128), true},
		{new(big.Int).Set(minInt128), true},
		{new(big.Int).Add(maxInt128, one), false},
		{new(big.Int).Sub(minInt128, one), false},
		{new(big.Int).Lsh(big.NewInt(1), 200), false},
		{new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 200)), false},
	} {
		if got := FitsSignedInt128(tc.v); got != tc.want {
			t.Fatalf("FitsSignedInt128(%v) = %v, want %v", tc.v, got, tc.want)
		}
	}

	// The reason the bound exists: a value that does not fit is packed by
	// truncation, and truncation can flip the SIGN of the money leg.
	over := new(big.Int).Add(maxInt128, one) // 2^127
	got, _ := UnpackBalanceDelta(PackBalanceDelta(over, big.NewInt(0)))
	if got.Cmp(over) == 0 {
		t.Fatalf("PackBalanceDelta no longer truncates an out-of-range leg; " +
			"FitsSignedInt128 may no longer be load-bearing")
	}
	if got.Sign() >= 0 {
		t.Fatalf("truncating 2^127 gave %s; the documented hazard is a sign flip", got)
	}
}

// =========================================================================
// 5. int24 and signed-256 helpers
// =========================================================================

func TestZzstInt24RoundTripAndShortInput(t *testing.T) {
	for _, v := range []int24{0, 1, -1, 60, -60, 1<<23 - 1, -(1 << 23), 0x7FFFFF, -8388608} {
		b := int24ToBytes(v)
		if len(b) != 3 {
			t.Fatalf("int24ToBytes(%d) produced %d bytes", v, len(b))
		}
		if got := decodeInt24(b); got != v {
			t.Fatalf("int24 round trip: %d -> %x -> %d", v, b, got)
		}
	}
	// Fewer than three bytes is not a number; it must read as zero, not as a
	// partially-shifted value.
	for n := 0; n < 3; n++ {
		if got := decodeInt24(make([]byte, n)); got != 0 {
			t.Fatalf("decodeInt24(%d bytes) = %d, want 0", n, got)
		}
	}
	if got := decodeInt24(nil); got != 0 {
		t.Fatalf("decodeInt24(nil) = %d", got)
	}
	// Extra bytes are ignored, not folded in.
	if got := decodeInt24([]byte{0x00, 0x00, 0x3C, 0xFF}); got != 60 {
		t.Fatalf("decodeInt24 with a trailing byte = %d, want 60", got)
	}
}

func TestZzstDecodeSigned256(t *testing.T) {
	for _, v := range []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(-1),
		new(big.Int).Set(maxInt128), new(big.Int).Set(minInt128),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 255)),
	} {
		b := make([]byte, 32)
		zzstPutSigned256(b, v)
		if got := decodeSigned256(b); got.Cmp(v) != 0 {
			t.Fatalf("decodeSigned256 round trip: %s -> %x -> %s", v, b, got)
		}
	}
	if got := decodeSigned256(nil); got.Sign() != 0 {
		t.Fatalf("decodeSigned256(nil) = %s", got)
	}
}

// =========================================================================
// 6. EncodePoolState
// =========================================================================

func TestZzstEncodePoolStateLayout(t *testing.T) {
	pool := &Pool{
		SqrtPriceX96:   new(big.Int).Lsh(big.NewInt(1), 96),
		Tick:           -60,
		Liquidity:      big.NewInt(123456789),
		FeeGrowth0X128: new(big.Int).Lsh(big.NewInt(1), 200),
		FeeGrowth1X128: big.NewInt(-7), // signed fields use two's complement
	}
	out := EncodePoolState(pool)
	if len(out) != 160 {
		t.Fatalf("EncodePoolState produced %d bytes, want 160", len(out))
	}
	if !bytes.Equal(out[0:32], bigIntTo32Bytes(pool.SqrtPriceX96)) {
		t.Fatalf("slot 0 is not sqrtPriceX96: %x", out[0:32])
	}
	if !bytes.Equal(out[64:96], bigIntTo32Bytes(pool.Liquidity)) {
		t.Fatalf("slot 2 is not liquidity: %x", out[64:96])
	}
	if !bytes.Equal(out[96:128], bigIntTo32Bytes(pool.FeeGrowth0X128)) {
		t.Fatalf("slot 3 is not feeGrowth0: %x", out[96:128])
	}
	if !bytes.Equal(out[128:160], bigIntTo32Bytes(pool.FeeGrowth1X128)) {
		t.Fatalf("slot 4 is not feeGrowth1: %x", out[128:160])
	}
	if new(big.Int).SetBytes(out[128:160]).Cmp(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(7))) != 0 {
		t.Fatalf("a negative fee growth is not two's complement: %x", out[128:160])
	}

	// DEFECT characterisation: the tick is written as a big-endian uint32 at the
	// FRONT of slot 1 (module.go:439), not right-aligned like every other ABI
	// value, so an int24 reader of slot 1 sees zero. EncodePoolState has no
	// non-test caller today, which is why this has gone unnoticed.
	if binary.BigEndian.Uint32(out[32:36]) != uint32(pool.Tick) {
		t.Fatalf("module.go:439 no longer writes the tick at the front of slot 1 — the layout "+
			"was corrected; update this characterisation test (%x)", out[32:64])
	}
	if !bytes.Equal(out[36:64], make([]byte, 28)) {
		t.Fatalf("slot 1 has data past the tick: %x", out[32:64])
	}

	// A nil pool value encodes as a zero word rather than panicking.
	zero := EncodePoolState(&Pool{})
	if !bytes.Equal(zero, make([]byte, 160)) {
		t.Fatalf("an empty pool encoded as %x", zero)
	}

	// bigIntTo32Bytes PANICS above 2^256 (big.Int.FillBytes refuses to truncate).
	// EncodePoolState is the only caller and is dead today; if it is ever wired to
	// a selector, a pool value wider than a word becomes a chain halt.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("module.go:450 bigIntTo32Bytes no longer panics above 2^256 — a bound " +
					"was added; update this characterisation test")
			}
		}()
		_ = bigIntTo32Bytes(new(big.Int).Lsh(big.NewInt(1), 256))
	}()
}

// =========================================================================
// 7. The state adapter
// =========================================================================

// zzstBareStateDB hides any capability the concrete StateDB has beyond
// contract.StateDB itself, by embedding the INTERFACE. The adapter's optional
// capability probes must then miss, which is the fail-closed path.
type zzstBareStateDB struct{ contract.StateDB }

func TestZzstPoolStateAdapterForwardsToTheStateDB(t *testing.T) {
	h := newSettleHarness(t)
	h.state.stateDB.SetBlockNumber(4242)
	a := newPoolStateAdapter(h.state)

	if a.underlyingStateDB() == nil {
		t.Fatalf("underlyingStateDB returned nil — the settle path would lose the ERC-20 vault")
	}
	if a.GetBlockNumber() != 4242 {
		t.Fatalf("GetBlockNumber = %d, want 4242", a.GetBlockNumber())
	}

	fresh := common.HexToAddress("0x0000000000000000000000000000000000000ABC")
	if a.Exist(fresh) {
		t.Fatalf("Exist reported a never-created account")
	}
	a.CreateAccount(fresh)
	if !a.Exist(fresh) {
		t.Fatalf("Exist = false after CreateAccount")
	}

	if got, want := a.TxHash(), h.state.GetStateDB().TxHash(); got != want {
		t.Fatalf("TxHash = %s, want %s", got.Hex(), want.Hex())
	}

	// CodeSizeOf forwards EXTCODESIZE when the StateDB can answer it.
	token := common.HexToAddress("0x0000000000000000000000000000000000000BEE")
	h.state.stateDB.SetCodeSize(token, 1234)
	if got := a.CodeSizeOf(token); got != 1234 {
		t.Fatalf("CodeSizeOf = %d, want 1234", got)
	}
	// ...and reports -1, not 0, when it cannot. 0 would read as "no code", which
	// the value path treats as a real answer; -1 means "cannot prove", which is
	// what makes the caller fail closed.
	bare := &poolStateAdapter{stateDB: zzstBareStateDB{h.state.GetStateDB()}}
	if got := bare.CodeSizeOf(token); got != -1 {
		t.Fatalf("CodeSizeOf over a StateDB with no code accessor = %d, want -1", got)
	}
}

// =========================================================================
// 8. Selector table and construction
// =========================================================================

// Every hard-coded selector must be the keccak of the signature it claims. init()
// asserts a subset; this asserts the whole table, including the admin selectors it
// computes, so a copy-paste in the constant block cannot dispatch the wrong handler.
func TestZzstSelectorTableMatchesSignatures(t *testing.T) {
	for sig, got := range map[string]uint32{
		"initialize((address,address,uint24,int24,address),uint160)":                                 SelectorInitialize,
		"swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)":                   SelectorSwap,
		"modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)": SelectorModifyLiquidity,
		"donate((address,address,uint24,int24,address),uint256,uint256,bytes)":                       SelectorDonate,
		"unlock(bytes)":                 SelectorUnlock,
		"settle()":                      SelectorSettle,
		"settleFor(address)":            SelectorSettleFor,
		"sync(address)":                 SelectorSync,
		"take(address,address,uint256)": SelectorTake,
		"clear(address,uint256)":        SelectorClear,
		"mint(address,uint256,uint256)": SelectorMint,
		"burn(address,uint256,uint256)": SelectorBurn,
		"updateDynamicLPFee((address,address,uint24,int24,address),uint24)": SelectorUpdateDynFee,
		"extsload(bytes32)":          SelectorExtsload,
		"extsload(bytes32[])":        SelectorExtsloadArray,
		"deposit(address,uint256)":   SelectorDeposit,
		"withdraw(address,uint256)":  SelectorWithdraw,
		"balanceOf(address,address)": SelectorBalanceOf,
		"pauseDEX()":                 SelectorPauseDEX,
		"resumeDEX()":                SelectorResumeDEX,
		"pausePool(bytes32)":         SelectorPausePool,
		"resumePool(bytes32)":        SelectorResumePool,
		"freezePool(bytes32)":        SelectorFreezePool,
	} {
		if want := keccak4(sig); got != want {
			t.Fatalf("selector for %s = 0x%08X, want 0x%08X", sig, got, want)
		}
	}

	// Distinct signatures must give distinct selectors — a clash routes one call
	// to the other's handler.
	seen := map[uint32]bool{}
	for _, s := range []uint32{
		SelectorInitialize, SelectorSwap, SelectorModifyLiquidity, SelectorDonate, SelectorUnlock,
		SelectorSettle, SelectorSettleFor, SelectorSync, SelectorTake, SelectorClear, SelectorMint,
		SelectorBurn, SelectorUpdateDynFee, SelectorExtsload, SelectorExtsloadArray,
		SelectorDeposit, SelectorWithdraw, SelectorBalanceOf,
		SelectorPauseDEX, SelectorResumeDEX, SelectorPausePool, SelectorResumePool, SelectorFreezePool,
	} {
		if seen[s] {
			t.Fatalf("selector 0x%08X appears twice in the dispatch table", s)
		}
		seen[s] = true
	}

	// keccak4 is the first four bytes, big-endian, of keccak256 — not the last.
	if keccak4("settle()") != binary.BigEndian.Uint32(crypto.Keccak256([]byte("settle()"))[:4]) {
		t.Fatalf("keccak4 is not the leading four bytes of keccak256")
	}
}

func TestZzstNewDEXContractRequiresAClient(t *testing.T) {
	c := newDEXContract(newDChainUnavailable())
	if c == nil || c.poolManager == nil {
		t.Fatalf("newDEXContract returned %+v", c)
	}
	if c.poolManager.engine == nil {
		t.Fatalf("newDEXContract did not bind the client to the pool manager")
	}

	// A nil client is a caller bug and must be loud at construction, not at the
	// first swap.
	defer func() {
		if recover() == nil {
			t.Fatalf("newDEXContract(nil) did not panic")
		}
	}()
	_ = newDEXContract(nil)
}

// InstallDChainClient resolves the singleton's on-ramp. It refuses a nil client
// and refuses to run after ANY per-pool state exists, because re-pointing the
// client under live state is a race with no owner. Each of the three per-pool maps
// is a separate guard, so each is exercised separately — a guard that reads only
// one map lets the other two through.
func TestZzstInstallDChainClientGuards(t *testing.T) {
	// DEXPrecompile is a package singleton other tests have already written to, so
	// swap in empty maps for the duration and hand back the originals untouched.
	// Nothing is lost: the map objects themselves are restored, not rebuilt.
	pm := DEXPrecompile.poolManager
	original, pools, states, positions := pm.engine, pm.pools, pm.poolStates, pm.positions
	t.Cleanup(func() {
		pm.engine, pm.pools, pm.poolStates, pm.positions = original, pools, states, positions
	})
	pm.pools = map[[32]byte]*Pool{}
	pm.poolStates = map[[32]byte]*PoolState{}
	pm.positions = map[[32]byte]*Position{}

	var probe [32]byte
	probe[0] = 0x5A
	pm.engine = nil
	if err := InstallDChainClient(nil); err == nil {
		t.Fatalf("InstallDChainClient(nil) succeeded")
	}
	if pm.engine != nil {
		t.Fatalf("a refused install still assigned a client")
	}

	for _, seed := range []struct {
		name    string
		add     func()
		remove  func()
		wantErr bool
	}{
		{"pools", func() { pm.pools[probe] = &Pool{} }, func() { delete(pm.pools, probe) }, true},
		{"poolStates", func() { pm.poolStates[probe] = &PoolState{} }, func() { delete(pm.poolStates, probe) }, true},
		{"positions", func() { pm.positions[probe] = &Position{} }, func() { delete(pm.positions, probe) }, true},
	} {
		seed.add()
		err := InstallDChainClient(newDChainUnavailable())
		seed.remove()
		if (err != nil) != seed.wantErr {
			t.Fatalf("install with a non-empty %s map = %v, want an error", seed.name, err)
		}
		if pm.engine != nil {
			t.Fatalf("install with a non-empty %s map assigned a client anyway", seed.name)
		}
	}

	// With every map empty the install lands and the client is bound.
	if err := InstallDChainClient(newDChainUnavailable()); err != nil {
		t.Fatalf("InstallDChainClient on a clean manager: %v", err)
	}
	if pm.engine == nil {
		t.Fatalf("InstallDChainClient returned nil but bound no client")
	}
	if pm.engine.Brand() == "" {
		t.Fatalf("the installed client reports no brand — the boot log would be blank")
	}
}
