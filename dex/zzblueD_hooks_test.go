// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// =========================================================================
// Shared helpers (blueD-prefixed so no other lane collides)
// =========================================================================

// blueDPoisoned returns a slice of exactly len(b) bytes whose spare capacity is
// filled with 0xA5. Precompile input arrives from geth as a two-index slice of EVM
// memory, so cap() is attacker-chosen: an over-read past len() does not panic in
// production, it silently reads bytes the caller wrote. Passing a poisoned fixture
// turns such an over-read into a wrong VALUE, which a test can see.
func blueDPoisoned(b []byte, spare int) []byte {
	full := make([]byte, len(b)+spare)
	for i := range full {
		full[i] = 0xA5
	}
	copy(full, b)
	return full[:len(b)]
}

// blueDTwos is an independent 256-bit two's-complement encoder: the mathematical
// definition (v mod 2^256, big-endian, 32 bytes) with no shared code with
// abiEncodeBigInt. Every event-data assertion below compares against THIS, never
// against the encoder's own output.
func blueDTwos(v *big.Int) []byte {
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	m := new(big.Int).Mod(v, mod) // Go's Mod is Euclidean: result is always >= 0
	return m.FillBytes(make([]byte, 32))
}

// blueDPanics reports whether f panicked.
func blueDPanics(f func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	f()
	return false
}

var (
	blueDLiquid     = common.HexToAddress("0x00000000000000000000000000000000000d1111")
	blueDUnderlying = Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000d2222")}
	blueDUser       = common.HexToAddress("0x00000000000000000000000000000000000d3333")
	blueDUser2      = common.HexToAddress("0x00000000000000000000000000000000000d4444")
)

// =========================================================================
// events.go -- topic0 must be keccak of the DECLARED signature
// =========================================================================

// blueDTopics are keccak-256 digests of the event signature strings declared in
// events.go, produced by a from-spec Keccak-256 implementation (not luxfi/crypto).
// The first three are additionally the topic0 values a real Uniswap V4
// PoolManager emits on Ethereum, so they are checkable against a third party.
var blueDTopics = []struct {
	sig  string
	want string
	got  common.Hash
}{
	{"Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)", "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438", initializeEventSig},
	{"Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)", "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f", swapEventSig},
	{"ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)", "0xf208f4912782fd25c7f114ca3723a2d5dd6f3bcc3ac8db5af63baa85f711d5ec", modifyLiquidityEventSig},
	{"DEXFill(bytes32,address,uint256,uint256)", "0x6f744d074efc4fa8512636853f8a4c67842f230d4279421c7599dc5c5daf9874", dexFillEventSig},
	{"DEXPaused(address)", "0x405fae8bcc48a74529e7adb64a995431399d68c864574581b09af20927bdfc3f", dexPausedEventSig},
	{"DEXResumed(address)", "0xf921e3f64f3d1ab08b9745a67d9781a9024c5ff60ac9422ec14220881e1e108b", dexResumedEventSig},
	{"PoolPaused(bytes32,address)", "0xae40394169ddb6b502dedda3a03d376b436968960d4ffa6a37ee68be079781bc", poolPausedEventSig},
	{"PoolResumed(bytes32,address)", "0xb78adc028ded8fa22638123dc0c4e628978c82708c698bdc08797485623a4a2f", poolResumedEventSig},
	{"PoolFrozen(bytes32,address)", "0xc092bba9f133af9b26ee4b1d436bc631a75fa432e7b34b78b2a21b3bda7400ee", poolFrozenEventSig},
}

func TestBlueDEventTopic0MatchesIndependentKeccak(t *testing.T) {
	seen := map[common.Hash]string{}
	for _, tc := range blueDTopics {
		if got := tc.got.Hex(); got != tc.want {
			t.Errorf("topic0 for %q: got %s, want %s (independent keccak)", tc.sig, got, tc.want)
		}
		if prev, dup := seen[tc.got]; dup {
			t.Errorf("topic0 collision: %q and %q share %s", prev, tc.sig, tc.got.Hex())
		}
		seen[tc.got] = tc.sig
	}
	if len(seen) != len(blueDTopics) {
		t.Fatalf("expected %d distinct topic0 values, got %d", len(blueDTopics), len(seen))
	}
}

// =========================================================================
// events.go -- abiEncode* are exact over their real domain
// =========================================================================

func TestBlueDABIEncodeBigIntExactOverInt256(t *testing.T) {
	// nil is the documented zero word (uncovered arm).
	if got := abiEncodeBigInt(nil); !bytes.Equal(got, make([]byte, 32)) {
		t.Fatalf("abiEncodeBigInt(nil) = %x, want 32 zero bytes", got)
	}

	two255 := new(big.Int).Lsh(big.NewInt(1), 255)
	vals := []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(-1), big.NewInt(255), big.NewInt(-255),
		big.NewInt(256), big.NewInt(-256), big.NewInt(math.MaxInt64), big.NewInt(math.MinInt64),
		new(big.Int).Lsh(big.NewInt(1), 128), new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 128)),
		new(big.Int).Sub(two255, big.NewInt(1)), // max int256
		new(big.Int).Neg(two255),                // min int256
	}
	// Every value decodeSigned256 can produce from 32 bytes of calldata lives in
	// [-2^255, 2^255); the encoder must be exact on all of it.
	for _, v := range vals {
		want := blueDTwos(v)
		if got := abiEncodeBigInt(v); !bytes.Equal(got, want) {
			t.Errorf("abiEncodeBigInt(%s) = %x, want %x", v, got, want)
		}
	}
}

// TestBlueDABIEncodeBigIntOutsideInt256 pins TWO defects that live outside the
// int256 domain. No caller can reach them today (decodeSigned256 reads 32 bytes,
// and both emit paths bound sqrtPriceX96 / fee / tickSpacing first), so they are
// latent -- but they are the reason the 0xff sign-extension loop exists and the
// reason it is wrong.
func TestBlueDABIEncodeBigIntOutsideInt256(t *testing.T) {
	// (a) v <= -(2^256 - 2^248): twos = 2^256+v needs fewer than 32 bytes, the loop
	// runs, and it pads with 0xff -- but the correct encoding here is ZERO-padded.
	// v = -(2^256-1) has two's complement 0x00..01; the encoder answers 0xff..ff01.
	v := new(big.Int).Neg(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)))
	got := abiEncodeBigInt(v)
	correct := blueDTwos(v) // 0x00..01
	if bytes.Equal(got, correct) {
		t.Fatalf("abiEncodeBigInt(-(2^256-1)) is now correct (%x) -- defect fixed, update this test", got)
	}
	wrong := append(bytes.Repeat([]byte{0xff}, 31), 0x01)
	if !bytes.Equal(got, wrong) {
		t.Fatalf("abiEncodeBigInt(-(2^256-1)) = %x, want the known-wrong %x", got, wrong)
	}

	// (b) v >= 2^256: len(v.Bytes()) > 32 makes word[32-len:] a negative index.
	// A slice-bounds panic inside a log builder is a validator halt.
	big2256 := new(big.Int).Lsh(big.NewInt(1), 256)
	if !blueDPanics(func() { abiEncodeBigInt(big2256) }) {
		t.Fatal("abiEncodeBigInt(2^256) no longer panics -- defect fixed, update this test")
	}
}

func TestBlueDABIEncodeInt24AndUint24Exact(t *testing.T) {
	for _, v := range []int24{0, 1, -1, 127, -127, 8388607, -8388608, MaxTick, MinTick} {
		want := blueDTwos(big.NewInt(int64(v)))
		if got := abiEncodeInt24(v); !bytes.Equal(got, want) {
			t.Errorf("abiEncodeInt24(%d) = %x, want %x", v, got, want)
		}
	}
	// uint24 is a Go ALIAS for uint32, so the compiler cannot refuse an out-of-range
	// fee; abiEncodeUint24 writes only 3 bytes and drops the 4th silently.
	for _, v := range []uint24{0, 1, Fee030, FeeMax, 0xFFFFFF} {
		want := blueDTwos(new(big.Int).SetUint64(uint64(v)))
		if got := abiEncodeUint24(v); !bytes.Equal(got, want) {
			t.Errorf("abiEncodeUint24(%d) = %x, want %x", v, got, want)
		}
	}
	// The truncation itself, pinned: 2^24 encodes as 0. Both emit paths bound the
	// fee (`key.Fee > FeeMax` -> refuse) before reaching here, so this is latent.
	if got := abiEncodeUint24(1 << 24); !bytes.Equal(got, make([]byte, 32)) {
		t.Fatalf("abiEncodeUint24(2^24) = %x, want 32 zero bytes (silent 3-byte truncation)", got)
	}
}

// =========================================================================
// events.go -- Swap log: address, topics, and byte-exact field positions
// =========================================================================

func TestBlueDSwapEventFieldsArePositionallyExact(t *testing.T) {
	db := NewMockStateDB()
	var poolId [32]byte
	for i := range poolId {
		poolId[i] = byte(i + 1)
	}
	sender := common.HexToAddress("0x00000000000000000000000000000000000dbeef")

	// Six mutually distinguishable values: if any pair of fields is transposed, or
	// any field slides by a word, at least one offset assertion fails.
	amount0 := big.NewInt(0x1111111111)
	amount1 := big.NewInt(-0x2222222222) // negative: pins the two's complement in the log
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(3), 96)
	liquidity := big.NewInt(0x4444444444)
	tick := int24(-4242)
	fee := Fee030

	emitSwapEvent(db, poolId, sender, NewBalanceDelta(amount0, amount1), sqrtPriceX96, liquidity, tick, fee)

	logs := db.Logs()
	if len(logs) != 1 {
		t.Fatalf("emitSwapEvent wrote %d logs, want 1", len(logs))
	}
	lg := logs[0]
	if lg.Address != lxPoolAddr {
		t.Errorf("Swap log address = %s, want lxPoolAddr %s", lg.Address, lxPoolAddr)
	}
	if len(lg.Topics) != 3 {
		t.Fatalf("Swap topics = %d, want 3 (sig + poolId + sender)", len(lg.Topics))
	}
	if lg.Topics[0].Hex() != "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f" {
		t.Errorf("Swap topic0 = %s, want the independently computed digest", lg.Topics[0].Hex())
	}
	if lg.Topics[1] != common.BytesToHash(poolId[:]) {
		t.Errorf("Swap topic1 = %s, want poolId", lg.Topics[1].Hex())
	}
	if lg.Topics[2] != common.BytesToHash(sender.Bytes()) {
		t.Errorf("Swap topic2 = %s, want sender left-padded", lg.Topics[2].Hex())
	}

	// Field packing, asserted at byte offsets against the independent encoder.
	fields := []struct {
		name string
		want []byte
	}{
		{"amount0", blueDTwos(amount0)},
		{"amount1", blueDTwos(amount1)},
		{"sqrtPriceX96", blueDTwos(sqrtPriceX96)},
		{"liquidity", blueDTwos(liquidity)},
		{"tick", blueDTwos(big.NewInt(int64(tick)))},
		{"fee", blueDTwos(new(big.Int).SetUint64(uint64(fee)))},
	}
	if len(lg.Data) != 32*len(fields) {
		t.Fatalf("Swap data = %d bytes, want %d", len(lg.Data), 32*len(fields))
	}
	for i, f := range fields {
		if got := lg.Data[i*32 : (i+1)*32]; !bytes.Equal(got, f.want) {
			t.Errorf("Swap data word %d (%s) = %x, want %x", i, f.name, got, f.want)
		}
	}
}

// =========================================================================
// hooks.go -- the permission bitmap, swept bit by bit
// =========================================================================

// blueDHookBits is the complete V4 bit table. `bit` is the position Uniswap V4's
// Hooks.sol assigns; a shifted mask in either direction fails here.
var blueDHookBits = []struct {
	name string
	flag HookFlags
	bit  uint
	get  func(HookPermissions) bool
	set  func(*HookPermissions)
}{
	{"beforeInitialize", HookBeforeInitialize, 13, func(p HookPermissions) bool { return p.BeforeInitialize }, func(p *HookPermissions) { p.BeforeInitialize = true }},
	{"afterInitialize", HookAfterInitialize, 12, func(p HookPermissions) bool { return p.AfterInitialize }, func(p *HookPermissions) { p.AfterInitialize = true }},
	{"beforeAddLiquidity", HookBeforeAddLiquidity, 11, func(p HookPermissions) bool { return p.BeforeAddLiquidity }, func(p *HookPermissions) { p.BeforeAddLiquidity = true }},
	{"afterAddLiquidity", HookAfterAddLiquidity, 10, func(p HookPermissions) bool { return p.AfterAddLiquidity }, func(p *HookPermissions) { p.AfterAddLiquidity = true }},
	{"beforeRemoveLiquidity", HookBeforeRemoveLiquidity, 9, func(p HookPermissions) bool { return p.BeforeRemoveLiquidity }, func(p *HookPermissions) { p.BeforeRemoveLiquidity = true }},
	{"afterRemoveLiquidity", HookAfterRemoveLiquidity, 8, func(p HookPermissions) bool { return p.AfterRemoveLiquidity }, func(p *HookPermissions) { p.AfterRemoveLiquidity = true }},
	{"beforeSwap", HookBeforeSwap, 7, func(p HookPermissions) bool { return p.BeforeSwap }, func(p *HookPermissions) { p.BeforeSwap = true }},
	{"afterSwap", HookAfterSwap, 6, func(p HookPermissions) bool { return p.AfterSwap }, func(p *HookPermissions) { p.AfterSwap = true }},
	{"beforeDonate", HookBeforeDonate, 5, func(p HookPermissions) bool { return p.BeforeDonate }, func(p *HookPermissions) { p.BeforeDonate = true }},
	{"afterDonate", HookAfterDonate, 4, func(p HookPermissions) bool { return p.AfterDonate }, func(p *HookPermissions) { p.AfterDonate = true }},
	{"beforeSwapReturnsDelta", HookBeforeSwapReturnsDelta, 3, func(p HookPermissions) bool { return p.BeforeSwapReturnsDelta }, func(p *HookPermissions) { p.BeforeSwapReturnsDelta = true }},
	{"afterSwapReturnsDelta", HookAfterSwapReturnsDelta, 2, func(p HookPermissions) bool { return p.AfterSwapReturnsDelta }, func(p *HookPermissions) { p.AfterSwapReturnsDelta = true }},
	{"afterAddLiquidityReturnsDelta", HookAfterAddLiquidityReturnsDelta, 1, func(p HookPermissions) bool { return p.AfterAddLiquidityReturnsDelta }, func(p *HookPermissions) { p.AfterAddLiquidityReturnsDelta = true }},
	{"afterRemoveLiquidityReturnsDelta", HookAfterRemoveLiquidityReturnsDelta, 0, func(p HookPermissions) bool { return p.AfterRemoveLiquidityReturnsDelta }, func(p *HookPermissions) { p.AfterRemoveLiquidityReturnsDelta = true }},
}

// blueDHookAddr places flags in the trailing 2 bytes and fills the leading 18 with
// noise, so any test that passes also proves the leading bytes are ignored.
func blueDHookAddr(flags HookFlags) common.Address {
	var a common.Address
	for i := 0; i < 18; i++ {
		a[i] = 0xA5
	}
	binary.BigEndian.PutUint16(a[18:20], uint16(flags))
	return a
}

func TestBlueDHookFlagLayoutIsExact(t *testing.T) {
	if len(blueDHookBits) != 14 {
		t.Fatalf("bit table has %d entries, want 14", len(blueDHookBits))
	}
	var union HookFlags
	for _, b := range blueDHookBits {
		if b.flag != HookFlags(1)<<b.bit {
			t.Errorf("%s = %#b, want 1<<%d", b.name, b.flag, b.bit)
		}
		if union&b.flag != 0 {
			t.Errorf("%s duplicates a bit already claimed", b.name)
		}
		union |= b.flag
	}
	if union != HookAllMask {
		t.Errorf("union of flags = %#b, HookAllMask = %#b", union, HookAllMask)
	}
	if HookAllMask != (1<<14)-1 {
		t.Errorf("HookAllMask = %#b, want 14 low bits set", HookAllMask)
	}
}

// TestBlueDDecodeIsExactPerBit sweeps every single bit position rather than a
// sample: setting bit b must light exactly one permission and leave the other 13
// dark. A mask shifted by one silently grants a permission nobody encoded.
func TestBlueDDecodeIsExactPerBit(t *testing.T) {
	for _, b := range blueDHookBits {
		flags := HookFlags(1) << b.bit
		p := DecodeHookPermissions(flags)
		for _, other := range blueDHookBits {
			want := other.name == b.name
			if got := other.get(p); got != want {
				t.Errorf("bit %d (%s): permission %s = %v, want %v", b.bit, b.name, other.name, got, want)
			}
		}
		// Encode is the exact inverse.
		var round HookPermissions
		b.set(&round)
		if enc := EncodeHookPermissions(round); enc != flags {
			t.Errorf("Encode(%s) = %#b, want %#b", b.name, enc, flags)
		}
		if EncodeHookPermissions(p) != flags {
			t.Errorf("Encode(Decode(%#b)) != identity", flags)
		}
	}
	// The empty and full points.
	if EncodeHookPermissions(HookPermissions{}) != 0 {
		t.Error("empty permissions must encode to 0")
	}
	var all HookPermissions
	for _, b := range blueDHookBits {
		b.set(&all)
	}
	if EncodeHookPermissions(all) != HookAllMask {
		t.Error("all permissions must encode to HookAllMask")
	}
}

// TestBlueDAddressBitsGrantExactlyWhatTheyEncode is the property that matters most:
// a hook address whose bits do NOT set a flag must never report that permission.
func TestBlueDAddressBitsGrantExactlyWhatTheyEncode(t *testing.T) {
	for _, b := range blueDHookBits {
		addr := blueDHookAddr(HookFlags(1) << b.bit)
		for _, other := range blueDHookBits {
			want := other.name == b.name
			if got := HasPermission(addr, other.flag); got != want {
				t.Errorf("addr bit %d: HasPermission(%s) = %v, want %v", b.bit, other.name, got, want)
			}
			// The address-derived decode must agree with HasPermission, always.
			if got := other.get(GetHookPermissionsFromAddress(addr)); got != want {
				t.Errorf("addr bit %d: GetHookPermissionsFromAddress().%s = %v, want %v", b.bit, other.name, got, want)
			}
		}
	}
	// The zero address -- the "no hooks" sentinel PoolKey uses -- grants nothing.
	for _, b := range blueDHookBits {
		if HasPermission(common.Address{}, b.flag) {
			t.Errorf("zero address must not grant %s", b.name)
		}
	}
	// Bits 14 and 15 of the trailing word map to no flag and must grant nothing.
	for _, spare := range []HookFlags{1 << 14, 1 << 15, 3 << 14} {
		addr := blueDHookAddr(spare)
		for _, b := range blueDHookBits {
			if HasPermission(addr, b.flag) {
				t.Errorf("address carrying only spare bit %#b must not grant %s", spare, b.name)
			}
		}
	}
}

// TestBlueDValidateHookAddressRefusesEveryOneBitDivergence: a single flipped bit
// -- in the address OR in the claimed permissions -- must be refused.
func TestBlueDValidateHookAddressRefusesEveryOneBitDivergence(t *testing.T) {
	base := HookPermissions{BeforeSwap: true, AfterSwap: true, BeforeDonate: true}
	baseFlags := EncodeHookPermissions(base)
	if err := ValidateHookAddress(blueDHookAddr(baseFlags), base); err != nil {
		t.Fatalf("matching address must validate: %v", err)
	}
	for _, b := range blueDHookBits {
		// Flip one bit of the ADDRESS.
		if err := ValidateHookAddress(blueDHookAddr(baseFlags^b.flag), base); err != ErrHookInvalidAddress {
			t.Errorf("address bit %d flipped: got %v, want ErrHookInvalidAddress", b.bit, err)
		}
		// Flip one bit of the CLAIMED permissions.
		claim := DecodeHookPermissions(baseFlags ^ b.flag)
		if err := ValidateHookAddress(blueDHookAddr(baseFlags), claim); err != ErrHookInvalidAddress {
			t.Errorf("permission bit %d flipped: got %v, want ErrHookInvalidAddress", b.bit, err)
		}
	}
	// The spare bits are NOT masked off: an address carrying bit 14 can never
	// validate, even though bit 14 grants nothing.
	var withSpare common.Address
	binary.BigEndian.PutUint16(withSpare[18:20], uint16(baseFlags|1<<14))
	if err := ValidateHookAddress(withSpare, base); err != ErrHookInvalidAddress {
		t.Errorf("address with spare bit 14 set: got %v, want ErrHookInvalidAddress", err)
	}
}

// TestBlueDRegistryCannotWidenPermissions: registration must never be a way to
// obtain a callback the address does not encode. RegisterHook refuses any flags
// that differ from the address, and IsHookEnabled answers identically whether or
// not the hook is registered -- so the map cannot grant anything.
func TestBlueDRegistryCannotWidenPermissions(t *testing.T) {
	for _, b := range blueDHookBits {
		flags := HookFlags(1) << b.bit
		addr := blueDHookAddr(flags)
		hr := NewHookRegistry()

		// Unregistered: derived straight from the trailing bits (uncovered arm).
		for _, other := range blueDHookBits {
			want := other.name == b.name
			if got := hr.IsHookEnabled(addr, other.flag); got != want {
				t.Errorf("unregistered addr bit %d: IsHookEnabled(%s) = %v, want %v", b.bit, other.name, got, want)
			}
		}
		if _, ok := hr.GetHookFlags(addr); ok {
			t.Errorf("bit %d: GetHookFlags reported a registration that never happened", b.bit)
		}

		// Every one-bit divergence from the address is refused.
		for _, other := range blueDHookBits {
			if err := hr.RegisterHook(addr, flags^other.flag); err != ErrHookInvalidAddress {
				t.Errorf("bit %d: RegisterHook with flags^%s: got %v, want ErrHookInvalidAddress", b.bit, other.name, err)
			}
		}
		if got, ok := hr.GetHookFlags(addr); ok {
			t.Errorf("bit %d: a refused RegisterHook still wrote %#b to the registry", b.bit, got)
		}

		// The honest registration succeeds and changes no answer.
		if err := hr.RegisterHook(addr, flags); err != nil {
			t.Fatalf("bit %d: RegisterHook(matching flags): %v", b.bit, err)
		}
		got, ok := hr.GetHookFlags(addr)
		if !ok || got != flags {
			t.Errorf("bit %d: GetHookFlags = (%#b, %v), want (%#b, true)", b.bit, got, ok, flags)
		}
		for _, other := range blueDHookBits {
			if hr.IsHookEnabled(addr, other.flag) != HasPermission(addr, other.flag) {
				t.Errorf("bit %d: registration changed the verdict for %s", b.bit, other.name)
			}
		}
	}
}

func TestBlueDGenerateHookAddressEncodesFlags(t *testing.T) {
	deployer := common.HexToAddress("0x00000000000000000000000000000000000dde01")
	var salt [32]byte
	copy(salt[:], "blueD-salt")

	cases := []HookPermissions{{}}
	for _, b := range blueDHookBits {
		var p HookPermissions
		b.set(&p)
		cases = append(cases, p)
	}
	var all HookPermissions
	for _, b := range blueDHookBits {
		b.set(&all)
	}
	cases = append(cases, all)

	seen := map[common.Address]bool{}
	for _, p := range cases {
		addr := GenerateHookAddress(deployer, salt, p)
		if err := ValidateHookAddress(addr, p); err != nil {
			t.Errorf("GenerateHookAddress produced an address that fails ValidateHookAddress: %v", err)
		}
		for _, b := range blueDHookBits {
			if HasPermission(addr, b.flag) != b.get(p) {
				t.Errorf("generated address: %s = %v, want %v", b.name, HasPermission(addr, b.flag), b.get(p))
			}
		}
		// Deterministic: two validators must derive the same address.
		if again := GenerateHookAddress(deployer, salt, p); again != addr {
			t.Errorf("GenerateHookAddress is not deterministic: %s != %s", addr, again)
		}
		if seen[addr] {
			t.Errorf("two distinct permission sets produced the same address %s", addr)
		}
		seen[addr] = true
	}
	// The leading 18 bytes come from the hash, so a different salt moves them.
	var salt2 [32]byte
	copy(salt2[:], "blueD-salt-2")
	if GenerateHookAddress(deployer, salt2, all) == GenerateHookAddress(deployer, salt, all) {
		t.Error("different salts must derive different hook addresses")
	}
}

// =========================================================================
// hooks.go -- hook call payload packing
// =========================================================================

func TestBlueDPackSwapParamsFieldOffsets(t *testing.T) {
	sender := common.HexToAddress("0x00000000000000000000000000000000000d5e11")
	key := newTestPoolKey()
	keyBytes := key.ToBytes()
	if len(keyBytes) != 66 {
		t.Fatalf("PoolKey.ToBytes() = %d bytes, want 66", len(keyBytes))
	}
	hookData := []byte("blueD-hookdata")
	amount := big.NewInt(0x1234567890)
	limit := big.NewInt(0x0fedcba987)
	delta := NewBalanceDelta(big.NewInt(0x1111), big.NewInt(0x2222))

	for _, zeroForOne := range []bool{true, false} {
		params := SwapParams{ZeroForOne: zeroForOne, AmountSpecified: amount, SqrtPriceLimitX96: limit}
		dir := byte(0)
		if zeroForOne {
			dir = 1
		}

		before := PackBeforeSwapParams(sender, key, params, hookData)
		wantBefore := bytes.Join([][]byte{
			SigBeforeSwap, sender.Bytes(), keyBytes, {dir},
			amount.FillBytes(make([]byte, 32)), limit.FillBytes(make([]byte, 32)), hookData,
		}, nil)
		if !bytes.Equal(before, wantBefore) {
			t.Errorf("PackBeforeSwapParams(zeroForOne=%v) = %x, want %x", zeroForOne, before, wantBefore)
		}
		if before[90] != dir {
			t.Errorf("beforeSwap direction byte at offset 90 = %d, want %d", before[90], dir)
		}

		after := PackAfterSwapParams(sender, key, params, delta, hookData)
		wantAfter := bytes.Join([][]byte{
			SigAfterSwap, sender.Bytes(), keyBytes, {dir},
			amount.FillBytes(make([]byte, 32)),
			delta.Amount0.FillBytes(make([]byte, 32)), delta.Amount1.FillBytes(make([]byte, 32)),
			hookData,
		}, nil)
		if !bytes.Equal(after, wantAfter) {
			t.Errorf("PackAfterSwapParams(zeroForOne=%v) = %x, want %x", zeroForOne, after, wantAfter)
		}
		if after[90] != dir {
			t.Errorf("afterSwap direction byte at offset 90 = %d, want %d", after[90], dir)
		}
		// The selector must be the one the init() check verified, not the other one.
		if bytes.Equal(before[:4], after[:4]) {
			t.Error("beforeSwap and afterSwap must not share a selector")
		}
	}
}

// TestBlueDPackSwapParamsDropsTheAmountSign pins a DEFECT. V4's convention is
// "AmountSpecified < 0 means exact input" -- the ordinary case. Both packers use
// big.Int.FillBytes, which writes the ABSOLUTE value, so a hook receives +N for a
// swap of -N and cannot tell exact-input from exact-output.
func TestBlueDPackSwapParamsDropsTheAmountSign(t *testing.T) {
	sender := common.HexToAddress("0x00000000000000000000000000000000000d5e11")
	key := newTestPoolKey()
	hookData := []byte{}
	pos := big.NewInt(1000)
	neg := big.NewInt(-1000)
	limit := big.NewInt(1)
	delta := NewBalanceDelta(big.NewInt(7), big.NewInt(-7))

	a := PackBeforeSwapParams(sender, key, SwapParams{ZeroForOne: true, AmountSpecified: pos, SqrtPriceLimitX96: limit}, hookData)
	b := PackBeforeSwapParams(sender, key, SwapParams{ZeroForOne: true, AmountSpecified: neg, SqrtPriceLimitX96: limit}, hookData)
	if !bytes.Equal(a, b) {
		t.Fatal("PackBeforeSwapParams now distinguishes +N from -N -- defect fixed, update this test")
	}
	c := PackAfterSwapParams(sender, key, SwapParams{ZeroForOne: true, AmountSpecified: pos, SqrtPriceLimitX96: limit}, delta, hookData)
	d := PackAfterSwapParams(sender, key, SwapParams{ZeroForOne: true, AmountSpecified: neg, SqrtPriceLimitX96: limit}, delta, hookData)
	if !bytes.Equal(c, d) {
		t.Fatal("PackAfterSwapParams now distinguishes +N from -N -- defect fixed, update this test")
	}
	// The delta loses its sign the same way: Amount1 = -7 packs identically to +7.
	if !bytes.Equal(c[155:187], c[123:155]) {
		t.Errorf("delta words differ (%x vs %x) -- the sign of Amount1 = -7 survived", c[123:155], c[155:187])
	}
}

func TestBlueDUnpackHookDeltaReturnBoundary(t *testing.T) {
	// Sweep the length boundary: below 64 there is no delta and no error.
	for n := 0; n < 64; n++ {
		delta, err := UnpackHookDeltaReturn(make([]byte, n))
		if err != nil {
			t.Fatalf("len=%d: unexpected error %v", n, err)
		}
		if delta != nil {
			t.Fatalf("len=%d: got a delta from a short return", n)
		}
		// A short return with attacker-poisoned spare capacity must give the SAME
		// verdict: no over-read past len().
		pd, perr := UnpackHookDeltaReturn(blueDPoisoned(make([]byte, n), 128))
		if perr != nil || pd != nil {
			t.Fatalf("len=%d poisoned: got (%v, %v), want (nil, nil)", n, pd, perr)
		}
	}

	data := make([]byte, 64)
	big.NewInt(0x0abc).FillBytes(data[0:32])
	big.NewInt(0x0def).FillBytes(data[32:64])
	delta, err := UnpackHookDeltaReturn(data)
	if err != nil {
		t.Fatalf("len=64: %v", err)
	}
	if delta == nil {
		t.Fatal("len=64: want a delta")
	}
	if delta.Amount0.Cmp(big.NewInt(0x0abc)) != 0 || delta.Amount1.Cmp(big.NewInt(0x0def)) != 0 {
		t.Fatalf("delta = (%s, %s), want (2748, 3567)", delta.Amount0, delta.Amount1)
	}
	// Trailing bytes past the 64th are ignored, and poisoned spare capacity does
	// not change the answer.
	pd, perr := UnpackHookDeltaReturn(blueDPoisoned(data, 256))
	if perr != nil || pd == nil || pd.Amount0.Cmp(delta.Amount0) != 0 || pd.Amount1.Cmp(delta.Amount1) != 0 {
		t.Fatalf("poisoned 64-byte return changed the verdict: %v %v", pd, perr)
	}

	// DEFECT: the decoder reads UNSIGNED. A hook returning the two's complement of
	// -1 -- the natural encoding for "the pool owes the user" -- is read as 2^256-1.
	neg := bytes.Repeat([]byte{0xff}, 64)
	nd, nerr := UnpackHookDeltaReturn(neg)
	if nerr != nil || nd == nil {
		t.Fatalf("all-ones return: %v %v", nd, nerr)
	}
	maxWord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if nd.Amount0.Cmp(maxWord) != 0 || nd.Amount1.Cmp(maxWord) != 0 {
		t.Fatalf("all-ones decoded as (%s, %s) -- signedness changed, update this test", nd.Amount0, nd.Amount1)
	}
}

// =========================================================================
// hooks.go -- dynamic fee calculator
// =========================================================================

func TestBlueDVolatilityFeeDegenerateWindows(t *testing.T) {
	calc := &VolatilityFeeCalculator{BaseFee: Fee030, MaxFee: Fee100, VolatilityScale: 100, WindowSize: 3600}
	for _, tc := range []struct {
		name string
		obs  []TWAPObservation
	}{
		{"nil", nil},
		{"one observation", []TWAPObservation{{Timestamp: 1, TickCumulative: big.NewInt(5)}}},
		{"zero time delta", []TWAPObservation{
			{Timestamp: 1000, TickCumulative: big.NewInt(0)},
			{Timestamp: 1000, TickCumulative: big.NewInt(1 << 40)}, // huge move, zero elapsed
		}},
	} {
		if fee := calc.CalculateFee(tc.obs); fee != Fee030 {
			t.Errorf("%s: fee = %d, want BaseFee %d", tc.name, fee, Fee030)
		}
	}
	// Only the LAST two observations decide the fee; earlier history is ignored.
	long := []TWAPObservation{
		{Timestamp: 1, TickCumulative: big.NewInt(1 << 40)},
		{Timestamp: 2, TickCumulative: big.NewInt(0)},
		{Timestamp: 3, TickCumulative: big.NewInt(0)},
	}
	if fee := calc.CalculateFee(long); fee != Fee030 {
		t.Errorf("long window: fee = %d, want BaseFee %d (only the last pair is read)", fee, Fee030)
	}
}

// TestBlueDVolatilityFeeWrapsBelowBaseFee pins a DEFECT: `uint24` is a Go alias for
// uint32, and the fee is built as `BaseFee + uint24(volatilityBps.Uint64())` with
// no bound. A large enough tick move wraps the uint32 addition and produces a fee
// BELOW BaseFee -- the arithmetic favours the swapper, which on a value path is
// exactly the wrong direction.
func TestBlueDVolatilityFeeWrapsBelowBaseFee(t *testing.T) {
	calc := &VolatilityFeeCalculator{BaseFee: 3000, MaxFee: 10000, VolatilityScale: 10000}
	obs := []TWAPObservation{
		{Timestamp: 1, TickCumulative: big.NewInt(0)},
		{Timestamp: 2, TickCumulative: big.NewInt(math.MaxUint32)}, // volatilityBps = 2^32-1
	}
	fee := calc.CalculateFee(obs)
	if fee >= calc.BaseFee {
		t.Fatalf("fee = %d >= BaseFee %d -- the wrap is gone, defect fixed, update this test", fee, calc.BaseFee)
	}
	if fee != 2999 {
		t.Fatalf("fee = %d, want 2999 (3000 + (2^32-1) mod 2^32)", fee)
	}
}

// TestBlueDVolatilityFeeIsDirectionAsymmetric pins a DEFECT: big.Int.Div is
// Euclidean, so it floors. A tick move of -1 over 2 seconds yields avgTick = -1
// (then |-1| = 1) while +1 over 2 seconds yields 0. Equal-magnitude moves in
// opposite directions are charged different fees.
func TestBlueDVolatilityFeeIsDirectionAsymmetric(t *testing.T) {
	calc := &VolatilityFeeCalculator{BaseFee: 3000, MaxFee: 10000, VolatilityScale: 10000}
	up := calc.CalculateFee([]TWAPObservation{
		{Timestamp: 10, TickCumulative: big.NewInt(0)},
		{Timestamp: 12, TickCumulative: big.NewInt(1)},
	})
	down := calc.CalculateFee([]TWAPObservation{
		{Timestamp: 10, TickCumulative: big.NewInt(0)},
		{Timestamp: 12, TickCumulative: big.NewInt(-1)},
	})
	if up == down {
		t.Fatalf("up and down both charge %d -- the asymmetry is gone, update this test", up)
	}
	if up != 3000 || down != 3001 {
		t.Fatalf("up = %d, down = %d; want 3000 and 3001", up, down)
	}
}

// TestBlueDVolatilityFeeOutOfOrderObservationsUnderflow pins a DEFECT: timeDelta is
// an unsigned subtraction with no ordering check. Observations that go backwards
// wrap it to ~2^64, and `int64(timeDelta)` then hands big.Int a NEGATIVE divisor.
func TestBlueDVolatilityFeeOutOfOrderObservationsUnderflow(t *testing.T) {
	calc := &VolatilityFeeCalculator{BaseFee: 3000, MaxFee: 10000, VolatilityScale: 10000}
	// prev at t=12, last at t=11: timeDelta wraps to 2^64-1, int64 = -1. Dividing
	// by -1 and then taking |.| gives back the forward answer, so a window that
	// runs BACKWARDS is priced exactly like the same window running forwards --
	// the elapsed-time denominator has stopped meaning anything.
	backward := calc.CalculateFee([]TWAPObservation{
		{Timestamp: 12, TickCumulative: big.NewInt(0)},
		{Timestamp: 11, TickCumulative: big.NewInt(500)},
	})
	forward := calc.CalculateFee([]TWAPObservation{
		{Timestamp: 11, TickCumulative: big.NewInt(0)},
		{Timestamp: 12, TickCumulative: big.NewInt(500)},
	})
	if backward != forward {
		t.Fatalf("backward = %d, forward = %d -- ordering is now checked, update this test", backward, forward)
	}
	if forward != 3500 {
		t.Fatalf("forward fee = %d, want 3500", forward)
	}
	// timeDelta wrapping to exactly 2^63 makes the divisor -2^63, which floors the
	// whole window to zero volatility: a huge move is priced at BaseFee.
	fee := calc.CalculateFee([]TWAPObservation{
		{Timestamp: 1 << 63, TickCumulative: big.NewInt(0)},
		{Timestamp: 0, TickCumulative: big.NewInt(1 << 62)},
	})
	if fee != calc.BaseFee {
		t.Fatalf("2^63 underflow fee = %d, want BaseFee %d", fee, calc.BaseFee)
	}
}

// =========================================================================
// hooks.go -- commit / reveal
// =========================================================================

// blueDCommitPreimage rebuilds ValidateReveal's preimage independently:
// sender(20) || direction(1) || amount(32) || minOutput(32).
func blueDCommitPreimage(sender common.Address, zeroForOne bool, amount, minOutput *big.Int) []byte {
	buf := make([]byte, 0, 85)
	buf = append(buf, sender.Bytes()...)
	if zeroForOne {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, amount.FillBytes(make([]byte, 32))...)
	buf = append(buf, minOutput.FillBytes(make([]byte, 32))...)
	return buf
}

func blueDCommitFor(r *RevealedSwap) *CommittedSwap {
	var h [32]byte
	copy(h[:], crypto.Keccak256(blueDCommitPreimage(r.Sender, r.ZeroForOne, r.Amount, r.MinOutput)))
	return &CommittedSwap{CommitHash: h, Sender: r.Sender, CommitBlock: 100, Amount: r.Amount}
}

func TestBlueDValidateRevealRefusesEveryMutation(t *testing.T) {
	crv := &CommitRevealValidator{CommitmentPeriod: 10}
	for _, dir := range []bool{true, false} {
		base := &RevealedSwap{
			Sender:     common.HexToAddress("0x00000000000000000000000000000000000dcafe"),
			ZeroForOne: dir,
			Amount:     big.NewInt(1_000_000),
			MinOutput:  big.NewInt(999_000),
		}
		commit := blueDCommitFor(base)
		if err := crv.ValidateReveal(commit, base); err != nil {
			t.Fatalf("dir=%v: honest reveal refused: %v", dir, err)
		}

		// A WRONG input must be refused -- one mutation per field, each alone.
		mutations := []struct {
			name string
			mut  func(r *RevealedSwap)
		}{
			{"sender", func(r *RevealedSwap) {
				r.Sender = common.HexToAddress("0x00000000000000000000000000000000000dbad0")
			}},
			{"direction", func(r *RevealedSwap) { r.ZeroForOne = !r.ZeroForOne }},
			{"amount +1", func(r *RevealedSwap) { r.Amount = big.NewInt(1_000_001) }},
			{"amount -1", func(r *RevealedSwap) { r.Amount = big.NewInt(999_999) }},
			{"minOutput +1", func(r *RevealedSwap) { r.MinOutput = big.NewInt(999_001) }},
			{"minOutput -1", func(r *RevealedSwap) { r.MinOutput = big.NewInt(998_999) }},
		}
		for _, m := range mutations {
			bad := *base
			m.mut(&bad)
			err := crv.ValidateReveal(commit, &bad)
			if err == nil {
				t.Errorf("dir=%v: mutated %s was ACCEPTED", dir, m.name)
				continue
			}
			if err.Error() != "reveal does not match commitment" {
				t.Errorf("dir=%v: mutated %s: got %q", dir, m.name, err)
			}
		}
		// A one-bit flip of the stored commitment is refused too.
		flipped := *commit
		flipped.CommitHash[31] ^= 1
		if err := crv.ValidateReveal(&flipped, base); err == nil {
			t.Errorf("dir=%v: a flipped commitment bit was accepted", dir)
		}
	}
}

// TestBlueDCommitmentCarriesNoSecret pins a DEFECT in the MEV-protection design:
// the preimage is sender||direction||amount||minOutput with NO nonce, salt, pool
// id or deadline. The commitment is therefore a deterministic function of a
// low-entropy intent, and an observer who guesses the four fields can confirm the
// guess offline -- which is the whole thing commit-reveal is supposed to prevent.
// It is also replayable: the same commitment validates against any pool.
func TestBlueDCommitmentCarriesNoSecret(t *testing.T) {
	crv := &CommitRevealValidator{CommitmentPeriod: 10}
	victim := &RevealedSwap{
		Sender:     common.HexToAddress("0x00000000000000000000000000000000000d01c7"),
		ZeroForOne: true,
		Amount:     big.NewInt(1e18),
		MinOutput:  big.NewInt(0),
	}
	commit := blueDCommitFor(victim)

	// A searcher who sees only commit.CommitHash and the sender brute-forces a
	// small candidate set of round amounts and recovers the intent exactly.
	var recovered *RevealedSwap
	for _, amt := range []int64{1e15, 1e16, 1e17, 1e18, 5e18} {
		for _, dir := range []bool{true, false} {
			guess := &RevealedSwap{Sender: victim.Sender, ZeroForOne: dir, Amount: big.NewInt(amt), MinOutput: big.NewInt(0)}
			if crv.ValidateReveal(commit, guess) == nil {
				recovered = guess
			}
		}
	}
	if recovered == nil {
		t.Fatal("commitment now resists a 10-candidate search -- a nonce was added, update this test")
	}
	if recovered.Amount.Cmp(victim.Amount) != 0 || recovered.ZeroForOne != victim.ZeroForOne {
		t.Fatalf("recovered (%s, %v), want (%s, %v)", recovered.Amount, recovered.ZeroForOne, victim.Amount, victim.ZeroForOne)
	}
}

// TestBlueDValidateCommitmentBoundary sweeps across the maturity boundary instead
// of sampling one point either side: the refuse window and the accept window must
// be adjacent and mutually exclusive.
func TestBlueDValidateCommitmentBoundary(t *testing.T) {
	crv := &CommitRevealValidator{CommitmentPeriod: 10}
	commit := &CommittedSwap{CommitBlock: 100, Amount: big.NewInt(1)}
	for b := uint64(96); b <= 114; b++ {
		err := crv.ValidateCommitment(commit, b)
		mature := b >= 110
		if mature && err != nil {
			t.Errorf("block %d: refused after maturity: %v", b, err)
		}
		if !mature && err == nil {
			t.Errorf("block %d: accepted before maturity (deadline 110)", b)
		}
	}
	// Period 0 matures immediately.
	zero := &CommitRevealValidator{CommitmentPeriod: 0}
	if err := zero.ValidateCommitment(commit, 100); err != nil {
		t.Errorf("period 0 must mature at the commit block: %v", err)
	}
	// There is no expiry: a commitment stays valid forever.
	if err := crv.ValidateCommitment(commit, math.MaxUint64); err != nil {
		t.Errorf("a commitment never expires today: %v", err)
	}
}

// TestBlueDValidateCommitmentOverflows pins a DEFECT: `commit.CommitBlock +
// crv.CommitmentPeriod` is unchecked uint64 addition. A commit block near 2^64
// wraps the deadline to a small number, so the commitment reads as mature
// immediately and the commit-reveal delay is skipped entirely.
func TestBlueDValidateCommitmentOverflows(t *testing.T) {
	crv := &CommitRevealValidator{CommitmentPeriod: 10}
	commit := &CommittedSwap{CommitBlock: math.MaxUint64 - 4, Amount: big.NewInt(1)}
	// True deadline is 2^64+5, which no block height can reach; the wrapped one is 5.
	if err := crv.ValidateCommitment(commit, 5); err != nil {
		t.Fatalf("overflow no longer opens the window at block 5 (%v) -- defect fixed, update this test", err)
	}
	if err := crv.ValidateCommitment(commit, 4); err == nil {
		t.Fatal("block 4 should still be below the wrapped deadline of 5")
	}
}

// =========================================================================
// transmuter.go -- refusals
// =========================================================================

func blueDTransmuter(t *testing.T) (*Transmuter, *MockStateDB) {
	t.Helper()
	tr := NewTransmuter(NewLiquid(NewPoolManager()))
	db := NewMockStateDB()
	if err := tr.InitializeTransmuter(db, blueDLiquid, blueDUnderlying); err != nil {
		t.Fatalf("InitializeTransmuter: %v", err)
	}
	return tr, db
}

func TestBlueDTransmuterInitializeIsNotIdempotent(t *testing.T) {
	tr, db := blueDTransmuter(t)
	// Move the state off its defaults so a silent re-initialize would be visible.
	if err := tr.Deposit(db, blueDLiquid, big.NewInt(777)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// NOTE: the second call reports ErrLiquidTokenNotRegistered, which is the
	// opposite of what happened -- the token IS registered. Misleading, but the
	// refusal itself is correct: the existing state must survive.
	err := tr.InitializeTransmuter(db, blueDLiquid, blueDUnderlying)
	if err != ErrLiquidTokenNotRegistered {
		t.Fatalf("re-initialize: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if got := tr.GetLiquidFXState(blueDLiquid).ExchangeBuffer; got.Cmp(big.NewInt(777)) != 0 {
		t.Fatalf("re-initialize clobbered the buffer: got %s, want 777", got)
	}
}

func TestBlueDTransmuterRefusesUnregisteredToken(t *testing.T) {
	tr, db := blueDTransmuter(t)
	other := common.HexToAddress("0x00000000000000000000000000000000000d9999")

	if err := tr.Stake(db, blueDUser, other, big.NewInt(1)); err != ErrLiquidTokenNotRegistered {
		t.Errorf("Stake: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if err := tr.Unstake(db, blueDUser, other, big.NewInt(1)); err != ErrLiquidTokenNotRegistered {
		t.Errorf("Unstake: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if _, err := tr.Claim(db, blueDUser, other); err != ErrLiquidTokenNotRegistered {
		t.Errorf("Claim: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if err := tr.Deposit(db, other, big.NewInt(1)); err != ErrLiquidTokenNotRegistered {
		t.Errorf("Deposit: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if got := tr.GetClaimable(db, blueDUser, other); got.Sign() != 0 {
		t.Errorf("GetClaimable on an unregistered token = %s, want 0", got)
	}
	// The unregistered exchange rate is the 1:1 identity, and it is a COPY.
	rate := tr.GetExchangeRate(other)
	if rate.Cmp(Q96) != 0 {
		t.Errorf("GetExchangeRate on an unregistered token = %s, want Q96", rate)
	}
	if rate == Q96 {
		t.Error("GetExchangeRate handed out the package-level Q96 itself, not a copy")
	}
	// No refusal may leave state behind.
	if n := len(tr.states); n != 1 {
		t.Errorf("refusals registered %d extra states", n-1)
	}
}

func TestBlueDTransmuterStakeRefusesNonPositive(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))

	for _, amt := range []*big.Int{big.NewInt(0), big.NewInt(-1), big.NewInt(-1e9)} {
		if err := tr.Stake(db, blueDUser, blueDLiquid, amt); err != ErrInvalidPositionSize {
			t.Errorf("Stake(%s): got %v, want ErrInvalidPositionSize", amt, err)
		}
	}
	if got := tr.GetLiquidFXState(blueDLiquid).TotalStaked; got.Sign() != 0 {
		t.Errorf("a refused stake moved TotalStaked to %s", got)
	}
	if got := db.GetBalance(blueDUser); !got.Eq(uint256.NewInt(1000)) {
		t.Errorf("a refused stake moved the balance to %s", got)
	}
	if tr.GetStake(db, blueDUser, blueDLiquid) != nil {
		t.Error("a refused stake created a stake record")
	}
}

func TestBlueDTransmuterUnstakeRefusesEmptyPosition(t *testing.T) {
	tr, db := blueDTransmuter(t)
	// No stake at all.
	if err := tr.Unstake(db, blueDUser, blueDLiquid, big.NewInt(1)); err != ErrInvalidPositionSize {
		t.Errorf("Unstake with no stake: got %v, want ErrInvalidPositionSize", err)
	}
	// A stake that exists but has been drained to zero.
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	if err := tr.Unstake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Unstake: %v", err)
	}
	if err := tr.Unstake(db, blueDUser, blueDLiquid, big.NewInt(1)); err != ErrInvalidPositionSize {
		t.Errorf("Unstake on a drained stake: got %v, want ErrInvalidPositionSize", err)
	}
}

func TestBlueDTransmuterUnstakeCapsAtStakedAmount(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// Ask for 10x the position: the excess must be silently capped, never minted.
	if err := tr.Unstake(db, blueDUser, blueDLiquid, big.NewInt(1000)); err != nil {
		t.Fatalf("Unstake: %v", err)
	}
	if got := tr.GetStake(db, blueDUser, blueDLiquid).StakedAmount; got.Sign() != 0 {
		t.Errorf("StakedAmount after over-unstake = %s, want 0", got)
	}
	if got := tr.GetLiquidFXState(blueDLiquid).TotalStaked; got.Sign() != 0 {
		t.Errorf("TotalStaked after over-unstake = %s, want 0", got)
	}
	// Exactly the staked amount came back -- not the amount asked for.
	if got := db.GetBalance(blueDUser); !got.Eq(uint256.NewInt(1000)) {
		t.Errorf("user balance = %s, want the original 1000", got)
	}
	if got := db.GetBalance(transmuterAddr); !got.IsZero() {
		t.Errorf("transmuter balance = %s, want 0", got)
	}
}

// TestBlueDTransmuterUnstakeAcceptsNegative pins a DEFECT: Stake guards
// `amount.Sign() <= 0` and Unstake does not. A negative unstake passes the
// `amount > StakedAmount` cap untouched, so `StakedAmount - amount` INCREASES the
// position and `TotalStaked - amount` inflates the pool total. The value move
// goes through uint256.FromBig, which turns a negative big.Int into its 2^256
// complement and reports overflow=false -- so even the discarded bool would not
// have caught it.
func TestBlueDTransmuterUnstakeAcceptsNegative(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	err := tr.Unstake(db, blueDUser, blueDLiquid, big.NewInt(-50))
	if err != nil {
		t.Fatalf("negative Unstake is now refused (%v) -- defect fixed, update this test", err)
	}
	if got := tr.GetStake(db, blueDUser, blueDLiquid).StakedAmount; got.Cmp(big.NewInt(150)) != 0 {
		t.Fatalf("StakedAmount after Unstake(-50) = %s, want 150 (the position GREW)", got)
	}
	if got := tr.GetLiquidFXState(blueDLiquid).TotalStaked; got.Cmp(big.NewInt(150)) != 0 {
		t.Fatalf("TotalStaked after Unstake(-50) = %s, want 150", got)
	}
	// uint256.FromBig(-50) is 2^256-50, so SubBalance/AddBalance run backwards.
	neg50, over := uint256.FromBig(big.NewInt(-50))
	if over {
		t.Fatal("uint256.FromBig now reports overflow for a negative -- update this test")
	}
	if !neg50.Eq(new(uint256.Int).Sub(uint256.NewInt(0), uint256.NewInt(50))) {
		t.Fatalf("uint256.FromBig(-50) = %s, want 2^256-50", neg50)
	}
}

func TestBlueDTransmuterClaimArms(t *testing.T) {
	tr, db := blueDTransmuter(t)

	// No stake record at all.
	if _, err := tr.Claim(db, blueDUser, blueDLiquid); err != ErrTransmuterEmpty {
		t.Errorf("Claim with no stake: got %v, want ErrTransmuterEmpty", err)
	}

	setBalance(db, blueDUser, big.NewInt(1000))
	setBalance(db, transmuterAddr, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	// Staked but nothing has converted: a zero claim is a success, not an error.
	got, err := tr.Claim(db, blueDUser, blueDLiquid)
	if err != nil {
		t.Fatalf("zero Claim: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("zero Claim returned %s, want 0", got)
	}

	// Accrue 50, then drain the buffer behind the staker's back so the claim must
	// be capped: a claim can never pay out more underlying than the buffer holds.
	if err := tr.Deposit(db, blueDLiquid, big.NewInt(50)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	state := tr.GetLiquidFXState(blueDLiquid)
	state.ExchangeBuffer = big.NewInt(15)
	got, err = tr.Claim(db, blueDUser, blueDLiquid)
	if err != nil {
		t.Fatalf("capped Claim: %v", err)
	}
	if got.Cmp(big.NewInt(15)) != 0 {
		t.Fatalf("capped Claim returned %s, want the buffer's 15", got)
	}
	if state.ExchangeBuffer.Sign() != 0 {
		t.Fatalf("buffer after a capped claim = %s, want 0", state.ExchangeBuffer)
	}
	if rem := tr.GetStake(db, blueDUser, blueDLiquid).UnclaimedAmount; rem.Cmp(big.NewInt(35)) != 0 {
		t.Fatalf("unclaimed remainder = %s, want 35 still owed", rem)
	}
}

func TestBlueDTransmuterDepositNonPositiveIsNoop(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	before := new(big.Int).Set(tr.GetExchangeRate(blueDLiquid))

	for _, amt := range []*big.Int{big.NewInt(0), big.NewInt(-1), big.NewInt(-1e12)} {
		if err := tr.Deposit(db, blueDLiquid, amt); err != nil {
			t.Errorf("Deposit(%s): got %v, want nil", amt, err)
		}
	}
	state := tr.GetLiquidFXState(blueDLiquid)
	if state.ExchangeBuffer.Sign() != 0 {
		t.Errorf("a non-positive deposit moved the buffer to %s", state.ExchangeBuffer)
	}
	if tr.GetExchangeRate(blueDLiquid).Cmp(before) != 0 {
		t.Error("a non-positive deposit moved the exchange rate")
	}
	if got := tr.GetClaimable(db, blueDUser, blueDLiquid); got.Sign() != 0 {
		t.Errorf("a non-positive deposit made %s claimable", got)
	}
}

func TestBlueDTransmuterGetClaimableArms(t *testing.T) {
	tr, db := blueDTransmuter(t)
	// Registered token, no stake record.
	if got := tr.GetClaimable(db, blueDUser, blueDLiquid); got.Sign() != 0 {
		t.Errorf("GetClaimable with no stake = %s, want 0", got)
	}

	setBalance(db, blueDUser, big.NewInt(1000))
	setBalance(db, transmuterAddr, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	if err := tr.Deposit(db, blueDLiquid, big.NewInt(50)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if got := tr.GetClaimable(db, blueDUser, blueDLiquid); got.Cmp(big.NewInt(50)) != 0 {
		t.Fatalf("GetClaimable = %s, want 50", got)
	}
	// Drain the buffer: the quote must be capped at what can actually be paid.
	tr.GetLiquidFXState(blueDLiquid).ExchangeBuffer = big.NewInt(11)
	if got := tr.GetClaimable(db, blueDUser, blueDLiquid); got.Cmp(big.NewInt(11)) != 0 {
		t.Fatalf("GetClaimable with an 11-wei buffer = %s, want 11", got)
	}
	// And a quote must never exceed what Claim actually pays.
	quote := tr.GetClaimable(db, blueDUser, blueDLiquid)
	paid, err := tr.Claim(db, blueDUser, blueDLiquid)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if quote.Cmp(paid) != 0 {
		t.Fatalf("GetClaimable quoted %s but Claim paid %s", quote, paid)
	}
}

func TestBlueDTransmuterExchangeRateIsACopy(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	if got := tr.GetExchangeRate(blueDLiquid); got.Cmp(Q96) != 0 {
		t.Fatalf("initial rate = %s, want Q96", got)
	}
	if err := tr.Deposit(db, blueDLiquid, big.NewInt(50)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	// 50 underlying over 100 staked lifts the rate by exactly Q96/2.
	want := new(big.Int).Add(Q96, new(big.Int).Div(Q96, big.NewInt(2)))
	rate := tr.GetExchangeRate(blueDLiquid)
	if rate.Cmp(want) != 0 {
		t.Fatalf("rate after a 50%% deposit = %s, want %s", rate, want)
	}
	rate.SetInt64(1)
	if tr.GetExchangeRate(blueDLiquid).Cmp(want) != 0 {
		t.Fatal("GetExchangeRate handed out a mutable alias of the live state")
	}
	// GetLiquidFXState, by contrast, DOES hand out the live struct: a "view" can
	// rewrite the transmuter's books. Pinned so a fix is deliberate.
	tr.GetLiquidFXState(blueDLiquid).ExchangeRate = big.NewInt(1)
	if tr.GetExchangeRate(blueDLiquid).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("GetLiquidFXState now returns a copy -- defect fixed, update this test")
	}
}

func TestBlueDTransmuterFullConversionZeroesTheStake(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	setBalance(db, transmuterAddr, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// Deposit MORE underlying than is staked: every staked token converts and the
	// position must land on exactly zero, never negative.
	if err := tr.Deposit(db, blueDLiquid, big.NewInt(250)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	paid, err := tr.Claim(db, blueDUser, blueDLiquid)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if paid.Cmp(big.NewInt(250)) != 0 {
		t.Fatalf("claimed %s, want the full 250", paid)
	}
	stake := tr.GetStake(db, blueDUser, blueDLiquid)
	if stake.StakedAmount.Sign() != 0 {
		t.Fatalf("StakedAmount after full conversion = %s, want 0", stake.StakedAmount)
	}
	if stake.UnclaimedAmount.Sign() != 0 {
		t.Fatalf("UnclaimedAmount after a full claim = %s, want 0", stake.UnclaimedAmount)
	}
	// TotalStaked is NOT reduced by conversion -- only Unstake touches it -- so the
	// pool total now overstates the live stake. Every later Deposit is divided by
	// this stale 100 and under-credits the remaining stakers.
	if got := tr.GetLiquidFXState(blueDLiquid).TotalStaked; got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("TotalStaked = %s; conversion no longer leaves it stale -- update this test", got)
	}
}

// TestBlueDTransmuterAccrualNeverExceedsDeposit is the rounding-direction check.
// Both divisions (rate = amount*Q96/total, accrual = staked*rateDiff/Q96) floor,
// so the sum of what stakers can claim must never exceed what was deposited. A
// rounding direction that favoured the caller would break this.
func TestBlueDTransmuterAccrualNeverExceedsDeposit(t *testing.T) {
	type row struct{ s1, s2, dep int64 }
	for _, r := range []row{
		{1, 1, 1}, {1, 2, 1}, {3, 7, 5}, {7, 11, 13}, {1, 999999937, 1},
		{999999937, 1, 999999937}, {1 << 40, 3, 7}, {17, 19, 1 << 40},
	} {
		tr, db := blueDTransmuter(t)
		setBalance(db, blueDUser, bigInt("1000000000000000000000000"))
		setBalance(db, blueDUser2, bigInt("1000000000000000000000000"))
		if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(r.s1)); err != nil {
			t.Fatalf("%+v Stake1: %v", r, err)
		}
		if err := tr.Stake(db, blueDUser2, blueDLiquid, big.NewInt(r.s2)); err != nil {
			t.Fatalf("%+v Stake2: %v", r, err)
		}
		if err := tr.Deposit(db, blueDLiquid, big.NewInt(r.dep)); err != nil {
			t.Fatalf("%+v Deposit: %v", r, err)
		}
		total := new(big.Int).Add(
			tr.GetClaimable(db, blueDUser, blueDLiquid),
			tr.GetClaimable(db, blueDUser2, blueDLiquid),
		)
		if total.Cmp(big.NewInt(r.dep)) > 0 {
			t.Errorf("%+v: stakers can claim %s from a %d deposit -- rounding favours the caller", r, total, r.dep)
		}
		if total.Sign() < 0 {
			t.Errorf("%+v: negative claimable %s", r, total)
		}
	}
}

// TestBlueDTransmuterFreeStakePoisonsTheRate pins a DEFECT: transferSynthetic
// discards the overflow verdict from uint256.FromBig. A stake of 2^256 moves ZERO
// value (the u256 is the low 256 bits = 0) yet credits the full big.Int to both
// StakedAmount and TotalStaked. Every later Deposit then divides by ~2^256, so
// the rate increase floors to zero and no honest staker ever accrues again --
// a permanent denial of yield bought for nothing.
func TestBlueDTransmuterFreeStakePoisonsTheRate(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("honest Stake: %v", err)
	}

	poison := new(big.Int).Lsh(big.NewInt(1), 256)
	attacker := common.HexToAddress("0x00000000000000000000000000000000000d0501")
	before := db.GetBalance(attacker).Clone()
	if err := tr.Stake(db, attacker, blueDLiquid, poison); err != nil {
		t.Fatalf("2^256 Stake is now refused (%v) -- defect fixed, update this test", err)
	}
	if got := db.GetBalance(attacker); !got.Eq(before) {
		t.Fatalf("attacker balance moved from %s to %s; the stake was supposed to cost nothing", before, got)
	}
	if got := tr.GetStake(db, attacker, blueDLiquid).StakedAmount; got.Cmp(poison) != 0 {
		t.Fatalf("attacker StakedAmount = %s, want the uncharged 2^256", got)
	}

	rateBefore := tr.GetExchangeRate(blueDLiquid)
	if err := tr.Deposit(db, blueDLiquid, bigInt("1000000000000000000")); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if tr.GetExchangeRate(blueDLiquid).Cmp(rateBefore) != 0 {
		t.Fatal("the poisoned TotalStaked no longer floors the rate increase -- update this test")
	}
	if got := tr.GetClaimable(db, blueDUser, blueDLiquid); got.Sign() != 0 {
		t.Fatalf("honest staker claimable = %s, want 0 (yield denied)", got)
	}
}

// TestBlueDTransmuterStakeIsNotBalanceChecked pins a DEFECT: transferSynthetic
// calls SubBalance directly, with no check that the payer holds the amount.
// uint256 subtraction wraps, so an under-funded stake leaves the caller holding
// ~2^256 wei of spendable balance.
func TestBlueDTransmuterStakeIsNotBalanceChecked(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(5))

	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(10)); err != nil {
		t.Fatalf("under-funded Stake is now refused (%v) -- defect fixed, update this test", err)
	}
	want := new(uint256.Int).Sub(uint256.NewInt(5), uint256.NewInt(10)) // 2^256-5
	if got := db.GetBalance(blueDUser); !got.Eq(want) {
		t.Fatalf("balance after staking 10 with 5 = %s, want the wrapped %s", got, want)
	}
	if got := tr.GetStake(db, blueDUser, blueDLiquid).StakedAmount; got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("StakedAmount = %s, want the full 10 credited", got)
	}
}

// =========================================================================
// transmuter.go -- storage round trip
// =========================================================================

// TestBlueDTransmuterStakeStorageRoundTrip pins a DEFECT in the only path that
// reads a stake back from StateDB. saveStake does `copy(data[:16], v.Bytes())`,
// which LEFT-aligns a minimal big-endian value inside the 16-byte field; getStake
// reads the field back with SetBytes, which is right-aligned. The two disagree by
// 2^(8*(16-len)) unless the value happens to occupy exactly 16 bytes.
//
// The in-memory `stakes` map hides this for the life of one Transmuter, so it
// surfaces only on a fresh instance reading persisted state -- which is precisely
// the case two validators must agree on.
func TestBlueDTransmuterStakeStorageRoundTrip(t *testing.T) {
	for _, amt := range []*big.Int{
		big.NewInt(1),
		big.NewInt(100),
		bigInt("100000000000000000000"),      // 1e20: 9 bytes
		new(big.Int).Lsh(big.NewInt(1), 127), // exactly 16 bytes
		new(big.Int).Lsh(big.NewInt(1), 128), // 17 bytes: truncated
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)), // exactly 16 bytes
	} {
		tr, db := blueDTransmuter(t)
		setBalance(db, blueDUser, new(big.Int).Lsh(big.NewInt(1), 200))
		if err := tr.Stake(db, blueDUser, blueDLiquid, amt); err != nil {
			t.Fatalf("Stake(%s): %v", amt, err)
		}
		// Drop the write-through cache: this is what a fresh Transmuter sees.
		tr.stakes = make(map[[32]byte]*TransmuterStake)

		restored := tr.GetStake(db, blueDUser, blueDLiquid)
		if restored == nil {
			t.Fatalf("Stake(%s): nothing persisted", amt)
		}

		n := len(amt.Bytes())
		var want *big.Int
		switch {
		case n == 16:
			want = new(big.Int).Set(amt) // the one length that survives
		case n < 16:
			want = new(big.Int).Lsh(amt, uint(8*(16-n))) // left-aligned, read right-aligned
		default:
			want = new(big.Int).SetBytes(amt.Bytes()[:16]) // high bytes kept, low bytes dropped
		}
		if restored.StakedAmount.Cmp(want) != 0 {
			t.Fatalf("Stake(%s) reloaded as %s, want the mis-aligned %s", amt, restored.StakedAmount, want)
		}
		if n != 16 && restored.StakedAmount.Cmp(amt) == 0 {
			t.Fatalf("Stake(%s) now round-trips -- defect fixed, update this test", amt)
		}
		// The owner and token are not persisted at all.
		if restored.Owner != (common.Address{}) || restored.LiquidToken != (common.Address{}) {
			t.Fatalf("reloaded stake carries an identity (%s / %s) it should not have", restored.Owner, restored.LiquidToken)
		}
		// LastUpdateIndex is reset to Q96 rather than restored, so a reloaded stake
		// re-accrues every rate move that ever happened.
		if restored.LastUpdateIndex.Cmp(Q96) != 0 {
			t.Fatalf("reloaded LastUpdateIndex = %s, want the hard-coded Q96", restored.LastUpdateIndex)
		}
	}
}

// TestBlueDTransmuterReloadReAccruesYield is the consequence of the hard-coded
// LastUpdateIndex above: a stake that reloads from storage after the exchange rate
// has moved accrues that entire move a SECOND time.
func TestBlueDTransmuterReloadReAccruesYield(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, new(big.Int).Lsh(big.NewInt(1), 200))
	setBalance(db, transmuterAddr, new(big.Int).Lsh(big.NewInt(1), 200))
	staked := new(big.Int).Lsh(big.NewInt(1), 127) // 16 bytes: round-trips exactly
	if err := tr.Stake(db, blueDUser, blueDLiquid, staked); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	// Move the rate, then settle the accrual so UnclaimedAmount is up to date.
	if err := tr.Deposit(db, blueDLiquid, new(big.Int).Rsh(staked, 1)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	firstAccrual := tr.GetClaimable(db, blueDUser, blueDLiquid)
	if firstAccrual.Sign() <= 0 {
		t.Fatalf("first accrual = %s, want a positive amount", firstAccrual)
	}

	tr.stakes = make(map[[32]byte]*TransmuterStake)
	reloaded := tr.GetClaimable(db, blueDUser, blueDLiquid)
	if reloaded.Sign() <= 0 {
		t.Fatalf("reloaded claimable = %s -- the reload no longer re-accrues, update this test", reloaded)
	}
	// The reloaded stake's UnclaimedAmount was persisted as 0 (nothing had been
	// settled), yet it still quotes a claim, because LastUpdateIndex came back as
	// Q96 while the live rate is 1.5*Q96.
	if got := tr.GetStake(db, blueDUser, blueDLiquid).UnclaimedAmount; got.Sign() != 0 {
		t.Fatalf("persisted UnclaimedAmount = %s, want 0", got)
	}
}

// TestBlueDTransmuterViewsWriteUnderAReadLock pins a DEFECT: GetStake and
// GetClaimable take mu.RLock and then call getStake, which writes t.stakes. Two
// concurrent readers therefore write the same map with no writer lock held --
// Go's runtime answers that with a fatal "concurrent map writes", which on a
// validator is a halt, not an error. Asserted deterministically here: a read-only
// call must not change the map, and it does.
func TestBlueDTransmuterViewsWriteUnderAReadLock(t *testing.T) {
	tr, db := blueDTransmuter(t)
	setBalance(db, blueDUser, big.NewInt(1000))
	if err := tr.Stake(db, blueDUser, blueDLiquid, big.NewInt(100)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	tr.stakes = make(map[[32]byte]*TransmuterStake)
	if got := tr.GetStake(db, blueDUser, blueDLiquid); got == nil {
		t.Fatal("GetStake found nothing to reload")
	}
	if len(tr.stakes) != 1 {
		t.Fatalf("GetStake (RLock) left %d cache entries, want the 1 it wrote", len(tr.stakes))
	}

	tr.stakes = make(map[[32]byte]*TransmuterStake)
	if got := tr.GetClaimable(db, blueDUser, blueDLiquid); got == nil {
		t.Fatal("GetClaimable returned nil")
	}
	if len(tr.stakes) != 1 {
		t.Fatalf("GetClaimable (RLock) left %d cache entries, want the 1 it wrote", len(tr.stakes))
	}
}
