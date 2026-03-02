// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// =========================================================================
// Selector Verification Tests
// =========================================================================

func TestABISelectors(t *testing.T) {
	tests := []struct {
		name     string
		selector uint32
		sig      string
	}{
		{"initialize", SelectorInitialize, "initialize((address,address,uint24,int24,address),uint160)"},
		{"swap", SelectorSwap, "swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)"},
		{"modifyLiquidity", SelectorModifyLiquidity, "modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"},
		{"donate", SelectorDonate, "donate((address,address,uint24,int24,address),uint256,uint256,bytes)"},
		{"unlock", SelectorUnlock, "unlock(bytes)"},
		{"settle", SelectorSettle, "settle()"},
		{"settleFor", SelectorSettleFor, "settleFor(address)"},
		{"sync", SelectorSync, "sync(address)"},
		{"take", SelectorTake, "take(address,address,uint256)"},
		{"clear", SelectorClear, "clear(address,uint256)"},
		{"mint", SelectorMint, "mint(address,uint256,uint256)"},
		{"burn", SelectorBurn, "burn(address,uint256,uint256)"},
		{"updateDynamicLPFee", SelectorUpdateDynFee, "updateDynamicLPFee((address,address,uint24,int24,address),uint24)"},
		{"extsload", SelectorExtsload, "extsload(bytes32)"},
		{"extsloadArray", SelectorExtsloadArray, "extsload(bytes32[])"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := crypto.Keccak256([]byte(tt.sig))
			want := binary.BigEndian.Uint32(hash[:4])
			if tt.selector != want {
				t.Errorf("selector mismatch for %s: got 0x%08X, want 0x%08X", tt.name, tt.selector, want)
			}
		})
	}
}

func TestABIKeccak4Helper(t *testing.T) {
	// Verify keccak4 helper produces correct results
	got := keccak4("initialize((address,address,uint24,int24,address),uint160)")
	if got != 0x6276CBBE {
		t.Errorf("keccak4 mismatch: got 0x%08X, want 0x6276CBBE", got)
	}
}

// =========================================================================
// PoolKey ABI Encoding/Decoding Tests
// =========================================================================

func TestABIPoolKeyRoundTrip(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.HexToAddress("0x0000000000000000000000000000000000002400"),
	}

	// Encode
	encoded := EncodePoolKeyABI(key)
	if len(encoded) != 160 {
		t.Fatalf("EncodePoolKeyABI should produce 160 bytes, got %d", len(encoded))
	}

	// Decode
	decoded, err := DecodePoolKey(encoded)
	if err != nil {
		t.Fatalf("DecodePoolKey failed: %v", err)
	}

	if decoded.Currency0.Address != key.Currency0.Address {
		t.Errorf("Currency0 mismatch: got %s, want %s", decoded.Currency0.Address.Hex(), key.Currency0.Address.Hex())
	}
	if decoded.Currency1.Address != key.Currency1.Address {
		t.Errorf("Currency1 mismatch: got %s, want %s", decoded.Currency1.Address.Hex(), key.Currency1.Address.Hex())
	}
	if decoded.Fee != key.Fee {
		t.Errorf("Fee mismatch: got %d, want %d", decoded.Fee, key.Fee)
	}
	if decoded.TickSpacing != key.TickSpacing {
		t.Errorf("TickSpacing mismatch: got %d, want %d", decoded.TickSpacing, key.TickSpacing)
	}
	if decoded.Hooks != key.Hooks {
		t.Errorf("Hooks mismatch: got %s, want %s", decoded.Hooks.Hex(), key.Hooks.Hex())
	}
}

func TestABIPoolKeyNegativeTickSpacing(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         500,
		TickSpacing: -10,
		Hooks:       common.Address{},
	}

	encoded := EncodePoolKeyABI(key)
	decoded, err := DecodePoolKey(encoded)
	if err != nil {
		t.Fatalf("DecodePoolKey failed: %v", err)
	}

	if decoded.TickSpacing != -10 {
		t.Errorf("Negative TickSpacing mismatch: got %d, want -10", decoded.TickSpacing)
	}
}

func TestABIPoolKeyTooShort(t *testing.T) {
	_, err := DecodePoolKey(make([]byte, 128))
	if err == nil {
		t.Error("Expected error for 128-byte input (V4 requires 160)")
	}
}

// =========================================================================
// PoolKey.ID() Tests (keccak256 of ABI-encoded PoolKey)
// =========================================================================

func TestABIPoolKeyID(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	id := key.ID()

	// Verify it equals keccak256(abi.encode(poolKey))
	encoded := EncodePoolKeyABI(key)
	expectedHash := crypto.Keccak256(encoded)
	var expected [32]byte
	copy(expected[:], expectedHash)

	if id != expected {
		t.Errorf("PoolKey.ID() mismatch:\ngot  %x\nwant %x", id, expected)
	}
}

func TestABIPoolKeyIDDeterministic(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7")},
		Currency1:   Currency{Address: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")},
		Fee:         100,
		TickSpacing: 1,
		Hooks:       common.Address{},
	}

	id1 := key.ID()
	id2 := key.ID()

	if id1 != id2 {
		t.Error("PoolKey.ID() should be deterministic")
	}
}

func TestABIPoolKeyIDDifferentKeys(t *testing.T) {
	key1 := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
	key2 := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         500, // different fee
		TickSpacing: 10,
		Hooks:       common.Address{},
	}

	if key1.ID() == key2.ID() {
		t.Error("Different PoolKeys should produce different IDs")
	}
}

// =========================================================================
// BalanceDelta Packing Tests
// =========================================================================

func TestABIBalanceDeltaPack(t *testing.T) {
	tests := []struct {
		name    string
		amount0 *big.Int
		amount1 *big.Int
	}{
		{"both positive", big.NewInt(1000), big.NewInt(2000)},
		{"both negative", big.NewInt(-1000), big.NewInt(-2000)},
		{"mixed signs", big.NewInt(1000), big.NewInt(-500)},
		{"zeros", big.NewInt(0), big.NewInt(0)},
		{"large positive", new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(42)},
		{"large negative", new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 100)), big.NewInt(-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := PackBalanceDelta(tt.amount0, tt.amount1)
			if len(packed) != 32 {
				t.Fatalf("packed should be 32 bytes, got %d", len(packed))
			}

			a0, a1 := UnpackBalanceDelta(packed)
			if a0.Cmp(tt.amount0) != 0 {
				t.Errorf("amount0 roundtrip failed: got %s, want %s", a0, tt.amount0)
			}
			if a1.Cmp(tt.amount1) != 0 {
				t.Errorf("amount1 roundtrip failed: got %s, want %s", a1, tt.amount1)
			}
		})
	}
}

func TestABIBalanceDeltaV4Format(t *testing.T) {
	// V4: BalanceDelta = (amount0 << 128) | (amount1 & ((1<<128)-1))
	// Example: amount0 = 100, amount1 = -200
	amount0 := big.NewInt(100)
	amount1 := big.NewInt(-200)
	packed := PackBalanceDelta(amount0, amount1)

	// Upper 128 bits should be amount0
	upper := new(big.Int).SetBytes(packed[0:16])
	if upper.Cmp(amount0) != 0 {
		t.Errorf("upper 128 bits should be amount0: got %s, want %s", upper, amount0)
	}

	// Lower 128 bits should be amount1 in two's complement (2^128 - 200)
	lower := new(big.Int).SetBytes(packed[16:32])
	expected := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), amount1)
	if lower.Cmp(expected) != 0 {
		t.Errorf("lower 128 bits should be amount1 twos complement: got %s, want %s", lower, expected)
	}
}

// =========================================================================
// Hook Address Trailing Bit Tests
// =========================================================================

func TestABIHookFlagsV4BitPositions(t *testing.T) {
	// V4 Hooks.sol defines:
	//   BEFORE_INITIALIZE_FLAG = 1 << 13
	//   AFTER_INITIALIZE_FLAG = 1 << 12
	//   ...
	//   AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG = 1 << 0
	if HookBeforeInitialize != 1<<13 {
		t.Errorf("HookBeforeInitialize should be 1<<13, got %d", HookBeforeInitialize)
	}
	if HookAfterInitialize != 1<<12 {
		t.Errorf("HookAfterInitialize should be 1<<12, got %d", HookAfterInitialize)
	}
	if HookBeforeAddLiquidity != 1<<11 {
		t.Errorf("HookBeforeAddLiquidity should be 1<<11, got %d", HookBeforeAddLiquidity)
	}
	if HookAfterAddLiquidity != 1<<10 {
		t.Errorf("HookAfterAddLiquidity should be 1<<10, got %d", HookAfterAddLiquidity)
	}
	if HookBeforeRemoveLiquidity != 1<<9 {
		t.Errorf("HookBeforeRemoveLiquidity should be 1<<9, got %d", HookBeforeRemoveLiquidity)
	}
	if HookAfterRemoveLiquidity != 1<<8 {
		t.Errorf("HookAfterRemoveLiquidity should be 1<<8, got %d", HookAfterRemoveLiquidity)
	}
	if HookBeforeSwap != 1<<7 {
		t.Errorf("HookBeforeSwap should be 1<<7, got %d", HookBeforeSwap)
	}
	if HookAfterSwap != 1<<6 {
		t.Errorf("HookAfterSwap should be 1<<6, got %d", HookAfterSwap)
	}
	if HookBeforeDonate != 1<<5 {
		t.Errorf("HookBeforeDonate should be 1<<5, got %d", HookBeforeDonate)
	}
	if HookAfterDonate != 1<<4 {
		t.Errorf("HookAfterDonate should be 1<<4, got %d", HookAfterDonate)
	}
	if HookBeforeSwapReturnsDelta != 1<<3 {
		t.Errorf("HookBeforeSwapReturnsDelta should be 1<<3, got %d", HookBeforeSwapReturnsDelta)
	}
	if HookAfterSwapReturnsDelta != 1<<2 {
		t.Errorf("HookAfterSwapReturnsDelta should be 1<<2, got %d", HookAfterSwapReturnsDelta)
	}
	if HookAfterAddLiquidityReturnsDelta != 1<<1 {
		t.Errorf("HookAfterAddLiquidityReturnsDelta should be 1<<1, got %d", HookAfterAddLiquidityReturnsDelta)
	}
	if HookAfterRemoveLiquidityReturnsDelta != 1<<0 {
		t.Errorf("HookAfterRemoveLiquidityReturnsDelta should be 1<<0, got %d", HookAfterRemoveLiquidityReturnsDelta)
	}
}

func TestABIHookAddressTrailingBits(t *testing.T) {
	// V4 example from Hooks.sol:
	// 0x0000000000000000000000000000000000002400
	// binary of 0x2400 = '10 0100 0000 0000'
	// bit 13 = 1 (BEFORE_INITIALIZE)
	// bit 10 = 1 (AFTER_ADD_LIQUIDITY)
	addr := common.HexToAddress("0x0000000000000000000000000000000000002400")
	perms := GetHookPermissionsFromAddress(addr)

	if !perms.BeforeInitialize {
		t.Error("Expected BeforeInitialize from 0x2400 (bit 13)")
	}
	if !perms.AfterAddLiquidity {
		t.Error("Expected AfterAddLiquidity from 0x2400 (bit 10)")
	}
	if perms.BeforeSwap {
		t.Error("Did not expect BeforeSwap from 0x2400")
	}
}

func TestABIHookAddressBeforeAfterSwap(t *testing.T) {
	// beforeSwap = 1<<7 = 0x0080, afterSwap = 1<<6 = 0x0040
	// combined = 0x00C0
	addr := common.HexToAddress("0x00000000000000000000000000000000000000C0")
	perms := GetHookPermissionsFromAddress(addr)

	if !perms.BeforeSwap {
		t.Error("Expected BeforeSwap from 0x00C0 (bit 7)")
	}
	if !perms.AfterSwap {
		t.Error("Expected AfterSwap from 0x00C0 (bit 6)")
	}
	if perms.BeforeInitialize {
		t.Error("Did not expect BeforeInitialize")
	}
}

// =========================================================================
// Swap Input Decoding Tests
// =========================================================================

func TestABIDecodeSwapInput(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	// Build V4 ABI-encoded swap input (after 4-byte selector)
	input := make([]byte, 256)
	// PoolKey (160 bytes)
	copy(input[0:160], EncodePoolKeyABI(key))
	// zeroForOne (32 bytes, bool)
	input[191] = 1
	// amountSpecified (32 bytes, int256) = -1000 (exact input in V4)
	amountSpec := big.NewInt(-1000)
	copy(input[192:224], bigIntTo32Bytes(amountSpec))
	// sqrtPriceLimitX96 (32 bytes, uint160)
	priceLimit := new(big.Int).SetUint64(4295128739)
	copy(input[224:256], bigIntTo32Bytes(priceLimit))

	decodedKey, params, hookData, err := DecodeSwapInput(input)
	if err != nil {
		t.Fatalf("DecodeSwapInput failed: %v", err)
	}

	if decodedKey.Fee != 3000 {
		t.Errorf("Fee mismatch: got %d, want 3000", decodedKey.Fee)
	}
	if !params.ZeroForOne {
		t.Error("Expected ZeroForOne to be true")
	}
	if params.AmountSpecified.Cmp(big.NewInt(-1000)) != 0 {
		t.Errorf("AmountSpecified mismatch: got %s, want -1000", params.AmountSpecified)
	}
	if params.SqrtPriceLimitX96.Cmp(priceLimit) != 0 {
		t.Errorf("SqrtPriceLimitX96 mismatch: got %s, want %s", params.SqrtPriceLimitX96, priceLimit)
	}
	if hookData != nil {
		t.Errorf("Expected nil hookData, got %x", hookData)
	}
}

func TestABIDecodeSwapInputTooShort(t *testing.T) {
	_, _, _, err := DecodeSwapInput(make([]byte, 200))
	if err == nil {
		t.Error("Expected error for short input")
	}
}

// =========================================================================
// ModifyLiquidity Input Decoding Tests
// =========================================================================

func TestABIDecodeModifyLiquidityInput(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	input := make([]byte, 288)
	copy(input[0:160], EncodePoolKeyABI(key))
	// tickLower = -120 (int24 sign-extended to 32 bytes)
	copy(input[160:192], bigIntTo32Bytes(big.NewInt(-120)))
	// tickUpper = 120
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(120)))
	// liquidityDelta = 1000000
	copy(input[224:256], bigIntTo32Bytes(big.NewInt(1000000)))
	// salt = 0
	// (already zeroed)

	decodedKey, params, _, err := DecodeModifyLiquidityInput(input)
	if err != nil {
		t.Fatalf("DecodeModifyLiquidityInput failed: %v", err)
	}

	if decodedKey.Fee != 3000 {
		t.Errorf("Fee mismatch: got %d, want 3000", decodedKey.Fee)
	}
	if params.TickLower != -120 {
		t.Errorf("TickLower mismatch: got %d, want -120", params.TickLower)
	}
	if params.TickUpper != 120 {
		t.Errorf("TickUpper mismatch: got %d, want 120", params.TickUpper)
	}
	if params.LiquidityDelta.Cmp(big.NewInt(1000000)) != 0 {
		t.Errorf("LiquidityDelta mismatch: got %s, want 1000000", params.LiquidityDelta)
	}
}

// =========================================================================
// PositionKey Tests (keccak256 of abi.encodePacked)
// =========================================================================

func TestABIPositionKeyDeterministic(t *testing.T) {
	owner := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var salt [32]byte
	salt[0] = 0xAB

	k1 := PositionKey(owner, -100, 100, salt)
	k2 := PositionKey(owner, -100, 100, salt)

	if k1 != k2 {
		t.Error("PositionKey should be deterministic")
	}
}

func TestABIPositionKeyDifferentOwners(t *testing.T) {
	owner1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	owner2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	var salt [32]byte

	k1 := PositionKey(owner1, -100, 100, salt)
	k2 := PositionKey(owner2, -100, 100, salt)

	if k1 == k2 {
		t.Error("Different owners should produce different position keys")
	}
}

func TestABIPositionKeyUsesKeccak256(t *testing.T) {
	owner := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var salt [32]byte

	key := PositionKey(owner, -100, 100, salt)

	// Manually compute: keccak256(abi.encodePacked(owner, int24(tickLower), int24(tickUpper), salt))
	data := make([]byte, 58) // 20 + 3 + 3 + 32
	copy(data[0:20], owner.Bytes())
	// tickLower = -100 as int24 (3 bytes)
	tl := int32(-100)
	data[20] = byte(tl >> 16)
	data[21] = byte(tl >> 8)
	data[22] = byte(tl)
	// tickUpper = 100 as int24 (3 bytes)
	tu := int32(100)
	data[23] = byte(tu >> 16)
	data[24] = byte(tu >> 8)
	data[25] = byte(tu)
	copy(data[26:58], salt[:])

	var expected [32]byte
	copy(expected[:], crypto.Keccak256(data))

	if key != expected {
		t.Errorf("PositionKey should use keccak256:\ngot  %x\nwant %x", key, expected)
	}
}

// =========================================================================
// EncodePoolKeyABI Tests
// =========================================================================

func TestABIEncodePoolKeySlotLayout(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7")},
		Currency1:   Currency{Address: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.HexToAddress("0x0000000000000000000000000000000000002400"),
	}

	encoded := EncodePoolKeyABI(key)

	// Slot 0 (bytes 0-31): currency0 address left-padded
	c0 := common.BytesToAddress(encoded[12:32])
	if c0 != key.Currency0.Address {
		t.Errorf("Slot 0 (currency0) mismatch: got %s, want %s", c0.Hex(), key.Currency0.Address.Hex())
	}
	// First 12 bytes should be zero (left-padding)
	for i := range 12 {
		if encoded[i] != 0 {
			t.Errorf("Slot 0 padding byte %d should be 0, got %x", i, encoded[i])
		}
	}

	// Slot 1 (bytes 32-63): currency1
	c1 := common.BytesToAddress(encoded[44:64])
	if c1 != key.Currency1.Address {
		t.Errorf("Slot 1 (currency1) mismatch: got %s, want %s", c1.Hex(), key.Currency1.Address.Hex())
	}

	// Slot 2 (bytes 64-95): fee as uint24
	feeVal := new(big.Int).SetBytes(encoded[64:96]).Uint64()
	if feeVal != 3000 {
		t.Errorf("Slot 2 (fee) mismatch: got %d, want 3000", feeVal)
	}

	// Slot 3 (bytes 96-127): tickSpacing as int24
	tsVal := new(big.Int).SetBytes(encoded[96:128]).Int64()
	if tsVal != 60 {
		t.Errorf("Slot 3 (tickSpacing) mismatch: got %d, want 60", tsVal)
	}

	// Slot 4 (bytes 128-159): hooks address
	hooks := common.BytesToAddress(encoded[140:160])
	if hooks != key.Hooks {
		t.Errorf("Slot 4 (hooks) mismatch: got %s, want %s", hooks.Hex(), key.Hooks.Hex())
	}
}
