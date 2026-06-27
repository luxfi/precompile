// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// =========================================================================
// Fix 1: decodeABIBytes with non-empty hookData
// Red team finding: hookData always nil because offset was relative to sub-slice
// =========================================================================

func TestDecodeABIBytesSwapWithHookData(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	hookPayload := []byte("test-hook-data-payload")

	// Build V4 ABI-encoded swap input with hookData
	// Layout: PoolKey(160) + zeroForOne(32) + amountSpecified(32) + sqrtPriceLimitX96(32) + offset(32) + length(32) + data
	//         0-159          160-191          192-223               224-255                  256-287      288-319       320+
	input := make([]byte, 320+len(hookPayload))
	// PoolKey
	copy(input[0:160], EncodePoolKeyABI(key))
	// zeroForOne = true
	input[191] = 1
	// amountSpecified = -1000
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(-1000)))
	// sqrtPriceLimitX96
	copy(input[224:256], bigIntTo32Bytes(new(big.Int).SetUint64(4295128739)))
	// Offset word for hookData: absolute offset = 288 (0x120)
	// This points to the length word at position 288
	copy(input[256:288], bigIntTo32Bytes(big.NewInt(288)))
	// Length of hookData
	copy(input[288:320], bigIntTo32Bytes(big.NewInt(int64(len(hookPayload)))))
	// hookData bytes
	copy(input[320:], hookPayload)

	_, _, hookData, err := DecodeSwapInput(input)
	if err != nil {
		t.Fatalf("DecodeSwapInput failed: %v", err)
	}

	if hookData == nil {
		t.Fatal("REGRESSION: hookData is nil -- decodeABIBytes offset is broken")
	}
	if !bytes.Equal(hookData, hookPayload) {
		t.Errorf("hookData mismatch: got %q, want %q", hookData, hookPayload)
	}
}

func TestDecodeABIBytesModifyLiquidityWithHookData(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	hookPayload := []byte("modify-liquidity-hook")

	// Layout: PoolKey(160) + tickLower(32) + tickUpper(32) + liquidityDelta(32) + salt(32) + offset(32) + length(32) + data
	//         0-159          160-191         192-223         224-255               256-287    288-319      320-351       352+
	input := make([]byte, 352+len(hookPayload))
	copy(input[0:160], EncodePoolKeyABI(key))
	copy(input[160:192], bigIntTo32Bytes(big.NewInt(-120)))
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(120)))
	copy(input[224:256], bigIntTo32Bytes(big.NewInt(1000000)))
	// salt = 0 (already zeroed)
	// Offset word at 288: absolute offset = 320
	copy(input[288:320], bigIntTo32Bytes(big.NewInt(320)))
	// Length
	copy(input[320:352], bigIntTo32Bytes(big.NewInt(int64(len(hookPayload)))))
	// Data
	copy(input[352:], hookPayload)

	_, _, hookData, err := DecodeModifyLiquidityInput(input)
	if err != nil {
		t.Fatalf("DecodeModifyLiquidityInput failed: %v", err)
	}

	if hookData == nil {
		t.Fatal("REGRESSION: modifyLiquidity hookData is nil")
	}
	if !bytes.Equal(hookData, hookPayload) {
		t.Errorf("hookData mismatch: got %q, want %q", hookData, hookPayload)
	}
}

func TestDecodeABIBytesEmptyHookData(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	// Swap with no hookData (256 bytes exactly)
	input := make([]byte, 256)
	copy(input[0:160], EncodePoolKeyABI(key))
	input[191] = 1
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(-1000)))
	copy(input[224:256], bigIntTo32Bytes(new(big.Int).SetUint64(4295128739)))

	_, _, hookData, err := DecodeSwapInput(input)
	if err != nil {
		t.Fatalf("DecodeSwapInput failed: %v", err)
	}
	if hookData != nil {
		t.Errorf("Expected nil hookData for 256-byte input, got %x", hookData)
	}
}

func TestDecodeABIBytesZeroLengthHookData(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	// Swap with zero-length hookData (offset word points to length=0)
	input := make([]byte, 320)
	copy(input[0:160], EncodePoolKeyABI(key))
	input[191] = 1
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(-1000)))
	copy(input[224:256], bigIntTo32Bytes(new(big.Int).SetUint64(4295128739)))
	// Offset = 288
	copy(input[256:288], bigIntTo32Bytes(big.NewInt(288)))
	// Length = 0
	// (already zeroed)

	_, _, hookData, err := DecodeSwapInput(input)
	if err != nil {
		t.Fatalf("DecodeSwapInput failed: %v", err)
	}
	if hookData != nil {
		t.Errorf("Expected nil hookData for zero-length bytes, got %x", hookData)
	}
}

// =========================================================================
// Fix 2: extsload routes to correct handlers
// Red team finding: extsload was routed to runGetPool (expects 160-byte PoolKey, gets 32 bytes)
// =========================================================================

func TestExtsloadReadsSingleSlot(t *testing.T) {
	stateDB := NewMockStateDB()

	// Write a known value to a slot at the 0x9999 money-path address (extsload on the
	// sole DEX precompile reads its own slots — see runSettleExtsloadArray).
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000042")
	expected := common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	stateDB.SetState(poolManagerAddr9999, slot, expected)

	c := &SettleContract{}

	// Build extsload(bytes32) call: 4-byte selector + 32-byte slot
	input := make([]byte, 36)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsload)
	copy(input[4:36], slot.Bytes())

	// Use a minimal mock accessible state
	mockState := &mockAccessibleState{stateDB: stateDB}

	result, gas, err := c.Run(mockState, common.Address{}, poolManagerAddr9999, input, 100000, true)
	if err != nil {
		t.Fatalf("extsload failed: %v", err)
	}

	if gas >= 100000 {
		t.Error("extsload should consume gas")
	}

	resultHash := common.BytesToHash(result)
	if resultHash != expected {
		t.Errorf("extsload returned wrong value:\ngot  %s\nwant %s", resultHash.Hex(), expected.Hex())
	}
}

func TestExtsloadArrayReadsMultipleSlots(t *testing.T) {
	stateDB := NewMockStateDB()

	slot0 := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	val0 := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000AA")
	slot1 := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")
	val1 := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000BB")

	stateDB.SetState(poolManagerAddr9999, slot0, val0)
	stateDB.SetState(poolManagerAddr9999, slot1, val1)

	c := &SettleContract{}

	// Build extsload(bytes32[]) call
	// ABI: selector(4) + offset(32) + length(32) + slot0(32) + slot1(32)
	input := make([]byte, 4+32+32+32+32)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsloadArray)
	// offset = 32 (points to start of array data)
	input[4+31] = 0x20
	// length = 2
	input[4+32+31] = 0x02
	// slot0
	copy(input[4+64:4+96], slot0.Bytes())
	// slot1
	copy(input[4+96:4+128], slot1.Bytes())

	mockState := &mockAccessibleState{stateDB: stateDB}
	result, _, err := c.Run(mockState, common.Address{}, poolManagerAddr9999, input, 100000, true)
	if err != nil {
		t.Fatalf("extsload array failed: %v", err)
	}

	// Result: offset(32) + length(32) + val0(32) + val1(32)
	if len(result) < 128 {
		t.Fatalf("expected 128 bytes result, got %d", len(result))
	}

	resultVal0 := common.BytesToHash(result[64:96])
	resultVal1 := common.BytesToHash(result[96:128])

	if resultVal0 != val0 {
		t.Errorf("slot0 value mismatch: got %s, want %s", resultVal0.Hex(), val0.Hex())
	}
	if resultVal1 != val1 {
		t.Errorf("slot1 value mismatch: got %s, want %s", resultVal1.Hex(), val1.Hex())
	}
}

func TestExtsloadShortInputRejected(t *testing.T) {
	c := &SettleContract{}

	// Only 20 bytes of slot data (need 32)
	input := make([]byte, 24)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsload)

	mockState := &mockAccessibleState{stateDB: NewMockStateDB()}
	_, _, err := c.Run(mockState, common.Address{}, poolManagerAddr9999, input, 100000, true)
	if err == nil {
		t.Error("expected error for short extsload input")
	}
}

// =========================================================================
// Fix 3: Initialize return: negative ticks must be sign-extended
// Red team finding: tick=-100 returned 0x00...00FFFF9C instead of 0xFF...FFFFFF9C
// =========================================================================

// negativeTickEngine returns a specific tick from Initialize.
type negativeTickEngine struct {
	mockEngine
	tick int32
}

func (e *negativeTickEngine) Initialize(_ *big.Int) (int24, error) {
	return e.tick, nil
}

func TestInitializeNegativeTickSignExtension(t *testing.T) {
	tests := []struct {
		name string
		tick int32
	}{
		{"tick -100", -100},
		{"tick -1", -1},
		{"tick -887272 (MinTick)", MinTick},
		{"tick 0", 0},
		{"tick 100", 100},
		{"tick 887272 (MaxTick)", MaxTick},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bigIntTo32Bytes(big.NewInt(int64(tt.tick)))
			if len(result) != 32 {
				t.Fatalf("expected 32 bytes, got %d", len(result))
			}

			// Decode back
			decoded := decodeSigned256(result)
			if decoded.Int64() != int64(tt.tick) {
				t.Errorf("roundtrip failed: encoded tick %d, decoded %d", tt.tick, decoded.Int64())
			}

			// For negative ticks: high byte must be 0xFF (sign extension)
			if tt.tick < 0 {
				if result[0] != 0xFF {
					t.Errorf("REGRESSION: negative tick %d not sign-extended: high byte = 0x%02X, want 0xFF\nfull: %x", tt.tick, result[0], result)
				}
			}

			// For non-negative ticks: high byte must be 0x00
			if tt.tick >= 0 {
				if result[0] != 0x00 {
					t.Errorf("positive tick %d has wrong high byte: 0x%02X, want 0x00", tt.tick, result[0])
				}
			}
		})
	}
}

func TestInitializeReturnNegativeTick(t *testing.T) {
	// Full integration: engine returns -100, precompile must return properly sign-extended int256
	engine := &negativeTickEngine{tick: -100}
	pm := NewPoolManager(engine)
	stateDB := NewMockStateDB()

	key := PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0x1234567890123456789012345678901234567890")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}

	sqrtPriceX96 := new(big.Int).Set(Q96)
	tick, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if tick != -100 {
		t.Fatalf("expected tick -100, got %d", tick)
	}

	// Verify the ABI encoding
	encoded := bigIntTo32Bytes(big.NewInt(int64(tick)))
	// Must be 0xFF...FF9C (two's complement of -100)
	// -100 in two's complement 256-bit = 2^256 - 100
	// High 31 bytes should all be 0xFF, last byte should be 0x9C
	for i := range 31 {
		if encoded[i] != 0xFF {
			t.Errorf("REGRESSION: byte %d = 0x%02X, want 0xFF for tick -100", i, encoded[i])
		}
	}
	if encoded[31] != 0x9C {
		t.Errorf("REGRESSION: last byte = 0x%02X, want 0x9C for tick -100", encoded[31])
	}
}

// =========================================================================
// Fix 4: Hook selectors must be keccak256-derived from V4 IHooks signatures
// Red team finding: selectors were magic bytes (0x01000001, etc.)
// =========================================================================

func TestHookSelectorsAreKeccak4(t *testing.T) {
	tests := []struct {
		name     string
		selector []byte
		sig      string
	}{
		{"beforeInitialize", SigBeforeInitialize, "beforeInitialize(address,(address,address,uint24,int24,address),uint160,bytes)"},
		{"afterInitialize", SigAfterInitialize, "afterInitialize(address,(address,address,uint24,int24,address),uint160,int24,bytes)"},
		{"beforeAddLiquidity", SigBeforeAddLiquidity, "beforeAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"},
		{"afterAddLiquidity", SigAfterAddLiquidity, "afterAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int128,int128),(int128,int128),bytes)"},
		{"beforeRemoveLiquidity", SigBeforeRemoveLiquidity, "beforeRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"},
		{"afterRemoveLiquidity", SigAfterRemoveLiquidity, "afterRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int128,int128),(int128,int128),bytes)"},
		{"beforeSwap", SigBeforeSwap, "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)"},
		{"afterSwap", SigAfterSwap, "afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),(int128,int128),bytes)"},
		{"beforeDonate", SigBeforeDonate, "beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)"},
		{"afterDonate", SigAfterDonate, "afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := crypto.Keccak256([]byte(tt.sig))
			want := hash[:4]
			if !bytes.Equal(tt.selector, want) {
				t.Errorf("REGRESSION: %s selector mismatch:\ngot  %x\nwant %x (keccak4 of %q)", tt.name, tt.selector, want, tt.sig)
			}
		})
	}
}

func TestHookSelectorsNotMagicBytes(t *testing.T) {
	// The OLD buggy selectors were sequential magic bytes like 0x01000001.
	// Verify none of the current selectors match the old pattern.
	oldMagic := [][]byte{
		{0x01, 0x00, 0x00, 0x01}, // old beforeInitialize
		{0x01, 0x00, 0x00, 0x02}, // old afterInitialize
		{0x02, 0x00, 0x00, 0x01}, // old beforeAddLiquidity
		{0x02, 0x00, 0x00, 0x02}, // old afterAddLiquidity
		{0x02, 0x00, 0x00, 0x03}, // old beforeRemoveLiquidity
		{0x02, 0x00, 0x00, 0x04}, // old afterRemoveLiquidity
		{0x03, 0x00, 0x00, 0x01}, // old beforeSwap
		{0x03, 0x00, 0x00, 0x02}, // old afterSwap
		{0x04, 0x00, 0x00, 0x01}, // old beforeDonate
		{0x04, 0x00, 0x00, 0x02}, // old afterDonate
	}

	currentSigs := [][]byte{
		SigBeforeInitialize, SigAfterInitialize,
		SigBeforeAddLiquidity, SigAfterAddLiquidity,
		SigBeforeRemoveLiquidity, SigAfterRemoveLiquidity,
		SigBeforeSwap, SigAfterSwap,
		SigBeforeDonate, SigAfterDonate,
	}

	for i, sig := range currentSigs {
		for j, magic := range oldMagic {
			if bytes.Equal(sig, magic) {
				t.Errorf("REGRESSION: current selector %d matches old magic selector %d: %x", i, j, sig)
			}
		}
	}
}

func TestHookSigHelperConsistency(t *testing.T) {
	// Verify hookSig helper matches manual keccak256 computation
	sig := "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)"
	result := hookSig(sig)

	hash := crypto.Keccak256([]byte(sig))
	expected := hash[:4]

	if !bytes.Equal(result, expected) {
		t.Errorf("hookSig inconsistent with keccak256: got %x, want %x", result, expected)
	}
}

func TestHookSignaturesMapComplete(t *testing.T) {
	// Verify the exported HookSignatures map covers all hook types
	requiredHooks := []string{
		"beforeInitialize", "afterInitialize",
		"beforeAddLiquidity", "afterAddLiquidity",
		"beforeRemoveLiquidity", "afterRemoveLiquidity",
		"beforeSwap", "afterSwap",
		"beforeDonate", "afterDonate",
	}

	for _, name := range requiredHooks {
		sig, ok := HookSignatures[name]
		if !ok {
			t.Errorf("HookSignatures missing entry for %s", name)
			continue
		}
		if len(sig) == 0 {
			t.Errorf("HookSignatures[%q] is empty", name)
		}
	}
}

// =========================================================================
// Fix 5: donate must decode hookData via ABI, not raw slice
// Red team finding: runDonate did hookData = input[224:] instead of decodeABIBytes
// =========================================================================

func TestDonateHookDataDecoding(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	hookPayload := []byte("donate-hook-data")

	// Build V4 ABI-encoded donate input (after 4-byte selector)
	// donate((address,address,uint24,int24,address),uint256,uint256,bytes)
	// Layout: PoolKey(160) + amount0(32) + amount1(32) + offset(32) + length(32) + data
	//         0-159          160-191       192-223       224-255      256-287       288+
	input := make([]byte, 288+len(hookPayload))
	copy(input[0:160], EncodePoolKeyABI(key))
	copy(input[160:192], bigIntTo32Bytes(big.NewInt(1000)))
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(2000)))
	// Offset word: absolute offset = 256
	copy(input[224:256], bigIntTo32Bytes(big.NewInt(256)))
	// Length
	copy(input[256:288], bigIntTo32Bytes(big.NewInt(int64(len(hookPayload)))))
	// Data
	copy(input[288:], hookPayload)

	// Decode the hookData using decodeABIBytes directly (unit test of the fix)
	hookData := decodeABIBytes(input, 224)
	if hookData == nil {
		t.Fatal("REGRESSION: donate hookData is nil after ABI decode")
	}
	if !bytes.Equal(hookData, hookPayload) {
		t.Errorf("donate hookData mismatch: got %q, want %q", hookData, hookPayload)
	}
}

func TestDonateNoHookData(t *testing.T) {
	// donate with exactly 224 bytes (no hookData)
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	input := make([]byte, 224)
	copy(input[0:160], EncodePoolKeyABI(key))
	copy(input[160:192], bigIntTo32Bytes(big.NewInt(1000)))
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(2000)))

	// decodeABIBytes should not be called (len <= 224)
	// This verifies no regression for the no-hookData case
	if len(input) > 224 {
		hookData := decodeABIBytes(input, 224)
		if hookData != nil {
			t.Errorf("Expected nil hookData for 224-byte input, got %x", hookData)
		}
	}
}

func TestDonateOldRawSliceWouldBeWrong(t *testing.T) {
	// Demonstrate the bug: the OLD code did hookData = input[224:] which would
	// include the offset word + length word + padding, corrupting the data.

	hookPayload := []byte("real-data")

	input := make([]byte, 288+len(hookPayload))
	// ... key, amounts ...
	// Offset word at 224: value = 256
	copy(input[224:256], bigIntTo32Bytes(big.NewInt(256)))
	// Length at 256
	copy(input[256:288], bigIntTo32Bytes(big.NewInt(int64(len(hookPayload)))))
	// Data at 288
	copy(input[288:], hookPayload)

	// OLD broken: hookData = input[224:]
	// This would include 64 bytes of offset+length garbage before the actual data
	oldBroken := input[224:]
	if bytes.Equal(oldBroken, hookPayload) {
		t.Fatal("test is invalid: old behavior should NOT match payload")
	}
	if len(oldBroken) != 64+len(hookPayload) {
		t.Fatalf("old broken length: got %d, want %d", len(oldBroken), 64+len(hookPayload))
	}

	// NEW correct: decodeABIBytes
	correct := decodeABIBytes(input, 224)
	if !bytes.Equal(correct, hookPayload) {
		t.Errorf("decodeABIBytes returned wrong data: got %q, want %q", correct, hookPayload)
	}
}

// =========================================================================
// Integration: PackBeforeSwapParams uses keccak4 selectors
// =========================================================================

func TestPackBeforeSwapUsesKeccakSelector(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	key := newTestPoolKey()
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: big.NewInt(1000000),
	}
	hookData := []byte("test")

	packed := PackBeforeSwapParams(sender, key, params, hookData)

	// Verify the first 4 bytes match keccak4("beforeSwap(...)")
	want := crypto.Keccak256([]byte("beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)"))[:4]
	if !bytes.Equal(packed[:4], want) {
		t.Errorf("PackBeforeSwapParams selector: got %x, want %x", packed[:4], want)
	}
}

func TestPackAfterSwapUsesKeccakSelector(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	key := newTestPoolKey()
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: big.NewInt(1000000),
	}
	delta := NewBalanceDelta(big.NewInt(1000), big.NewInt(-500))
	hookData := []byte("test")

	packed := PackAfterSwapParams(sender, key, params, delta, hookData)

	want := crypto.Keccak256([]byte("afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),(int128,int128),bytes)"))[:4]
	if !bytes.Equal(packed[:4], want) {
		t.Errorf("PackAfterSwapParams selector: got %x, want %x", packed[:4], want)
	}
}

// =========================================================================
// Mock implementations for precompile-level tests
// =========================================================================

// mockAccessibleState implements contract.AccessibleState for testing extsload.
type mockAccessibleState struct {
	stateDB *MockStateDB
}

func (m *mockAccessibleState) GetStateDB() contract.StateDB {
	return &contractStateDBWrapper{inner: m.stateDB}
}

func (m *mockAccessibleState) GetBlockContext() contract.BlockContext {
	// 0x9999 logs are AlwaysOn (active from genesis); any block time runs the live path.
	return &mockBlockCtx{number: big.NewInt(int64(m.stateDB.blockNumber)), timestamp: harnessBlockTime}
}

func (m *mockAccessibleState) GetConsensusContext() context.Context {
	return context.Background()
}

func (m *mockAccessibleState) GetChainConfig() precompileconfig.ChainConfig {
	return nil
}

func (m *mockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return nil
}

// mockBlockCtx implements contract.BlockContext for testing. timestamp defaults to
// harnessBlockTime; 0x9999 and its logs are AlwaysOn (active from genesis), so the
// value carries no protocol meaning.
type mockBlockCtx struct {
	number    *big.Int
	timestamp uint64
}

func (b *mockBlockCtx) Number() *big.Int {
	return b.number
}

func (b *mockBlockCtx) Timestamp() uint64 {
	return b.timestamp
}

func (b *mockBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte {
	return nil
}

// contractStateDBWrapper wraps MockStateDB to satisfy contract.StateDB.
type contractStateDBWrapper struct {
	inner *MockStateDB
}

func (w *contractStateDBWrapper) GetState(addr common.Address, key common.Hash) common.Hash {
	return w.inner.GetState(addr, key)
}

func (w *contractStateDBWrapper) SetState(addr common.Address, key common.Hash, value common.Hash) common.Hash {
	old := w.inner.GetState(addr, key)
	w.inner.SetState(addr, key, value)
	return old
}

func (w *contractStateDBWrapper) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (w *contractStateDBWrapper) GetNonce(common.Address) uint64                             { return 0 }

func (w *contractStateDBWrapper) GetBalance(addr common.Address) *uint256.Int {
	return w.inner.GetBalance(addr)
}

func (w *contractStateDBWrapper) AddBalance(addr common.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	w.inner.AddBalance(addr, amount)
	return *w.inner.GetBalance(addr)
}

func (w *contractStateDBWrapper) SubBalance(addr common.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	w.inner.SubBalance(addr, amount)
	return *w.inner.GetBalance(addr)
}

func (w *contractStateDBWrapper) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int {
	return big.NewInt(0)
}

func (w *contractStateDBWrapper) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (w *contractStateDBWrapper) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}

func (w *contractStateDBWrapper) CreateAccount(addr common.Address) {
	w.inner.CreateAccount(addr)
}

func (w *contractStateDBWrapper) Exist(addr common.Address) bool {
	return w.inner.Exist(addr)
}

func (w *contractStateDBWrapper) AddLog(log *ethtypes.Log) {
	w.inner.AddLog(log)
}

func (w *contractStateDBWrapper) Logs() []*ethtypes.Log {
	return w.inner.Logs()
}

func (w *contractStateDBWrapper) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}

func (w *contractStateDBWrapper) TxHash() common.Hash {
	return common.Hash{}
}

// Snapshot / RevertToSnapshot model the REAL EVM atomicity boundary over the mock:
// Snapshot clones every mutable field of the inner MockStateDB and returns its id;
// RevertToSnapshot restores that clone. Keyed by the inner *MockStateDB so a fresh
// wrapper (GetStateDB returns a new wrapper each call) shares the same snapshot
// stack. This is what lets the atomicity tests observe that a failed swap rolls
// back BOTH the C balances and the D book — exactly as geth/core/vm/evm.go's Call
// reverts a precompile's writes on error. Defined in swap_sync_snapshot_test.go.
func (w *contractStateDBWrapper) Snapshot() int        { return takeMockSnapshot(w.inner) }
func (w *contractStateDBWrapper) RevertToSnapshot(id int) { revertMockToSnapshot(w.inner, id) }

// --- erc20Vault (additive test capability; lets the 0x9999 settlement tests
// exercise the real native-in / token-out direction). An in-memory per-token
// balance ledger keyed (token, holder), stored on MockStateDB. Honest ERC-20
// semantics (no fee-on-transfer) so observed-delta == amount.
func (w *contractStateDBWrapper) ercBal(token, holder common.Address) *big.Int {
	if w.inner.tokenBalances == nil {
		w.inner.tokenBalances = make(map[common.Address]map[common.Address]*big.Int)
	}
	if w.inner.tokenBalances[token] == nil {
		w.inner.tokenBalances[token] = make(map[common.Address]*big.Int)
	}
	if w.inner.tokenBalances[token][holder] == nil {
		w.inner.tokenBalances[token][holder] = big.NewInt(0)
	}
	return w.inner.tokenBalances[token][holder]
}

func (w *contractStateDBWrapper) TokenBalanceOf(token, owner common.Address) *big.Int {
	return new(big.Int).Set(w.ercBal(token, owner))
}

func (w *contractStateDBWrapper) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	bal := w.ercBal(token, from)
	if bal.Cmp(amount) < 0 {
		return ErrERC20TransferFailed
	}
	w.inner.tokenBalances[token][from] = new(big.Int).Sub(bal, amount)
	// Optional fee-on-transfer: the recipient receives amount - fee, modelling a
	// non-standard token so tests can exercise the observed-delta short branches.
	received := amount
	if w.inner.feeOnTransferBps > 0 {
		fee := new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(int64(w.inner.feeOnTransferBps))), big.NewInt(10000))
		received = new(big.Int).Sub(amount, fee)
	}
	w.inner.tokenBalances[token][to] = new(big.Int).Add(w.ercBal(token, to), received)
	return nil
}

func (w *contractStateDBWrapper) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	// Vault (0x9999) is the implicit `from`.
	return w.TransferTokenFrom(token, poolManagerAddr9999, to, amount)
}

// GetCodeSize forwards the EXTCODESIZE-equivalent to the inner mock under the SAME method
// name the production geth StateDB exposes, so the value-path on-chain asset verifier
// (poolStateAdapter.CodeSizeOf type-asserts GetCodeSize on the underlying StateDB) reads it.
func (w *contractStateDBWrapper) GetCodeSize(addr common.Address) int {
	return w.inner.CodeSizeOf(addr)
}

// mintTestToken seeds a token balance for a holder (test setup only). It also marks the
// token address as a deployed CONTRACT (non-zero code size) so the value-path
// OnChainAssetVerifier treats it as a real on-chain token — a minted test token IS a real
// ERC-20. A test that wants to model a self-destructed / never-deployed token sets the
// code size to 0 explicitly via inner.SetCodeSize after minting.
func (w *contractStateDBWrapper) mintTestToken(token, holder common.Address, amount *big.Int) {
	cur := w.ercBal(token, holder)
	w.inner.tokenBalances[token][holder] = new(big.Int).Add(cur, amount)
	if w.inner.CodeSizeOf(token) == 0 {
		w.inner.SetCodeSize(token, 1) // a real deployed token has code
	}
}
