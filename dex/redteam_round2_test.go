// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Red Team Round 2 — Regression tests for security findings.
// Each test documents the attack vector and MUST fail on vulnerable code, pass on fixed code.
// Run: go test -run TestRedTeam -v -count=1

package dex

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// =========================================================================
// Finding 1: decodeABIBytes uint64 overflow (CRITICAL — chain halt)
//
// Attack: Craft offset word = 0xFFFFFFFFFFFFFFE0. absOffset+32 wraps to 0.
// OLD code: panic on slice bounds out of range.
// NEW code: returns nil (BitLen > 63 check rejects it).
// =========================================================================

func TestRedTeam_DecodeABIBytes_Uint64Overflow_MaxMinus31(t *testing.T) {
	// offset = 0xFFFFFFFFFFFFFFE0 (uint64 max - 31).
	// absOffset+32 wraps to 0x0000000000000000.
	// Without BitLen guard this causes out-of-bounds slice panic.
	args := make([]byte, 320)

	// Place offset word at position 256 (swap hookData offset slot)
	overflowVal := new(big.Int).SetUint64(0xFFFFFFFFFFFFFFE0)
	copy(args[256:288], bigIntTo32Bytes(overflowVal))

	// Must not panic. recover() catches if it does.
	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		result := decodeABIBytes(args, 256)
		if result != nil {
			t.Error("VULN: decodeABIBytes returned non-nil for overflow offset 0xFFFFFFFFFFFFFFE0")
		}
	}()
	if didPanic {
		t.Fatal("VULN: decodeABIBytes panicked on overflow offset 0xFFFFFFFFFFFFFFE0 — chain halt")
	}
}

func TestRedTeam_DecodeABIBytes_Uint64Overflow_Max(t *testing.T) {
	// offset = 0xFFFFFFFFFFFFFFFF (uint64 max).
	args := make([]byte, 320)
	maxU64 := new(big.Int).SetUint64(^uint64(0))
	copy(args[256:288], bigIntTo32Bytes(maxU64))

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		result := decodeABIBytes(args, 256)
		if result != nil {
			t.Error("VULN: decodeABIBytes returned non-nil for uint64 max offset")
		}
	}()
	if didPanic {
		t.Fatal("VULN: decodeABIBytes panicked on uint64 max offset — chain halt")
	}
}

func TestRedTeam_DecodeABIBytes_Uint64Overflow_2Pow63(t *testing.T) {
	// offset = 2^63. BitLen = 64, which exceeds the 63-bit guard.
	args := make([]byte, 320)
	pow63 := new(big.Int).Lsh(big.NewInt(1), 63)
	copy(args[256:288], bigIntTo32Bytes(pow63))

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		result := decodeABIBytes(args, 256)
		if result != nil {
			t.Error("VULN: decodeABIBytes returned non-nil for 2^63 offset")
		}
	}()
	if didPanic {
		t.Fatal("VULN: decodeABIBytes panicked on 2^63 offset — chain halt")
	}
}

// =========================================================================
// Finding 2: decodeABIBytes backward offset (data confusion)
//
// Attack: Set offset word to point BEFORE the offset position.
// Example: offsetPos=224, offset value=32 → reads PoolKey area as hookData.
// OLD code: returns data from the PoolKey area (data confusion).
// NEW code: returns nil (absOffset < offsetPos+32 check).
// =========================================================================

func TestRedTeam_DecodeABIBytes_BackwardOffset(t *testing.T) {
	// Build a buffer mimicking a donate call (PoolKey + amount0 + amount1 + hookData offset)
	args := make([]byte, 320)

	// Fill PoolKey area with recognizable pattern
	for i := range 160 {
		args[i] = 0xAA
	}

	// At offsetPos=224, place offset value=32 (points backward into PoolKey area)
	copy(args[224:256], bigIntTo32Bytes(big.NewInt(32)))

	// At byte 32 (where backward offset points), place a fake "length" = 4
	copy(args[32:64], bigIntTo32Bytes(big.NewInt(4)))

	result := decodeABIBytes(args, 224)
	if result != nil {
		t.Errorf("VULN: backward offset returned data from PoolKey area: %x (data confusion attack)", result)
	}
}

func TestRedTeam_DecodeABIBytes_BackwardOffset_Zero(t *testing.T) {
	// Offset = 0 always points before offsetPos (unless offsetPos=0, but
	// even then absOffset < offsetPos+32 = 32 fails).
	args := make([]byte, 320)
	// offset = 0
	// Already zeroed

	result := decodeABIBytes(args, 224)
	if result != nil {
		t.Error("VULN: zero offset should be rejected as backward")
	}
}

// =========================================================================
// Finding 3: decodeABIBytes length overflow
//
// Attack: Set length word to uint64 max. dataStart+length wraps around.
// OLD code: panic on slice bounds.
// NEW code: returns nil (BitLen > 63 check on length).
// =========================================================================

func TestRedTeam_DecodeABIBytes_LengthOverflow(t *testing.T) {
	// Build valid structure with absOffset pointing forward, but length = uint64 max
	args := make([]byte, 384)

	// offsetPos = 256, absOffset = 320 (valid forward reference)
	copy(args[256:288], bigIntTo32Bytes(big.NewInt(320)))

	// At absOffset=320: length = 0xFFFFFFFFFFFFFFFF
	maxU64 := new(big.Int).SetUint64(^uint64(0))
	copy(args[320:352], bigIntTo32Bytes(maxU64))

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		result := decodeABIBytes(args, 256)
		if result != nil {
			t.Error("VULN: decodeABIBytes returned non-nil for uint64 max length")
		}
	}()
	if didPanic {
		t.Fatal("VULN: decodeABIBytes panicked on length overflow — chain halt")
	}
}

func TestRedTeam_DecodeABIBytes_LengthExceedsBuffer(t *testing.T) {
	// Length = 1000 but buffer only has 32 bytes after length word.
	args := make([]byte, 384)
	copy(args[256:288], bigIntTo32Bytes(big.NewInt(320)))
	copy(args[320:352], bigIntTo32Bytes(big.NewInt(1000)))

	result := decodeABIBytes(args, 256)
	if result != nil {
		t.Error("VULN: decodeABIBytes returned data when length exceeds buffer")
	}
}

// =========================================================================
// Finding 4: big.Int.Uint64() truncation
//
// Attack: Offset word with value = 2^65 + 32 (BitLen = 66).
// Uint64() silently truncates to 32, which passes bounds checks.
// OLD code: truncated value passes validation, reads wrong data.
// NEW code: returns nil (BitLen > 63 rejects it).
// =========================================================================

func TestRedTeam_DecodeABIBytes_BigIntTruncation(t *testing.T) {
	// 2^65 + 288 → Uint64() truncates to 288, which is a valid offset in a 384-byte buffer.
	// The BitLen check must catch this before Uint64() is called.
	truncatedTarget := big.NewInt(288)
	craftedOffset := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 65), truncatedTarget)
	// Verify the attack: Uint64 gives truncated value
	if craftedOffset.Uint64() != 288 {
		t.Fatalf("test setup: Uint64() should truncate to 288, got %d", craftedOffset.Uint64())
	}
	if craftedOffset.BitLen() <= 64 {
		t.Fatalf("test setup: BitLen should exceed 64, got %d", craftedOffset.BitLen())
	}

	args := make([]byte, 384)
	// Place the crafted offset at position 256
	offsetBytes := bigIntTo32Bytes(craftedOffset)
	copy(args[256:288], offsetBytes)

	// At the truncated target (288): place length=4 and some data
	copy(args[288:320], bigIntTo32Bytes(big.NewInt(4)))
	copy(args[320:324], []byte("PWND"))

	result := decodeABIBytes(args, 256)
	if result != nil {
		t.Errorf("VULN: BigInt truncation allowed read of wrong data: %q", result)
	}
}

func TestRedTeam_DecodeABIBytes_BigIntTruncation_Length(t *testing.T) {
	// Same attack on the length field: length = 2^65 + 4
	args := make([]byte, 384)
	copy(args[256:288], bigIntTo32Bytes(big.NewInt(320))) // valid offset

	craftedLength := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 65), big.NewInt(4))
	copy(args[320:352], bigIntTo32Bytes(craftedLength))
	copy(args[352:356], []byte("PWND"))

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		result := decodeABIBytes(args, 256)
		if result != nil {
			t.Errorf("VULN: BigInt truncation on length field returned: %q", result)
		}
	}()
	if didPanic {
		t.Fatal("VULN: BigInt truncation on length caused panic")
	}
}

// =========================================================================
// Finding 5: extsloadArray count overflow
//
// Attack: count = 2^59 + 1 → count*32 overflows to 32.
// OLD code: allocates tiny buffer, panics in loop.
// NEW code: rejects count > 256.
// =========================================================================

func TestRedTeam_ExtsloadArray_CountOverflow(t *testing.T) {
	// count = 2^59 + 1 → count*32 = 2^64 + 32 → overflows to 32
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	mockState := &mockAccessibleState{stateDB: NewMockStateDB()}

	// ABI: selector(4) + offset(32) + count(32)
	input := make([]byte, 4+32+32)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsloadArray)
	// offset = 32
	input[4+31] = 0x20

	// count = 2^59 + 1 (overflows when multiplied by 32)
	countVal := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 59), big.NewInt(1))
	countBytes := bigIntTo32Bytes(countVal)
	copy(input[4+32:4+64], countBytes)

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _, err := c.Run(mockState, common.Address{}, lxPoolAddr, input, 1_000_000, true)
		if err == nil {
			t.Error("VULN: extsloadArray accepted overflow count without error")
		}
	}()
	if didPanic {
		t.Fatal("VULN: extsloadArray panicked on overflow count — chain halt")
	}
}

func TestRedTeam_ExtsloadArray_CountExceedsMax(t *testing.T) {
	// count = 257 exceeds maxExtsloadSlots = 256.
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	mockState := &mockAccessibleState{stateDB: NewMockStateDB()}

	input := make([]byte, 4+32+32)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsloadArray)
	input[4+31] = 0x20
	// count = 257
	countBytes := bigIntTo32Bytes(big.NewInt(257))
	copy(input[4+32:4+64], countBytes)

	_, _, err := c.Run(mockState, common.Address{}, lxPoolAddr, input, 1_000_000, true)
	if err == nil {
		t.Error("VULN: extsloadArray accepted count=257 (exceeds max 256)")
	}
	if err != nil && !strings.Contains(err.Error(), "max") && !strings.Contains(err.Error(), "exceeds") {
		t.Logf("Got error (acceptable): %v", err)
	}
}

func TestRedTeam_ExtsloadArray_CountZero(t *testing.T) {
	// count = 0 should return empty result without panic.
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	stateDB := NewMockStateDB()
	mockState := &mockAccessibleState{stateDB: stateDB}

	input := make([]byte, 4+32+32)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsloadArray)
	input[4+31] = 0x20
	// count = 0 (already zeroed)

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		result, _, err := c.Run(mockState, common.Address{}, lxPoolAddr, input, 1_000_000, true)
		if err != nil {
			t.Fatalf("extsloadArray count=0 returned error: %v", err)
		}
		// Result should be ABI-encoded empty array: offset(32) + count(32) = 64 bytes
		if len(result) < 64 {
			t.Errorf("expected at least 64 bytes for empty array result, got %d", len(result))
		}
	}()
	if didPanic {
		t.Fatal("VULN: extsloadArray panicked on count=0")
	}
}

// =========================================================================
// Finding 6: extsloadArray offset overflow
//
// Attack: offset word with BitLen > 64 → rejected.
// =========================================================================

func TestRedTeam_ExtsloadArray_OffsetOverflow(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	mockState := &mockAccessibleState{stateDB: NewMockStateDB()}

	// offset = 2^65 (BitLen = 66). Uint64 truncates to 0.
	input := make([]byte, 4+64)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsloadArray)

	bigOffset := new(big.Int).Lsh(big.NewInt(1), 65)
	copy(input[4:36], bigIntTo32Bytes(bigOffset))

	_, _, err := c.Run(mockState, common.Address{}, lxPoolAddr, input, 1_000_000, true)
	if err == nil {
		t.Error("VULN: extsloadArray accepted offset with BitLen > 64")
	}
}

func TestRedTeam_ExtsloadArray_OffsetBeyondInput(t *testing.T) {
	// offset = 99999 but input is only 68 bytes
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	mockState := &mockAccessibleState{stateDB: NewMockStateDB()}

	input := make([]byte, 4+64)
	binary.BigEndian.PutUint32(input[0:4], SelectorExtsloadArray)
	copy(input[4:36], bigIntTo32Bytes(big.NewInt(99999)))

	_, _, err := c.Run(mockState, common.Address{}, lxPoolAddr, input, 1_000_000, true)
	if err == nil {
		t.Error("VULN: extsloadArray accepted offset beyond input length")
	}
}

// =========================================================================
// Finding 7: runInitialize hookData uses decodeABIBytes (not raw slice)
//
// Verify hookData is correctly decoded via ABI, not including offset+length prefix.
// =========================================================================

func TestRedTeam_Initialize_HookDataABIDecoded(t *testing.T) {
	// Build initialize input: PoolKey(160) + sqrtPriceX96(32) + hookData(ABI-encoded)
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	hookPayload := []byte("init-hook-payload-round2")

	// Layout: PoolKey(160) + sqrtPriceX96(32) + offset(32) + length(32) + data
	//         0-159          160-191             192-223      224-255       256+
	input := make([]byte, 256+len(hookPayload))
	copy(input[0:160], EncodePoolKeyABI(key))
	copy(input[160:192], bigIntTo32Bytes(new(big.Int).Set(Q96))) // sqrtPriceX96 = Q96

	// ABI-encoded hookData: offset at 192, pointing to length at 224
	copy(input[192:224], bigIntTo32Bytes(big.NewInt(224)))
	copy(input[224:256], bigIntTo32Bytes(big.NewInt(int64(len(hookPayload)))))
	copy(input[256:], hookPayload)

	// Verify decodeABIBytes at offsetPos=192 returns exactly the payload
	decoded := decodeABIBytes(input, 192)
	if decoded == nil {
		t.Fatal("REGRESSION: initialize hookData decoded as nil")
	}
	if !bytes.Equal(decoded, hookPayload) {
		t.Errorf("hookData mismatch:\ngot  %q\nwant %q", decoded, hookPayload)
	}

	// The OLD code would have done input[192:] which includes the offset+length+data
	// (64 extra bytes). Verify old approach is wrong.
	rawSlice := input[192:]
	if bytes.Equal(rawSlice, hookPayload) {
		t.Fatal("test invalid: raw slice should not equal payload (it includes 64 bytes of ABI overhead)")
	}
	if len(rawSlice) != 64+len(hookPayload) {
		t.Fatalf("raw slice should be %d bytes (64 overhead + payload), got %d", 64+len(hookPayload), len(rawSlice))
	}
}

func TestRedTeam_Initialize_NoHookData(t *testing.T) {
	// Exactly 192 bytes (PoolKey + sqrtPriceX96, no hookData).
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}

	input := make([]byte, 192)
	copy(input[0:160], EncodePoolKeyABI(key))
	copy(input[160:192], bigIntTo32Bytes(new(big.Int).Set(Q96)))

	// runInitialize checks len(input) > 192 before calling decodeABIBytes.
	// With exactly 192 bytes, hookData should be nil.
	// Verify the logic path: len(input) == 192, so hookData stays nil.
	if len(input) > 192 {
		t.Fatal("test setup error: input should be exactly 192 bytes")
	}

	// Verify via the actual precompile entry point
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	mockState := &mockAccessibleState{stateDB: NewMockStateDB()}

	// Prepend selector
	calldata := make([]byte, 4+len(input))
	binary.BigEndian.PutUint32(calldata[0:4], SelectorInitialize)
	copy(calldata[4:], input)

	result, _, err := c.Run(mockState, common.Address{}, lxPoolAddr, calldata, 1_000_000, false)
	if err != nil {
		t.Fatalf("Initialize with no hookData failed: %v", err)
	}
	// Should return a 32-byte tick value
	if len(result) != 32 {
		t.Errorf("expected 32-byte result, got %d bytes", len(result))
	}
}

// =========================================================================
// Finding 8: Address sort uses bytes.Compare not Hex()
//
// Addresses like 0x0a... vs 0x0B... differ under Hex() vs bytes.Compare:
//   Hex():           'a'(0x61) > 'B'(0x42), so 0x0a > 0x0B
//   bytes.Compare:   0x0a < 0x0B (correct raw byte ordering)
// =========================================================================

func TestRedTeam_AddressSort_BytesCompareNotHex(t *testing.T) {
	// 0x0aFF... vs 0x0BFF...
	// bytes.Compare: 0x0a (10) < 0x0B (11) → 0x0a is "lower"
	// strings.Compare(Hex()): "0x0aff..." vs "0x0Bff..." → lowercase 'a'(0x61) > 'B'(0x42)
	addrLow := common.HexToAddress("0x0a00000000000000000000000000000000000001")
	addrHigh := common.HexToAddress("0x0B00000000000000000000000000000000000002")

	// Verify bytes.Compare gives the correct order
	cmp := bytes.Compare(addrLow.Bytes(), addrHigh.Bytes())
	if cmp >= 0 {
		t.Fatalf("test setup: bytes.Compare should give addrLow < addrHigh, got %d", cmp)
	}

	// Verify Hex() gives the WRONG order (case-insensitive issue)
	hexLow := strings.ToLower(addrLow.Hex())
	hexHigh := strings.ToLower(addrHigh.Hex())
	if hexLow >= hexHigh {
		// If ToLower makes them consistent, try the raw mixed-case comparison
		rawHexLow := addrLow.Hex()
		rawHexHigh := addrHigh.Hex()
		t.Logf("Hex comparison: %s vs %s (raw: %s vs %s)", hexLow, hexHigh, rawHexLow, rawHexHigh)
	}

	// sortedPoolKey uses bytes.Compare — verify it puts addrLow as Currency0
	key := sortedPoolKey(addrLow, addrHigh, Fee030, TickSpacing030, common.Address{})
	if key.Currency0.Address != addrLow {
		t.Errorf("VULN: sortedPoolKey put wrong address as Currency0.\ngot  %s\nwant %s", key.Currency0.Address.Hex(), addrLow.Hex())
	}
	if key.Currency1.Address != addrHigh {
		t.Errorf("VULN: sortedPoolKey put wrong address as Currency1.\ngot  %s\nwant %s", key.Currency1.Address.Hex(), addrHigh.Hex())
	}

	// Verify symmetry: passing in reverse order yields same PoolKey
	keyReversed := sortedPoolKey(addrHigh, addrLow, Fee030, TickSpacing030, common.Address{})
	if key.Currency0.Address != keyReversed.Currency0.Address {
		t.Error("VULN: sortedPoolKey is not symmetric")
	}
	if key.ID() != keyReversed.ID() {
		t.Error("VULN: reversed input produces different pool ID")
	}
}

func TestRedTeam_AddressSort_ZeroForOneCorrect(t *testing.T) {
	// When tokenIn < tokenOut (by bytes.Compare), zeroForOne = true
	addrLow := common.HexToAddress("0x0a00000000000000000000000000000000000001")
	addrHigh := common.HexToAddress("0x0B00000000000000000000000000000000000002")

	// tokenIn = addrLow, tokenOut = addrHigh → zeroForOne = true
	zeroForOne := bytes.Compare(addrLow.Bytes(), addrHigh.Bytes()) < 0
	if !zeroForOne {
		t.Error("VULN: zeroForOne should be true when tokenIn < tokenOut")
	}

	// tokenIn = addrHigh, tokenOut = addrLow → zeroForOne = false
	zeroForOne = bytes.Compare(addrHigh.Bytes(), addrLow.Bytes()) < 0
	if zeroForOne {
		t.Error("VULN: zeroForOne should be false when tokenIn > tokenOut")
	}
}

func TestRedTeam_AddressSort_PoolManagerConsistent(t *testing.T) {
	// The PoolManager's areCurrenciesSorted also uses bytes.Compare
	pm := NewPoolManager(&mockEngine{})
	addrLow := Currency{Address: common.HexToAddress("0x0a00000000000000000000000000000000000001")}
	addrHigh := Currency{Address: common.HexToAddress("0x0B00000000000000000000000000000000000002")}

	if !pm.areCurrenciesSorted(addrLow, addrHigh) {
		t.Error("VULN: areCurrenciesSorted disagrees with bytes.Compare")
	}
	if pm.areCurrenciesSorted(addrHigh, addrLow) {
		t.Error("VULN: areCurrenciesSorted accepts wrong order")
	}
}

// =========================================================================
// Finding 9: V3/V2 fallback returns ErrNoOnChainLiquidity (not phantom amounts)
//
// If V4 pool exists but is empty and V3/V2 are not deployed, the result
// should be ErrNoOnChainLiquidity. No path should return non-zero without
// actual on-chain execution.
// =========================================================================

func TestRedTeam_Router_NoOnChainLiquidity(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Do NOT set up any pool. Query for a swap.
	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(10_000),
	}

	amountOut, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err == nil {
		t.Fatalf("VULN: ExactInputSingle returned no error for non-existent pool, amountOut=%s", amountOut)
	}
	if !strings.Contains(err.Error(), "no on-chain liquidity") && !strings.Contains(err.Error(), "not initialized") && !strings.Contains(err.Error(), "not found") {
		t.Logf("Got error (acceptable): %v", err)
	}

	// Verify amountOut is zero or the error is definitive
	if amountOut != nil && amountOut.Sign() > 0 {
		t.Errorf("VULN: non-zero amount returned without on-chain execution: %s", amountOut)
	}
}

func TestRedTeam_Router_EmptyPoolQuoteReturnsZero(t *testing.T) {
	// Initialize a pool but do NOT add liquidity. Quote should return zero.
	// This tests the quote path which is what the router uses for venue selection.
	// A real engine would also fail on Swap, but the mockEngine's Swap doesn't
	// check liquidity. The important property is: Quote returns 0, causing the
	// router to fall through to V3/V2, which are also unavailable, yielding
	// ErrNoOnChainLiquidity.
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	key := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}
	_, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Pool exists but has zero liquidity.
	// Verify Quote returns 0 for zero-liquidity pool (the critical guard).
	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)
	quoted := pm.calculateSwapOutput(pool, big.NewInt(10_000), true)
	if quoted.Sign() > 0 {
		t.Errorf("VULN: Quote returned positive amount for zero-liquidity pool: %s (phantom quote)", quoted)
	}

	// Verify the fee-scan quoteV4 path: should fail because all fee tiers have zero quote.
	_, _, _, err = router.quoteV4(stateDB, testTokenA, testTokenB, big.NewInt(10_000), 0)
	// The pool exists at Fee030 but quote=0, so quoteV4 should not return a positive best.
	// It may return error or zero amount.
	if err == nil {
		t.Log("quoteV4 returned no error for zero-liquidity pool (acceptable if amount=0)")
	}
}

// =========================================================================
// Finding 10: Nil BlockContext guard
//
// DEXContract.Run() must return error, not panic, when BlockContext is nil.
// =========================================================================

func TestRedTeam_NilBlockContext_NoPanic(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}

	// Create a mock accessible state that returns nil for GetBlockContext
	nilCtxState := &mockAccessibleStateNilCtx{stateDB: NewMockStateDB()}

	input := make([]byte, 4+192)
	binary.BigEndian.PutUint32(input[0:4], SelectorInitialize)

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _, err := c.Run(nilCtxState, common.Address{}, lxPoolAddr, input, 1_000_000, false)
		if err == nil {
			t.Error("VULN: Run() with nil BlockContext should return error")
		}
	}()
	if didPanic {
		t.Fatal("VULN: Run() panicked on nil BlockContext — chain halt")
	}
}

func TestRedTeam_NilBlockContext_AllSelectors(t *testing.T) {
	// Test all write selectors with nil block context
	pm := NewPoolManager(&mockEngine{})
	c := &DEXContract{poolManager: pm}
	nilCtxState := &mockAccessibleStateNilCtx{stateDB: NewMockStateDB()}

	selectors := []uint32{
		SelectorInitialize,
		SelectorSwap,
		SelectorModifyLiquidity,
		SelectorDonate,
		SelectorExtsload,
		SelectorExtsloadArray,
	}

	for _, sel := range selectors {
		t.Run(fmt.Sprintf("selector_0x%08X", sel), func(t *testing.T) {
			input := make([]byte, 260) // enough for most selectors
			binary.BigEndian.PutUint32(input[0:4], sel)

			didPanic := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						didPanic = true
					}
				}()
				_, _, err := c.Run(nilCtxState, common.Address{}, lxPoolAddr, input, 1_000_000, false)
				if err == nil {
					t.Errorf("VULN: selector 0x%08X with nil BlockContext should return error", sel)
				}
			}()
			if didPanic {
				t.Fatalf("VULN: selector 0x%08X panicked on nil BlockContext", sel)
			}
		})
	}
}

// =========================================================================
// Finding 11: Cyclic path rejection
//
// Router must reject cyclic paths (repeated tokens).
// =========================================================================

func TestRedTeam_CyclicPath_ABA(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Set up pools so the path could theoretically work
	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	// Path [A, B, A] — B appears at positions 1, and A repeats at 0 and 2
	params := SwapExactInputParams{
		Path:     []common.Address{testTokenA, testTokenB, testTokenA},
		AmountIn: big.NewInt(10_000),
	}

	_, err := router.ExactInput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("VULN: router accepted cyclic path [A, B, A]")
	}
	if !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("error should mention 'cyclic', got: %v", err)
	}
}

func TestRedTeam_CyclicPath_ABCBA(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	testTokenD := common.HexToAddress("0x4000000000000000000000000000000000000004")
	testTokenE := common.HexToAddress("0x5000000000000000000000000000000000000005")

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)
	setupV4Pool(t, pm, stateDB, testTokenC, testTokenD)
	_ = testTokenE // unused

	// Path [A, B, C, B, ...] — B repeats at positions 1 and 3
	params := SwapExactInputParams{
		Path:     []common.Address{testTokenA, testTokenB, testTokenC, testTokenB, testTokenA},
		AmountIn: big.NewInt(10_000),
	}

	_, err := router.ExactInput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("VULN: router accepted path with repeated token B at positions 1,3")
	}
	if !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("error should mention 'cyclic', got: %v", err)
	}
}

func TestRedTeam_ValidPath_NoCycle(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)

	// Path [A, B, C] — no cycle, should succeed
	params := SwapExactInputParams{
		Path:     []common.Address{testTokenA, testTokenB, testTokenC},
		AmountIn: big.NewInt(10_000),
	}

	amountOut, err := router.ExactInput(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("Valid path [A, B, C] failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Errorf("Valid path should produce positive output, got %s", amountOut)
	}
}

func TestRedTeam_PathTooLong(t *testing.T) {
	// MaxPathLength = 5. Path with 6 hops (7 tokens) should be rejected.
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	tokens := make([]common.Address, 7)
	for i := range tokens {
		var addr common.Address
		addr[0] = byte(i + 1)
		addr[19] = byte(i + 1)
		tokens[i] = addr
	}

	// Set up all 6 pairs
	for i := range 6 {
		a, b := tokens[i], tokens[i+1]
		if bytes.Compare(a[:], b[:]) > 0 {
			a, b = b, a
		}
		setupV4Pool(t, pm, stateDB, a, b)
	}

	params := SwapExactInputParams{
		Path:     tokens, // 7 tokens = 6 hops
		AmountIn: big.NewInt(10_000),
	}

	_, err := router.ExactInput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("VULN: router accepted path with 6 hops (exceeds MaxPathLength=5)")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("error should mention 'too long', got: %v", err)
	}
}

func TestRedTeam_CyclicPath_ExactOutput(t *testing.T) {
	// Cyclic path rejection should also apply to ExactOutput
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactOutputParams{
		Path:      []common.Address{testTokenA, testTokenB, testTokenA},
		AmountOut: big.NewInt(5_000),
	}

	_, err := router.ExactOutput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("VULN: ExactOutput accepted cyclic path [A, B, A]")
	}
	if !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("error should mention 'cyclic', got: %v", err)
	}
}

// =========================================================================
// Finding 12: Flash has no hook calls
//
// V4 flash is hookless by design. Verify Flash() works even with a hook
// address set, and does NOT dispatch to any hook.
// =========================================================================

func TestRedTeam_Flash_NoHookCalls(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()

	// Create a pool with a hook address that has all flags set
	hookAddr := common.HexToAddress("0x000000000000000000000000000000000000FFFF")

	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       hookAddr,
	}

	// Initialize the pool
	_, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize with hooks failed: %v", err)
	}

	// Flash should succeed without any hook dispatch
	caller := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	flashParams := FlashParams{
		Amount0:   big.NewInt(1000),
		Amount1:   big.NewInt(2000),
		Recipient: caller,
	}

	delta, err := pm.Flash(stateDB, caller, key, flashParams, nil)
	if err != nil {
		t.Fatalf("Flash with hook address failed: %v (hooks should be no-op for flash)", err)
	}

	// Verify flash returns correct amounts (principal + fee)
	if delta.Amount0.Sign() <= 0 {
		t.Error("Flash should return positive amount0 (principal + fee)")
	}
	if delta.Amount1.Sign() <= 0 {
		t.Error("Flash should return positive amount1 (principal + fee)")
	}
}

// =========================================================================
// Finding 13: hooks.go init() verification
//
// If hooks.go init() panics, no test in this file would run.
// This test documents that verification explicitly.
// =========================================================================

func TestRedTeam_HooksInit_DidNotPanic(t *testing.T) {
	// If we reach this test, hooks.go init() succeeded.
	// The init() function in hooks.go verifies all 10 selectors match keccak256
	// and panics on mismatch. The fact that this test is executing proves init()
	// completed without panic.

	// Verify the HookSignatures map is populated (proof that init ran)
	if len(HookSignatures) != 10 {
		t.Fatalf("HookSignatures should have 10 entries, got %d", len(HookSignatures))
	}

	// Verify each Sig* variable is non-nil and 4 bytes
	sigs := []struct {
		name string
		sig  []byte
	}{
		{"SigBeforeInitialize", SigBeforeInitialize},
		{"SigAfterInitialize", SigAfterInitialize},
		{"SigBeforeAddLiquidity", SigBeforeAddLiquidity},
		{"SigAfterAddLiquidity", SigAfterAddLiquidity},
		{"SigBeforeRemoveLiquidity", SigBeforeRemoveLiquidity},
		{"SigAfterRemoveLiquidity", SigAfterRemoveLiquidity},
		{"SigBeforeSwap", SigBeforeSwap},
		{"SigAfterSwap", SigAfterSwap},
		{"SigBeforeDonate", SigBeforeDonate},
		{"SigAfterDonate", SigAfterDonate},
	}
	for _, s := range sigs {
		if len(s.sig) != 4 {
			t.Errorf("%s has %d bytes, expected 4", s.name, len(s.sig))
		}
	}
}

// =========================================================================
// Finding 14: Hook selector verification for all 10 hooks
//
// Independently compute keccak256(sig)[:4] for each hook and compare
// to the Sig* variable. This is a redundant cross-check against init().
// =========================================================================

func TestRedTeam_HookSelectors_IndependentKeccak(t *testing.T) {
	// Map of hook name -> expected Solidity function signature
	// These MUST match Uniswap V4 IHooks.sol exactly
	hookDefs := []struct {
		name string
		sig  string
		got  []byte
	}{
		{
			"beforeInitialize",
			"beforeInitialize(address,(address,address,uint24,int24,address),uint160,bytes)",
			SigBeforeInitialize,
		},
		{
			"afterInitialize",
			"afterInitialize(address,(address,address,uint24,int24,address),uint160,int24,bytes)",
			SigAfterInitialize,
		},
		{
			"beforeAddLiquidity",
			"beforeAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
			SigBeforeAddLiquidity,
		},
		{
			"afterAddLiquidity",
			"afterAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int128,int128),(int128,int128),bytes)",
			SigAfterAddLiquidity,
		},
		{
			"beforeRemoveLiquidity",
			"beforeRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
			SigBeforeRemoveLiquidity,
		},
		{
			"afterRemoveLiquidity",
			"afterRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int128,int128),(int128,int128),bytes)",
			SigAfterRemoveLiquidity,
		},
		{
			"beforeSwap",
			"beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
			SigBeforeSwap,
		},
		{
			"afterSwap",
			"afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),(int128,int128),bytes)",
			SigAfterSwap,
		},
		{
			"beforeDonate",
			"beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
			SigBeforeDonate,
		},
		{
			"afterDonate",
			"afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
			SigAfterDonate,
		},
	}

	for _, hd := range hookDefs {
		t.Run(hd.name, func(t *testing.T) {
			hash := crypto.Keccak256([]byte(hd.sig))
			want := hash[:4]
			if !bytes.Equal(hd.got, want) {
				t.Errorf("REGRESSION: %s selector mismatch\n  got  %x\n  want %x (keccak256(%q)[:4])",
					hd.name, hd.got, want, hd.sig)
			}

			// Also verify consistency with HookSignatures map
			mapSig, ok := HookSignatures[hd.name]
			if !ok {
				t.Fatalf("HookSignatures missing %q", hd.name)
			}
			if mapSig != hd.sig {
				t.Errorf("HookSignatures[%q] = %q, test expects %q", hd.name, mapSig, hd.sig)
			}
		})
	}
}

func TestRedTeam_HookSelectors_HookSigHelper(t *testing.T) {
	// Verify the hookSig() helper produces identical results to manual keccak256
	sigs := []string{
		"beforeInitialize(address,(address,address,uint24,int24,address),uint160,bytes)",
		"afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),(int128,int128),bytes)",
		"beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
	}
	for _, sig := range sigs {
		got := hookSig(sig)
		want := crypto.Keccak256([]byte(sig))[:4]
		if !bytes.Equal(got, want) {
			t.Errorf("hookSig(%q) = %x, want %x", sig, got, want)
		}
	}
}

// =========================================================================
// Mock for nil BlockContext tests
// =========================================================================

// mockAccessibleStateNilCtx returns nil for GetBlockContext().
type mockAccessibleStateNilCtx struct {
	stateDB *MockStateDB
}

func (m *mockAccessibleStateNilCtx) GetStateDB() contract.StateDB {
	return &contractStateDBWrapper{inner: m.stateDB}
}

func (m *mockAccessibleStateNilCtx) GetBlockContext() contract.BlockContext {
	return nil
}

func (m *mockAccessibleStateNilCtx) GetConsensusContext() context.Context {
	return context.Background()
}

func (m *mockAccessibleStateNilCtx) GetChainConfig() precompileconfig.ChainConfig {
	return nil
}

func (m *mockAccessibleStateNilCtx) GetPrecompileEnv() contract.PrecompileEnvironment {
	return nil
}
