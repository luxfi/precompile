// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// =========================================================================
// Hook Permission Tests
// =========================================================================

func TestEncodeDecodeHookPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions HookPermissions
	}{
		{
			name:        "no permissions",
			permissions: HookPermissions{},
		},
		{
			name: "beforeSwap only",
			permissions: HookPermissions{
				BeforeSwap: true,
			},
		},
		{
			name: "afterSwap only",
			permissions: HookPermissions{
				AfterSwap: true,
			},
		},
		{
			name: "swap hooks",
			permissions: HookPermissions{
				BeforeSwap: true,
				AfterSwap:  true,
			},
		},
		{
			name: "all hooks",
			permissions: HookPermissions{
				BeforeInitialize:      true,
				AfterInitialize:       true,
				BeforeAddLiquidity:    true,
				AfterAddLiquidity:     true,
				BeforeRemoveLiquidity: true,
				AfterRemoveLiquidity:  true,
				BeforeSwap:            true,
				AfterSwap:             true,
				BeforeDonate:          true,
				AfterDonate:           true,
				BeforeFlash:           true,
				AfterFlash:            true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			flags := EncodeHookPermissions(tt.permissions)

			// Decode
			decoded := DecodeHookPermissions(flags)

			// Verify all fields match
			if decoded.BeforeInitialize != tt.permissions.BeforeInitialize {
				t.Errorf("BeforeInitialize mismatch: got %v, want %v", decoded.BeforeInitialize, tt.permissions.BeforeInitialize)
			}
			if decoded.AfterInitialize != tt.permissions.AfterInitialize {
				t.Errorf("AfterInitialize mismatch: got %v, want %v", decoded.AfterInitialize, tt.permissions.AfterInitialize)
			}
			if decoded.BeforeAddLiquidity != tt.permissions.BeforeAddLiquidity {
				t.Errorf("BeforeAddLiquidity mismatch: got %v, want %v", decoded.BeforeAddLiquidity, tt.permissions.BeforeAddLiquidity)
			}
			if decoded.AfterAddLiquidity != tt.permissions.AfterAddLiquidity {
				t.Errorf("AfterAddLiquidity mismatch: got %v, want %v", decoded.AfterAddLiquidity, tt.permissions.AfterAddLiquidity)
			}
			if decoded.BeforeSwap != tt.permissions.BeforeSwap {
				t.Errorf("BeforeSwap mismatch: got %v, want %v", decoded.BeforeSwap, tt.permissions.BeforeSwap)
			}
			if decoded.AfterSwap != tt.permissions.AfterSwap {
				t.Errorf("AfterSwap mismatch: got %v, want %v", decoded.AfterSwap, tt.permissions.AfterSwap)
			}
		})
	}
}

func TestGetHookPermissionsFromAddress(t *testing.T) {
	// Create address with known permissions
	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}
	flags := EncodeHookPermissions(permissions)

	// Create address with flags in first 2 bytes
	var addr common.Address
	binary.BigEndian.PutUint16(addr[0:2], uint16(flags))

	// Get permissions from address
	decoded := GetHookPermissionsFromAddress(addr)

	if decoded.BeforeSwap != true {
		t.Error("Expected BeforeSwap to be true")
	}
	if decoded.AfterSwap != true {
		t.Error("Expected AfterSwap to be true")
	}
	if decoded.BeforeInitialize != false {
		t.Error("Expected BeforeInitialize to be false")
	}
}

func TestHasPermission(t *testing.T) {
	// Create address with beforeSwap and afterSwap
	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}
	flags := EncodeHookPermissions(permissions)

	var addr common.Address
	binary.BigEndian.PutUint16(addr[0:2], uint16(flags))

	// Test has permission
	if !HasPermission(addr, HookBeforeSwap) {
		t.Error("Expected HasPermission(BeforeSwap) to be true")
	}
	if !HasPermission(addr, HookAfterSwap) {
		t.Error("Expected HasPermission(AfterSwap) to be true")
	}
	if HasPermission(addr, HookBeforeInitialize) {
		t.Error("Expected HasPermission(BeforeInitialize) to be false")
	}
}

func TestValidateHookAddress(t *testing.T) {
	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}
	flags := EncodeHookPermissions(permissions)

	// Create valid address
	var validAddr common.Address
	binary.BigEndian.PutUint16(validAddr[0:2], uint16(flags))

	// Validation should pass
	err := ValidateHookAddress(validAddr, permissions)
	if err != nil {
		t.Errorf("ValidateHookAddress failed for valid address: %v", err)
	}

	// Create invalid address (wrong permissions encoded)
	var invalidAddr common.Address
	binary.BigEndian.PutUint16(invalidAddr[0:2], uint16(HookBeforeInitialize))

	// Validation should fail
	err = ValidateHookAddress(invalidAddr, permissions)
	if err != ErrHookInvalidAddress {
		t.Errorf("Expected ErrHookInvalidAddress, got: %v", err)
	}
}

// =========================================================================
// Hook Registry Tests
// =========================================================================

func TestHookRegistryRegister(t *testing.T) {
	registry := NewHookRegistry()

	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}
	flags := EncodeHookPermissions(permissions)

	// Create valid address
	var addr common.Address
	binary.BigEndian.PutUint16(addr[0:2], uint16(flags))

	// Register should succeed
	err := registry.RegisterHook(addr, flags)
	if err != nil {
		t.Errorf("RegisterHook failed: %v", err)
	}

	// Get flags should return correct value
	registeredFlags, ok := registry.GetHookFlags(addr)
	if !ok {
		t.Error("Expected hook to be registered")
	}
	if registeredFlags != flags {
		t.Errorf("Flags mismatch: got %d, want %d", registeredFlags, flags)
	}
}

func TestHookRegistryRegisterInvalidAddress(t *testing.T) {
	registry := NewHookRegistry()

	// Create address with different flags than claimed
	var addr common.Address
	binary.BigEndian.PutUint16(addr[0:2], uint16(HookBeforeSwap))

	// Try to register with different flags
	err := registry.RegisterHook(addr, HookAfterSwap)
	if err != ErrHookInvalidAddress {
		t.Errorf("Expected ErrHookInvalidAddress, got: %v", err)
	}
}

func TestHookRegistryIsEnabled(t *testing.T) {
	registry := NewHookRegistry()

	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}
	flags := EncodeHookPermissions(permissions)

	var addr common.Address
	binary.BigEndian.PutUint16(addr[0:2], uint16(flags))

	registry.RegisterHook(addr, flags)

	// Check enabled hooks
	if !registry.IsHookEnabled(addr, HookBeforeSwap) {
		t.Error("Expected BeforeSwap to be enabled")
	}
	if !registry.IsHookEnabled(addr, HookAfterSwap) {
		t.Error("Expected AfterSwap to be enabled")
	}
	if registry.IsHookEnabled(addr, HookBeforeInitialize) {
		t.Error("Expected BeforeInitialize to be disabled")
	}
}

// =========================================================================
// Hook Address Generation Tests
// =========================================================================

func TestGenerateHookAddress(t *testing.T) {
	deployer := common.HexToAddress("0x1234567890123456789012345678901234567890")
	var salt [32]byte
	copy(salt[:], []byte("test-salt"))

	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}

	addr := GenerateHookAddress(deployer, salt, permissions)

	// Verify permissions are encoded in address
	decoded := GetHookPermissionsFromAddress(addr)
	if decoded.BeforeSwap != true {
		t.Error("Generated address should have BeforeSwap permission")
	}
	if decoded.AfterSwap != true {
		t.Error("Generated address should have AfterSwap permission")
	}
}

// =========================================================================
// Dynamic Fee Calculator Tests
// =========================================================================

func TestVolatilityFeeCalculator(t *testing.T) {
	calc := &VolatilityFeeCalculator{
		BaseFee:         Fee030,
		MaxFee:          Fee100,
		VolatilityScale: 100,
		WindowSize:      3600,
	}

	// Test with no observations
	fee := calc.CalculateFee(nil)
	if fee != Fee030 {
		t.Errorf("Expected base fee with no observations, got: %d", fee)
	}

	// Test with stable observations
	observations := []TWAPObservation{
		{
			Timestamp:      1000,
			TickCumulative: big.NewInt(0),
			Initialized:    true,
		},
		{
			Timestamp:      2000,
			TickCumulative: big.NewInt(0), // No tick movement
			Initialized:    true,
		},
	}

	fee = calc.CalculateFee(observations)
	if fee != Fee030 {
		t.Errorf("Expected base fee with no volatility, got: %d", fee)
	}

	// Test with volatile observations
	volatileObservations := []TWAPObservation{
		{
			Timestamp:      1000,
			TickCumulative: big.NewInt(0),
			Initialized:    true,
		},
		{
			Timestamp:      2000,
			TickCumulative: big.NewInt(100000), // High tick movement
			Initialized:    true,
		},
	}

	volatileFee := calc.CalculateFee(volatileObservations)
	if volatileFee <= Fee030 {
		t.Error("Expected higher fee with volatility")
	}
	if volatileFee > Fee100 {
		t.Errorf("Fee should not exceed max: got %d", volatileFee)
	}
}

// =========================================================================
// Commit-Reveal Validator Tests
// =========================================================================

func TestCommitRevealValidator(t *testing.T) {
	validator := &CommitRevealValidator{
		CommitmentPeriod: 10,
	}

	commit := &CommittedSwap{
		CommitHash:  [32]byte{1, 2, 3},
		Sender:      common.HexToAddress("0x1111111111111111111111111111111111111111"),
		CommitBlock: 100,
		Amount:      big.NewInt(1000),
	}

	// Test before commitment period
	err := validator.ValidateCommitment(commit, 105)
	if err == nil {
		t.Error("Expected error when commitment period not elapsed")
	}

	// Test after commitment period
	err = validator.ValidateCommitment(commit, 115)
	if err != nil {
		t.Errorf("Validation should pass after commitment period: %v", err)
	}
}

// =========================================================================
// Pack/Unpack Tests
// =========================================================================

func TestPackBeforeSwapParams(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	key := newTestPoolKey()
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: big.NewInt(1000000),
	}
	hookData := []byte("test-hook-data")

	packed := PackBeforeSwapParams(sender, key, params, hookData)

	// Verify selector
	if len(packed) < 4 {
		t.Fatal("Packed data too short")
	}

	for i, b := range SigBeforeSwap {
		if packed[i] != b {
			t.Errorf("Selector mismatch at byte %d: got %x, want %x", i, packed[i], b)
		}
	}
}

func TestPackAfterSwapParams(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	key := newTestPoolKey()
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: big.NewInt(1000000),
	}
	delta := NewBalanceDelta(big.NewInt(1000), big.NewInt(-500))
	hookData := []byte("test-hook-data")

	packed := PackAfterSwapParams(sender, key, params, delta, hookData)

	// Verify selector
	if len(packed) < 4 {
		t.Fatal("Packed data too short")
	}

	for i, b := range SigAfterSwap {
		if packed[i] != b {
			t.Errorf("Selector mismatch at byte %d: got %x, want %x", i, packed[i], b)
		}
	}
}

func TestUnpackHookDeltaReturn(t *testing.T) {
	// Test with no data
	delta, err := UnpackHookDeltaReturn(nil)
	if err != nil || delta != nil {
		t.Error("Expected nil delta with no data")
	}

	// Test with short data
	delta, err = UnpackHookDeltaReturn(make([]byte, 32))
	if err != nil || delta != nil {
		t.Error("Expected nil delta with short data")
	}

	// Test with valid data
	data := make([]byte, 64)
	amount0 := big.NewInt(1000)
	amount1 := big.NewInt(2000)
	amount0.FillBytes(data[0:32])
	amount1.FillBytes(data[32:64])

	delta, err = UnpackHookDeltaReturn(data)
	if err != nil {
		t.Fatalf("UnpackHookDeltaReturn failed: %v", err)
	}

	if delta.Amount0.Cmp(amount0) != 0 {
		t.Errorf("Amount0 mismatch: got %s, want %s", delta.Amount0, amount0)
	}
	if delta.Amount1.Cmp(amount1) != 0 {
		t.Errorf("Amount1 mismatch: got %s, want %s", delta.Amount1, amount1)
	}
}

// =========================================================================
// Benchmark Tests
// =========================================================================

func BenchmarkEncodeHookPermissions(b *testing.B) {
	permissions := HookPermissions{
		BeforeSwap:         true,
		AfterSwap:          true,
		BeforeAddLiquidity: true,
		AfterAddLiquidity:  true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeHookPermissions(permissions)
	}
}

func BenchmarkDecodeHookPermissions(b *testing.B) {
	flags := HookFlags(0x00FF)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DecodeHookPermissions(flags)
	}
}

func BenchmarkHasPermission(b *testing.B) {
	var addr common.Address
	binary.BigEndian.PutUint16(addr[0:2], uint16(HookBeforeSwap|HookAfterSwap))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HasPermission(addr, HookBeforeSwap)
	}
}

func BenchmarkGenerateHookAddress(b *testing.B) {
	deployer := common.HexToAddress("0x1234567890123456789012345678901234567890")
	var salt [32]byte
	permissions := HookPermissions{
		BeforeSwap: true,
		AfterSwap:  true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GenerateHookAddress(deployer, salt, permissions)
	}
}
