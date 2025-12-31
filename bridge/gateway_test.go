// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
)

// Helper functions for large big.Int values (avoid overflow in big.NewInt)
func bigExp(base, exp int64) *big.Int {
	result := big.NewInt(1)
	b := big.NewInt(base)
	for i := int64(0); i < exp; i++ {
		result.Mul(result, b)
	}
	return result
}

// e19 returns 10^19
func e19() *big.Int { return bigExp(10, 19) }

// e20 returns 10^20
func e20() *big.Int { return bigExp(10, 20) }

// e21 returns 10^21
func e21() *big.Int { return bigExp(10, 21) }

// e24 returns 10^24
func e24() *big.Int { return bigExp(10, 24) }

// e25 returns 10^25
func e25() *big.Int { return bigExp(10, 25) }

// e22 returns 10^22
func e22() *big.Int { return bigExp(10, 22) }

// e30 returns 10^30
func e30() *big.Int { return bigExp(10, 30) }

// fiveE19 returns 5 * 10^19
func fiveE19() *big.Int { return new(big.Int).Mul(big.NewInt(5), e19()) }

// TestNewBridgeGateway tests gateway creation
func TestNewBridgeGateway(t *testing.T) {
	gw := NewBridgeGateway()
	if gw == nil {
		t.Fatal("Expected non-nil BridgeGateway")
	}

	if gw.Requests == nil {
		t.Error("Expected Requests map to be initialized")
	}
	if gw.Nonces == nil {
		t.Error("Expected Nonces map to be initialized")
	}
	if gw.SupportedTokens == nil {
		t.Error("Expected SupportedTokens map to be initialized")
	}
	if gw.SupportedChains == nil {
		t.Error("Expected SupportedChains map to be initialized")
	}
	if gw.Pools == nil {
		t.Error("Expected Pools map to be initialized")
	}
	if gw.SignerSet == nil {
		t.Error("Expected SignerSet to be initialized")
	}
	if gw.Config == nil {
		t.Error("Expected Config to be initialized")
	}
	if !gw.Enabled {
		t.Error("Expected gateway to be enabled")
	}
}

// TestSupportedChains tests chain support initialization
func TestSupportedChains(t *testing.T) {
	gw := NewBridgeGateway()

	expectedChains := []uint32{
		ChainLux, ChainLuxTest,
		ChainHanzo, ChainHanzoTest,
		ChainZoo, ChainZooTest,
		ChainSPC, ChainSPCTest,
		ChainEthereum, ChainArbitrum, ChainOptimism,
		ChainBase, ChainPolygon, ChainBSC, ChainAvalanche,
	}

	for _, chainID := range expectedChains {
		if !gw.SupportedChains[chainID] {
			t.Errorf("Expected chain %d to be supported", chainID)
		}
	}

	// Verify unsupported chain
	if gw.SupportedChains[99999] {
		t.Error("Chain 99999 should not be supported")
	}
}

// TestRegisterToken tests token registration
func TestRegisterToken(t *testing.T) {
	gw := NewBridgeGateway()
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	err := gw.RegisterToken(
		token,
		18,
		"TEST",
		"Test Token",
		big.NewInt(1e17),                                      // min bridge
		new(big.Int).Mul(big.NewInt(1e12), big.NewInt(1e12)),  // max bridge (1e24)
		new(big.Int).Mul(big.NewInt(1e13), big.NewInt(1e12)),  // daily limit (1e25)
	)

	if err != nil {
		t.Fatalf("RegisterToken failed: %v", err)
	}

	// Verify token was registered
	tokenInfo := gw.SupportedTokens[token]
	if tokenInfo == nil {
		t.Fatal("Token not stored")
	}
	if tokenInfo.Symbol != "TEST" {
		t.Errorf("Expected symbol TEST, got %s", tokenInfo.Symbol)
	}
	if tokenInfo.Decimals != 18 {
		t.Errorf("Expected decimals 18, got %d", tokenInfo.Decimals)
	}
	if !tokenInfo.Enabled {
		t.Error("Expected token to be enabled")
	}
}

// TestRegisterTokenDuplicate tests duplicate token registration
func TestRegisterTokenDuplicate(t *testing.T) {
	gw := NewBridgeGateway()
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	// First registration
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1), e24(), e25())

	// Duplicate registration
	err := gw.RegisterToken(token, 18, "TEST2", "Test2", big.NewInt(1), e24(), e25())
	if err == nil {
		t.Error("Expected error for duplicate token registration")
	}
}

// TestInitiateBridge tests bridge initiation
func TestInitiateBridge(t *testing.T) {
	gw := NewBridgeGateway()

	// Setup token
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())

	// Add liquidity on destination chain
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e21())

	// Initiate bridge
	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	recipient := common.HexToAddress("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
	amount := big.NewInt(1e18)

	request, err := gw.InitiateBridge(
		sender,
		recipient,
		token,
		amount,
		ChainLux,
		ChainEthereum,
		uint64(time.Now().Add(time.Hour).Unix()),
		nil,
	)

	if err != nil {
		t.Fatalf("InitiateBridge failed: %v", err)
	}

	if request == nil {
		t.Fatal("Expected non-nil request")
	}
	if request.ID == [32]byte{} {
		t.Error("Expected non-zero request ID")
	}
	if request.Sender != sender {
		t.Error("Sender mismatch")
	}
	if request.Recipient != recipient {
		t.Error("Recipient mismatch")
	}
	if request.Status != StatusPending {
		t.Errorf("Expected pending status, got %v", request.Status)
	}

	// Verify nonce incremented
	if gw.Nonces[sender] != 1 {
		t.Errorf("Expected nonce 1, got %d", gw.Nonces[sender])
	}
}

// TestInitiateBridgeDisabled tests bridging when gateway is disabled
func TestInitiateBridgeDisabled(t *testing.T) {
	gw := NewBridgeGateway()
	gw.Enabled = false

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, common.Address{}, big.NewInt(1), 1, 2, 0, nil)
	if err != ErrBridgeDisabled {
		t.Errorf("Expected ErrBridgeDisabled, got %v", err)
	}
}

// TestInitiateBridgePaused tests bridging when gateway is paused
func TestInitiateBridgePaused(t *testing.T) {
	gw := NewBridgeGateway()
	gw.Paused = true

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, common.Address{}, big.NewInt(1), 1, 2, 0, nil)
	if err != ErrBridgeDisabled {
		t.Errorf("Expected ErrBridgeDisabled, got %v", err)
	}
}

// TestInitiateBridgeChainNotSupported tests unsupported destination chain
func TestInitiateBridgeChainNotSupported(t *testing.T) {
	gw := NewBridgeGateway()

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, common.Address{}, big.NewInt(1), ChainLux, 99999, 0, nil)
	if err != ErrChainNotSupported {
		t.Errorf("Expected ErrChainNotSupported, got %v", err)
	}
}

// TestInitiateBridgeTokenNotSupported tests unsupported token
func TestInitiateBridgeTokenNotSupported(t *testing.T) {
	gw := NewBridgeGateway()

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	unsupportedToken := common.HexToAddress("0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD")

	_, err := gw.InitiateBridge(sender, sender, unsupportedToken, big.NewInt(1e18), ChainLux, ChainEthereum, 0, nil)
	if err != ErrTokenNotSupported {
		t.Errorf("Expected ErrTokenNotSupported, got %v", err)
	}
}

// TestInitiateBridgeAmountTooLow tests minimum amount validation
func TestInitiateBridgeAmountTooLow(t *testing.T) {
	gw := NewBridgeGateway()

	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, token, big.NewInt(1e16), ChainLux, ChainEthereum, 0, nil) // Below min
	if err != ErrAmountTooLow {
		t.Errorf("Expected ErrAmountTooLow, got %v", err)
	}
}

// TestInitiateBridgeAmountTooHigh tests maximum amount validation
func TestInitiateBridgeAmountTooHigh(t *testing.T) {
	gw := NewBridgeGateway()

	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e20(), e25()) // Max 100 tokens

	// Add liquidity
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e24())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, token, e21(), ChainLux, ChainEthereum, 0, nil) // Above max
	if err != ErrAmountTooHigh {
		t.Errorf("Expected ErrAmountTooHigh, got %v", err)
	}
}

// TestInitiateBridgeInsufficientLiquidity tests liquidity check
func TestInitiateBridgeInsufficientLiquidity(t *testing.T) {
	gw := NewBridgeGateway()

	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())

	// No liquidity added

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, token, big.NewInt(1e18), ChainLux, ChainEthereum, 0, nil)
	if err != ErrInsufficientLiquidity {
		t.Errorf("Expected ErrInsufficientLiquidity, got %v", err)
	}
}

// TestInitiateBridgeDailyLimitExceeded tests daily limit
func TestInitiateBridgeDailyLimitExceeded(t *testing.T) {
	gw := NewBridgeGateway()

	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e19()) // Daily limit 10 tokens

	// Add liquidity
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e24())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	_, err := gw.InitiateBridge(sender, sender, token, e20(), ChainLux, ChainEthereum, 0, nil) // Exceeds daily limit
	if err != ErrDailyLimitExceeded {
		t.Errorf("Expected ErrDailyLimitExceeded, got %v", err)
	}
}

// TestCompleteBridge tests bridge completion
func TestCompleteBridge(t *testing.T) {
	gw := NewBridgeGateway()

	// Setup
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e21())

	// Initiate
	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	request, _ := gw.InitiateBridge(sender, sender, token, big.NewInt(1e18), ChainLux, ChainEthereum, 0, nil)

	// Complete with signatures
	signatures := [][]byte{[]byte("sig1")}
	err := gw.CompleteBridge(request.ID, signatures)
	if err != nil {
		t.Fatalf("CompleteBridge failed: %v", err)
	}

	// Verify status
	completedRequest, _ := gw.GetRequest(request.ID)
	if completedRequest.Status != StatusCompleted {
		t.Errorf("Expected completed status, got %v", completedRequest.Status)
	}
	if completedRequest.CompletedAt == 0 {
		t.Error("Expected non-zero CompletedAt")
	}
}

// TestCompleteBridgeNotFound tests error for non-existent request
func TestCompleteBridgeNotFound(t *testing.T) {
	gw := NewBridgeGateway()

	nonExistent := [32]byte{0xFF}
	err := gw.CompleteBridge(nonExistent, [][]byte{[]byte("sig")})
	if err != ErrRequestNotFound {
		t.Errorf("Expected ErrRequestNotFound, got %v", err)
	}
}

// TestCompleteBridgeAlreadyDone tests double completion
func TestCompleteBridgeAlreadyDone(t *testing.T) {
	gw := NewBridgeGateway()

	// Setup and complete
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e21())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	request, _ := gw.InitiateBridge(sender, sender, token, big.NewInt(1e18), ChainLux, ChainEthereum, 0, nil)
	_ = gw.CompleteBridge(request.ID, [][]byte{[]byte("sig")})

	// Try to complete again
	err := gw.CompleteBridge(request.ID, [][]byte{[]byte("sig")})
	if err != ErrRequestAlreadyDone {
		t.Errorf("Expected ErrRequestAlreadyDone, got %v", err)
	}
}

// TestCompleteBridgeExpired tests expired request
func TestCompleteBridgeExpired(t *testing.T) {
	gw := NewBridgeGateway()

	// Setup
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e21())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	request, _ := gw.InitiateBridge(sender, sender, token, big.NewInt(1e18), ChainLux, ChainEthereum, 1, nil) // Already expired

	err := gw.CompleteBridge(request.ID, [][]byte{[]byte("sig")})
	if err != ErrRequestExpired {
		t.Errorf("Expected ErrRequestExpired, got %v", err)
	}
}

// TestRefundExpired tests refunding expired requests
func TestRefundExpired(t *testing.T) {
	gw := NewBridgeGateway()

	// Setup
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e21())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	request, _ := gw.InitiateBridge(sender, sender, token, big.NewInt(1e18), ChainLux, ChainEthereum, 1, nil) // Already expired

	err := gw.RefundExpired(request.ID)
	if err != nil {
		t.Fatalf("RefundExpired failed: %v", err)
	}

	// Verify status
	refundedRequest, _ := gw.GetRequest(request.ID)
	if refundedRequest.Status != StatusRefunded {
		t.Errorf("Expected refunded status, got %v", refundedRequest.Status)
	}
}

// TestAddLiquidity tests adding liquidity
func TestAddLiquidity(t *testing.T) {
	gw := NewBridgeGateway()

	provider := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	amount := e20()

	position, err := gw.AddLiquidity(provider, token, ChainEthereum, amount)
	if err != nil {
		t.Fatalf("AddLiquidity failed: %v", err)
	}

	if position == nil {
		t.Fatal("Expected non-nil position")
	}
	if position.Provider != provider {
		t.Error("Provider mismatch")
	}
	if position.Amount.Cmp(amount) != 0 {
		t.Errorf("Expected amount %v, got %v", amount, position.Amount)
	}

	// Verify pool state
	pool := gw.Pools[ChainEthereum][token]
	if pool == nil {
		t.Fatal("Pool not created")
	}
	if pool.TotalLiq.Cmp(amount) != 0 {
		t.Errorf("Expected total liquidity %v, got %v", amount, pool.TotalLiq)
	}
	if pool.Available.Cmp(amount) != 0 {
		t.Errorf("Expected available %v, got %v", amount, pool.Available)
	}
}

// TestAddLiquidityChainNotSupported tests error for unsupported chain
func TestAddLiquidityChainNotSupported(t *testing.T) {
	gw := NewBridgeGateway()

	provider := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	_, err := gw.AddLiquidity(provider, token, 99999, big.NewInt(1e18))
	if err != ErrChainNotSupported {
		t.Errorf("Expected ErrChainNotSupported, got %v", err)
	}
}

// TestAddLiquidityMultiple tests adding liquidity multiple times
func TestAddLiquidityMultiple(t *testing.T) {
	gw := NewBridgeGateway()

	provider := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e20())
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e20())

	pool := gw.Pools[ChainEthereum][token]
	expected := new(big.Int).Mul(big.NewInt(2), e20())
	if pool.TotalLiq.Cmp(expected) != 0 {
		t.Errorf("Expected total %v, got %v", expected, pool.TotalLiq)
	}
}

// TestRemoveLiquidity tests removing liquidity
func TestRemoveLiquidity(t *testing.T) {
	gw := NewBridgeGateway()

	provider := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e20())

	total, err := gw.RemoveLiquidity(provider, token, ChainEthereum, fiveE19())
	if err != nil {
		t.Fatalf("RemoveLiquidity failed: %v", err)
	}

	// Should return amount + fees
	if total.Cmp(fiveE19()) < 0 {
		t.Errorf("Expected at least %v, got %v", fiveE19(), total)
	}

	// Verify pool updated
	pool := gw.Pools[ChainEthereum][token]
	if pool.TotalLiq.Cmp(fiveE19()) != 0 {
		t.Errorf("Expected remaining %v, got %v", fiveE19(), pool.TotalLiq)
	}
}

// TestRemoveLiquidityInsufficientBalance tests removing more than deposited
func TestRemoveLiquidityInsufficientBalance(t *testing.T) {
	gw := NewBridgeGateway()

	provider := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, big.NewInt(1e18))

	_, err := gw.RemoveLiquidity(provider, token, ChainEthereum, e20()) // More than deposited
	if err != ErrInsufficientLiquidity {
		t.Errorf("Expected ErrInsufficientLiquidity, got %v", err)
	}
}

// TestGetRequest tests request retrieval
func TestGetRequest(t *testing.T) {
	gw := NewBridgeGateway()

	nonExistent := [32]byte{0xFF}
	_, err := gw.GetRequest(nonExistent)
	if err != ErrRequestNotFound {
		t.Errorf("Expected ErrRequestNotFound, got %v", err)
	}
}

// TestCalculateFee tests fee calculation
func TestCalculateFee(t *testing.T) {
	gw := NewBridgeGateway()

	tests := []struct {
		name   string
		amount *big.Int
		minFee *big.Int
	}{
		{"Small amount", big.NewInt(1e17), gw.Config.MinFee},   // Fee would be below min
		{"Large amount", e22(), gw.Config.MaxFee},   // Fee would exceed max
		{"Medium amount", e19(), nil},               // Normal calculation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee := gw.calculateFee(tt.amount)
			if fee.Sign() <= 0 {
				t.Error("Expected positive fee")
			}
			if gw.Config.MinFee.Sign() > 0 && fee.Cmp(gw.Config.MinFee) < 0 {
				t.Errorf("Fee %v below minimum %v", fee, gw.Config.MinFee)
			}
			if gw.Config.MaxFee.Sign() > 0 && fee.Cmp(gw.Config.MaxFee) > 0 {
				t.Errorf("Fee %v above maximum %v", fee, gw.Config.MaxFee)
			}
		})
	}
}

// TestNonceIncrement tests nonce handling
func TestNonceIncrement(t *testing.T) {
	gw := NewBridgeGateway()

	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e25())
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, e24())

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")

	for i := uint64(0); i < 5; i++ {
		_, _ = gw.InitiateBridge(sender, sender, token, big.NewInt(1e18), ChainLux, ChainEthereum, 0, nil)
		if gw.Nonces[sender] != i+1 {
			t.Errorf("Expected nonce %d, got %d", i+1, gw.Nonces[sender])
		}
	}
}

// TestSignerThreshold tests threshold calculation
func TestSignerThreshold(t *testing.T) {
	gw := NewBridgeGateway()

	// No signers
	threshold := gw.getThreshold()
	if threshold != 1 {
		t.Errorf("Expected threshold 1 with no signers, got %d", threshold)
	}

	// Add signers
	gw.SignerSet.Signers = make([]*SignerInfo, 10)
	threshold = gw.getThreshold()
	expected := uint32((10 * 2 / 3) + 1) // 2/3 + 1 = 7
	if threshold != expected {
		t.Errorf("Expected threshold %d, got %d", expected, threshold)
	}
}

// Benchmark tests

func BenchmarkInitiateBridge(b *testing.B) {
	gw := NewBridgeGateway()
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	_ = gw.RegisterToken(token, 18, "TEST", "Test", big.NewInt(1e17), e24(), e30())
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, _ = gw.AddLiquidity(provider, token, ChainEthereum, new(big.Int).Mul(e24(), big.NewInt(int64(b.N)+1)))

	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	amount := big.NewInt(1e18)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gw.InitiateBridge(sender, sender, token, amount, ChainLux, ChainEthereum, 0, nil)
	}
}

func BenchmarkCalculateFee(b *testing.B) {
	gw := NewBridgeGateway()
	amount := e20()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gw.calculateFee(amount)
	}
}

func BenchmarkAddLiquidity(b *testing.B) {
	gw := NewBridgeGateway()
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	amount := big.NewInt(1e18)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider := common.BigToAddress(big.NewInt(int64(i)))
		_, _ = gw.AddLiquidity(provider, token, ChainEthereum, amount)
	}
}
