// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MockStateDB implements StateDB interface for testing
type MockStateDB struct {
	storage map[[20]byte]map[[32]byte][32]byte
}

func NewMockStateDB() *MockStateDB {
	return &MockStateDB{
		storage: make(map[[20]byte]map[[32]byte][32]byte),
	}
}

func (m *MockStateDB) GetState(addr [20]byte, key [32]byte) [32]byte {
	if m.storage[addr] == nil {
		return [32]byte{}
	}
	return m.storage[addr][key]
}

func (m *MockStateDB) SetState(addr [20]byte, key [32]byte, value [32]byte) {
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[[32]byte][32]byte)
	}
	m.storage[addr][key] = value
}

func TestVerifyMLDSA65(t *testing.T) {
	// Generate test key pair
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Test message
	message := []byte("test message for AI mining verification")

	// Sign message
	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(priv, message, nil, true, sig); err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify valid signature
	valid, err := VerifyMLDSA(pubBytes, message, sig)
	if err != nil {
		t.Fatalf("VerifyMLDSA error: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature")
	}

	// Verify with wrong message
	wrongMessage := []byte("wrong message")
	valid, err = VerifyMLDSA(pubBytes, wrongMessage, sig)
	if err != nil {
		t.Fatalf("VerifyMLDSA error: %v", err)
	}
	if valid {
		t.Error("Expected invalid signature for wrong message")
	}

	// Verify with corrupted signature
	corruptedSig := make([]byte, len(sig))
	copy(corruptedSig, sig)
	corruptedSig[0] ^= 0xFF
	valid, err = VerifyMLDSA(pubBytes, message, corruptedSig)
	if err != nil {
		t.Fatalf("VerifyMLDSA error: %v", err)
	}
	if valid {
		t.Error("Expected invalid signature for corrupted signature")
	}
}

func TestVerifyMLDSAInvalidSizes(t *testing.T) {
	// Invalid public key size
	_, err := VerifyMLDSA([]byte("short"), []byte("msg"), []byte("sig"))
	if err != ErrInvalidPublicKeySize {
		t.Errorf("Expected ErrInvalidPublicKeySize, got %v", err)
	}

	// Valid public key size but invalid signature size
	pubkey := make([]byte, MLDSA65PublicKeySize)
	_, err = VerifyMLDSA(pubkey, []byte("msg"), []byte("short sig"))
	if err != ErrInvalidSignatureSize {
		t.Errorf("Expected ErrInvalidSignatureSize, got %v", err)
	}
}

func TestCalculateReward(t *testing.T) {
	tests := []struct {
		name           string
		privacyLevel   uint16
		computeMinutes uint32
		chainId        uint64
		expectedMult   uint64 // expected multiplier in basis points
	}{
		{"Public 10 min", PrivacyPublic, 10, 96369, 2500},
		{"Private 10 min", PrivacyPrivate, 10, 96369, 5000},
		{"Confidential 10 min", PrivacyConfidential, 10, 96369, 10000},
		{"Sovereign 10 min", PrivacySovereign, 10, 96369, 15000},
		{"Public 60 min", PrivacyPublic, 60, 36963, 2500},
		{"Confidential 120 min", PrivacyConfidential, 120, 200200, 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceId := [32]byte{1, 2, 3}
			nonce := [32]byte{4, 5, 6}
			timestamp := uint64(1700000000)

			workProof := BuildWorkProof(deviceId, nonce, timestamp, tt.privacyLevel, tt.computeMinutes, nil)

			reward, err := CalculateReward(workProof, tt.chainId)
			if err != nil {
				t.Fatalf("CalculateReward error: %v", err)
			}

			// Expected: baseReward * computeMinutes * multiplier / 10000
			expected := new(big.Int).Set(baseRewardPerMinute)
			expected.Mul(expected, big.NewInt(int64(tt.computeMinutes)))
			expected.Mul(expected, big.NewInt(int64(tt.expectedMult)))
			expected.Div(expected, big.NewInt(10000))

			if reward.Cmp(expected) != 0 {
				t.Errorf("Expected reward %s, got %s", expected.String(), reward.String())
			}
		})
	}
}

func TestCalculateRewardInvalidInput(t *testing.T) {
	// Too short work proof
	_, err := CalculateReward([]byte("short"), 96369)
	if err != ErrInvalidWorkProof {
		t.Errorf("Expected ErrInvalidWorkProof, got %v", err)
	}

	// Invalid privacy level
	deviceId := [32]byte{1}
	nonce := [32]byte{2}
	workProof := BuildWorkProof(deviceId, nonce, 1700000000, 99, 10, nil) // Invalid privacy level 99

	_, err = CalculateReward(workProof, 96369)
	if err != ErrInvalidPrivacyLevel {
		t.Errorf("Expected ErrInvalidPrivacyLevel, got %v", err)
	}
}

func TestComputeWorkId(t *testing.T) {
	deviceId := [32]byte{0x01, 0x02, 0x03}
	nonce := [32]byte{0x04, 0x05, 0x06}
	chainId := uint64(96369)

	workId1 := ComputeWorkId(deviceId, nonce, chainId)
	workId2 := ComputeWorkId(deviceId, nonce, chainId)

	// Same inputs should produce same output
	if workId1 != workId2 {
		t.Error("Same inputs should produce same work ID")
	}

	// Different inputs should produce different output
	differentNonce := [32]byte{0x07, 0x08, 0x09}
	workId3 := ComputeWorkId(deviceId, differentNonce, chainId)
	if workId1 == workId3 {
		t.Error("Different inputs should produce different work ID")
	}

	// Different chain ID should produce different output
	workId4 := ComputeWorkId(deviceId, nonce, 36963)
	if workId1 == workId4 {
		t.Error("Different chain ID should produce different work ID")
	}
}

func TestSpentSet(t *testing.T) {
	stateDB := NewMockStateDB()

	workId := [32]byte{0x01, 0x02, 0x03}

	// Initially not spent
	if IsSpent(stateDB, workId) {
		t.Error("Work ID should not be spent initially")
	}

	// Mark as spent
	err := MarkSpent(stateDB, workId)
	if err != nil {
		t.Fatalf("MarkSpent error: %v", err)
	}

	// Now should be spent
	if !IsSpent(stateDB, workId) {
		t.Error("Work ID should be spent after marking")
	}

	// Trying to mark again should fail
	err = MarkSpent(stateDB, workId)
	if err != ErrWorkAlreadySpent {
		t.Errorf("Expected ErrWorkAlreadySpent, got %v", err)
	}
}

func TestParseWorkProof(t *testing.T) {
	expectedDeviceId := [32]byte{0x01, 0x02, 0x03}
	expectedNonce := [32]byte{0x04, 0x05, 0x06}
	expectedTimestamp := uint64(1700000000)
	expectedPrivacy := uint16(PrivacyConfidential)
	expectedComputeMins := uint32(60)
	expectedTEEQuote := []byte("tee quote data")

	workProof := BuildWorkProof(
		expectedDeviceId,
		expectedNonce,
		expectedTimestamp,
		expectedPrivacy,
		expectedComputeMins,
		expectedTEEQuote,
	)

	deviceId, nonce, timestamp, privacy, computeMins, teeQuote, err := ParseWorkProof(workProof)
	if err != nil {
		t.Fatalf("ParseWorkProof error: %v", err)
	}

	if deviceId != expectedDeviceId {
		t.Error("Device ID mismatch")
	}
	if nonce != expectedNonce {
		t.Error("Nonce mismatch")
	}
	if timestamp != expectedTimestamp {
		t.Error("Timestamp mismatch")
	}
	if privacy != expectedPrivacy {
		t.Error("Privacy level mismatch")
	}
	if computeMins != expectedComputeMins {
		t.Error("Compute minutes mismatch")
	}
	if string(teeQuote) != string(expectedTEEQuote) {
		t.Error("TEE quote mismatch")
	}
}

func TestGetSecurityLevel(t *testing.T) {
	tests := []struct {
		size     int
		expected uint8
		hasError bool
	}{
		{MLDSA44PublicKeySize, 2, false},
		{MLDSA65PublicKeySize, 3, false},
		{MLDSA87PublicKeySize, 5, false},
		{100, 0, true},
	}

	for _, tt := range tests {
		pubkey := make([]byte, tt.size)
		level, err := GetSecurityLevel(pubkey)

		if tt.hasError {
			if err == nil {
				t.Errorf("Expected error for size %d", tt.size)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for size %d: %v", tt.size, err)
			}
			if level != tt.expected {
				t.Errorf("Expected level %d for size %d, got %d", tt.expected, tt.size, level)
			}
		}
	}
}

func TestGetExpectedSignatureSize(t *testing.T) {
	tests := []struct {
		level    uint8
		expected int
		hasError bool
	}{
		{2, MLDSA44SignatureSize, false},
		{3, MLDSA65SignatureSize, false},
		{5, MLDSA87SignatureSize, false},
		{1, 0, true},
		{4, 0, true},
	}

	for _, tt := range tests {
		size, err := GetExpectedSignatureSize(tt.level)

		if tt.hasError {
			if err == nil {
				t.Errorf("Expected error for level %d", tt.level)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for level %d: %v", tt.level, err)
			}
			if size != tt.expected {
				t.Errorf("Expected size %d for level %d, got %d", tt.expected, tt.level, size)
			}
		}
	}
}

func TestGetPrivacyMultiplier(t *testing.T) {
	tests := []struct {
		level    uint16
		expected uint64
		hasError bool
	}{
		{PrivacyPublic, 2500, false},
		{PrivacyPrivate, 5000, false},
		{PrivacyConfidential, 10000, false},
		{PrivacySovereign, 15000, false},
		{0, 0, true},
		{99, 0, true},
	}

	for _, tt := range tests {
		mult, err := GetPrivacyMultiplier(tt.level)

		if tt.hasError {
			if err == nil {
				t.Errorf("Expected error for level %d", tt.level)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for level %d: %v", tt.level, err)
			}
			if mult != tt.expected {
				t.Errorf("Expected multiplier %d for level %d, got %d", tt.expected, tt.level, mult)
			}
		}
	}
}

func TestVerifyNVTrust(t *testing.T) {
	// Valid receipt structure (minimal)
	deviceId := [32]byte{0x01, 0x02, 0x03}
	timestamp := uint64(1700000000)
	nonce := uint64(12345)

	receipt := make([]byte, 48)
	copy(receipt[0:32], deviceId[:])
	copy(receipt[32:40], []byte{
		byte(timestamp >> 56), byte(timestamp >> 48),
		byte(timestamp >> 40), byte(timestamp >> 32),
		byte(timestamp >> 24), byte(timestamp >> 16),
		byte(timestamp >> 8), byte(timestamp),
	})
	copy(receipt[40:48], []byte{
		byte(nonce >> 56), byte(nonce >> 48),
		byte(nonce >> 40), byte(nonce >> 32),
		byte(nonce >> 24), byte(nonce >> 16),
		byte(nonce >> 8), byte(nonce),
	})

	signature := []byte("valid signature placeholder")

	valid, err := VerifyNVTrust(receipt, signature)
	if err != nil {
		t.Fatalf("VerifyNVTrust error: %v", err)
	}
	if !valid {
		t.Error("Expected valid NVTrust attestation")
	}

	// Empty receipt should fail
	_, err = VerifyNVTrust([]byte{}, signature)
	if err != ErrInvalidNVTrustReceipt {
		t.Errorf("Expected ErrInvalidNVTrustReceipt, got %v", err)
	}

	// Short receipt should fail
	_, err = VerifyNVTrust([]byte("short"), signature)
	if err != ErrInvalidNVTrustReceipt {
		t.Errorf("Expected ErrInvalidNVTrustReceipt, got %v", err)
	}
}

// Benchmark tests

func BenchmarkComputeWorkId(b *testing.B) {
	deviceId := [32]byte{0x01, 0x02, 0x03}
	nonce := [32]byte{0x04, 0x05, 0x06}
	chainId := uint64(96369)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeWorkId(deviceId, nonce, chainId)
	}
}

func BenchmarkCalculateReward(b *testing.B) {
	deviceId := [32]byte{0x01}
	nonce := [32]byte{0x02}
	workProof := BuildWorkProof(deviceId, nonce, 1700000000, PrivacyConfidential, 60, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CalculateReward(workProof, 96369)
	}
}

func BenchmarkIsSpent(b *testing.B) {
	stateDB := NewMockStateDB()
	workId := [32]byte{0x01, 0x02, 0x03}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsSpent(stateDB, workId)
	}
}

func BenchmarkVerifyMLDSA65(b *testing.B) {
	// Generate test key pair
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		b.Fatalf("Failed to marshal public key: %v", err)
	}

	message := []byte("test message for benchmarking")
	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(priv, message, nil, true, sig); err != nil {
		b.Fatalf("Failed to sign: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyMLDSA(pubBytes, message, sig)
	}
}
