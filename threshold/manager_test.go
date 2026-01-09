// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"testing"
	"time"

	"github.com/luxfi/geth/common"
)

// TestNewThresholdManager tests manager creation
func TestNewThresholdManager(t *testing.T) {
	tm := NewThresholdManager()
	if tm == nil {
		t.Fatal("Expected non-nil ThresholdManager")
	}

	if tm.Keys == nil {
		t.Error("Expected Keys map to be initialized")
	}
	if tm.KeygenRequests == nil {
		t.Error("Expected KeygenRequests map to be initialized")
	}
	if tm.SignRequests == nil {
		t.Error("Expected SignRequests map to be initialized")
	}
	if tm.DefaultThreshold != 2 {
		t.Errorf("Expected default threshold 2, got %d", tm.DefaultThreshold)
	}
	if tm.MaxKeysPerOwner != 100 {
		t.Errorf("Expected max keys per owner 100, got %d", tm.MaxKeysPerOwner)
	}
}

// TestRequestKeygen tests key generation request
func TestRequestKeygen(t *testing.T) {
	tm := NewThresholdManager()
	requester := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create participants
	participants := make([][20]byte, 5)
	for i := 0; i < 5; i++ {
		participants[i] = [20]byte{byte(i + 1)}
	}

	requestID, err := tm.RequestKeygen(
		requester,
		ProtocolFROST,
		KeyTypeSecp256k1,
		2, // threshold
		5, // total parties
		participants,
	)

	if err != nil {
		t.Fatalf("RequestKeygen failed: %v", err)
	}

	if requestID == [32]byte{} {
		t.Error("Expected non-zero request ID")
	}

	// Verify request was stored
	request := tm.KeygenRequests[requestID]
	if request == nil {
		t.Fatal("Request not stored")
	}
	if request.Protocol != ProtocolFROST {
		t.Errorf("Expected FROST protocol, got %v", request.Protocol)
	}
	if request.KeyType != KeyTypeSecp256k1 {
		t.Errorf("Expected secp256k1 key type, got %v", request.KeyType)
	}
	if request.Threshold != 2 {
		t.Errorf("Expected threshold 2, got %d", request.Threshold)
	}
	if request.TotalParties != 5 {
		t.Errorf("Expected 5 parties, got %d", request.TotalParties)
	}
	if request.Status != KeygenStatusPending {
		t.Errorf("Expected pending status, got %v", request.Status)
	}
}

// TestRequestKeygenInvalidParams tests validation of keygen parameters
func TestRequestKeygenInvalidParams(t *testing.T) {
	tm := NewThresholdManager()
	requester := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tests := []struct {
		name         string
		protocol     Protocol
		keyType      KeyType
		threshold    uint32
		totalParties uint32
		participants int
		expectedErr  error
	}{
		{
			name:         "Invalid protocol",
			protocol:     99, // Invalid
			keyType:      KeyTypeSecp256k1,
			threshold:    2,
			totalParties: 5,
			participants: 5,
			expectedErr:  ErrInvalidProtocol,
		},
		{
			name:         "Invalid key type for CGGMP21",
			protocol:     ProtocolCGGMP21,
			keyType:      KeyTypeEd25519, // Only secp256k1 allowed
			threshold:    2,
			totalParties: 5,
			participants: 5,
			expectedErr:  ErrInvalidKeyType,
		},
		{
			name:         "Threshold >= total parties",
			protocol:     ProtocolFROST,
			keyType:      KeyTypeSecp256k1,
			threshold:    5,
			totalParties: 5,
			participants: 5,
			expectedErr:  ErrInvalidThreshold,
		},
		{
			name:         "Zero threshold",
			protocol:     ProtocolFROST,
			keyType:      KeyTypeSecp256k1,
			threshold:    0,
			totalParties: 5,
			participants: 5,
			expectedErr:  ErrInvalidThreshold,
		},
		{
			name:         "Too many parties",
			protocol:     ProtocolFROST,
			keyType:      KeyTypeSecp256k1,
			threshold:    2,
			totalParties: MaxParties + 1,
			participants: MaxParties + 1,
			expectedErr:  ErrInvalidPartyCount,
		},
		{
			name:         "Mismatched participant count",
			protocol:     ProtocolFROST,
			keyType:      KeyTypeSecp256k1,
			threshold:    2,
			totalParties: 5,
			participants: 3, // Should be 5
			expectedErr:  ErrInvalidPartyCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			participants := make([][20]byte, tt.participants)
			for i := 0; i < tt.participants; i++ {
				participants[i] = [20]byte{byte(i + 1)}
			}

			_, err := tm.RequestKeygen(
				requester,
				tt.protocol,
				tt.keyType,
				tt.threshold,
				tt.totalParties,
				participants,
			)

			if err != tt.expectedErr {
				t.Errorf("Expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

// TestCompleteKeygen tests completing a keygen request
func TestCompleteKeygen(t *testing.T) {
	tm := NewThresholdManager()
	requester := common.HexToAddress("0x1234567890123456789012345678901234567890")

	participants := make([][20]byte, 5)
	for i := 0; i < 5; i++ {
		participants[i] = [20]byte{byte(i + 1)}
	}

	requestID, _ := tm.RequestKeygen(
		requester,
		ProtocolFROST,
		KeyTypeSecp256k1,
		2,
		5,
		participants,
	)

	// Complete keygen
	keyID := [32]byte{0x01, 0x02, 0x03}
	publicKey := []byte("public_key_bytes_here")
	address := common.HexToAddress("0xABCD000000000000000000000000000000000001")

	err := tm.CompleteKeygen(requestID, keyID, publicKey, address)
	if err != nil {
		t.Fatalf("CompleteKeygen failed: %v", err)
	}

	// Verify key was created
	key, err := tm.GetKey(keyID)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("Key not found")
	}
	if key.Protocol != ProtocolFROST {
		t.Errorf("Expected FROST protocol, got %v", key.Protocol)
	}
	if key.Status != KeyStatusActive {
		t.Errorf("Expected active status, got %v", key.Status)
	}
	if key.Owner != requester {
		t.Errorf("Expected owner %v, got %v", requester, key.Owner)
	}
	if key.Generation != 1 {
		t.Errorf("Expected generation 1, got %d", key.Generation)
	}
}

// TestRequestSignature tests signature request
func TestRequestSignature(t *testing.T) {
	tm := NewThresholdManager()
	requester := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create a key first
	keyID := setupTestKey(t, tm, requester)

	// Request signature
	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	requestID, err := tm.RequestSignature(requester, keyID, messageHash)
	if err != nil {
		t.Fatalf("RequestSignature failed: %v", err)
	}

	if requestID == [32]byte{} {
		t.Error("Expected non-zero request ID")
	}

	// Verify request
	sig, status, err := tm.GetSignature(requestID)
	if err != nil {
		t.Fatalf("GetSignature failed: %v", err)
	}
	if status != SignStatusPending {
		t.Errorf("Expected pending status, got %v", status)
	}
	if sig != nil {
		t.Error("Expected nil signature for pending request")
	}
}

// TestRequestSignatureUnauthorized tests authorization checks
func TestRequestSignatureUnauthorized(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	unauthorized := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	keyID := setupTestKey(t, tm, owner)

	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	_, err := tm.RequestSignature(unauthorized, keyID, messageHash)
	if err != ErrUnauthorized {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}
}

// TestAddRemoveSigner tests adding and removing authorized signers
func TestAddRemoveSigner(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	signer := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	keyID := setupTestKey(t, tm, owner)

	// Add signer
	err := tm.AddSigner(owner, keyID, signer)
	if err != nil {
		t.Fatalf("AddSigner failed: %v", err)
	}

	// Verify signer can sign
	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	_, err = tm.RequestSignature(signer, keyID, messageHash)
	if err != nil {
		t.Errorf("Authorized signer should be able to sign: %v", err)
	}

	// Remove signer
	err = tm.RemoveSigner(owner, keyID, signer)
	if err != nil {
		t.Fatalf("RemoveSigner failed: %v", err)
	}

	// Verify signer can no longer sign
	_, err = tm.RequestSignature(signer, keyID, [32]byte{0xFF})
	if err != ErrUnauthorized {
		t.Errorf("Expected ErrUnauthorized after removal, got %v", err)
	}
}

// TestRequestRefresh tests key refresh request
func TestRequestRefresh(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID := setupTestKey(t, tm, owner)

	requestID, err := tm.RequestRefresh(owner, keyID)
	if err != nil {
		t.Fatalf("RequestRefresh failed: %v", err)
	}

	if requestID == [32]byte{} {
		t.Error("Expected non-zero request ID")
	}

	// Verify key status changed
	key, _ := tm.GetKey(keyID)
	if key.Status != KeyStatusRefreshing {
		t.Errorf("Expected refreshing status, got %v", key.Status)
	}
}

// TestRequestReshare tests key reshare request
func TestRequestReshare(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID := setupTestKey(t, tm, owner)

	newParties := make([][20]byte, 7)
	for i := 0; i < 7; i++ {
		newParties[i] = [20]byte{byte(i + 100)}
	}

	requestID, err := tm.RequestReshare(owner, keyID, 3, newParties)
	if err != nil {
		t.Fatalf("RequestReshare failed: %v", err)
	}

	if requestID == [32]byte{} {
		t.Error("Expected non-zero request ID")
	}

	// Verify key status changed
	key, _ := tm.GetKey(keyID)
	if key.Status != KeyStatusResharing {
		t.Errorf("Expected resharing status, got %v", key.Status)
	}
}

// TestRevokeKey tests key revocation
func TestRevokeKey(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID := setupTestKey(t, tm, owner)

	err := tm.RevokeKey(owner, keyID)
	if err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	key, _ := tm.GetKey(keyID)
	if key.Status != KeyStatusRevoked {
		t.Errorf("Expected revoked status, got %v", key.Status)
	}

	// Verify signing fails
	_, err = tm.RequestSignature(owner, keyID, [32]byte{})
	if err != ErrKeyRevoked {
		t.Errorf("Expected ErrKeyRevoked, got %v", err)
	}
}

// TestSigningLimit tests daily signing limit
func TestSigningLimit(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID := setupTestKey(t, tm, owner)

	// Set low limit for testing
	key, _ := tm.GetKey(keyID)
	key.Permissions.MaxSignsPerDay = 3

	// Sign up to limit
	for i := 0; i < 3; i++ {
		_, err := tm.RequestSignature(owner, keyID, [32]byte{byte(i)})
		if err != nil {
			t.Fatalf("Sign %d failed: %v", i, err)
		}
	}

	// Next sign should fail
	_, err := tm.RequestSignature(owner, keyID, [32]byte{0xFF})
	if err != ErrSigningLimitExceeded {
		t.Errorf("Expected ErrSigningLimitExceeded, got %v", err)
	}
}

// TestKeyNotFound tests error for non-existent key
func TestKeyNotFound(t *testing.T) {
	tm := NewThresholdManager()
	nonExistent := [32]byte{0xFF, 0xFF, 0xFF}

	_, err := tm.GetKey(nonExistent)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}

	_, err = tm.GetPublicKey(nonExistent)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}

	_, err = tm.GetAddress(nonExistent)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestVerifySignature tests signature verification
func TestVerifySignature(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID := setupTestKey(t, tm, owner)

	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	signature := []byte("test_signature")

	result, err := tm.VerifySignature(keyID, messageHash, signature)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.SignerKeyID != keyID {
		t.Error("Signer key ID mismatch")
	}
	if result.MessageHash != messageHash {
		t.Error("Message hash mismatch")
	}
}

// TestCompleteSigning tests completing a signing request
func TestCompleteSigning(t *testing.T) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID := setupTestKey(t, tm, owner)

	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	requestID, _ := tm.RequestSignature(owner, keyID, messageHash)

	// Complete signing
	signature := []byte("completed_threshold_signature")
	err := tm.CompleteSigning(requestID, signature)
	if err != nil {
		t.Fatalf("CompleteSigning failed: %v", err)
	}

	// Verify signature is available
	sig, status, err := tm.GetSignature(requestID)
	if err != nil {
		t.Fatalf("GetSignature failed: %v", err)
	}
	if status != SignStatusComplete {
		t.Errorf("Expected complete status, got %v", status)
	}
	if string(sig) != string(signature) {
		t.Error("Signature mismatch")
	}
}

// TestProtocolKeyTypeValidation tests protocol-key type combinations
func TestProtocolKeyTypeValidation(t *testing.T) {
	tm := NewThresholdManager()
	requester := common.HexToAddress("0x1234567890123456789012345678901234567890")

	tests := []struct {
		name      string
		protocol  Protocol
		keyType   KeyType
		expectErr bool
	}{
		{"FROST with secp256k1", ProtocolFROST, KeyTypeSecp256k1, false},
		{"FROST with Ed25519", ProtocolFROST, KeyTypeEd25519, false},
		{"CGGMP21 with secp256k1", ProtocolCGGMP21, KeyTypeSecp256k1, false},
		{"CGGMP21 with Ed25519", ProtocolCGGMP21, KeyTypeEd25519, true}, // Invalid
		{"Ringtail with Ringtail", ProtocolRingtail, KeyTypeRingtail, false},
		{"Ringtail with secp256k1", ProtocolRingtail, KeyTypeSecp256k1, true}, // Invalid
		{"LSS with any", ProtocolLSS, KeyTypeSecp256k1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			participants := make([][20]byte, 5)
			for i := 0; i < 5; i++ {
				participants[i] = [20]byte{byte(i + 1)}
			}

			_, err := tm.RequestKeygen(
				requester,
				tt.protocol,
				tt.keyType,
				2,
				5,
				participants,
			)

			if tt.expectErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// Helper to create a test key
func setupTestKey(t *testing.T, tm *ThresholdManager, owner common.Address) [32]byte {
	t.Helper()

	participants := make([][20]byte, 5)
	for i := 0; i < 5; i++ {
		participants[i] = [20]byte{byte(i + 1)}
	}

	requestID, _ := tm.RequestKeygen(
		owner,
		ProtocolFROST,
		KeyTypeSecp256k1,
		2,
		5,
		participants,
	)

	keyID := [32]byte{0x01, 0x02, 0x03, byte(time.Now().UnixNano())}
	publicKey := []byte("test_public_key")
	address := common.HexToAddress("0xABCD000000000000000000000000000000000001")

	_ = tm.CompleteKeygen(requestID, keyID, publicKey, address)
	return keyID
}

// Benchmark tests

func BenchmarkRequestKeygen(b *testing.B) {
	tm := NewThresholdManager()
	requester := common.HexToAddress("0x1234567890123456789012345678901234567890")
	participants := make([][20]byte, 5)
	for i := 0; i < 5; i++ {
		participants[i] = [20]byte{byte(i + 1)}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.RequestKeygen(requester, ProtocolFROST, KeyTypeSecp256k1, 2, 5, participants)
	}
}

func BenchmarkRequestSignature(b *testing.B) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Setup key
	participants := make([][20]byte, 5)
	for i := 0; i < 5; i++ {
		participants[i] = [20]byte{byte(i + 1)}
	}
	requestID, _ := tm.RequestKeygen(owner, ProtocolFROST, KeyTypeSecp256k1, 2, 5, participants)
	keyID := [32]byte{0x01}
	_ = tm.CompleteKeygen(requestID, keyID, []byte("pk"), common.Address{})

	// Set high limit
	key, _ := tm.GetKey(keyID)
	key.Permissions.MaxSignsPerDay = uint64(b.N) + 1000

	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.RequestSignature(owner, keyID, messageHash)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	tm := NewThresholdManager()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Setup key
	participants := make([][20]byte, 5)
	for i := 0; i < 5; i++ {
		participants[i] = [20]byte{byte(i + 1)}
	}
	requestID, _ := tm.RequestKeygen(owner, ProtocolFROST, KeyTypeSecp256k1, 2, 5, participants)
	keyID := [32]byte{0x01}
	_ = tm.CompleteKeygen(requestID, keyID, []byte("pk"), common.Address{})

	messageHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	signature := []byte("test_signature")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.VerifySignature(keyID, messageHash, signature)
	}
}
