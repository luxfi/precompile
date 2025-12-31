// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantum

import (
	"testing"

	"github.com/luxfi/crypto/bls"
)

// TestNewQuantumVerifier tests verifier creation
func TestNewQuantumVerifier(t *testing.T) {
	qv := NewQuantumVerifier()
	if qv == nil {
		t.Fatal("Expected non-nil QuantumVerifier")
	}

	if qv.RingtailKeys == nil {
		t.Error("Expected RingtailKeys map to be initialized")
	}
	if qv.MLDSAKeys == nil {
		t.Error("Expected MLDSAKeys map to be initialized")
	}
	if qv.BLSKeys == nil {
		t.Error("Expected BLSKeys map to be initialized")
	}
	if qv.Stamps == nil {
		t.Error("Expected Stamps map to be initialized")
	}
	if qv.Anchors == nil {
		t.Error("Expected Anchors map to be initialized")
	}
}

// TestRegisterRingtailKey tests Ringtail key registration
func TestRegisterRingtailKey(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 128) // Mock Ringtail public key
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	keyID, err := qv.RegisterRingtailKey(publicKey, 2, 5, RingtailParams{})
	if err != nil {
		t.Fatalf("RegisterRingtailKey failed: %v", err)
	}

	if keyID == [32]byte{} {
		t.Error("Expected non-zero key ID")
	}

	// Verify key was stored
	key := qv.RingtailKeys[keyID]
	if key == nil {
		t.Fatal("Key not stored")
	}
	if key.Threshold != 2 {
		t.Errorf("Expected threshold 2, got %d", key.Threshold)
	}
	if key.TotalParties != 5 {
		t.Errorf("Expected 5 parties, got %d", key.TotalParties)
	}
	if key.Generation != 1 {
		t.Errorf("Expected generation 1, got %d", key.Generation)
	}
}

// TestRegisterBLSKey tests BLS key registration
func TestRegisterBLSKey(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, BLSPublicKeySize)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	keyID, err := qv.RegisterBLSKey(publicKey)
	if err != nil {
		t.Fatalf("RegisterBLSKey failed: %v", err)
	}

	if keyID == [32]byte{} {
		t.Error("Expected non-zero key ID")
	}

	// Verify key was stored
	key := qv.BLSKeys[keyID]
	if key == nil {
		t.Fatal("Key not stored")
	}
}

// TestRegisterBLSKeyInvalidSize tests BLS key registration with invalid size
func TestRegisterBLSKeyInvalidSize(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 10) // Invalid size
	_, err := qv.RegisterBLSKey(publicKey)
	if err != ErrInvalidPublicKey {
		t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
	}
}

// TestVerifyRingtail tests Ringtail signature verification
func TestVerifyRingtail(t *testing.T) {
	qv := NewQuantumVerifier()

	// Register key
	publicKey := make([]byte, 128)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}
	keyID, _ := qv.RegisterRingtailKey(publicKey, 2, 5, RingtailParams{})

	// Create test signature with valid signer mask (3 of 5 signers)
	signerMask := []byte{0b00010111} // 3 bits set
	signature := &RingtailSignature{
		KeyID:      keyID,
		Signature:  []byte("test_ringtail_signature"),
		SignerMask: signerMask,
		Generation: 1,
	}

	message := []byte("test message")
	result, err := qv.VerifyRingtail(keyID, message, signature)
	if err != nil {
		t.Fatalf("VerifyRingtail failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.Algorithm != AlgRingtail {
		t.Errorf("Expected Ringtail algorithm, got %v", result.Algorithm)
	}
	if result.GasUsed != GasRingtailVerify {
		t.Errorf("Expected gas %d, got %d", GasRingtailVerify, result.GasUsed)
	}

	// Verify stats updated
	if qv.TotalVerifications != 1 {
		t.Errorf("Expected 1 verification, got %d", qv.TotalVerifications)
	}
}

// TestVerifyRingtailKeyNotFound tests error for non-existent key
func TestVerifyRingtailKeyNotFound(t *testing.T) {
	qv := NewQuantumVerifier()

	nonExistent := [32]byte{0xFF}
	signature := &RingtailSignature{KeyID: nonExistent}

	_, err := qv.VerifyRingtail(nonExistent, []byte("msg"), signature)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestVerifyRingtailGenerationMismatch tests generation validation
func TestVerifyRingtailGenerationMismatch(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 128)
	keyID, _ := qv.RegisterRingtailKey(publicKey, 2, 5, RingtailParams{})

	signature := &RingtailSignature{
		KeyID:      keyID,
		Signature:  []byte("sig"),
		SignerMask: []byte{0xFF},
		Generation: 99, // Wrong generation
	}

	_, err := qv.VerifyRingtail(keyID, []byte("msg"), signature)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

// TestVerifyRingtailThresholdNotMet tests threshold validation
func TestVerifyRingtailThresholdNotMet(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 128)
	keyID, _ := qv.RegisterRingtailKey(publicKey, 3, 5, RingtailParams{}) // Need 4 signers

	signature := &RingtailSignature{
		KeyID:      keyID,
		Signature:  []byte("sig"),
		SignerMask: []byte{0b00000011}, // Only 2 signers
		Generation: 1,
	}

	_, err := qv.VerifyRingtail(keyID, []byte("msg"), signature)
	if err != ErrThresholdNotMet {
		t.Errorf("Expected ErrThresholdNotMet, got %v", err)
	}
}

// TestVerifyMLDSA tests ML-DSA signature verification
func TestVerifyMLDSA(t *testing.T) {
	qv := NewQuantumVerifier()

	tests := []struct {
		name    string
		mode    uint8
		pkSize  int
		sigSize int
	}{
		{"ML-DSA-44", 44, MLDSA44PublicKeySize, MLDSA44SignatureSize},
		{"ML-DSA-65", 65, MLDSA65PublicKeySize, MLDSA65SignatureSize},
		{"ML-DSA-87", 87, MLDSA87PublicKeySize, MLDSA87SignatureSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey := make([]byte, tt.pkSize)
			signature := &MLDSASignature{
				Mode:      tt.mode,
				Signature: make([]byte, tt.sigSize),
			}

			result, err := qv.VerifyMLDSA(publicKey, []byte("test message"), signature)
			if err != nil {
				t.Fatalf("VerifyMLDSA failed: %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}
			if result.GasUsed != GasMLDSAVerify {
				t.Errorf("Expected gas %d, got %d", GasMLDSAVerify, result.GasUsed)
			}
		})
	}
}

// TestVerifyMLDSAInvalidKeySize tests ML-DSA with wrong key size
func TestVerifyMLDSAInvalidKeySize(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 100) // Invalid size
	signature := &MLDSASignature{Mode: 65, Signature: make([]byte, MLDSA65SignatureSize)}

	_, err := qv.VerifyMLDSA(publicKey, []byte("msg"), signature)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}
}

// TestVerifyMLDSAInvalidSigSize tests ML-DSA with wrong signature size
func TestVerifyMLDSAInvalidSigSize(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, MLDSA65PublicKeySize)
	signature := &MLDSASignature{Mode: 65, Signature: make([]byte, 100)} // Wrong size

	_, err := qv.VerifyMLDSA(publicKey, []byte("msg"), signature)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

// TestVerifySLHDSA tests SLH-DSA signature verification
func TestVerifySLHDSA(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 64)
	signature := make([]byte, 128)
	message := []byte("test message")

	result, err := qv.VerifySLHDSA(publicKey, message, signature, 0) // mode 0 = SHA2-128f
	if err != nil {
		t.Fatalf("VerifySLHDSA failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.GasUsed != GasSLHDSAVerify {
		t.Errorf("Expected gas %d, got %d", GasSLHDSAVerify, result.GasUsed)
	}
}

// TestVerifyHybrid tests hybrid signature verification
func TestVerifyHybrid(t *testing.T) {
	qv := NewQuantumVerifier()

	tests := []struct {
		name         string
		scheme       HybridScheme
		bothRequired bool
	}{
		{"BLS+Ringtail both required", HybridBLSRingtail, true},
		{"BLS+Ringtail either ok", HybridBLSRingtail, false},
		{"ECDSA+ML-DSA both required", HybridECDSAMLDSA, true},
		{"Schnorr+Ringtail", HybridSchnorrRingtail, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := &HybridSignature{
				Scheme:          tt.scheme,
				ClassicalPubKey: make([]byte, 48), // BLS or ECDSA pk size
				ClassicalSig:    make([]byte, 96), // BLS or ECDSA sig size
				QuantumPubKey:   make([]byte, 128),
				QuantumSig:      make([]byte, 256),
			}

			if tt.scheme == HybridECDSAMLDSA {
				signature.ClassicalPubKey = make([]byte, 33)
				signature.ClassicalSig = make([]byte, 65)
				signature.QuantumPubKey = make([]byte, MLDSA65PublicKeySize)
				signature.QuantumSig = make([]byte, MLDSA65SignatureSize)
			} else if tt.scheme == HybridSchnorrRingtail {
				signature.ClassicalPubKey = make([]byte, 32)
				signature.ClassicalSig = make([]byte, 64)
			}

			result, err := qv.VerifyHybrid([]byte("test message"), signature, tt.bothRequired)
			if err != nil {
				t.Fatalf("VerifyHybrid failed: %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}
			if result.HybridComponents == nil {
				t.Fatal("Expected HybridComponents")
			}
			if result.HybridComponents.BothRequired != tt.bothRequired {
				t.Error("BothRequired mismatch")
			}
			if result.GasUsed != GasHybridVerify {
				t.Errorf("Expected gas %d, got %d", GasHybridVerify, result.GasUsed)
			}
		})
	}
}

// TestVerifyHybridUnsupportedScheme tests unsupported hybrid scheme
func TestVerifyHybridUnsupportedScheme(t *testing.T) {
	qv := NewQuantumVerifier()

	signature := &HybridSignature{Scheme: 99} // Invalid scheme
	_, err := qv.VerifyHybrid([]byte("msg"), signature, false)
	if err != ErrUnsupportedHybrid {
		t.Errorf("Expected ErrUnsupportedHybrid, got %v", err)
	}
}

// TestVerifyBLS tests BLS signature verification
func TestVerifyBLS(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, BLSPublicKeySize)
	signature := make([]byte, BLSSignatureSize)
	message := []byte("test message")

	valid, err := qv.VerifyBLS(publicKey, message, signature)
	if err != nil {
		t.Fatalf("VerifyBLS failed: %v", err)
	}

	// Verify stats updated
	if qv.TotalVerifications != 1 {
		t.Errorf("Expected 1 verification, got %d", qv.TotalVerifications)
	}

	_ = valid // Placeholder logic returns true
}

// TestVerifyBLSInvalidSizes tests BLS with invalid sizes
func TestVerifyBLSInvalidSizes(t *testing.T) {
	qv := NewQuantumVerifier()

	// Invalid public key size
	_, err := qv.VerifyBLS(make([]byte, 10), make([]byte, BLSSignatureSize), []byte("msg"))
	if err != ErrInvalidPublicKey {
		t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
	}

	// Invalid signature size
	_, err = qv.VerifyBLS(make([]byte, BLSPublicKeySize), []byte("msg"), make([]byte, 10))
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

// TestAggregateBLSSignatures tests BLS signature aggregation
func TestAggregateBLSSignatures(t *testing.T) {
	qv := NewQuantumVerifier()

	// Generate real BLS key pairs and signatures
	message := []byte("test message for aggregation")
	numSigners := 5
	signatures := make([][]byte, numSigners)

	for i := 0; i < numSigners; i++ {
		// Create unique seed for each key
		seed := make([]byte, 32)
		for j := range seed {
			seed[j] = byte(i*32 + j + 1) // Non-zero deterministic seed
		}

		sk, err := bls.SecretKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to create BLS secret key %d: %v", i, err)
		}

		sig, err := sk.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}

		signatures[i] = bls.SignatureToBytes(sig)
	}

	aggregated, err := qv.AggregateBLSSignatures(signatures)
	if err != nil {
		t.Fatalf("AggregateBLSSignatures failed: %v", err)
	}

	if len(aggregated) != BLSSignatureSize {
		t.Errorf("Expected aggregated sig size %d, got %d", BLSSignatureSize, len(aggregated))
	}
}

// TestAggregateBLSSignaturesEmpty tests empty signature list
func TestAggregateBLSSignaturesEmpty(t *testing.T) {
	qv := NewQuantumVerifier()

	_, err := qv.AggregateBLSSignatures([][]byte{})
	if err != ErrBLSAggregationFailed {
		t.Errorf("Expected ErrBLSAggregationFailed, got %v", err)
	}
}

// TestAggregateBLSSignaturesInvalidSize tests aggregation with invalid signature size
func TestAggregateBLSSignaturesInvalidSize(t *testing.T) {
	qv := NewQuantumVerifier()

	signatures := [][]byte{
		make([]byte, BLSSignatureSize),
		make([]byte, 10), // Invalid size
	}

	_, err := qv.AggregateBLSSignatures(signatures)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

// TestVerifyAggregateBLS tests aggregate BLS verification
func TestVerifyAggregateBLS(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKeys := make([][]byte, 3)
	messages := make([][32]byte, 3)
	for i := 0; i < 3; i++ {
		publicKeys[i] = make([]byte, BLSPublicKeySize)
		messages[i] = [32]byte{byte(i)}
	}

	aggregateSig := make([]byte, BLSSignatureSize)

	valid, err := qv.VerifyAggregateBLS(publicKeys, messages, aggregateSig)
	if err != nil {
		t.Fatalf("VerifyAggregateBLS failed: %v", err)
	}

	_ = valid // Placeholder returns true
}

// TestVerifyAggregateBLSMismatchedLengths tests mismatched inputs
func TestVerifyAggregateBLSMismatchedLengths(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKeys := make([][]byte, 3)
	messages := make([][32]byte, 5) // Different length

	_, err := qv.VerifyAggregateBLS(publicKeys, messages, make([]byte, BLSSignatureSize))
	if err != ErrInvalidPublicKey {
		t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
	}
}

// TestDeriveAddress tests address derivation from quantum public key
func TestDeriveAddress(t *testing.T) {
	qv := NewQuantumVerifier()

	publicKey := make([]byte, 128)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	addr1 := qv.DeriveAddress(publicKey, AlgRingtail)
	addr2 := qv.DeriveAddress(publicKey, AlgRingtail)

	// Same key should derive same address
	if addr1 != addr2 {
		t.Error("Same public key should derive same address")
	}

	// Different key should derive different address
	differentKey := make([]byte, 128)
	addr3 := qv.DeriveAddress(differentKey, AlgRingtail)
	if addr1 == addr3 {
		t.Error("Different public keys should derive different addresses")
	}
}

// TestCountBits tests bit counting helper
func TestCountBits(t *testing.T) {
	tests := []struct {
		mask     []byte
		expected int
	}{
		{[]byte{0b00000000}, 0},
		{[]byte{0b00000001}, 1},
		{[]byte{0b00000011}, 2},
		{[]byte{0b11111111}, 8},
		{[]byte{0b10101010}, 4},
		{[]byte{0b11111111, 0b11111111}, 16},
		{[]byte{0b00010111}, 4},
	}

	for _, tt := range tests {
		result := countBits(tt.mask)
		if result != tt.expected {
			t.Errorf("countBits(%v) = %d, expected %d", tt.mask, result, tt.expected)
		}
	}
}

// TestVerificationStatistics tests stats tracking
func TestVerificationStatistics(t *testing.T) {
	qv := NewQuantumVerifier()

	// Register keys
	rtKey := make([]byte, 128)
	blsKey := make([]byte, BLSPublicKeySize)
	rtKeyID, _ := qv.RegisterRingtailKey(rtKey, 1, 3, RingtailParams{})
	_, _ = qv.RegisterBLSKey(blsKey)

	// Perform some verifications
	sig := &RingtailSignature{
		KeyID:      rtKeyID,
		Signature:  []byte("sig"),
		SignerMask: []byte{0b00000111}, // 3 signers
		Generation: 1,
	}
	qv.VerifyRingtail(rtKeyID, []byte("msg1"), sig)
	qv.VerifyRingtail(rtKeyID, []byte("msg2"), sig)
	qv.VerifyBLS(blsKey, []byte("msg3"), make([]byte, BLSSignatureSize))

	if qv.TotalVerifications != 3 {
		t.Errorf("Expected 3 verifications, got %d", qv.TotalVerifications)
	}
}

// Benchmark tests

func BenchmarkVerifyRingtail(b *testing.B) {
	qv := NewQuantumVerifier()
	publicKey := make([]byte, 128)
	keyID, _ := qv.RegisterRingtailKey(publicKey, 2, 5, RingtailParams{})

	signature := &RingtailSignature{
		KeyID:      keyID,
		Signature:  make([]byte, 256),
		SignerMask: []byte{0b00010111},
		Generation: 1,
	}
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qv.VerifyRingtail(keyID, message, signature)
	}
}

func BenchmarkVerifyMLDSA65(b *testing.B) {
	qv := NewQuantumVerifier()
	publicKey := make([]byte, MLDSA65PublicKeySize)
	signature := &MLDSASignature{Mode: 65, Signature: make([]byte, MLDSA65SignatureSize)}
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qv.VerifyMLDSA(publicKey, message, signature)
	}
}

func BenchmarkVerifyBLS(b *testing.B) {
	qv := NewQuantumVerifier()
	publicKey := make([]byte, BLSPublicKeySize)
	signature := make([]byte, BLSSignatureSize)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qv.VerifyBLS(publicKey, message, signature)
	}
}

func BenchmarkAggregateBLSSignatures(b *testing.B) {
	qv := NewQuantumVerifier()
	signatures := make([][]byte, 10)
	for i := range signatures {
		signatures[i] = make([]byte, BLSSignatureSize)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qv.AggregateBLSSignatures(signatures)
	}
}

func BenchmarkVerifyHybrid(b *testing.B) {
	qv := NewQuantumVerifier()
	signature := &HybridSignature{
		Scheme:          HybridBLSRingtail,
		ClassicalPubKey: make([]byte, 48),
		ClassicalSig:    make([]byte, 96),
		QuantumPubKey:   make([]byte, 128),
		QuantumSig:      make([]byte, 256),
	}
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = qv.VerifyHybrid(message, signature, true)
	}
}
