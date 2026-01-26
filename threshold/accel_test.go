// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"testing"

	"github.com/luxfi/accel"
	"github.com/stretchr/testify/require"
)

func TestVerifyBatchSignatures(t *testing.T) {
	tm := NewThresholdManager()
	defer tm.Close()

	// Test empty batch
	results, err := tm.VerifyBatchSignatures(KeyTypeSecp256k1, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, results)

	// Test mismatched lengths
	_, err = tm.VerifyBatchSignatures(KeyTypeSecp256k1, [][]byte{{1}}, nil, nil)
	require.ErrorIs(t, err, ErrInvalidSignature)

	// Test small batch (CPU path) with zero-filled data
	// Note: Real verification correctly rejects invalid signatures
	sigs := [][]byte{
		make([]byte, 64), // ECDSA signatures are 64 bytes [R || S]
		make([]byte, 64),
	}
	pks := [][]byte{
		make([]byte, 33),
		make([]byte, 33),
	}
	msgs := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
	}

	results, err = tm.VerifyBatchSignatures(KeyTypeSecp256k1, sigs, pks, msgs)
	require.NoError(t, err)
	require.Len(t, results, 2)
	// Real verification correctly rejects zero-filled invalid signatures
	require.False(t, results[0])
	require.False(t, results[1])
}

func TestVerifyBatchSignaturesLarge(t *testing.T) {
	tm := NewThresholdManager()
	defer tm.Close()

	// Test batch >= BatchVerifyThreshold (triggers GPU path if available)
	n := BatchVerifyThreshold + 2
	sigs := make([][]byte, n)
	pks := make([][]byte, n)
	msgs := make([][]byte, n)

	for i := 0; i < n; i++ {
		sigs[i] = make([]byte, 65)
		pks[i] = make([]byte, 33)
		msgs[i] = make([]byte, 32)
	}

	results, err := tm.VerifyBatchSignatures(KeyTypeSecp256k1, sigs, pks, msgs)
	require.NoError(t, err)
	require.Len(t, results, n)
}

func TestVerifyBatchSignaturesKeyTypes(t *testing.T) {
	tm := NewThresholdManager()
	defer tm.Close()

	tests := []struct {
		name    string
		keyType KeyType
		sigLen  int
		pkLen   int
		msgLen  int
	}{
		{"ECDSA", KeyTypeSecp256k1, 65, 33, 32},
		{"Ed25519", KeyTypeEd25519, 64, 32, 32},
		{"BLS", KeyTypeBLS12381, 96, 48, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs := [][]byte{make([]byte, tt.sigLen)}
			pks := [][]byte{make([]byte, tt.pkLen)}
			msgs := [][]byte{make([]byte, tt.msgLen)}

			results, err := tm.VerifyBatchSignatures(tt.keyType, sigs, pks, msgs)
			require.NoError(t, err)
			require.Len(t, results, 1)
		})
	}
}

func TestAccelAvailability(t *testing.T) {
	// Just verify we can check availability without panicking
	available := accel.Available()
	t.Logf("GPU acceleration available: %v", available)

	if available {
		devices := accel.Devices()
		t.Logf("Found %d GPU device(s)", len(devices))
		for i, d := range devices {
			t.Logf("  Device %d: %s (%s)", i, d.Name, d.Vendor)
		}
	}
}

func BenchmarkVerifyBatchSignatures(b *testing.B) {
	tm := NewThresholdManager()
	defer tm.Close()

	sizes := []int{1, 4, 16, 64, 256}

	for _, n := range sizes {
		sigs := make([][]byte, n)
		pks := make([][]byte, n)
		msgs := make([][]byte, n)

		for i := 0; i < n; i++ {
			sigs[i] = make([]byte, 65)
			pks[i] = make([]byte, 33)
			msgs[i] = make([]byte, 32)
		}

		name := "batch_" + itoa(n)
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = tm.VerifyBatchSignatures(KeyTypeSecp256k1, sigs, pks, msgs)
			}
		})
	}
}

// itoa converts int to string without importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
