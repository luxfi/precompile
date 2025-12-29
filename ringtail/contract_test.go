// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ringtailthreshold

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/lattice/v6/ring"
	"github.com/luxfi/ringtail/sign"
	"github.com/luxfi/ringtail/threshold"
	"github.com/stretchr/testify/require"
)

// TestRingtailThresholdVerify_2of3 tests 2-of-3 threshold signature
func TestRingtailThresholdVerify_2of3(t *testing.T) {
	thresholdVal := uint32(2)
	totalParties := uint32(3)
	message := "test message for 2-of-3 threshold"

	// Generate threshold signature
	signature, messageHash, err := generateThresholdSignature(thresholdVal, totalParties, message)
	require.NoError(t, err)

	// Create input
	input := createInput(thresholdVal, totalParties, messageHash, signature)

	// Verify signature
	precompile := &ringtailThresholdPrecompile{}
	result, _, err := precompile.Run(nil, common.Address{}, precompile.Address(), input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, byte(1), result[31], "Signature should be valid")
}

// TestRingtailThresholdVerify_3of5 tests 3-of-5 threshold signature
func TestRingtailThresholdVerify_3of5(t *testing.T) {
	thresholdVal := uint32(3)
	totalParties := uint32(5)
	message := "test message for 3-of-5 threshold"

	// Generate threshold signature
	signature, messageHash, err := generateThresholdSignature(thresholdVal, totalParties, message)
	require.NoError(t, err)

	// Create input
	input := createInput(thresholdVal, totalParties, messageHash, signature)

	// Verify signature
	precompile := &ringtailThresholdPrecompile{}
	result, _, err := precompile.Run(nil, common.Address{}, precompile.Address(), input, 2_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, byte(1), result[31], "Signature should be valid")
}

// TestRingtailThresholdVerify_FullThreshold tests n-of-n (full threshold)
func TestRingtailThresholdVerify_FullThreshold(t *testing.T) {
	thresholdVal := uint32(3) // Use 3-of-4 since threshold package requires t < n
	totalParties := uint32(4)
	message := "test message for full threshold"

	// Generate threshold signature
	signature, messageHash, err := generateThresholdSignature(thresholdVal, totalParties, message)
	require.NoError(t, err)

	// Create input
	input := createInput(thresholdVal, totalParties, messageHash, signature)

	// Verify signature
	precompile := &ringtailThresholdPrecompile{}
	result, _, err := precompile.Run(nil, common.Address{}, precompile.Address(), input, 2_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, byte(1), result[31], "Signature should be valid")
}

// TestRingtailThresholdVerify_InvalidSignature tests invalid signature rejection
func TestRingtailThresholdVerify_InvalidSignature(t *testing.T) {
	thresholdVal := uint32(2)
	totalParties := uint32(3)
	message := "test message"

	// Generate valid signature
	signature, messageHash, err := generateThresholdSignature(thresholdVal, totalParties, message)
	require.NoError(t, err)

	// Corrupt signature
	signature[100] ^= 0xFF

	// Create input with corrupted signature
	input := createInput(thresholdVal, totalParties, messageHash, signature)

	// Verify should fail
	precompile := &ringtailThresholdPrecompile{}
	result, _, err := precompile.Run(nil, common.Address{}, precompile.Address(), input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, byte(0), result[31], "Invalid signature should be rejected")
}

// TestRingtailThresholdVerify_WrongMessage tests wrong message rejection
func TestRingtailThresholdVerify_WrongMessage(t *testing.T) {
	thresholdVal := uint32(2)
	totalParties := uint32(3)
	message := "original message"

	// Generate signature for original message
	signature, _, err := generateThresholdSignature(thresholdVal, totalParties, message)
	require.NoError(t, err)

	// Use different message hash
	wrongMessage := "different message"
	wrongHash := hashMessage(wrongMessage)

	// Create input with wrong message hash
	input := createInput(thresholdVal, totalParties, wrongHash, signature)

	// Verify should fail
	precompile := &ringtailThresholdPrecompile{}
	result, _, err := precompile.Run(nil, common.Address{}, precompile.Address(), input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, byte(0), result[31], "Wrong message should be rejected")
}

// TestRingtailThresholdVerify_ThresholdNotMet tests threshold not met rejection
func TestRingtailThresholdVerify_ThresholdNotMet(t *testing.T) {
	// Generate signature with 2 parties
	actualParties := uint32(2)
	claimedThreshold := uint32(3)
	message := "test message"

	// Use valid threshold for generation (1 < 2)
	signature, messageHash, err := generateThresholdSignature(1, actualParties, message)
	require.NoError(t, err)

	// Claim higher threshold than available
	input := createInput(claimedThreshold, actualParties, messageHash, signature)

	// Verify should fail
	precompile := &ringtailThresholdPrecompile{}
	_, _, err = precompile.Run(nil, common.Address{}, precompile.Address(), input, 1_000_000, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid threshold")
}

// TestRingtailThresholdVerify_InputTooShort tests short input rejection
func TestRingtailThresholdVerify_InputTooShort(t *testing.T) {
	input := make([]byte, 20) // Too short

	precompile := &ringtailThresholdPrecompile{}
	_, _, err := precompile.Run(nil, common.Address{}, precompile.Address(), input, 1_000_000, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid input length")
}

// TestRingtailThresholdVerify_GasCost tests gas cost calculation
func TestRingtailThresholdVerify_GasCost(t *testing.T) {
	tests := []struct {
		name        string
		parties     uint32
		expectedGas uint64
	}{
		{"3 parties", 3, 150_000 + (3 * 10_000)},
		{"5 parties", 5, 150_000 + (5 * 10_000)},
		{"10 parties", 10, 150_000 + (10 * 10_000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create minimal valid input
			input := make([]byte, MinInputSize+100)
			binary.BigEndian.PutUint32(input[0:4], tt.parties)
			binary.BigEndian.PutUint32(input[4:8], tt.parties)

			precompile := &ringtailThresholdPrecompile{}
			gas := precompile.RequiredGas(input)
			require.Equal(t, tt.expectedGas, gas)
		})
	}
}

// TestRingtailThresholdPrecompile_Address tests precompile address
func TestRingtailThresholdPrecompile_Address(t *testing.T) {
	precompile := &ringtailThresholdPrecompile{}
	expectedAddress := common.HexToAddress("0x020000000000000000000000000000000000000B")
	require.Equal(t, expectedAddress, precompile.Address())
}

// TestEstimateGas tests gas estimation utility
func TestEstimateGas(t *testing.T) {
	tests := []struct {
		parties uint32
		gas     uint64
	}{
		{2, 170_000},
		{3, 180_000},
		{5, 200_000},
		{10, 250_000},
	}

	for _, tt := range tests {
		gas := EstimateGas(tt.parties)
		require.Equal(t, tt.gas, gas)
	}
}

// Helper functions

// generateThresholdSignature generates a threshold signature using the threshold package
func generateThresholdSignature(thresholdVal, totalParties uint32, message string) ([]byte, []byte, error) {
	// Generate key shares using threshold package
	shares, groupKey, err := threshold.GenerateKeys(int(thresholdVal), int(totalParties), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	// Create PRF key for signing session
	prfKey := make([]byte, sign.KeySize)
	if _, err := rand.Read(prfKey); err != nil {
		return nil, nil, err
	}

	// All parties participate
	signers := make([]int, totalParties)
	for i := range signers {
		signers[i] = i
	}
	sessionID := 1

	// Create signers from shares
	thresholdSigners := make([]*threshold.Signer, totalParties)
	for i, share := range shares {
		thresholdSigners[i] = threshold.NewSigner(share)
	}

	// Hash message first - this is what will be passed to the precompile
	messageHash := hashMessage(message)
	// Use hex encoding of messageHash as the signing message
	// This matches what contract.go does: mu := fmt.Sprintf("%x", messageHash)
	signMessage := fmt.Sprintf("%x", messageHash)

	// Round 1: Each party generates D matrix and MACs
	round1Data := make(map[int]*threshold.Round1Data)
	for i, signer := range thresholdSigners {
		round1Data[i] = signer.Round1(sessionID, prfKey, signers)
	}

	// Round 2: Each party generates z share (use hex-encoded message)
	round2Data := make(map[int]*threshold.Round2Data)
	for i, signer := range thresholdSigners {
		r2, err := signer.Round2(sessionID, signMessage, prfKey, signers, round1Data)
		if err != nil {
			return nil, nil, fmt.Errorf("round 2 failed for party %d: %w", i, err)
		}
		round2Data[i] = r2
	}

	// Finalize: Any party can aggregate the signature
	sig, err := thresholdSigners[0].Finalize(round2Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalize failed: %w", err)
	}

	// Verify the signature before serializing (sanity check)
	if !threshold.Verify(groupKey, signMessage, sig) {
		return nil, nil, fmt.Errorf("signature verification failed before serialization")
	}

	// Serialize signature and group key
	signatureBytes, err := serializeSignature(groupKey.Params, sig, groupKey)
	if err != nil {
		return nil, nil, err
	}

	return signatureBytes, messageHash, nil
}

// serializeSignature serializes signature components to bytes
func serializeSignature(params *threshold.Params, sig *threshold.Signature, groupKey *threshold.GroupKey) ([]byte, error) {
	var buf bytes.Buffer

	r := params.R
	r_xi := params.RXi
	r_nu := params.RNu

	// Serialize c (convert from NTT first)
	cCopy := *sig.C.CopyNew()
	r.IMForm(cCopy, cCopy)
	r.INTT(cCopy, cCopy)
	if err := serializePoly(&buf, r, cCopy); err != nil {
		return nil, err
	}

	// Serialize z vector (convert from NTT first)
	for i := 0; i < sign.N; i++ {
		zCopy := *sig.Z[i].CopyNew()
		r.IMForm(zCopy, zCopy)
		r.INTT(zCopy, zCopy)
		if err := serializePoly(&buf, r, zCopy); err != nil {
			return nil, err
		}
	}

	// Serialize Delta vector (already in coefficient form)
	for i := 0; i < sign.M; i++ {
		if err := serializePoly(&buf, r_nu, sig.Delta[i]); err != nil {
			return nil, err
		}
	}

	// Serialize A matrix (convert from NTT first)
	for i := 0; i < sign.M; i++ {
		for j := 0; j < sign.N; j++ {
			aCopy := *groupKey.A[i][j].CopyNew()
			r.IMForm(aCopy, aCopy)
			r.INTT(aCopy, aCopy)
			if err := serializePoly(&buf, r, aCopy); err != nil {
				return nil, err
			}
		}
	}

	// Serialize bTilde vector (already in coefficient form)
	for i := 0; i < sign.M; i++ {
		if err := serializePoly(&buf, r_xi, groupKey.BTilde[i]); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// serializePoly serializes a polynomial to binary data
func serializePoly(buf *bytes.Buffer, r *ring.Ring, poly ring.Poly) error {
	coeffs := make([]*big.Int, r.N())
	r.PolyToBigint(poly, 1, coeffs)

	for _, coeff := range coeffs {
		coeffBytes := make([]byte, 8) // 64-bit coefficients
		coeff.FillBytes(coeffBytes)
		if _, err := buf.Write(coeffBytes); err != nil {
			return err
		}
	}
	return nil
}

// hashMessage creates a 32-byte hash of a message using the same
// encoding that will be used during verification (hex encoding)
func hashMessage(message string) []byte {
	// The message hash should be raw bytes that, when hex-encoded,
	// produce the message string used during signing.
	// Since contract.go does: mu := fmt.Sprintf("%x", messageHash)
	// We need to hash the message and return raw bytes, then
	// signing should use the hex representation.
	hash := make([]byte, 32)
	copy(hash, []byte(message))
	return hash
}

// createInput creates precompile input from components
func createInput(thresholdVal, totalParties uint32, messageHash, signature []byte) []byte {
	input := make([]byte, 0, MinInputSize+len(signature))

	// Add threshold
	thresholdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(thresholdBytes, thresholdVal)
	input = append(input, thresholdBytes...)

	// Add total parties
	partiesBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(partiesBytes, totalParties)
	input = append(input, partiesBytes...)

	// Add message hash
	input = append(input, messageHash...)

	// Add signature
	input = append(input, signature...)

	return input
}
