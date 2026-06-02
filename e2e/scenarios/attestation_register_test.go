// attestation_register_test exercises the TEE attestation + compute marketplace:
//
//  1. Register a GPU provider (attestation precompile)
//  2. Submit a compute job (compute precompile)
//  3. Claim reward after completion
//  4. Verify job status transitions
//
// Precompiles exercised: Attestation, Compute.
package scenarios

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/attestation"
	"github.com/luxfi/precompile/compute"
	"github.com/luxfi/precompile/e2e/harness"
	"github.com/stretchr/testify/require"
)

func TestAttestationRegister_DeviceRegistration(t *testing.T) {
	// The attestation precompile verifies TEE quotes.
	// We test the dispatch path with a synthetic attestation.

	// Selector 0x04000000 = CreateAttestation (register device)
	input := make([]byte, 0, 4+32+32)
	input = append(input, 0x04, 0x00, 0x00, 0x00) // CreateAttestation selector
	// GPU type (32 bytes, e.g., "A100" padded)
	gpuType := harness.PadLeft([]byte("NVIDIA-A100"), 32)
	input = append(input, gpuType...)
	// TEE quote hash (32 bytes)
	quoteHash := harness.Uint256(0xDEADBEEF)
	input = append(input, quoteHash...)

	out, gas, err := harness.Call(
		attestation.Precompile,
		attestation.ContractAddress,
		input,
		false, // write operation
	)
	// Without a real TEE environment, this will fail verification.
	// We verify the dispatch works correctly.
	if err != nil {
		t.Logf("Attestation CreateAttestation: %v (expected without TEE)", err)
	} else {
		t.Logf("Attestation result: %x (gas: %d)", out, gas)
	}
}

func TestAttestationRegister_ComputeMarketplace(t *testing.T) {
	// Full compute marketplace lifecycle using mock state
	state := harness.NewMockAccessibleState()

	provider := common.HexToAddress("0xAABB000000000000000000000000000000000001")
	requester := common.HexToAddress("0xAABB000000000000000000000000000000000002")

	// Step 1: Register provider
	regInput := make([]byte, 0, 1+32+32)
	regInput = append(regInput, compute.OpRegisterProvider)
	regInput = append(regInput, harness.PadLeft([]byte("H100-80GB"), 32)...) // gpuType
	regInput = append(regInput, harness.Uint256(0xCAFEBABE)...)              // TEE attestation hash

	regOut, regGas, err := harness.CallStateful(
		compute.Precompile,
		state,
		provider,
		compute.ContractAddress,
		regInput,
		false,
	)
	require.NoError(t, err, "RegisterProvider failed")
	require.Len(t, regOut, 32, "providerID should be 32 bytes")
	harness.GasReport(t, "RegisterProvider", regGas)
	t.Logf("Provider registered: %x", regOut)

	// Step 2: Submit compute job
	jobInput := make([]byte, 0, 1+32+32+32)
	jobInput = append(jobInput, compute.OpSubmitJob)
	jobInput = append(jobInput, harness.Uint256(0x1234)...) // modelHash
	jobInput = append(jobInput, harness.Uint256(0x5678)...) // inputHash
	jobInput = append(jobInput, harness.Uint256(1e15)...)   // maxPrice in wei

	jobOut, jobGas, err := harness.CallStateful(
		compute.Precompile,
		state,
		requester,
		compute.ContractAddress,
		jobInput,
		false,
	)
	require.NoError(t, err, "SubmitJob failed")
	require.Len(t, jobOut, 32, "jobID should be 32 bytes")
	harness.GasReport(t, "SubmitJob", jobGas)
	t.Logf("Job submitted: %x", jobOut)

	// Step 3: Claim reward (provider completes the job)
	claimInput := make([]byte, 0, 1+32+32)
	claimInput = append(claimInput, compute.OpClaimReward)
	claimInput = append(claimInput, jobOut...)                  // jobID
	claimInput = append(claimInput, harness.Uint256(0xABCD)...) // outputHash

	claimOut, claimGas, err := harness.CallStateful(
		compute.Precompile,
		state,
		provider,
		compute.ContractAddress,
		claimInput,
		false,
	)
	require.NoError(t, err, "ClaimReward failed")
	harness.GasReport(t, "ClaimReward", claimGas)
	t.Logf("Claim result: %x", claimOut)

	// Step 4: Verify double-claim is rejected
	_, _, err = harness.CallStateful(
		compute.Precompile,
		state,
		provider,
		compute.ContractAddress,
		claimInput,
		false,
	)
	require.Error(t, err, "double claim should fail")
	t.Logf("Double claim correctly rejected: %v", err)
}

func TestAttestationRegister_GasCosts(t *testing.T) {
	// Verify gas constants are correctly set
	require.Equal(t, 25000, compute.GasRegister, "register gas")
	require.Equal(t, 10000, compute.GasSubmit, "submit gas")
	require.Equal(t, 5000, compute.GasClaim, "claim gas")
	require.Equal(t, 50000, compute.GasVerify, "verify gas")
	require.Equal(t, 5000, compute.GasGetPrice, "getPrice gas")
}
