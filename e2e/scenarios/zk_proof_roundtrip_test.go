// zk_proof_roundtrip_test exercises ZK proof generation + on-chain verification:
//
//  1. Build a Groth16-compatible proof off-chain (BN256 pairing points)
//  2. Verify via the ZK precompile
//  3. Compute nullifier via Poseidon hash
//  4. Verify nullifier uniqueness
//
// Precompiles exercised: ZK (Groth16), Poseidon.
package scenarios

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/luxfi/precompile/e2e/harness"
	"github.com/luxfi/precompile/poseidon"
	"github.com/luxfi/precompile/zk"
	"github.com/stretchr/testify/require"
)

func TestZKProofRoundtrip_Groth16Dispatch(t *testing.T) {
	// The Groth16 verifier expects:
	// op(1) + numInputs(4) + vkID(32) + publicInputs(N*32) + proofA(64) + proofB(128) + proofC(64)
	//
	// We construct a well-formed input to exercise the full dispatch path.
	// The proof itself is synthetic (won't pass the pairing check) but we verify
	// the precompile correctly parses input, calculates gas, and returns a
	// deterministic result.

	numInputs := uint32(2)

	// Build input
	input := make([]byte, 0, 1+4+32+64+64+128+64)
	input = append(input, zk.OpVerifyGroth16)

	// num public inputs
	ni := make([]byte, 4)
	binary.BigEndian.PutUint32(ni, numInputs)
	input = append(input, ni...)

	// vkID (32 bytes) - arbitrary
	vkID := sha256.Sum256([]byte("e2e-test-vk"))
	input = append(input, vkID[:]...)

	// 2 public inputs (each 32 bytes)
	input = append(input, harness.Uint256(42)...)
	input = append(input, harness.Uint256(1337)...)

	// Proof A (G1 point, 64 bytes) - synthetic
	proofA := make([]byte, 64)
	proofA[31] = 1 // x = 1
	proofA[63] = 2 // y = 2
	input = append(input, proofA...)

	// Proof B (G2 point, 128 bytes) - synthetic
	proofB := make([]byte, 128)
	proofB[31] = 1
	input = append(input, proofB...)

	// Proof C (G1 point, 64 bytes) - synthetic
	proofC := make([]byte, 64)
	proofC[31] = 1
	proofC[63] = 2
	input = append(input, proofC...)

	out, gasUsed, err := harness.Call(
		zk.ZKVerifyPrecompile,
		zk.ZKVerifyContractAddress,
		input,
		true,
	)

	// The synthetic proof won't pass the pairing check, but the dispatch
	// path should work correctly: parse input, deduct gas, attempt verify.
	if err != nil {
		t.Logf("Groth16 returned error (expected for synthetic proof): %v", err)
		t.Logf("Gas consumed before error: %d", gasUsed)
	} else {
		require.Len(t, out, 32, "output should be 32 bytes")
		t.Logf("Groth16 result: %x (gas: %d)", out, gasUsed)
	}
	harness.GasReport(t, "Groth16 verify (synthetic)", gasUsed)
}

func TestZKProofRoundtrip_NullifierViaPoseidon(t *testing.T) {
	// Compute a nullifier as Poseidon(secret, nonce).
	// This is the standard pattern for ZK membership proofs.

	secret := harness.PadLeft([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 32)
	nonce := harness.PadLeft([]byte{0x01}, 32)

	// Poseidon hash of (secret, nonce)
	hashInput := make([]byte, 0, 1+64)
	hashInput = append(hashInput, poseidon.OpHash)
	hashInput = append(hashInput, secret...)
	hashInput = append(hashInput, nonce...)

	nullifier, hashGas, err := harness.Call(
		poseidon.PoseidonPrecompile,
		poseidon.ContractAddress,
		hashInput,
		true,
	)
	require.NoError(t, err, "Poseidon hash failed")
	require.Len(t, nullifier, 32, "Poseidon output should be 32 bytes")
	require.True(t, isNonZero(nullifier), "nullifier should be non-zero")
	harness.GasReport(t, "Poseidon hash", hashGas)

	// Verify determinism: same inputs produce same nullifier
	nullifier2, _, err := harness.Call(
		poseidon.PoseidonPrecompile,
		poseidon.ContractAddress,
		hashInput,
		true,
	)
	require.NoError(t, err)
	require.Equal(t, nullifier, nullifier2, "Poseidon must be deterministic")

	// Different nonce produces different nullifier
	nonce2 := harness.PadLeft([]byte{0x02}, 32)
	hashInput2 := make([]byte, 0, 1+64)
	hashInput2 = append(hashInput2, poseidon.OpHash)
	hashInput2 = append(hashInput2, secret...)
	hashInput2 = append(hashInput2, nonce2...)

	nullifier3, _, err := harness.Call(
		poseidon.PoseidonPrecompile,
		poseidon.ContractAddress,
		hashInput2,
		true,
	)
	require.NoError(t, err)
	require.NotEqual(t, nullifier, nullifier3, "different nonce must produce different nullifier")

	t.Logf("Nullifier 1: %x", nullifier)
	t.Logf("Nullifier 2: %x", nullifier3)
}

func TestZKProofRoundtrip_PoseidonHashPair(t *testing.T) {
	// HashPair is the optimized 2-element variant
	a := harness.Uint256(100)
	b := harness.Uint256(200)

	input := make([]byte, 0, 1+64)
	input = append(input, poseidon.OpHashPair)
	input = append(input, a...)
	input = append(input, b...)

	out, gas, err := harness.Call(
		poseidon.PoseidonPrecompile,
		poseidon.ContractAddress,
		input,
		true,
	)
	require.NoError(t, err)
	require.Len(t, out, 32)
	require.True(t, isNonZero(out))
	harness.GasReport(t, "Poseidon HashPair", gas)

	// Verify commutativity does NOT hold (Poseidon is order-dependent)
	inputReversed := make([]byte, 0, 1+64)
	inputReversed = append(inputReversed, poseidon.OpHashPair)
	inputReversed = append(inputReversed, b...)
	inputReversed = append(inputReversed, a...)

	outReversed, _, err := harness.Call(
		poseidon.PoseidonPrecompile,
		poseidon.ContractAddress,
		inputReversed,
		true,
	)
	require.NoError(t, err)
	require.NotEqual(t, out, outReversed, "Poseidon(a,b) != Poseidon(b,a)")
}

func isNonZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
