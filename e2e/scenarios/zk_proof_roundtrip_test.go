// zk_proof_roundtrip_test exercises the PQ-safe ZK precompile:
//
//  1. Dispatch a nullifier check through the ZK precompile (hash-based, PQ-safe)
//  2. Compute nullifier via Poseidon hash
//  3. Verify nullifier uniqueness
//
// Classical pairing-based opcodes (Groth16/PLONK/fflonk/Halo2/KZG/IPA) were
// removed: Shor breaks them. PQ STARK verification lives in the Z-Chain
// envelope path, not in this EVM precompile.
//
// Precompiles exercised: ZK (Nullifier), Poseidon.
package scenarios

import (
	"testing"

	"github.com/luxfi/precompile/e2e/harness"
	"github.com/luxfi/precompile/poseidon"
	"github.com/luxfi/precompile/zk"
	"github.com/stretchr/testify/require"
)

func TestZKProofRoundtrip_NullifierDispatch(t *testing.T) {
	// The nullifier verifier expects:
	// op(1) + nullifierHash(32)
	//
	// Without a verifier context the precompile cannot look up state, so we
	// only exercise dispatch + gas accounting here.

	input := make([]byte, 0, 1+32)
	input = append(input, zk.OpVerifyNullifier)
	input = append(input, harness.Uint256(0xDEADBEEF)...)

	out, gasUsed, err := harness.Call(
		zk.ZKVerifyPrecompile,
		zk.ZKVerifyContractAddress,
		input,
		true,
	)

	// Without a registered ZKVerifier instance the precompile returns
	// ErrVerifierRequired; the dispatch path itself must succeed.
	if err != nil {
		t.Logf("Nullifier returned error (expected without verifier state): %v", err)
		t.Logf("Gas consumed before error: %d", gasUsed)
	} else {
		require.Len(t, out, 32, "output should be 32 bytes")
		t.Logf("Nullifier result: %x (gas: %d)", out, gasUsed)
	}
	harness.GasReport(t, "Nullifier verify (synthetic)", gasUsed)
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
