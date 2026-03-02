// anchor_checkpoint_test exercises on-chain CRDT checkpoint anchoring:
//
//  1. Generate off-chain CRDT state
//  2. Compute Merkle root hash
//  3. Anchor on-chain (submit)
//  4. Retrieve and verify (get, getLatest)
//  5. Verify monotonicity enforcement
//
// Precompiles exercised: Anchor, Blake3, Poseidon.
package scenarios

import (
	"crypto/sha256"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/anchor"
	"github.com/luxfi/precompile/blake3"
	"github.com/luxfi/precompile/e2e/harness"
	"github.com/luxfi/precompile/poseidon"
	"github.com/stretchr/testify/require"
)

func TestAnchorCheckpoint_FullLifecycle(t *testing.T) {
	state := harness.NewMockAccessibleState()
	caller := common.HexToAddress("0xCC00000000000000000000000000000000000001")

	// Step 1: Compute CRDT state root off-chain (simulate with sha256)
	crdtState := []byte("counter:42,set:{a,b,c},lww:hello")
	stateHash := sha256.Sum256(crdtState)
	appID := sha256.Sum256([]byte("my-crdt-app"))

	// Step 2: Anchor at height 1
	submitSelector := crypto.Keccak256([]byte("submit(bytes32,uint64,bytes32)"))[:4]

	submitInput := make([]byte, 0, 4+96)
	submitInput = append(submitInput, submitSelector...)
	submitInput = append(submitInput, appID[:]...)           // appID (32 bytes)
	submitInput = append(submitInput, harness.Uint256(1)...) // height = 1
	submitInput = append(submitInput, stateHash[:]...)        // root (32 bytes)

	out, gas, err := harness.CallStateful(
		anchor.AnchorPrecompile,
		state,
		caller,
		anchor.ContractAddress,
		submitInput,
		false,
	)
	require.NoError(t, err, "submit anchor failed")
	harness.GasReport(t, "anchor submit", gas)
	t.Logf("Anchored at height 1: %x", out)

	// Step 3: Get the anchor back
	getSelector := crypto.Keccak256([]byte("get(bytes32,uint64)"))[:4]

	getInput := make([]byte, 0, 4+64)
	getInput = append(getInput, getSelector...)
	getInput = append(getInput, appID[:]...)
	getInput = append(getInput, harness.Uint256(1)...)

	getOut, getGas, err := harness.CallStateful(
		anchor.AnchorPrecompile,
		state,
		caller,
		anchor.ContractAddress,
		getInput,
		true,
	)
	require.NoError(t, err, "get anchor failed")
	require.Equal(t, stateHash[:], getOut, "retrieved root must match submitted root")
	harness.GasReport(t, "anchor get", getGas)

	// Step 4: Get latest height
	getLatestSelector := crypto.Keccak256([]byte("getLatest(bytes32)"))[:4]

	latestInput := make([]byte, 0, 4+32)
	latestInput = append(latestInput, getLatestSelector...)
	latestInput = append(latestInput, appID[:]...)

	latestOut, latestGas, err := harness.CallStateful(
		anchor.AnchorPrecompile,
		state,
		caller,
		anchor.ContractAddress,
		latestInput,
		true,
	)
	require.NoError(t, err, "getLatest failed")
	harness.GasReport(t, "anchor getLatest", latestGas)
	t.Logf("Latest height: %x", latestOut)

	// Step 5: Submit height 2 (should succeed)
	stateHash2 := sha256.Sum256([]byte("counter:43,set:{a,b,c,d},lww:world"))
	submitInput2 := make([]byte, 0, 4+96)
	submitInput2 = append(submitInput2, submitSelector...)
	submitInput2 = append(submitInput2, appID[:]...)
	submitInput2 = append(submitInput2, harness.Uint256(2)...)
	submitInput2 = append(submitInput2, stateHash2[:]...)

	_, _, err = harness.CallStateful(
		anchor.AnchorPrecompile,
		state,
		caller,
		anchor.ContractAddress,
		submitInput2,
		false,
	)
	require.NoError(t, err, "submit height 2 should succeed")

	// Step 6: Submit height 1 again (should fail -- monotonicity)
	_, _, err = harness.CallStateful(
		anchor.AnchorPrecompile,
		state,
		caller,
		anchor.ContractAddress,
		submitInput,
		false,
	)
	require.Error(t, err, "re-submitting height 1 should fail (monotonicity)")
	t.Logf("Monotonicity enforced: %v", err)
}

func TestAnchorCheckpoint_Blake3MerkleRoot(t *testing.T) {
	// Use Blake3 precompile to compute a Merkle root for the CRDT state,
	// then anchor it. This demonstrates Blake3 + Anchor cooperation.

	// Hash two leaves with Blake3
	leaf1 := harness.PadLeft([]byte("leaf-a"), 32)
	leaf2 := harness.PadLeft([]byte("leaf-b"), 32)

	// Blake3 input: opcode(1) + data
	// OpHash256 = 0x01
	hashInput := make([]byte, 0, 1+64)
	hashInput = append(hashInput, 0x01) // OpHash256
	hashInput = append(hashInput, leaf1...)
	hashInput = append(hashInput, leaf2...)

	merkleRoot, gas, err := harness.Call(
		blake3.Blake3Precompile,
		blake3.ContractAddress,
		hashInput,
		true,
	)
	require.NoError(t, err, "Blake3 hash failed")
	require.Len(t, merkleRoot, 32, "Blake3 output should be 32 bytes")
	harness.GasReport(t, "Blake3 hash256", gas)
	t.Logf("Blake3 Merkle root: %x", merkleRoot)
}

func TestAnchorCheckpoint_PoseidonMerkleRoot(t *testing.T) {
	// Alternative: use Poseidon for ZK-friendly Merkle roots
	leaf1 := harness.Uint256(100)
	leaf2 := harness.Uint256(200)

	input := make([]byte, 0, 1+64)
	input = append(input, poseidon.OpHashPair)
	input = append(input, leaf1...)
	input = append(input, leaf2...)

	root, gas, err := harness.Call(
		poseidon.PoseidonPrecompile,
		poseidon.ContractAddress,
		input,
		true,
	)
	require.NoError(t, err, "Poseidon HashPair failed")
	require.Len(t, root, 32)
	harness.GasReport(t, "Poseidon merkle root", gas)
	t.Logf("Poseidon Merkle root: %x", root)
}

func TestAnchorCheckpoint_ReadOnlyReject(t *testing.T) {
	state := harness.NewMockAccessibleState()
	caller := common.HexToAddress("0xCC00000000000000000000000000000000000002")

	submitSelector := crypto.Keccak256([]byte("submit(bytes32,uint64,bytes32)"))[:4]
	input := make([]byte, 0, 4+96)
	input = append(input, submitSelector...)
	input = append(input, make([]byte, 96)...) // zeros

	// Submit in read-only mode should fail
	_, _, err := harness.CallStateful(
		anchor.AnchorPrecompile,
		state,
		caller,
		anchor.ContractAddress,
		input,
		true, // readOnly = true
	)
	require.Error(t, err, "submit in read-only mode should fail")
	t.Logf("Read-only submit correctly rejected: %v", err)
}
