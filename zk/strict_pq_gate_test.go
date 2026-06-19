// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"context"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// This file proves the post-quantum security invariant for the classical
// (pairing-/DLOG-based) ZK verifier ops: under a strict-PQ chain profile
// the precompile REFUSES to execute Groth16 (and the other classical
// proof systems) and returns contract.ErrClassicalForbiddenInPQ — the
// Groth16/bn254 code is KEPT but GATED, never deleted. The hash-based
// ops (Nullifier, Commitment) stay open on every chain.
//
// The gate is contract.RefuseUnderStrictPQ, called once at the top of
// the precompile's Run() (contract.go). These tests exercise it end-to-
// end through ZKVerifyPrecompile.Run, not just the gate function in
// isolation (which contract/strict_pq_test.go already covers), so a
// future refactor that drops the gate from the Groth16 op path is caught
// here.

// --- minimal strict-PQ AccessibleState (the contract package's mocks
//     live in its own _test.go and are not importable here).
//
// RefuseUnderStrictPQ only touches GetChainConfig() and
// GetBlockContext().Timestamp(); the classical-op Run() path is refused
// by the gate BEFORE the body, so GetStateDB()/GetPrecompileEnv() are
// never dereferenced here and may return nil. We deliberately do NOT
// implement the full contract.StateDB surface — it is not on the gate
// path and stubbing it would be dead, fragile ballast. ---

type stubBlockContext struct{ ts uint64 }

func (b stubBlockContext) Number() *big.Int                                     { return big.NewInt(1) }
func (b stubBlockContext) Timestamp() uint64                                    { return b.ts }
func (stubBlockContext) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

// strictPQConfig is a ChainConfig (the empty interface) that also
// implements contract.StrictPQReporter, reporting strict-PQ active iff
// the block timestamp is at or past strictFrom.
type strictPQConfig struct{ strictFrom uint64 }

func (c strictPQConfig) IsStrictPQ(time uint64) bool { return time >= c.strictFrom }

var _ contract.StrictPQReporter = strictPQConfig{}
var _ precompileconfig.ChainConfig = strictPQConfig{}

type stubAccessibleState struct {
	cfg precompileconfig.ChainConfig
	bc  contract.BlockContext
}

func (s stubAccessibleState) GetStateDB() contract.StateDB                 { return nil }
func (s stubAccessibleState) GetBlockContext() contract.BlockContext       { return s.bc }
func (s stubAccessibleState) GetConsensusContext() context.Context         { return context.Background() }
func (s stubAccessibleState) GetChainConfig() precompileconfig.ChainConfig { return s.cfg }
func (s stubAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return nil
}

var _ contract.AccessibleState = stubAccessibleState{}

func strictPQState(active bool) stubAccessibleState {
	// strict-PQ active from ts=1000; pick the block ts accordingly.
	ts := uint64(500)
	if active {
		ts = 1500
	}
	return stubAccessibleState{
		cfg: strictPQConfig{strictFrom: 1000},
		bc:  stubBlockContext{ts: ts},
	}
}

// classicalZKOps are the pairing-/DLOG-based ops that MUST be refused
// under strict-PQ. They are the quantum-breakable verifiers kept-but-
// gated. (OpVerifyBatch is included because a batch may carry Groth16.)
var classicalZKOps = []byte{
	OpVerifyGroth16,
	OpVerifyPLONK,
	OpVerifyFflonk,
	OpVerifyHalo2,
	OpVerifyKZG,
	OpVerifyIPA,
	OpVerifyRangeProof,
	OpVerifyBatch,
}

// TestZK_ClassicalOpsRefusedUnderStrictPQ proves every classical ZK
// verifier op returns ErrClassicalForbiddenInPQ when the chain is in
// strict-PQ mode — the Groth16/bn254 path cannot execute there.
func TestZK_ClassicalOpsRefusedUnderStrictPQ(t *testing.T) {
	state := strictPQState(true)
	gas := uint64(10_000_000)
	for _, op := range classicalZKOps {
		// A 5-byte input: [op][num_public_inputs:4=0]. The gate fires
		// before any proof parsing, so the body never sees this.
		input := []byte{op, 0x00, 0x00, 0x00, 0x00}
		_, _, err := ZKVerifyPrecompile.Run(
			state, common.Address{}, ZKVerifyContractAddress, input, gas, true,
		)
		require.ErrorIsf(t, err, contract.ErrClassicalForbiddenInPQ,
			"op 0x%02x must be refused under strict-PQ", op)
	}
}

// TestZK_ClassicalOpsAllowedWhenNotStrictPQ confirms the same ops are
// NOT refused by the strict-PQ gate when the chain is not in strict-PQ
// mode. (They may still fail downstream on a malformed proof — we only
// assert the gate did NOT fire, i.e. the error is not the strict-PQ
// refusal.)
func TestZK_ClassicalOpsAllowedWhenNotStrictPQ(t *testing.T) {
	state := strictPQState(false)
	gas := uint64(10_000_000)
	for _, op := range classicalZKOps {
		input := []byte{op, 0x00, 0x00, 0x00, 0x00}
		_, _, err := ZKVerifyPrecompile.Run(
			state, common.Address{}, ZKVerifyContractAddress, input, gas, true,
		)
		require.NotErrorIsf(t, err, contract.ErrClassicalForbiddenInPQ,
			"op 0x%02x must NOT be refused when strict-PQ is inactive", op)
	}
}

// TestZK_HashBasedOpsOpenUnderStrictPQ confirms the genuinely hash-based
// op (Nullifier 0x21) is NOT gated by strict-PQ — it is quantum-safe and
// must stay available on a strict-PQ chain.
//
// Commitment (0x22) is deliberately NOT in this list: it is dual-mode and
// only its Merkle sub-mode is hash-based. The Pedersen sub-mode is bn254
// DLOG and is covered (refused) by TestZK_PedersenCommitmentRefusedUnderStrictPQ.
func TestZK_HashBasedOpsOpenUnderStrictPQ(t *testing.T) {
	state := strictPQState(true)
	gas := uint64(10_000_000)
	for _, op := range []byte{OpVerifyNullifier} {
		input := []byte{op, 0x00, 0x00, 0x00, 0x00}
		_, _, err := ZKVerifyPrecompile.Run(
			state, common.Address{}, ZKVerifyContractAddress, input, gas, true,
		)
		require.NotErrorIsf(t, err, contract.ErrClassicalForbiddenInPQ,
			"hash-based op 0x%02x must remain open under strict-PQ", op)
	}
}

// pedersenCommitmentInput builds a 0x22 payload that selects the DEFAULT
// (Pedersen-opening) sub-mode: [op=0x22][96 bytes commitment‖value‖blinding]
// whose first byte is NOT 0x01, so verifyCommitment routes to the bn254
// globalPedersen.Verify path.
func pedersenCommitmentInput() []byte {
	body := make([]byte, 96) // commitment(32)+value(32)+blinding(32), all zero
	body[0] = 0x02           // anything != 0x01 ⇒ not the Merkle sub-mode
	return append([]byte{OpVerifyCommitment}, body...)
}

// merkleCommitmentInput builds a 0x22 payload that selects the Merkle
// sub-mode: [op=0x22][0x01][≥76 more bytes]. verifyCommitment routes this
// to the hash-based verifyCommitmentMerkle path, which stays open under
// strict-PQ.
func merkleCommitmentInput() []byte {
	// post-selector payload must be ≥77 bytes with data[0]==0x01.
	body := make([]byte, 96)
	body[0] = 0x01
	return append([]byte{OpVerifyCommitment}, body...)
}

// TestZK_PedersenCommitmentRefusedUnderStrictPQ is the NEW HIGH (Red): the
// DEFAULT 0x22 sub-path is verifyCommitmentPedersen -> globalPedersen.Verify
// = bn254 G1 DLOG, which a CRQC breaks. Under strict-PQ it MUST be refused
// with ErrClassicalForbiddenInPQ, BEFORE reaching the Pedersen verifier.
func TestZK_PedersenCommitmentRefusedUnderStrictPQ(t *testing.T) {
	state := strictPQState(true)
	gas := uint64(10_000_000)
	_, _, err := ZKVerifyPrecompile.Run(
		state, common.Address{}, ZKVerifyContractAddress, pedersenCommitmentInput(), gas, true,
	)
	require.ErrorIs(t, err, contract.ErrClassicalForbiddenInPQ,
		"the Pedersen (bn254 DLOG) 0x22 sub-path must be refused under strict-PQ")
}

// TestZK_PedersenCommitmentOpenWhenNotStrictPQ confirms the Pedersen 0x22
// sub-path is NOT refused on a non-strict chain — it remains available as
// a (quantum-breakable) building block. It may still fail on its own
// merits (no cached point), but never with the strict-PQ refusal.
func TestZK_PedersenCommitmentOpenWhenNotStrictPQ(t *testing.T) {
	state := strictPQState(false)
	gas := uint64(10_000_000)
	_, _, err := ZKVerifyPrecompile.Run(
		state, common.Address{}, ZKVerifyContractAddress, pedersenCommitmentInput(), gas, true,
	)
	require.NotErrorIs(t, err, contract.ErrClassicalForbiddenInPQ,
		"Pedersen 0x22 must NOT be refused on a non-strict chain")
}

// TestZK_MerkleCommitmentOpenUnderStrictPQ confirms the Merkle-inclusion
// sub-mode of 0x22 (hash-based, quantum-safe) stays OPEN on a strict-PQ
// chain. The gate must distinguish the sub-modes by data[0], not refuse
// all of 0x22.
func TestZK_MerkleCommitmentOpenUnderStrictPQ(t *testing.T) {
	state := strictPQState(true)
	gas := uint64(10_000_000)
	_, _, err := ZKVerifyPrecompile.Run(
		state, common.Address{}, ZKVerifyContractAddress, merkleCommitmentInput(), gas, true,
	)
	require.NotErrorIs(t, err, contract.ErrClassicalForbiddenInPQ,
		"the Merkle 0x22 sub-mode must remain open under strict-PQ")
}

// TestZK_CommitmentSubmodeDiscriminator is a unit check on the SINGLE
// source of truth that the gate and verifyCommitment's dispatch share, so
// they can never disagree about which 0x22 bytes are the hash-based path.
func TestZK_CommitmentSubmodeDiscriminator(t *testing.T) {
	// Merkle: data[0]==0x01 and len>=77.
	merkle := merkleCommitmentInput()[1:]
	require.True(t, isMerkleCommitment(merkle))
	require.False(t, isPedersenCommitment(merkle))

	// Pedersen: first byte != 0x01.
	ped := pedersenCommitmentInput()[1:]
	require.False(t, isMerkleCommitment(ped))
	require.True(t, isPedersenCommitment(ped))

	// data[0]==0x01 but too short (<77) is NOT Merkle ⇒ Pedersen (fail-closed).
	short := make([]byte, 40)
	short[0] = 0x01
	require.False(t, isMerkleCommitment(short))
	require.True(t, isPedersenCommitment(short))
}
