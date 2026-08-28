// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// A rollup batch advances the chain's state root on the strength of one
// proof, so every guard around it is load-bearing: who may propose, how
// much a batch may contain, and — above all — that the proof is checked
// against the state the batch claims to extend. A rollup verifier that
// accepts a batch whose PrevStateRoot does not match the chain lets an
// operator rewrite history.

var (
	rolOwner     = common.HexToAddress("0x1111111111111111111111111111111111111111")
	rolSequencer = common.HexToAddress("0x2222222222222222222222222222222222222222")
	rolStranger  = common.HexToAddress("0x3333333333333333333333333333333333333333")
)

// rolBatchInputs mirrors verifyGroth16Batch's public-input vector:
// [prevRoot, newRoot, txCount, l1BatchNum].
func rolBatchInputs(prev, next [32]byte, txs, l1 uint64) []*big.Int {
	return []*big.Int{
		new(big.Int).SetBytes(prev[:]),
		new(big.Int).SetBytes(next[:]),
		new(big.Int).SetInt64(int64(txs)),
		new(big.Int).SetInt64(int64(l1)),
	}
}

// rolSetup registers a rollup whose verifying key admits a genuine proof
// for the batch described, and returns the rollup id and that batch.
func rolSetup(t *testing.T, prev, next [32]byte, txs, l1 uint64) (*ZKVerifier, [32]byte, *RollupBatch) {
	t.Helper()
	zv := NewZKVerifier()

	in := grBuild(t, rolBatchInputs(prev, next, txs, l1))
	keyID := grRegister(t, zv, in)

	rollupID, err := zv.RegisterRollup(rolOwner, keyID, ProofSystemGroth16, 1000, 60, rolSequencer)
	require.NoError(t, err)

	return zv, rollupID, &RollupBatch{
		BatchID:       [32]byte{0xB1},
		RollupID:      rollupID,
		PrevStateRoot: prev,
		NewStateRoot:  next,
		Transactions:  txs,
		L1BatchNum:    l1,
		Proposer:      rolSequencer,
		Proof: &Proof{
			ProofSystem: ProofSystemGroth16,
			A:           in.a,
			B:           in.b,
			C:           in.c,
		},
	}
}

// TestRol_AcceptsAValidBatchAndAdvancesState is the control: a batch with
// a genuine proof must be accepted, and must move the recorded state on.
// Without it every refusal below would pass against a rollup that never
// accepts anything.
func TestRol_AcceptsAValidBatchAndAdvancesState(t *testing.T) {
	next := [32]byte{0xAB, 0xCD}
	zv, id, batch := rolSetup(t, [32]byte{}, next, 42, 7)

	require.NoError(t, zv.VerifyRollupBatch(id, batch),
		"a batch with a satisfying proof must be accepted")

	state, err := zv.GetRollupState(id)
	require.NoError(t, err)
	require.Equal(t, next, state.LastStateRoot, "the state root must advance")
	require.Equal(t, batch.BatchID, state.LastBatchID)
	require.Equal(t, uint64(7), state.LastL1Block)
	require.Equal(t, uint64(1), state.TotalBatches)
	require.Equal(t, uint64(42), state.TotalTxs)

	// Replaying the same batch must now fail: its PrevStateRoot no longer
	// matches the chain. This is what stops a batch being applied twice.
	require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrInvalidStateRoot,
		"a batch was replayable after it had been applied")
}

// TestRol_RefusesOnEveryGuard walks each refusal in turn, from a batch
// that is otherwise valid, so each assertion isolates one guard.
func TestRol_RefusesOnEveryGuard(t *testing.T) {
	next := [32]byte{0x11, 0x22}

	t.Run("unknown rollup", func(t *testing.T) {
		zv, _, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		require.ErrorIs(t, zv.VerifyRollupBatch([32]byte{0xFF}, batch), ErrRollupNotFound)
	})

	t.Run("disabled rollup", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		zv.Rollups[id].Enabled = false
		require.Error(t, zv.VerifyRollupBatch(id, batch))
	})

	t.Run("unauthorized proposer", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		batch.Proposer = rolStranger
		require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrUnauthorizedProposer)
	})

	t.Run("owner may also propose", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		batch.Proposer = rolOwner
		require.NoError(t, zv.VerifyRollupBatch(id, batch))
	})

	t.Run("batch too large", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		zv.Rollups[id].MaxTxPerBatch = 9
		require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrBatchTooLarge)

		// Exactly at the limit is allowed — the bound is inclusive.
		zv.Rollups[id].MaxTxPerBatch = 10
		require.NoError(t, zv.VerifyRollupBatch(id, batch))
	})

	t.Run("wrong previous state root", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		batch.PrevStateRoot = [32]byte{0x99}
		require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrInvalidStateRoot,
			"a batch extending a state the chain is not in was accepted")
	})

	t.Run("missing proof", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		batch.Proof = nil
		require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrInvalidProof)
	})

	t.Run("tampered proof", func(t *testing.T) {
		for _, mut := range []func(*Proof){
			func(p *Proof) { p.A[0] ^= 0x01 },
			func(p *Proof) { p.B[0] ^= 0x01 },
			func(p *Proof) { p.C[0] ^= 0x01 },
		} {
			zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
			mut(batch.Proof)
			require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrInvalidProof)
		}
	})

	t.Run("proof bound to the batch contents", func(t *testing.T) {
		// The proof commits to [prevRoot, newRoot, txCount, l1BatchNum].
		// Changing any of them while keeping the proof must fail, or an
		// operator could substitute a different state transition.
		for name, mut := range map[string]func(*RollupBatch){
			"new state root": func(b *RollupBatch) { b.NewStateRoot = [32]byte{0xEE} },
			"tx count":       func(b *RollupBatch) { b.Transactions = 11 },
			"l1 batch num":   func(b *RollupBatch) { b.L1BatchNum = 2 },
		} {
			zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
			mut(batch)
			require.ErrorIsf(t, zv.VerifyRollupBatch(id, batch), ErrInvalidProof,
				"the proof did not bind %s", name)
		}
	})

	t.Run("unsupported proof system", func(t *testing.T) {
		zv, id, batch := rolSetup(t, [32]byte{}, next, 10, 1)
		zv.Rollups[id].ProofSystem = ProofSystemStark
		require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrProofSystemMismatch)
	})
}

// TestRol_PlonkBatchPath drives the PLONK branch of the dispatch.
func TestRol_PlonkBatchPath(t *testing.T) {
	zv := NewZKVerifier()

	ic := make([][]byte, 9)
	for i := range 8 {
		ic[i] = grG1(big.NewInt(int64(i + 61)))
	}
	ic[8] = grG2(big.NewInt(71))

	keyID, err := zv.RegisterVerifyingKey(common.Address{},
		ProofSystemPlonk, CircuitRollupBatch,
		grG1(big.NewInt(73)), grG2(big.NewInt(79)),
		grG2(big.NewInt(83)), grG2(big.NewInt(89)), ic)
	require.NoError(t, err)

	id, err := zv.RegisterRollup(rolOwner, keyID, ProofSystemPlonk, 100, 60, rolSequencer)
	require.NoError(t, err)

	// verifyPlonkBatch concatenates A‖B‖C, so together they must form the
	// 768-byte PLONK layout: nine G1 points then six scalars.
	proof := make([]byte, 0, 768)
	for i := range 9 {
		proof = append(proof, grG1(big.NewInt(int64(200+i)))...)
	}
	for i := range 6 {
		proof = append(proof, padScalar32(big.NewInt(int64(400+i)))...)
	}
	require.Len(t, proof, 768)

	batch := &RollupBatch{
		RollupID:     id,
		NewStateRoot: [32]byte{0x77},
		Transactions: 5,
		Proposer:     rolSequencer,
		Proof: &Proof{
			ProofSystem: ProofSystemPlonk,
			A:           proof[0:256:256],
			B:           proof[256:512:512],
			C:           proof[512:768:768],
		},
	}

	// Arbitrary curve points are not a PLONK proof: refuse.
	require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrInvalidProof)

	// A missing proof is refused before any arithmetic.
	batch.Proof = nil
	require.ErrorIs(t, zv.VerifyRollupBatch(id, batch), ErrInvalidProof)
}

// TestRol_RegisterGuards covers registration itself.
func TestRol_RegisterGuards(t *testing.T) {
	zv := NewZKVerifier()

	_, err := zv.RegisterRollup(rolOwner, [32]byte{0xDE}, ProofSystemGroth16, 10, 60, rolSequencer)
	require.ErrorIs(t, err, ErrInvalidVerifyingKey,
		"a rollup must not register against a key that does not exist")

	in := grBuild(t, []*big.Int{big.NewInt(1)})
	keyID := grRegister(t, zv, in)

	id, err := zv.RegisterRollup(rolOwner, keyID, ProofSystemGroth16, 10, 60, rolSequencer)
	require.NoError(t, err)

	state, err := zv.GetRollupState(id)
	require.NoError(t, err)
	require.Equal(t, [32]byte{}, state.LastStateRoot, "a new rollup starts at genesis")
	require.Zero(t, state.TotalBatches)

	_, err = zv.GetRollupState([32]byte{0xAA})
	require.ErrorIs(t, err, ErrRollupNotFound)

	// The declared proof system is NOT checked against the key's own. A
	// Groth16 key can be registered as PLONK, and the batch dispatch will
	// then hand it to the PLONK verifier. It refuses — but on the proof,
	// not on the mismatch, so the confusion is silent.
	mixed, err := zv.RegisterRollup(rolOwner, keyID, ProofSystemPlonk, 10, 60, rolSequencer)
	require.NoError(t, err,
		"registration does not cross-check the declared system against the key")
	require.Equal(t, ProofSystemGroth16, zv.Rollups[mixed].VerifyingKey.ProofSystem)
	require.Equal(t, ProofSystemPlonk, zv.Rollups[mixed].ProofSystem)
}

// TestRol_PoolLifecycle covers confidential-pool creation and commitment
// insertion, including the refusals.
func TestRol_PoolLifecycle(t *testing.T) {
	zv := NewZKVerifier()
	token := common.HexToAddress("0x4444444444444444444444444444444444444444")

	poolID, err := zv.CreateConfidentialPool(rolOwner, token, 20)
	require.NoError(t, err)

	c := &Commitment{
		CommitType: CommitPedersen,
		Value:      []byte("a-commitment"),
		Amount:     big.NewInt(100),
	}
	cid, err := zv.AddCommitment(poolID, c)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, cid)
	require.Equal(t, big.NewInt(100), zv.Pools[poolID].TotalDeposits)

	// A second deposit accumulates.
	_, err = zv.AddCommitment(poolID, &Commitment{
		CommitType: CommitPedersen,
		Value:      []byte("another"),
		Amount:     big.NewInt(50),
	})
	require.NoError(t, err)
	require.Equal(t, big.NewInt(150), zv.Pools[poolID].TotalDeposits)

	// Unknown and disabled pools are refused.
	_, err = zv.AddCommitment([32]byte{0xFF}, c)
	require.ErrorIs(t, err, ErrPoolNotFound)

	zv.Pools[poolID].Enabled = false
	_, err = zv.AddCommitment(poolID, c)
	require.ErrorIs(t, err, ErrPoolDisabled)

	// Inclusion against an unknown pool is an error, not a false verdict.
	_, err = zv.VerifyCommitmentInclusion([32]byte{0xFF}, cid, nil, 0)
	require.ErrorIs(t, err, ErrPoolNotFound)

	// An empty proof only verifies if the leaf hash IS the root; with the
	// genesis root it must not.
	ok, err := zv.VerifyCommitmentInclusion(poolID, cid, nil, 0)
	require.NoError(t, err)
	require.False(t, ok, "a commitment must not be provable against an empty tree")
}

// TestRol_StatsTracking pins the counters, which are the only signal an
// operator has that verification is happening at all.
func TestRol_StatsTracking(t *testing.T) {
	zv := NewZKVerifier()
	in := grBuild(t, []*big.Int{big.NewInt(3)})
	id := grRegister(t, zv, in)

	require.Zero(t, zv.TotalVerifications)

	res, err := zv.VerifyGroth16(id, in.a, in.b, in.c, in.public)
	require.NoError(t, err)
	require.True(t, res.Valid)
	require.Equal(t, uint64(1), zv.TotalVerifications)
	require.Equal(t, uint64(1), zv.TotalProofsValid)
	require.Zero(t, zv.TotalProofsFailed)

	_, err = zv.VerifyGroth16(id, in.a, in.b, in.c, []*big.Int{big.NewInt(4)})
	require.NoError(t, err)
	require.Equal(t, uint64(2), zv.TotalVerifications)
	require.Equal(t, uint64(1), zv.TotalProofsValid)
	require.Equal(t, uint64(1), zv.TotalProofsFailed,
		"a rejected proof must be counted as failed, not valid")

	// A refusal before verification must not be counted at all.
	_, err = zv.VerifyGroth16([32]byte{0xFF}, in.a, in.b, in.c, in.public)
	require.ErrorIs(t, err, ErrInvalidVerifyingKey)
	require.Equal(t, uint64(2), zv.TotalVerifications)
}
