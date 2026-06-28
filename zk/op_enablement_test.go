// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Enable-everything policy (public permissionless launch): the classical
// SNARK / commitment verifier ops are ENABLED for builders on every chain —
// they are verify-only and key-safe, and a builder choosing classical
// (quantum-breakable) crypto for their own application is making THAT app's
// security decision, not the chain's. There is NO strict-PQ refusal on the
// builder precompile surface; Lux's own consensus and identity are PQ
// (quasar / p3q), enforced in the consensus layer — never by refusing an
// EVM verifier a dapp asked for.
//
// The single exception is fflonk (0x03): DISABLED because verifyFflonk is
// unsound — a nil verifying-key singleton path accepts a crafted proof for
// any statement (a universal forge). That is a security disable, fully
// independent of any PQ profile.

// classicalEnabledOps are the verify-only ops that MUST stay reachable (no
// policy refusal) on every chain. fflonk is deliberately excluded — see
// TestZK_FflonkDisabled.
var classicalEnabledOps = []byte{
	OpVerifyGroth16,
	OpVerifyPLONK,
	OpVerifyHalo2,
	OpVerifyKZG,
	OpVerifyIPA,
	OpVerifyRangeProof,
	OpVerifyBatch,
	OpVerifyNullifier,
	OpVerifyCommitment,
}

// TestZK_FflonkDisabled proves the unsound fflonk verifier refuses to execute
// and returns the typed ErrFflonkDisabled — the forge path is unreachable from
// the precompile entry.
func TestZK_FflonkDisabled(t *testing.T) {
	input := []byte{OpVerifyFflonk, 0x00, 0x00, 0x00, 0x00}
	_, _, err := ZKVerifyPrecompile.Run(
		nil, common.Address{}, ZKVerifyContractAddress, input, 10_000_000, true,
	)
	require.ErrorIs(t, err, ErrFflonkDisabled,
		"fflonk (0x03) must be disabled (unsound verifier)")
}

// TestZK_ClassicalOpsEnabled proves every other classical verifier op is
// ENABLED: it dispatches to its verifier (failing only on the deliberately
// minimal input here) and is never short-circuited by a PQ / policy refusal.
// A regression that re-introduces a strict-PQ gate refusing these ops — or
// that lets the fflonk disable bleed into a sibling op — is caught here.
func TestZK_ClassicalOpsEnabled(t *testing.T) {
	for _, op := range classicalEnabledOps {
		input := []byte{op, 0x00, 0x00, 0x00, 0x00}
		_, _, err := ZKVerifyPrecompile.Run(
			nil, common.Address{}, ZKVerifyContractAddress, input, 10_000_000, true,
		)
		require.NotErrorIsf(t, err, ErrFflonkDisabled,
			"op 0x%02x must be enabled (not disabled like fflonk)", op)
	}
}

// TestZK_CommitmentSubmodeDiscriminator pins the single source of truth that
// verifyCommitment's dispatch uses to route a 0x22 payload: Merkle iff
// data[0]==0x01 and len>=77; everything else (including a too-short 0x01) is
// the Pedersen opening.
func TestZK_CommitmentSubmodeDiscriminator(t *testing.T) {
	merkle := make([]byte, 96)
	merkle[0] = 0x01
	require.True(t, isMerkleCommitment(merkle))

	ped := make([]byte, 96)
	ped[0] = 0x02
	require.False(t, isMerkleCommitment(ped))

	// data[0]==0x01 but too short (<77) is NOT Merkle ⇒ Pedersen (fail-closed).
	short := make([]byte, 40)
	short[0] = 0x01
	require.False(t, isMerkleCommitment(short))
}
