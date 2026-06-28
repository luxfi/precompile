// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestMLDSA_ContextBindingIsAuthoritative is the regression proof for the
// ctx-divergence accel bug. This precompile binds a non-empty FIPS-204 context
// (precompileCtx) into mu = CRH(tr || 0x00 || ctxlen || ctx || M). The deleted
// accel ML-DSA kernel verified with an EMPTY context and could not absorb
// precompileCtx, so for the SAME signature it produced a different verdict than
// the CPU path -- a CPU/GPU consensus split.
//
// A signature produced with an EMPTY context (exactly what the accel path would
// have accepted) must be REJECTED by the precompile, while the same key/message
// signed WITH precompileCtx must be ACCEPTED. That pair pins the verdict to the
// ctx-bound CPU verifier.
func TestMLDSA_ContextBindingIsAuthoritative(t *testing.T) {
	message := []byte("ml-dsa context-binding parity")

	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pk := priv.PublicKey.Bytes()

	// Signature under the precompile's bound context: must verify.
	sigBound, err := priv.SignCtx(rand.Reader, message, precompileCtx)
	require.NoError(t, err)

	// Signature under the EMPTY context (the accel/GPU framing): must be
	// rejected by the precompile, since it verifies under precompileCtx.
	sigEmptyCtx, err := priv.SignCtx(rand.Reader, message, nil)
	require.NoError(t, err)

	run := func(sig []byte) byte {
		input := createInputWithMode(ModeMLDSA65, pk, sig, message)
		gas := MLDSAVerifyPrecompile.RequiredGas(input)
		res, _, err := MLDSAVerifyPrecompile.Run(
			nil, common.Address{}, ContractMLDSAVerifyAddress, input, gas, false,
		)
		require.NoError(t, err)
		return res[31]
	}

	require.Equal(t, byte(1), run(sigBound),
		"signature under precompileCtx must verify")
	require.Equal(t, byte(0), run(sigEmptyCtx),
		"empty-context signature (the accel framing) must be REJECTED (ctx binding authoritative)")
}
