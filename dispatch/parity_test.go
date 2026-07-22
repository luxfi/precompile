// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dispatch

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	acrypto "github.com/luxfi/accel/ops/crypto"
	luxgpu "github.com/luxfi/gpu"
)

// The tests below are the executable proof behind package dispatch's invariant:
// they run the real libluxgpu batch kernels against the precompiles' CPU oracles
// and assert the current byte-level relationship. Each "…StaysCPU" test asserts
// that the GPU kernel is NOT yet byte-equal to the pinned CPU oracle — the
// reason the corresponding family resolves to CPU. If accel ever ships a kernel
// that matches, that test fails; the failure is the signal to wire that one
// primitive through this package (and to promote its check to a positive parity
// assertion). This keeps the wiring decision in one place, backed by facts, not
// by prose scattered across the family packages.

func eccCfg() ecc.MultiExpConfig { return ecc.MultiExpConfig{} }

func requireGPU(t *testing.T) {
	t.Helper()
	if !Available() {
		t.Skip("no accelerated backend on this host; GPU parity is a no-op")
	}
	t.Logf("accel backend: %s", Backend())
}

// TestPoseidon2StaysCPU pins why the poseidon precompile (0x05) does not use the
// libluxgpu Poseidon2 kernel: the precompile hashes via gnark's BN254 Poseidon2
// Merkle-Damgard construction, while lux_gpu_poseidon2 is a bare 2-to-1
// compression with different round framing. For the same field pair the two
// disagree byte-for-byte, so wiring the kernel would split consensus.
func TestPoseidon2StaysCPU(t *testing.T) {
	requireGPU(t)

	var l, r fr.Element
	l.SetUint64(1)
	r.SetUint64(2)

	// CPU oracle: exactly what poseidon.hashPair computes.
	h := poseidon2.NewMerkleDamgardHasher()
	lb := l.Bytes()
	rb := r.Bytes()
	h.Write(lb[:])
	h.Write(rb[:])
	cpu := h.Sum(nil)

	// GPU kernel: 2-to-1 compression over the canonical field limbs.
	lf := luxgpu.Fr256{l.Bits()[0], l.Bits()[1], l.Bits()[2], l.Bits()[3]}
	rf := luxgpu.Fr256{r.Bits()[0], r.Bits()[1], r.Bits()[2], r.Bits()[3]}
	out, err := luxgpu.Poseidon2Hash([]luxgpu.Fr256{lf}, []luxgpu.Fr256{rf})
	if err != nil {
		t.Skipf("poseidon2 kernel unavailable: %v", err)
	}
	gpu := make([]byte, 32)
	for i := 0; i < 4; i++ {
		v := out[0][3-i]
		for j := 0; j < 8; j++ {
			gpu[i*8+j] = byte(v >> (8 * (7 - j)))
		}
	}

	if bytes.Equal(cpu, gpu) {
		t.Fatalf("lux_gpu_poseidon2 is now byte-equal to the gnark Merkle-Damgard "+
			"oracle (cpu=%x) — evaluate wiring poseidon through dispatch", cpu)
	}
	t.Logf("poseidon2 diverges (expected): cpu=%x gpu=%x — precompile stays CPU", cpu, gpu)
}

// TestMSMStaysCPU pins why bls12381 G1MSM (0x0d) does not use the accel MSM
// kernel: MSM is a deterministic function, but accel's luxcpp multi-Pippenger
// wire encoding differs from gnark's EIP-2537 point/scalar encoding, so the two
// 96-byte results disagree byte-for-byte. (On this host the GPU path also
// reports the curve unsupported; the CPU multi-Pippenger oracle is opt-in behind
// the lux_crypto_native build tag.) Either way the precompile stays on gnark.
func TestMSMStaysCPU(t *testing.T) {
	requireGPU(t)

	const k = 8
	scalars := make([]blsfr.Element, k)
	points := make([]bls12381.G1Affine, k)
	scalarBytes := make([][]byte, k)
	pointBytes := make([][]byte, k)
	for i := 0; i < k; i++ {
		scalars[i].SetRandom()
		var si blsfr.Element
		si.SetRandom()
		points[i].ScalarMultiplicationBase(si.BigInt(new(big.Int)))
		sb := scalars[i].Bytes()
		scalarBytes[i] = append([]byte(nil), sb[:]...)
		pointBytes[i] = points[i].Marshal()
	}

	var jac bls12381.G1Jac
	if _, err := jac.MultiExp(points, scalars, eccCfg()); err != nil {
		t.Fatalf("gnark MultiExp: %v", err)
	}
	var aff bls12381.G1Affine
	aff.FromJacobian(&jac)
	cpu := aff.Marshal()

	gpu, err := acrypto.MSM(acrypto.CurveBLS12_381, scalarBytes, pointBytes)
	if err != nil {
		t.Skipf("accel BLS12-381 MSM unavailable on this build/host: %v", err)
	}
	if bytes.Equal(cpu, gpu) {
		t.Fatalf("accel BLS12-381 MSM is now byte-equal to gnark (cpu=%x) — "+
			"evaluate wiring bls12381 G1MSM through dispatch", cpu)
	}
	t.Logf("bls12381 MSM diverges (expected): encoding mismatch — precompile stays CPU")
}
