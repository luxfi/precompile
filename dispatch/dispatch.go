// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dispatch is the single, canonical authority for GPU-batch-versus-CPU
// dispatch of the precompile crypto/PQ/ZK/curve primitives. It wraps the latest
// accelerated substrate — luxfi/accel (the batch kernel dispatch library) over
// luxfi/gpu (the libluxgpu bindings) — behind ONE policy surface, so no family
// carries its own ad-hoc cgo or its own "should we use the GPU?" decision.
//
// The invariant, and the reason this package is separate from contract:
//
//   - A GPU batch kernel may back a precompile ONLY when a parity test in this
//     package proves it byte-equal to that precompile's CPU oracle. Consensus
//     determinism requires that GPU-equipped and CPU-only validators return the
//     byte-identical verdict on every input, including adversarial ones. Until a
//     kernel is proven byte-equal, the CPU oracle is the single source of truth.
//
//   - Every precompile is, at the EVM call boundary, a batch-of-1 (one Run() per
//     call). n=1 is always below MinBatch, so a precompile always resolves to its
//     CPU oracle regardless of what kernels exist. The GPU path only earns its
//     dispatch overhead for a genuine multi-item batch (block/consensus-level
//     multi-signature or multi-hash verification), and only for a byte-equal
//     primitive.
//
//   - This package deliberately does NOT live in contract: linking libluxgpu
//     pulls the GPU substrate (and its slhdsa/dilithium host archives) into the
//     cgo link. Keeping that linkage in one opt-in package means the 54 families
//     that do not use the GPU never link the substrate and stay CPU-lean.
//
// Current state (see parity_test.go, which runs the real kernels against the CPU
// oracles): NO precompile family has a libluxgpu batch kernel that is byte-equal
// to its consensus-pinned CPU oracle — the signature families diverge by
// context-binding / host-prehash framing / partial-vs-full operation, the
// Poseidon2 kernel diverges by construction, and BLS12-381 MSM diverges by wire
// encoding. Every family therefore resolves to its CPU oracle. The parity tests
// are the executable proof of that, and the guard that flips the day accel ships
// a byte-equal, framing-matched kernel: a parity test starts passing, and wiring
// that one primitive through here becomes a local change in exactly one place.
package dispatch

import luxgpu "github.com/luxfi/gpu"

// MinBatch is the batch size below which the CPU oracle always wins: GPU
// dispatch plus host<->device copy overhead exceeds the throughput gain. It
// tracks the luxgpu substrate's own built-in ZK thresholds (Poseidon2=64,
// Merkle=128). A single EVM precompile Run() is a batch-of-1 and so is always
// served by the CPU oracle.
const MinBatch = 64

// Available reports whether the accelerated luxgpu substrate is present and
// usable on this host. It is the one place a batch caller asks "is the GPU path
// even worth considering?" before assembling a batch; the answer never changes
// the verdict, only the path taken to it. Note the substrate ZK kernels can be
// live (this returns true) while accel's higher-level session backend registers
// none — the two are checked independently, and the parity gate makes the
// verdict backend-invariant regardless.
func Available() bool { return luxgpu.ZKGPUAvailable() }

// Backend names the active luxgpu backend (metal/cuda/cpu) for diagnostics and
// benchmarks. It carries no consensus meaning — the verdict is backend-invariant
// by the parity gate above.
func Backend() string { return luxgpu.ZKGetBackend() }
