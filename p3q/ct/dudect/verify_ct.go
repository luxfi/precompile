// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build p3q_verify_ct

// verify_ct.go — cgo bridge exposing the P3Q precompile structural
// gate to the C dudect harness in dudect_verify.c.
//
// CT-population framing
// ---------------------
//
// The P3Q precompile holds NO long-term secret. Wire calldata is
// PUBLIC by EVM-precompile-ABI. The CT property we test is therefore
// not confidentiality but SOUNDNESS:
//
//   * A timing oracle over magic-mismatch vs length-mismatch lets an
//     attacker probe the chain's structural pre-filter.
//   * An attacker who can distinguish accept-cycles from reject-
//     cycles on the verification dispatch can use the signal as a
//     consensus-relevant oracle over time.
//
// Concretely we measure two complementary populations:
//
//   * Class A (fixed): a single well-formed input passed through the
//     precompile gate. Welch's t-test requires identical class-A
//     samples, so we use pool[0] for every class-A draw.
//
//   * Class B (varying valid): uniformly-drawn well-formed inputs from
//     a precomputed pool. Each pool entry has the magic header and a
//     correct backend dispatch path; the byte payload of proof and
//     pub fields varies so the dispatch boundary exercises different
//     calldata content.
//
// dudect compares cycle distributions of (A) vs (B). Any timing
// difference detected by dudect under this design is a REAL
// content-dependent path in the precompile structural gate (i.e.,
// in `precompile/p3q/contract.go::Run` lines 119..190) or its cgo
// dispatch to the backend verifier.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//     -tags p3q_verify_ct \
//     -o libp3q_verify.dylib ./verify_ct.go
//
// On Linux the output extension is .so; the Makefile selects.

package main

// Force-include the ARM compat shim on AArch64 hosts so that
// dudect/src/dudect.h's unconditional <emmintrin.h>/<x86intrin.h>
// includes resolve via the shim's blocking #defines. Matches the
// Makefile behavior so `go build` and `make` agree on arm64.

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	"unsafe"

	"github.com/luxfi/geth/common"
	p3q "github.com/luxfi/precompile/p3q"
)

// Pool size: 64 valid inputs is enough to expose any per-content
// timing variation without making startup pathologically slow.
const kValidPool = 64

// Per-pool-entry input length. We use the canonical Pulsar-65
// signature byte-length-equivalent (3293 bytes for ML-DSA-65) wrapped
// in the P3Q magic header, plus a 96-byte representative public-input
// payload. This is the production hot-path width.
const (
	kProofBodyLen = 3293
	kPubLen       = 96
)

// Fixed magic header "P3Q1".
var magicHeader = []byte{0x50, 0x33, 0x51, 0x31}

// Per-input total wire size.
const kInputLen = 1 + 4 + (len("P3Q1") + kProofBodyLen) + 4 + kPubLen

var validPool [kValidPool][]byte

// buildValidInput constructs a structurally well-formed input whose
// proof field begins with the magic header. The remaining bytes are
// drawn from `randSrc` so each pool entry's content differs.
func buildValidInput(randSrc *[kProofBodyLen + kPubLen]byte) []byte {
	out := make([]byte, 0, kInputLen)
	// Version byte.
	out = append(out, 0x01)
	// proof_len (BE32): 4 (magic) + kProofBodyLen.
	plen := uint32(len(magicHeader) + kProofBodyLen)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], plen)
	out = append(out, b4[:]...)
	// Magic header + body.
	out = append(out, magicHeader...)
	out = append(out, randSrc[:kProofBodyLen]...)
	// pub_len (BE32).
	binary.BigEndian.PutUint32(b4[:], uint32(kPubLen))
	out = append(out, b4[:]...)
	// pub body.
	out = append(out, randSrc[kProofBodyLen:kProofBodyLen+kPubLen]...)
	return out
}

//export p3q_verify_ct_setup
//
// Initialise the per-startup pool of valid inputs. Returns 0 on
// success, non-zero on failure.
func p3q_verify_ct_setup() C.int {
	// Register a backend verifier that always accepts. This pins the
	// CT measurement on the precompile dispatch + backend invocation
	// itself, not on a particular verification outcome. (The CT
	// property we want must hold regardless of backend acceptance.)
	p3q.RegisterVerifier(func(byte, []byte, []byte) (bool, error) {
		return true, nil
	})

	for i := 0; i < kValidPool; i++ {
		var src [kProofBodyLen + kPubLen]byte
		if _, err := rand.Read(src[:]); err != nil {
			return 1
		}
		validPool[i] = buildValidInput(&src)
	}
	return 0
}

//export p3q_verify_ct_input_size
//
// Returns the per-sample input size for the C harness scratch buffer.
func p3q_verify_ct_input_size() C.size_t {
	return C.size_t(kInputLen)
}

//export p3q_verify_ct_pool_size
//
// Returns the number of valid inputs in the per-startup pool.
func p3q_verify_ct_pool_size() C.size_t {
	return C.size_t(kValidPool)
}

//export p3q_verify_ct_copy_pool
//
// Copies validPool[idx] into the caller-supplied dst buffer
// (kInputLen bytes). Returns 0 on success, non-zero on bounds violation.
func p3q_verify_ct_copy_pool(idx C.size_t, dst *C.uint8_t) C.int {
	i := int(idx)
	if i < 0 || i >= kValidPool || validPool[i] == nil {
		return 1
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), kInputLen)
	copy(dstSlice, validPool[i])
	return 0
}

// Static singleton — RequiredGas is a pure function of input length.
var (
	dummyCaller = common.Address{}
	supplied    = uint64(1 << 30) // far above required for kInputLen
)

//export p3q_verify_ct
//
// One dudect measurement sample.
//
// data points to kInputLen bytes of caller-controlled wire calldata.
// The cgo bridge constructs an input slice over those bytes and calls
// the P3Q precompile Run() dispatch; the return value is ignored
// (dudect measures cycles, not result).
//
// The function MUST be branchless on `data` — any data-dependent
// branch we introduce here pollutes the measurement before Run()
// even starts. We only copy data into a fresh slice and dispatch.
func p3q_verify_ct(data *C.uint8_t) {
	inputSlice := unsafe.Slice((*byte)(unsafe.Pointer(data)), kInputLen)
	input := append([]byte{}, inputSlice...)
	_, _, _ = p3q.P3QVerifyPrecompile.Run(
		nil,
		dummyCaller,
		p3q.ContractP3QVerifyAddress,
		input,
		supplied,
		true,
	)
}

// main is required for `go build -buildmode=c-shared`.
func main() {}
