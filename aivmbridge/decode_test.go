// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// decode_test.go — wire decode hardening for receipts, proofs, and the verify
// calldata frame. A malformed object must be REJECTED (never mis-decoded into a value
// that could pass verification). Also covers the merkle edge cases (single-leaf tree,
// over-wide index, over-deep path).

package aivmbridge

import (
	"testing"

	"github.com/luxfi/geth/common"
)

func TestDecodeReceipt_RejectsBadLength(t *testing.T) {
	good := EncodeReceipt(fixtureReceipt())
	if _, err := DecodeReceipt(good[:len(good)-1]); err != ErrReceiptDecode {
		t.Fatalf("short: err = %v, want ErrReceiptDecode", err)
	}
	if _, err := DecodeReceipt(append(good, 0x00)); err != ErrReceiptDecode {
		t.Fatalf("long: err = %v, want ErrReceiptDecode", err)
	}
	if _, err := DecodeReceipt(nil); err != ErrReceiptDecode {
		t.Fatalf("nil: err = %v, want ErrReceiptDecode", err)
	}
}

func TestDecodeReceipt_RejectsBadVersion(t *testing.T) {
	r := fixtureReceipt()
	r.Version = 999
	enc := EncodeReceipt(r)
	if _, err := DecodeReceipt(enc); err != ErrReceiptDecode {
		t.Fatalf("err = %v, want ErrReceiptDecode (bad version)", err)
	}
}

func TestDecodeProof_RejectsTruncated(t *testing.T) {
	if _, err := DecodeProof(make([]byte, 41)); err != ErrProofDecode {
		t.Fatalf("err = %v, want ErrProofDecode (below header)", err)
	}
}

func TestDecodeProof_RejectsLengthMismatch(t *testing.T) {
	// Declare pathLen=2 but supply only 1 node worth of trailing bytes.
	b := make([]byte, 42+32)
	b[41] = 2 // pathLen = 2
	if _, err := DecodeProof(b); err != ErrProofDecode {
		t.Fatalf("err = %v, want ErrProofDecode (truncated path)", err)
	}
	// Trailing junk past a correct path.
	b2 := make([]byte, 42+32+1)
	b2[41] = 1
	if _, err := DecodeProof(b2); err != ErrProofDecode {
		t.Fatalf("err = %v, want ErrProofDecode (trailing junk)", err)
	}
}

func TestDecodeProof_RejectsOverDeep(t *testing.T) {
	// pathLen > MaxProofDepth.
	depth := MaxProofDepth + 1
	b := make([]byte, 42+depth*32)
	b[40] = byte(depth >> 8)
	b[41] = byte(depth)
	if _, err := DecodeProof(b); err != ErrProofDecode {
		t.Fatalf("err = %v, want ErrProofDecode (over-deep path)", err)
	}
}

func TestMerkle_SingleLeaf(t *testing.T) {
	leaf := h32(0xAB)
	// A depth-0 proof: root == leaf, index 0, empty path.
	p := AInferenceProof{ReceiptRoot: leaf, Path: nil, Index: 0}
	if !VerifyMerkle(leaf, p) {
		t.Fatal("single-leaf proof should verify")
	}
	// Non-zero index on a depth-0 tree must fail.
	p.Index = 1
	if VerifyMerkle(leaf, p) {
		t.Fatal("depth-0 tree with index!=0 must fail")
	}
}

func TestMerkle_OverWideIndex(t *testing.T) {
	leaves := [][32]byte{h32(1), h32(2), h32(3), h32(4)}
	tree := buildMerkleTree(leaves)
	p := tree.proof(1) // depth 2, valid index 1
	// buildMerkleTree leaf-hashes internally (production tree), so VerifyMerkle — a pure
	// path-folder — is given the leaf-hashed leaf, exactly as verifyInferenceReceipt does.
	leaf := leafHash(leaves[1])
	if !VerifyMerkle(leaf, p) {
		t.Fatal("valid proof should verify")
	}
	// Index with a high bit beyond the tree depth (depth=2 -> valid 0..3); set bit 2.
	bad := p
	bad.Index = 1 | (1 << 2)
	if VerifyMerkle(leaf, bad) {
		t.Fatal("over-wide index must fail (high-bit aliasing)")
	}
}

func TestVerifyFrame_RejectsBadFraming(t *testing.T) {
	f := newVerifyFixture(t)
	receipt := EncodeReceipt(f.receipt)
	proof := encodeProof(f.proof)
	good := encodeVerify(receipt, proof)

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		// Truncate the whole frame below the 4-byte selector+header.
		{"below header", good[:6], ErrInputTooShort},
		// Corrupt the declared receiptLen so total != actual.
		{"len mismatch", corruptVerifyLen(good), ErrInputOversized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gas := GasVerifyInferenceReceiptBase + 100_000
			if _, _, err := BridgePrecompile.Run(f.st, f.caller, ContractAddress, tc.in, gas, false); err != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// corruptVerifyLen bumps the declared receiptLen by 1 so the framed total no longer
// matches the actual byte length.
func corruptVerifyLen(good []byte) []byte {
	cp := append([]byte(nil), good...)
	// header is at args offset 0 (after the 4-byte selector): args[0:2] = receiptLen.
	// So in the full input, that's bytes [4:6].
	rl := uint16(cp[4])<<8 | uint16(cp[5])
	rl++
	cp[4] = byte(rl >> 8)
	cp[5] = byte(rl)
	return cp
}

func TestVerifyFrame_UnknownSelector(t *testing.T) {
	st := newMockState(common.HexToHash("0x01"))
	in := make([]byte, 4)
	putU32(in, 0xDEADBEEF)
	if _, _, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, in, 100_000, false); err == nil {
		t.Fatal("unknown selector should error")
	}
}

func TestRun_EmptyInput(t *testing.T) {
	st := newMockState(common.HexToHash("0x01"))
	if _, _, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, nil, 100_000, false); err != ErrInputTooShort {
		t.Fatalf("err = %v, want ErrInputTooShort", err)
	}
}
