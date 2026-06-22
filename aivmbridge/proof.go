// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// proof.go — the keccak merkle INCLUSION proof for a receipt under a committed
// receipt root.
//
// THE SHARED WIRE SPEC (pinned; Blue-B's chains/aivm builds the tree the same way):
//
//	AInferenceProof = { ReceiptRoot[32], Path [][32]byte, Index uint64 }
//
// Verification recomputes the root from the leaf (receipt_hash) up the Path. At each
// level, bit i of Index selects sibling order: bit==0 => leaf is the LEFT child
// (node = keccak(node || sibling)); bit==1 => leaf is the RIGHT child
// (node = keccak(sibling || node)). After consuming all Path nodes the recomputed
// node MUST equal ReceiptRoot AND all higher Index bits MUST be zero (Index must
// address a leaf within a tree of exactly len(Path) levels — reject an over-wide
// index that could otherwise alias a different position).
//
// This is a standard fixed-arity (binary) keccak merkle proof. It is deliberately
// the SAME hash (keccak256) the receipt and intent use, so the whole bridge speaks
// one hash. The C side independently recomputes the leaf from the receipt bytes
// (ReceiptHash) — the proof never carries the leaf, so a caller cannot substitute a
// leaf that differs from the receipt it submitted.

package aivmbridge

import (
	"encoding/binary"

	"github.com/luxfi/crypto"
)

// MaxProofDepth bounds the merkle path length. 2^64 leaves is the absolute ceiling
// of a uint64 index; a path deeper than 64 can never be addressed by Index and is
// rejected at decode (also caps verify gas). A real receipt tree is far shallower.
const MaxProofDepth = 64

// AInferenceProof is a keccak merkle inclusion proof: the committed root, the sibling
// path from leaf to root, and the leaf's index (its left/right turns up the tree).
type AInferenceProof struct {
	ReceiptRoot [32]byte
	Path        [][32]byte
	Index       uint64
}

// VerifyMerkle reports whether leaf is included under p.ReceiptRoot at p.Index along
// p.Path. It recomputes the root and compares; it also enforces that Index addresses
// a leaf within a tree of exactly len(Path) levels (no high-bit aliasing).
func VerifyMerkle(leaf [32]byte, p AInferenceProof) bool {
	depth := len(p.Path)
	if depth > MaxProofDepth {
		return false
	}
	// Index must fit in `depth` bits. depth==0 means a single-leaf tree: root==leaf,
	// Index must be 0. (For depth>=64, every uint64 fits, so the shift guard is
	// skipped — MaxProofDepth==64 already bounds it.)
	if depth < 64 && p.Index >= (uint64(1)<<uint(depth)) {
		return false
	}
	node := leaf
	idx := p.Index
	for _, sib := range p.Path {
		if idx&1 == 0 {
			node = hashPair(node, sib) // leaf is LEFT child
		} else {
			node = hashPair(sib, node) // leaf is RIGHT child
		}
		idx >>= 1
	}
	return node == p.ReceiptRoot
}

// hashPair returns keccak256(left || right) for an internal merkle node. This matches
// the A side's merkleNode (chains/aivm/quorum_merkle.go) byte-for-byte (luxfi/crypto
// Keccak256(l, r) concatenates l||r before hashing, identical to this 64-byte buffer).
func hashPair(left, right [32]byte) [32]byte {
	buf := make([]byte, 64)
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out
}

// leafHash is the receipt-tree LEAF derivation: keccak256(receipt_hash). It MUST match
// the A side's leafHash (chains/aivm/quorum_merkle.go:leafHash) byte-for-byte, because A
// is the PRODUCER of the receipt_root (it commits the root over leafHash(receipt_hash)
// leaves and exports inclusion proofs against that tree); C is the VERIFIER and must fold
// from the same leaf. The extra keccak over the (already-keccak) receipt_hash provides
// leaf-vs-node domain separation: a leaf preimage is 32 bytes and an internal-node
// preimage is 64 bytes, so an internal node value can never be reinterpreted as a leaf
// (second-preimage hardening). Cross-module byte-equality is asserted by
// crossmodule_test.go TestCrossModuleMerkleSeam.
func leafHash(receiptHash [32]byte) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(receiptHash[:]))
	return out
}

// DecodeProof parses the wire encoding of an AInferenceProof from the verify
// calldata's proof bytes:
//
//	[0:32]   ReceiptRoot
//	[32:40]  u64be Index
//	[40:42]  u16be pathLen
//	[42:..]  pathLen * 32 bytes of sibling nodes
//
// It REJECTS a truncated frame, a pathLen above MaxProofDepth, or trailing junk past
// the declared path (a fixed, length-checked frame — no ambiguity).
func DecodeProof(b []byte) (AInferenceProof, error) {
	const headLen = 32 + 8 + 2
	if len(b) < headLen {
		return AInferenceProof{}, ErrProofDecode
	}
	var p AInferenceProof
	copy(p.ReceiptRoot[:], b[0:32])
	p.Index = binary.BigEndian.Uint64(b[32:40])
	pathLen := int(binary.BigEndian.Uint16(b[40:42]))
	if pathLen > MaxProofDepth {
		return AInferenceProof{}, ErrProofDecode
	}
	want := headLen + pathLen*32
	if len(b) != want {
		// Reject both truncation and trailing junk — the proof frame is exact.
		return AInferenceProof{}, ErrProofDecode
	}
	p.Path = make([][32]byte, pathLen)
	for i := 0; i < pathLen; i++ {
		off := headLen + i*32
		copy(p.Path[i][:], b[off:off+32])
	}
	return p, nil
}
