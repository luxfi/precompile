// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// crossmodule_test.go — RED-A cross-module byte-equality proof.
//
// This is the load-bearing seam: the C side (this package, github.com/luxfi/precompile/aivmbridge)
// and the A side (the counterparty, github.com/luxfi/chains/aivm) MUST agree, BYTE FOR BYTE, on
//   (1) the intent_id keccak preimage   (DeriveIntentID   vs aivm.ComputeIntentID)
//   (2) the receipt_hash keccak preimage (ReceiptHash      vs aivm.AInferenceReceipt.Hash)
//   (3) the receipt-tree merkle construction (a root+proof aivm EXPORTS must verify under
//       the C-side Pattern-B path verifyInferenceReceipt).
//
// If any of these drift, a genuine A receipt can never settle a C intent and the bridge is
// silently dead. The two modules' own wire tests use DIFFERENT fixtures, so they have never
// actually compared bytes against each other. This test closes that gap permanently.
//
// Both modules are joined by the repo go.work, so we import BOTH here.

package aivmbridge

import (
	"encoding/hex"
	"testing"

	aivm "github.com/luxfi/chains/aivm"
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// sharedInput is ONE identical logical input expressed in both modules' parameter shapes.
// Every field is a distinct, recognizable pattern so a mis-ordered preimage is obvious.
type sharedInput struct {
	cChainID      [32]byte
	aChainID      [32]byte
	cTxHash       [32]byte
	callIndex     uint32
	caller        common.Address
	modelSpecHash [32]byte
	promptHash    [32]byte
	n             uint16
	threshold     uint16
	fee           uint64
}

// hh returns common.Hash filled with byte b (addressable, for slicing into A-side fields).
func hh(b byte) common.Hash {
	x := h32(b)
	return common.BytesToHash(x[:])
}

func crossFixture() sharedInput {
	return sharedInput{
		cChainID:      h32(0xC0),
		aChainID:      h32(0xA0),
		cTxHash:       h32(0x77),
		callIndex:     0x01020304,
		caller:        common.HexToAddress("0x1111111111111111111111111111111111111111"),
		modelSpecHash: h32(0x5E),
		promptHash:    h32(0x9D),
		n:             3,
		threshold:     2,
		fee:           1_000_000,
	}
}

// cIntent builds the C-side InferenceIntent from the shared input.
func (s sharedInput) cIntent() InferenceIntent {
	return InferenceIntent{
		CChainID:        s.cChainID,
		AChainID:        s.aChainID,
		CTxHash:         s.cTxHash,
		CallIndex:       s.callIndex,
		Caller:          s.caller,
		ModelSpecHash:   s.modelSpecHash,
		ModelPromptHash: s.promptHash,
		N:               s.n,
		Threshold:       s.threshold,
		Fee:             feeWord(s.fee),
	}
}

// aIntentArgs returns the A-side ComputeIntentID arguments from the shared input.
func (s sharedInput) aIntentArgs() (cChain, aChain, cTx common.Hash, callIdx uint32, caller common.Address, ms, ph common.Hash, n, threshold uint16, fee *uint256.Int) {
	return common.BytesToHash(s.cChainID[:]),
		common.BytesToHash(s.aChainID[:]),
		common.BytesToHash(s.cTxHash[:]),
		s.callIndex,
		s.caller,
		common.BytesToHash(s.modelSpecHash[:]),
		common.BytesToHash(s.promptHash[:]),
		s.n,
		s.threshold,
		uint256.NewInt(s.fee)
}

// TestCrossModuleIntentIDByteEquality is JOB-1 part (1): one identical logical input MUST
// derive a byte-identical intent_id on both sides.
func TestCrossModuleIntentIDByteEquality(t *testing.T) {
	s := crossFixture()

	cID := DeriveIntentID(s.cIntent())
	aID := aivm.ComputeIntentID(s.aIntentArgs())

	cHex := hex.EncodeToString(cID[:])
	aHex := hex.EncodeToString(aID.Bytes())
	if cHex != aHex {
		t.Fatalf("INTENT-ID CROSS-MODULE DRIFT:\n  C aivmbridge.DeriveIntentID = %s\n  A aivm.ComputeIntentID      = %s", cHex, aHex)
	}
	t.Logf("SHARED intent_id (C==A) = %s", cHex)
}

// crossReceipt is the fully-populated receipt for the shared input, in both shapes. The
// IntentID is the shared (C==A) intent id; every other field is a distinct pattern.
func (s sharedInput) cReceipt(intentID [32]byte) AInferenceReceipt {
	return AInferenceReceipt{
		Version:             ReceiptVersion,
		IntentID:            intentID,
		TaskID:              h32(0x7A),
		CChainID:            s.cChainID,
		AChainID:            s.aChainID,
		Requester:           s.caller,
		ModelSpecHash:       s.modelSpecHash,
		PromptHash:          s.promptHash,
		CanonicalOutputHash: h32(0x0F),
		Status:              StatusCompleted,
		N:                   s.n,
		Threshold:           s.threshold,
		WinnersRoot:         h32(0x44),
		OperatorsRoot:       h32(0x55),
		FeePaid:             feeWord(s.fee),
		SettledAtHeight:     0x0102030405060708,
	}
}

func (s sharedInput) aReceipt(intentID common.Hash) aivm.AInferenceReceipt {
	return aivm.AInferenceReceipt{
		Version:             aivm.ReceiptVersion,
		IntentID:            intentID,
		TaskID:              hh(0x7A),
		CChainID:            common.BytesToHash(s.cChainID[:]),
		AChainID:            common.BytesToHash(s.aChainID[:]),
		Requester:           s.caller,
		ModelSpecHash:       common.BytesToHash(s.modelSpecHash[:]),
		PromptHash:          common.BytesToHash(s.promptHash[:]),
		CanonicalOutputHash: hh(0x0F),
		Status:              aivm.StatusCompleted,
		N:                   s.n,
		Threshold:           s.threshold,
		WinnersRoot:         hh(0x44),
		OperatorsRoot:       hh(0x55),
		FeePaid:             uint256.NewInt(s.fee),
		SettledAtHeight:     0x0102030405060708,
	}
}

// TestCrossModuleReceiptHashByteEquality is JOB-1 part (2): the canonical receipt encoding
// AND its keccak hash MUST be byte-identical on both sides for an identical receipt.
func TestCrossModuleReceiptHashByteEquality(t *testing.T) {
	s := crossFixture()
	intentID := DeriveIntentID(s.cIntent())
	intentHash := common.BytesToHash(intentID[:])

	cR := s.cReceipt(intentID)
	aR := s.aReceipt(intentHash)

	// (2a) canonical encoding bytes must match.
	cEnc := EncodeReceipt(cR)
	aEnc := aR.Encode()
	if hex.EncodeToString(cEnc) != hex.EncodeToString(aEnc) {
		t.Fatalf("RECEIPT-ENCODING CROSS-MODULE DRIFT:\n  C EncodeReceipt = %s\n  A .Encode()     = %s",
			hex.EncodeToString(cEnc), hex.EncodeToString(aEnc))
	}
	if len(cEnc) != aivm.ReceiptEncodedLen {
		t.Fatalf("encoding length %d != aivm.ReceiptEncodedLen %d", len(cEnc), aivm.ReceiptEncodedLen)
	}

	// (2b) receipt_hash must match.
	cH := ReceiptHash(cR)
	aH := aR.Hash()
	if hex.EncodeToString(cH[:]) != hex.EncodeToString(aH.Bytes()) {
		t.Fatalf("RECEIPT-HASH CROSS-MODULE DRIFT:\n  C ReceiptHash = %s\n  A .Hash()     = %s",
			hex.EncodeToString(cH[:]), hex.EncodeToString(aH.Bytes()))
	}
	t.Logf("SHARED receipt_hash (C==A) = %s", hex.EncodeToString(cH[:]))
}

// --- JOB-1 part (3): the merkle SEAM ------------------------------------------
//
// This is the part single-module testing cannot reach. The A side EXPORTS a (receipt, proof,
// root) where the tree is built over leafHash(receipt_hash) = keccak(receipt_hash). The C side
// must verify exactly that exported triple via the full Pattern-B path. We reconstruct the A
// tree faithfully (and PROVE the reconstruction is faithful by checking aivm.VerifyReceiptProof
// accepts it), then drive the C verify.

// aLeafHash mirrors aivm.quorum_merkle.leafHash (unexported there): keccak(receipt_hash).
func aLeafHash(receiptHash common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(receiptHash.Bytes()))
}

// aMerkleNode mirrors aivm.quorum_merkle.merkleNode: keccak(l || r).
func aMerkleNode(l, r common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(l.Bytes(), r.Bytes()))
}

// aMerkleRoot mirrors aivm.quorum_merkle.merkleRoot over already-leaf-hashed leaves.
func aMerkleRoot(leaves []common.Hash) common.Hash {
	if len(leaves) == 0 {
		return common.Hash{}
	}
	level := append([]common.Hash(nil), leaves...)
	for len(level) > 1 {
		next := make([]common.Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, aMerkleNode(level[i], level[i+1]))
			} else {
				next = append(next, aMerkleNode(level[i], level[i]))
			}
		}
		level = next
	}
	return level[0]
}

// aMerkleProof mirrors aivm.quorum_merkle.merkleProof over already-leaf-hashed leaves.
func aMerkleProof(leaves []common.Hash, idx uint32) aivm.MerkleProof {
	proof := aivm.MerkleProof{Index: idx}
	level := append([]common.Hash(nil), leaves...)
	i := int(idx)
	for len(level) > 1 {
		var sib common.Hash
		if i%2 == 0 {
			if i+1 < len(level) {
				sib = level[i+1]
			} else {
				sib = level[i]
			}
		} else {
			sib = level[i-1]
		}
		proof.Siblings = append(proof.Siblings, sib)
		next := make([]common.Hash, 0, (len(level)+1)/2)
		for j := 0; j < len(level); j += 2 {
			if j+1 < len(level) {
				next = append(next, aMerkleNode(level[j], level[j+1]))
			} else {
				next = append(next, aMerkleNode(level[j], level[j]))
			}
		}
		level = next
		i /= 2
	}
	return proof
}

// TestCrossModuleMerkleSeam is JOB-1 part (3): an A-exported receipt_root + proof MUST verify
// under the C-side Pattern-B path. This is the one that exposes the leaf-hash drift.
func TestCrossModuleMerkleSeam(t *testing.T) {
	s := crossFixture()
	intentID := DeriveIntentID(s.cIntent())
	intentHash := common.BytesToHash(intentID[:])

	// A side mints the receipt for the settled intent (same input → byte-identical to C's).
	aR := s.aReceipt(intentHash)
	aReceiptHash := aR.Hash()

	// A builds a receipt tree. Put our receipt at index 2 in a 5-leaf tree (a realistic
	// settlement order) so the proof actually has a non-trivial path.
	rawLeaves := []common.Hash{
		hh(0x01),
		hh(0x02),
		aReceiptHash, // our receipt
		hh(0x04),
		hh(0x05),
	}
	const ourIdx = 2

	// A's committed tree is over LEAF-HASHED values (this is what export.go does).
	aLeaves := make([]common.Hash, len(rawLeaves))
	for i, lh := range rawLeaves {
		aLeaves[i] = aLeafHash(lh)
	}
	aRoot := aMerkleRoot(aLeaves)
	aProof := aMerkleProof(aLeaves, ourIdx)

	// FAITHFULNESS CHECK: prove our reconstruction equals the real A construction by asking
	// the REAL aivm verifier to accept it. If this fails, the test reconstruction is wrong
	// (not the bridge); guard against that so the seam result below is trustworthy.
	if !aivm.VerifyReceiptProof(aReceiptHash, aProof, aRoot) {
		t.Fatalf("test reconstruction of the A tree is not faithful: aivm.VerifyReceiptProof rejected our own root+proof")
	}
	t.Logf("A-side committed receipt_root = %s (aivm.VerifyReceiptProof accepts)", aRoot.Hex())

	// Now drive the FULL C Pattern-B path against the A-exported (root, receipt, proof).
	// Set up C state: a matching pending intent + the A root committed.
	db := newMemStateDB()
	store := newStateKVStore(db, 100)
	store.PutPendingIntent(intentID, OutboxIntent{
		Status:        OutboxPending,
		Caller:        s.caller,
		CChainID:      s.cChainID,
		AChainID:      s.aChainID,
		ModelSpecHash: s.modelSpecHash,
		PromptHash:    s.promptHash,
		N:             s.n,
		Threshold:     s.threshold,
	})
	var rootArr [32]byte
	copy(rootArr[:], aRoot.Bytes())
	CommitReceiptRoot(db, rootArr, 100)

	// Translate the A proof into the C proof wire shape (same root, same index, same sibling
	// path — only the struct field names differ; the BYTES are identical).
	cProof := AInferenceProof{ReceiptRoot: rootArr, Index: uint64(ourIdx)}
	for _, sib := range aProof.Siblings {
		var n [32]byte
		copy(n[:], sib.Bytes())
		cProof.Path = append(cProof.Path, n)
	}

	cR := s.cReceipt(intentID)

	verified, err := verifyInferenceReceipt(store, cR, cProof)
	if err != nil {
		t.Fatalf("C Pattern-B REJECTED a genuine A-exported receipt+proof under the A-committed root: %v\n"+
			"  → the bridge cannot settle any real A receipt (merkle leaf-hash drift between A export.go and C verify.go)", err)
	}
	if verified.IntentID != intentID {
		t.Fatalf("verified intent id mismatch: got %x want %x", verified.IntentID, intentID)
	}
	if verified.CanonicalOutputHash != h32(0x0F) {
		t.Fatalf("verified output mismatch")
	}
	t.Logf("SEAM OK: A-exported receipt verifies under the C Pattern-B path")
}
