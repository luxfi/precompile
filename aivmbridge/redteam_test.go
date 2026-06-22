// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// redteam_test.go — RED-A consensus-safety probes that go beyond Blue-A's own suite:
//   - gas symmetry: RequiredGas(input) (what the EVM pre-charges) is ALWAYS >= the gas
//     Run actually consumes, for every well-formed AND malformed frame. A violation
//     means Run could OOG a call the EVM thought it had paid for, or (worse) charge less
//     than metered — a determinism/grief hole. (Blue-A self-flag #3.)
//   - cross-rail receipt: a receipt minted for a DIFFERENT C<->A rail, carried with a
//     valid merkle proof under a committed root, cannot settle an intent on THIS rail.
//     (Blue-A self-flag #1, end-to-end.)
//   - merkle odd-leaf duplication + high-bit index aliasing at the FULL Run() layer.

package aivmbridge

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// chargedGas runs the precompile and returns the gas it actually consumed
// (suppliedGas - remainingGas) plus the error. suppliedGas is set to RequiredGas(input)
// — exactly what the EVM deducts before calling Run — so charged>supplied is the bug we
// hunt (Run needing more than the EVM pre-charged).
func chargedGas(t *testing.T, st *mockState, caller common.Address, input []byte) (charged uint64, supplied uint64, err error) {
	t.Helper()
	supplied = BridgePrecompile.RequiredGas(input)
	_, rem, e := BridgePrecompile.Run(st, caller, ContractAddress, input, supplied, false)
	if rem > supplied {
		t.Fatalf("remaining gas %d > supplied %d (impossible)", rem, supplied)
	}
	return supplied - rem, supplied, e
}

// TestGasSymmetry_RequiredGasCoversRun asserts the EVM-charged RequiredGas always covers
// the gas Run consumes, for a battery of well-formed and crafted verify frames. The
// invariant is charged <= supplied (never OOG a pre-paid call) AND charged is
// deterministic (a pure function of the calldata).
func TestGasSymmetry_RequiredGasCoversRun(t *testing.T) {
	f := newVerifyFixture(t)

	// A well-formed valid frame (consumes the full metered verifyGas).
	validReceipt := EncodeReceipt(f.receipt)
	validProof := encodeProof(f.proof)
	valid := encodeVerify(validReceipt, validProof)

	// Crafted frames that exercise the malformed branches of BOTH RequiredGas and Run.
	craft := func(mut func(b []byte) []byte) []byte { return mut(append([]byte(nil), valid...)) }

	cases := []struct {
		name string
		in   []byte
	}{
		{"valid", valid},
		// proofLen declares more bytes than the path actually needs (proofLen !=
		// 42+pathLen*32) — RequiredGas reads pathLen from offset 40:42 and returns
		// verifyGas(pathLen); Run's DecodeProof rejects the inexact frame after charging
		// only Base. charged (Base) must be <= supplied.
		{"proofLen padded", padProof(valid, validReceipt, validProof)},
		// receiptLen/proofLen sum mismatches the actual args length → both sides take the
		// "length mismatch" branch (RequiredGas → Base, Run → ErrInputOversized@Base).
		{"trailing junk", craft(func(b []byte) []byte { return append(b, 0xAA) })},
		// truncated below the 4-byte header.
		{"below header", valid[:4+2]},
		// a dirty/huge declared pathLen beyond MaxProofDepth in the proof header.
		{"pathLen over max", overMaxPathLen(valid, validReceipt, validProof)},
		// submit frame (different selector) routed through the same gas check.
		{"submit frame", encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})},
		// unknown selector.
		{"unknown selector", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00}},
		// empty.
		{"empty", nil},
		// 3 bytes (below the 4-byte selector).
		{"three bytes", []byte{0x11, 0x00, 0x00}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh state each case so a successful "valid" consume doesn't poison reruns.
			ff := newVerifyFixture(t)
			charged, supplied, _ := chargedGas(t, ff.st, ff.caller, tc.in)
			if charged > supplied {
				t.Fatalf("GAS DESYNC: Run consumed %d but RequiredGas only pre-charged %d (EVM would under-charge / Run OOGs a paid call)", charged, supplied)
			}
			// Determinism: RequiredGas is a pure function of calldata — same input twice → same gas.
			if g2 := BridgePrecompile.RequiredGas(tc.in); g2 != supplied {
				t.Fatalf("RequiredGas non-deterministic: %d vs %d", supplied, g2)
			}
		})
	}
}

// padProof builds a verify frame whose OUTER proofLen is inflated (extra trailing bytes
// appended to the proof segment) while the proof header's pathLen stays small. This is the
// gas-desync attack shape from Blue-A self-flag #3: RequiredGas computes from the small
// header pathLen, Run rejects the inexact proof frame at DecodeProof.
func padProof(valid, receipt, proof []byte) []byte {
	padded := append(append([]byte(nil), proof...), make([]byte, 64)...) // +64 junk bytes
	return encodeVerify(receipt, padded)
}

// overMaxPathLen sets the proof header's pathLen field above MaxProofDepth.
func overMaxPathLen(valid, receipt, proof []byte) []byte {
	p := append([]byte(nil), proof...)
	// proof header pathLen is at proofBytes[40:42].
	if len(p) >= 42 {
		over := MaxProofDepth + 1
		p[40] = byte(over >> 8)
		p[41] = byte(over)
	}
	return encodeVerify(receipt, p)
}

// TestCrossRailReceiptCannotSettle is Blue-A self-flag #1 end-to-end: a receipt minted for
// a DIFFERENT C<->A rail (different AChainID), carried with a VALID merkle proof under a
// genuinely committed root, must NOT settle a pending intent on THIS rail.
func TestCrossRailReceiptCannotSettle(t *testing.T) {
	// Rail A: the intent the C side actually submitted (achainID 0xA0).
	f := newVerifyFixture(t) // installs rail 0xA0, submits an intent, commits a root

	// Forge a receipt for rail B (achainID 0xB0) but otherwise pointed at our intent id.
	railB := f.receipt
	railB.AChainID = h32(0xB0) // DIFFERENT rail
	// Give it a valid proof under a freshly committed root so it passes merkle + root and
	// reaches the bind-mismatch check (the rail binding is what must reject it).
	leaves := [][32]byte{ReceiptHash(railB), h32(0x02)}
	tree := buildMerkleTree(leaves)
	p := tree.proof(0)
	CommitReceiptRoot(f.st.db, p.ReceiptRoot, f.st.blockNumber)

	if _, err := f.run(t, railB, p); err != ErrReceiptBindMismatch {
		t.Fatalf("cross-rail receipt err = %v, want ErrReceiptBindMismatch", err)
	}
	// The intent MUST still be pending (no cross-rail settlement).
	store := newStateKVStore(f.st.db, f.st.blockNumber)
	if store.IntentStatus(f.intentID) != OutboxPending {
		t.Fatal("cross-rail receipt wrongly consumed the intent")
	}
}

// TestVerify_RejectsHighBitIndexAtRun is Blue-A self-flag #2 at the FULL Run() layer: a
// merkle Index with a bit set ABOVE the tree depth must be rejected (no high-bit aliasing
// to a different leaf position). TestMerkle_OverWideIndex covers VerifyMerkle directly;
// this drives the whole precompile so the decode + verify path is exercised together.
func TestVerify_RejectsHighBitIndexAtRun(t *testing.T) {
	f := newVerifyFixture(t) // receipt at index 2 of 5 → depth 3 path
	bad := f.proof
	// Set a bit far above the path depth (len(Path) levels address indices 0..2^depth-1).
	bad.Index = f.proof.Index | (uint64(1) << uint(len(f.proof.Path)))
	if _, err := f.run(t, f.receipt, bad); err != ErrMerkleVerify {
		t.Fatalf("high-bit index err = %v, want ErrMerkleVerify", err)
	}
	// Intent stays pending — no settlement on an aliased index.
	store := newStateKVStore(f.st.db, f.st.blockNumber)
	if store.IntentStatus(f.intentID) != OutboxPending {
		t.Fatal("high-bit index wrongly consumed the intent")
	}
}

// TestSubmit_RejectsZeroTxHash is the regression for Blue-A self-flag #4: when BOTH the
// EVM tx hash and the atomic TxID resolve to zero (a broken host wiring), two distinct C
// txs would otherwise alias the same deterministic intent id. The bridge must reject
// (ErrZeroTxHash), never mint an unbound id. (In a correctly-wired C-Chain StateDB.TxHash()
// is always a unique non-zero value, so this never trips in production.)
func TestSubmit_RejectsZeroTxHash(t *testing.T) {
	installSpy(t, h32(0xA0))
	// mockState with txHash==0 (newMockState(zero)) AND txID==ids.Empty → both id sources
	// zero → the fallback yields a zero c_tx_hash.
	st := newMockState(common.Hash{}) // StateDB.TxHash() == 0
	st.txID = ids.Empty                // atomic TxID() == 0 (the fallback is also zero)

	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	_, rem, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, input, gas, false)
	if err != ErrZeroTxHash {
		t.Fatalf("err = %v, want ErrZeroTxHash", err)
	}
	// Clean revert: the op gas is charged, the remainder returned (no all-gas burn), and
	// NOTHING was written to the outbox (we reverted before the client write).
	if rem != gas-GasSubmitInferenceIntent {
		t.Fatalf("remaining gas = %d, want %d (clean revert, charged op gas only)", rem, gas-GasSubmitInferenceIntent)
	}
}

// TestSubmit_AtomicTxIDFallbackStillBinds proves the fallback is sound when only the
// atomic TxID is set (StateDB.TxHash()==0 but TxID()!=0): the id binds the TxID and two
// distinct TxIDs yield distinct ids (no collision via the fallback path).
func TestSubmit_AtomicTxIDFallbackStillBinds(t *testing.T) {
	installSpy(t, h32(0xA0))
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})

	run := func(txID ids.ID) [32]byte {
		st := newMockState(common.Hash{}) // StateDB.TxHash()==0 → fallback to TxID
		st.txID = txID
		gas := BridgePrecompile.RequiredGas(input)
		ret, _, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas, false)
		if err != nil {
			t.Fatalf("run txID=%x: %v", txID, err)
		}
		return toArr(ret)
	}
	id1 := run(ids.ID{0x01})
	id2 := run(ids.ID{0x02})
	if id1 == id2 {
		t.Fatal("distinct atomic TxIDs produced the same intent_id via the fallback (collision)")
	}
}

// TestMerkle_OddLeafDuplicationVerifies proves the C verify accepts a receipt that sits as
// the duplicated odd tail of a tree (the i+1==len → sibling-is-self case in
// buildMerkleTree / aivm.merkleRoot). A drift in the odd-leaf rule would silently fail
// genuine receipts whose index is the last of an odd level.
func TestMerkle_OddLeafDuplicationVerifies(t *testing.T) {
	f := newVerifyFixture(t)
	// Place the receipt at the LAST index of an ODD-sized level (index 2 of 3) so the
	// odd-tail duplication path is exercised at level 0.
	leaves := [][32]byte{h32(0x01), h32(0x02), ReceiptHash(f.receipt)}
	tree := buildMerkleTree(leaves)
	p := tree.proof(2)
	CommitReceiptRoot(f.st.db, p.ReceiptRoot, f.st.blockNumber)

	ret, err := f.run(t, f.receipt, p)
	if err != nil {
		t.Fatalf("odd-tail receipt should verify, got %v", err)
	}
	if toArr(ret[0:32]) != f.intentID {
		t.Fatal("odd-tail verify returned wrong intent id")
	}
}
