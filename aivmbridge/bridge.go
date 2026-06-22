// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// bridge.go — the dispatch + ABI decode for the two A-Chain inference bridge ops.
// This is the precompile's Run() body. It owns: selector routing, gas, calldata
// hardening, sourcing the C tx identity (caller / tx hash / chain ids / call index),
// constructing the C-state store, and routing to Pattern A (submit) or Pattern B
// (verify). It NEVER calls into aivm.
//
// REVERT DISCIPLINE (geth-canonical, mirror of the inference + dex paths): an
// out-of-gas condition returns (nil, 0, err) — charged gas consumed; a decode /
// state / client error returns (nil, remainingGas, err) — only the gas already
// charged for this call is consumed, the leftover is returned. There is NO
// all-gas-burn beyond the charged amount.

package aivmbridge

import (
	"encoding/binary"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// Bridge method selectors (first 4 bytes). Chosen in the AI range, disjoint from the
// inference precompile's SelectorGenerate (0x01000000) — this is a SEPARATE precompile
// at its own address, but we keep the selector space tidy and self-documenting.
const (
	// submitInferenceIntent(bytes32 modelSpecHash, bytes32 promptHash,
	//                        uint16 n, uint16 threshold, uint256 fee, bytes32 routing)
	//   -> bytes32 intentID
	SelectorSubmitInferenceIntent uint32 = 0x10000000

	// verifyInferenceReceipt(bytes receiptBytes, bytes proofBytes)
	//   -> (bytes32 intentID, bytes32 canonicalOutputHash, uint8 status)
	SelectorVerifyInferenceReceipt uint32 = 0x11000000
)

// MaxFanout bounds N so a single intent cannot request an unbounded provider fan-out
// (defense-in-depth on calldata; the A settlement layer also bounds it).
const MaxFanout uint16 = 256

// submitIntentArgsLen is the fixed ABI frame for SubmitInferenceIntent (after the
// 4-byte selector): 6 words = 192 bytes.
//
//	[0:32]    modelSpecHash (bytes32)
//	[32:64]   promptHash    (bytes32)
//	[64:96]   n             (uint16, right-aligned)
//	[96:128]  threshold     (uint16, right-aligned)
//	[128:160] fee           (uint256)
//	[160:192] routing       (bytes32, opaque routing hint — recorded off-state, in ZAP)
const submitIntentArgsLen = 6 * 32

// runBridge is the precompile Run() body. Selector-routed; OOG-checked per op.
func runBridge(
	accessibleState contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < 4 {
		return nil, suppliedGas, ErrInputTooShort
	}
	selector := binary.BigEndian.Uint32(input[:4])
	args := input[4:]

	switch selector {
	case SelectorSubmitInferenceIntent:
		return submitIntent(accessibleState, caller, args, suppliedGas, readOnly)
	case SelectorVerifyInferenceReceipt:
		return verifyReceipt(accessibleState, args, suppliedGas, readOnly)
	default:
		return nil, suppliedGas, fmt.Errorf("aivmbridge: unknown selector %#x", selector)
	}
}

// --- Pattern A: SubmitInferenceIntent -----------------------------------------

func submitIntent(
	accessibleState contract.AccessibleState,
	caller common.Address,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Gas first (OOG burns charged gas).
	if suppliedGas < GasSubmitInferenceIntent {
		return nil, 0, fmt.Errorf("aivmbridge: out of gas: need %d have %d", GasSubmitInferenceIntent, suppliedGas)
	}
	remainingGas := suppliedGas - GasSubmitInferenceIntent

	// A write op cannot run in a static call.
	if readOnly {
		return nil, remainingGas, ErrReadOnly
	}

	// Calldata hardening: EXACT frame length (reject short AND oversized/trailing junk).
	if len(args) < submitIntentArgsLen {
		return nil, remainingGas, ErrInputTooShort
	}
	if len(args) > submitIntentArgsLen {
		return nil, remainingGas, ErrInputOversized
	}

	var in InferenceIntent
	in.Caller = caller // bound from the C tx caller (identity binding)
	copy(in.ModelSpecHash[:], args[0:32])
	copy(in.ModelPromptHash[:], args[32:64])

	n, err := readUint16Word(args[64:96])
	if err != nil {
		return nil, remainingGas, err
	}
	thr, err := readUint16Word(args[96:128])
	if err != nil {
		return nil, remainingGas, err
	}
	in.N = n
	in.Threshold = thr
	copy(in.Fee[:], args[128:160])
	// args[160:192] is the opaque routing hint — it is NOT consensus state and NOT in
	// the intent_id preimage; it travels only in the (transport-only) ZAP nudge. The
	// committed C outbox is the source of truth, so a routing hint can never affect the
	// state root. We read it for the notifier but do not store it on-state.
	var routing [32]byte
	copy(routing[:], args[160:192])

	// Commitments must be non-zero (an all-zero commitment would alias an unbound
	// request across callers/models).
	if isZero32(in.ModelSpecHash) {
		return nil, remainingGas, ErrZeroModelSpec
	}
	if isZero32(in.ModelPromptHash) {
		return nil, remainingGas, ErrZeroPrompt
	}
	// Fan-out hardening: N in [1, MaxFanout], threshold in [1, N]. A malformed fan-out
	// reverts BEFORE any intent is recorded.
	if in.N == 0 || in.N > MaxFanout {
		return nil, remainingGas, ErrBadFanout
	}
	if in.Threshold == 0 || in.Threshold > in.N {
		return nil, remainingGas, ErrBadThreshold
	}

	// Source the C tx identity for the deterministic id. The atomic capability supplies
	// the network-scoped chain ids + tx id + call index; without it the bridge cannot
	// mint a rail-scoped id and reverts (it will NOT guess a peer). This mirrors dex's
	// AtomicState requirement on its native seam.
	atomicState, ok := accessibleState.(contract.AtomicState)
	if !ok {
		return nil, remainingGas, ErrNoAtomicState
	}
	cChainID := atomicState.CChainID()
	copy(in.CChainID[:], cChainID[:])
	txID := atomicState.TxID()
	// c_tx_hash: prefer the EVM tx hash (StateDB.TxHash()); fall back to the atomic
	// TxID when the StateDB hash is zero (some harnesses only set one). Both are the
	// same logical "this C tx" identity.
	txHash := accessibleState.GetStateDB().TxHash()
	if txHash == (common.Hash{}) {
		copy(in.CTxHash[:], txID[:])
	} else {
		copy(in.CTxHash[:], txHash[:])
	}
	// Fail-secure: c_tx_hash is a load-bearing component of the deterministic id (it
	// makes the id injective per C tx). A zero value means BOTH the EVM tx hash and the
	// atomic TxID were unset — a broken host wiring under which two distinct C txs would
	// alias the same id. Reject rather than mint an unbound id (same principle as the
	// zero model/prompt/AChainID guards). In a correctly-wired C-Chain this never trips
	// (StateDB.TxHash() is always a unique non-zero value).
	if isZero32(in.CTxHash) {
		return nil, remainingGas, ErrZeroTxHash
	}
	in.CallIndex = atomicState.CallIndex()

	// The installed client (default achainUnavailable until a node wires its A on-ramp).
	client := currentAChainClient()
	// Bind the rail peer from the client (the committed C<->A peer id).
	in.AChainID = client.AChainID()

	// Construct the C-state store (the ONLY place value-class state is written), stamped
	// at the current block height.
	blockNumber := accessibleState.GetBlockContext().Number().Uint64()
	store := newStateKVStore(accessibleState.GetStateDB(), blockNumber)

	ctx := accessibleState.GetConsensusContext()
	intentID, serr := client.SubmitInferenceIntent(ctx, store, in)
	if serr != nil {
		// Clean revert (includes ErrAChainUnavailable when no local A on-ramp, and
		// ErrIntentReplay when the id was already recorded).
		return nil, remainingGas, serr
	}

	out := make([]byte, 32)
	copy(out, intentID[:])
	return out, remainingGas, nil
}

// --- Pattern B: VerifyInferenceReceipt ----------------------------------------
//
// calldata (after the 4-byte selector) is a 2-arg dynamic-bytes ABI frame, but we use
// a TIGHT fixed-header encoding for determinism (no Solidity-ABI offset ambiguity):
//
//	[0:2]     u16be receiptLen
//	[2:4]     u16be proofLen
//	[4:4+rl]  receipt bytes (canonical AInferenceReceipt encoding)
//	[..]      proof bytes   (DecodeProof wire encoding)
//
// returns 3 ABI-ish words (96 bytes):
//
//	[0:32]    intentID            (bytes32)
//	[32:64]   canonicalOutputHash (bytes32)
//	[64:96]   status              (uint8, right-aligned) — always 2 (Completed) on success
func verifyReceipt(
	accessibleState contract.AccessibleState,
	args []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Decode the framing first (cheap) so verify gas can include the proof depth, but
	// charge a minimum base before any work to bound griefing on a malformed frame.
	const headLen = 4
	if suppliedGas < GasVerifyInferenceReceiptBase {
		return nil, 0, fmt.Errorf("aivmbridge: out of gas: need %d have %d", GasVerifyInferenceReceiptBase, suppliedGas)
	}
	if readOnly {
		// Verify mutates the C outbox (marks consumed); a static call reverts. Charge
		// the base then revert (the base was affordable per the check above).
		return nil, suppliedGas - GasVerifyInferenceReceiptBase, ErrReadOnly
	}
	if len(args) < headLen {
		return nil, suppliedGas - GasVerifyInferenceReceiptBase, ErrInputTooShort
	}
	receiptLen := int(binary.BigEndian.Uint16(args[0:2]))
	proofLen := int(binary.BigEndian.Uint16(args[2:4]))
	want := headLen + receiptLen + proofLen
	if len(args) != want {
		// Reject truncation AND trailing junk — the frame is exact.
		return nil, suppliedGas - GasVerifyInferenceReceiptBase, ErrInputOversized
	}
	receiptBytes := args[headLen : headLen+receiptLen]
	proofBytes := args[headLen+receiptLen:]

	r, derr := DecodeReceipt(receiptBytes)
	if derr != nil {
		return nil, suppliedGas - GasVerifyInferenceReceiptBase, derr
	}
	p, perr := DecodeProof(proofBytes)
	if perr != nil {
		return nil, suppliedGas - GasVerifyInferenceReceiptBase, perr
	}

	// Now we know the proof depth — charge the full metered gas (base + per-node).
	gas := verifyGas(len(p.Path))
	if suppliedGas < gas {
		return nil, 0, fmt.Errorf("aivmbridge: out of gas: need %d have %d", gas, suppliedGas)
	}
	remainingGas := suppliedGas - gas

	blockNumber := accessibleState.GetBlockContext().Number().Uint64()
	vs := newStateKVStore(accessibleState.GetStateDB(), blockNumber)

	// Pure C-state verification (NO aivm query). On success it marks the intent
	// consumed and returns the verified output.
	verified, verr := verifyInferenceReceipt(vs, r, p)
	if verr != nil {
		return nil, remainingGas, verr
	}

	out := make([]byte, 96)
	copy(out[0:32], verified.IntentID[:])
	copy(out[32:64], verified.CanonicalOutputHash[:])
	out[95] = byte(verified.Status)
	return out, remainingGas, nil
}

// --- ABI word decoders (fixed-width, right-aligned, dirty-byte rejecting) ------

// readUint16Word reads a uint16 from the LOW 2 bytes of a 32-byte ABI word and
// REJECTS any non-zero byte in the high 30 bytes (a caller must not smuggle bits
// above the declared width — that is the calldata-hardening discipline).
func readUint16Word(word []byte) (uint16, error) {
	if len(word) < 32 {
		return 0, ErrInputTooShort
	}
	for i := 0; i < 30; i++ {
		if word[i] != 0 {
			return 0, ErrDirtyWord
		}
	}
	return binary.BigEndian.Uint16(word[30:32]), nil
}
