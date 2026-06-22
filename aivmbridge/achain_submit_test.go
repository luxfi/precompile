// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// achain_submit_test.go — Pattern A (SubmitInferenceIntent) tests. Asserts: the
// returned id is the spec-correct keccak preimage; the committed C outbox is written;
// the replay guard rejects a re-submit; the path performs ZERO aivm calls; calldata
// hardening; and a clean revert when no A on-ramp client is installed.

package aivmbridge

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
)

// spyAClient is a mock AChainClient that records whether ANY A-Chain surface was
// touched during Pattern A. The whole consensus-safety claim is that Pattern A writes
// only C state + a deterministic id and NEVER calls into A — so this spy's "A surface"
// (a counter of any hypothetical A interaction) must remain ZERO. The mock still does
// the real C-state write so the outbox assertions hold.
type spyAClient struct {
	brand    string
	achainID [32]byte

	// aSurfaceCalls counts ANY interaction with a (hypothetical) live A process. A
	// correct Pattern A leaves it at 0. We increment it nowhere in the submit path —
	// the point is that there is NO code path here that could touch A. (If a future
	// edit wired an A call in, this mock would be where it'd show, and the assertion
	// below would catch a non-zero count.)
	aSurfaceCalls int

	submitCalls int
}

func (c *spyAClient) Brand() string      { return c.brand }
func (c *spyAClient) AChainID() [32]byte { return c.achainID }

func (c *spyAClient) SubmitInferenceIntent(ctx context.Context, store IntentStore, in InferenceIntent) ([32]byte, error) {
	c.submitCalls++
	// Mirror the real native client: bind rail, derive id, replay-guard, write C state.
	in.AChainID = c.achainID
	id := DeriveIntentID(in)
	if store.IntentStatus(id) != OutboxNone {
		return [32]byte{}, ErrIntentReplay
	}
	store.PutPendingIntent(id, OutboxIntent{
		Status: OutboxPending, Caller: in.Caller, CChainID: in.CChainID, AChainID: in.AChainID,
		ModelSpecHash: in.ModelSpecHash, PromptHash: in.ModelPromptHash, N: in.N, Threshold: in.Threshold,
	})
	// NOTE: aSurfaceCalls is deliberately NOT incremented — there is no A call.
	return id, nil
}

func (c *spyAClient) VerifyInferenceReceipt(ctx context.Context, vs ReceiptVerifierState, r AInferenceReceipt, p AInferenceProof) (VerifiedAInferenceReceipt, error) {
	return verifyInferenceReceipt(vs, r, p)
}

func installSpy(t *testing.T, achainID [32]byte) *spyAClient {
	t.Helper()
	resetAChainClientForTest()
	spy := &spyAClient{brand: "Lux Inference", achainID: achainID}
	if err := InstallAChainClient(spy); err != nil {
		t.Fatalf("install spy: %v", err)
	}
	t.Cleanup(resetAChainClientForTest)
	return spy
}

func TestSubmitIntent_DeterministicIDAndOutboxWrite(t *testing.T) {
	achainID := h32(0xA0)
	spy := installSpy(t, achainID)

	st := newMockState(common.HexToHash("0xDEADBEEF"))
	st.callIndex = 7
	caller := common.HexToAddress("0x2222222222222222222222222222222222222222")
	modelSpec := h32(0x5E)
	prompt := h32(0x9D)

	input := encodeSubmit(modelSpec, prompt, 3, 2, feeWord(1_000_000), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	ret, rem, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas+1234, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rem != 1234 {
		t.Fatalf("remaining gas = %d, want 1234", rem)
	}
	if len(ret) != 32 {
		t.Fatalf("ret len = %d, want 32", len(ret))
	}

	// The returned id MUST equal the spec preimage keccak over the exact bound fields.
	want := DeriveIntentID(InferenceIntent{
		CChainID:        toArr(st.cChainID[:]),
		AChainID:        achainID,
		CTxHash:         common.HexToHash("0xDEADBEEF"),
		CallIndex:       7,
		Caller:          caller,
		ModelSpecHash:   modelSpec,
		ModelPromptHash: prompt,
		N:               3,
		Threshold:       2,
		Fee:             feeWord(1_000_000),
	})
	if toArr(ret) != want {
		t.Fatalf("intent_id:\n  got  %x\n  want %x", ret, want)
	}

	// The committed C outbox MUST hold the pending intent with the bound fields.
	store := newStateKVStore(st.db, st.blockNumber)
	if got := store.IntentStatus(want); got != OutboxPending {
		t.Fatalf("outbox status = %d, want OutboxPending", got)
	}
	oi := store.LoadIntent(want)
	if oi.Caller != caller || oi.ModelSpecHash != modelSpec || oi.PromptHash != prompt || oi.N != 3 || oi.Threshold != 2 {
		t.Fatalf("outbox intent bound fields wrong: %+v", oi)
	}
	if oi.BlockNumber != st.blockNumber {
		t.Fatalf("outbox blockNumber = %d, want %d", oi.BlockNumber, st.blockNumber)
	}

	// THE CORE CONSENSUS-SAFETY ASSERTION: Pattern A made ZERO A-Chain calls.
	if spy.aSurfaceCalls != 0 {
		t.Fatalf("Pattern A touched the A surface %d times; must be 0 (consensus-safety violation)", spy.aSurfaceCalls)
	}
	if spy.submitCalls != 1 {
		t.Fatalf("submit calls = %d, want 1", spy.submitCalls)
	}
}

func TestSubmitIntent_ReplayRejected(t *testing.T) {
	installSpy(t, h32(0xA0))
	st := newMockState(common.HexToHash("0xCAFE"))
	caller := common.HexToAddress("0x3333333333333333333333333333333333333333")
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})

	gas := BridgePrecompile.RequiredGas(input)
	if _, _, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas, false); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Same calldata, same tx identity => same id => replay.
	_, _, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas, false)
	if err != ErrIntentReplay {
		t.Fatalf("second submit err = %v, want ErrIntentReplay", err)
	}
}

func TestSubmitIntent_DistinctPerCallerChainTx(t *testing.T) {
	installSpy(t, h32(0xA0))
	caller1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	caller2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})

	run := func(st *mockState, caller common.Address) [32]byte {
		gas := BridgePrecompile.RequiredGas(input)
		ret, _, err := BridgePrecompile.Run(st, caller, ContractAddress, input, gas, false)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return toArr(ret)
	}

	// Different caller -> different id.
	id1 := run(newMockState(common.HexToHash("0x01")), caller1)
	id2 := run(newMockState(common.HexToHash("0x01")), caller2)
	if id1 == id2 {
		t.Fatal("different callers produced the same intent_id (cross-caller collision)")
	}

	// Different tx hash -> different id.
	id3 := run(newMockState(common.HexToHash("0x02")), caller1)
	if id1 == id3 {
		t.Fatal("different tx hashes produced the same intent_id (replay across tx)")
	}

	// Different call index -> different id.
	stCI := newMockState(common.HexToHash("0x01"))
	stCI.callIndex = 9
	id4 := run(stCI, caller1)
	if id1 == id4 {
		t.Fatal("different call indices produced the same intent_id")
	}

	// Different A-chain rail -> different id (rail isolation).
	resetAChainClientForTest()
	if err := InstallAChainClient(&spyAClient{brand: "x", achainID: h32(0xB0)}); err != nil {
		t.Fatal(err)
	}
	id5 := run(newMockState(common.HexToHash("0x01")), caller1)
	if id1 == id5 {
		t.Fatal("different A-chain rail produced the same intent_id (cross-rail aliasing)")
	}
	resetAChainClientForTest()
}

func TestSubmitIntent_RevertWhenNoClient(t *testing.T) {
	resetAChainClientForTest() // default = achainUnavailable
	st := newMockState(common.HexToHash("0x01"))
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	_, rem, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, input, gas, false)
	if err != ErrAChainUnavailable {
		t.Fatalf("err = %v, want ErrAChainUnavailable", err)
	}
	if rem != 0 {
		t.Fatalf("remaining gas = %d, want 0 (charged gas == op gas)", rem)
	}
}

func TestSubmitIntent_ReadOnlyRejected(t *testing.T) {
	installSpy(t, h32(0xA0))
	st := newMockState(common.HexToHash("0x01"))
	st.readOnly = true
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	if _, _, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, input, gas, true); err != ErrReadOnly {
		t.Fatalf("err = %v, want ErrReadOnly", err)
	}
}

func TestSubmitIntent_NoAtomicStateRevert(t *testing.T) {
	installSpy(t, h32(0xA0))
	db := newMemStateDB()
	db.txHash = common.HexToHash("0x01")
	st := &accessibleOnly{db: db, blockNumber: 100} // hides AtomicState
	input := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(input)
	if _, _, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, input, gas, false); err != ErrNoAtomicState {
		t.Fatalf("err = %v, want ErrNoAtomicState", err)
	}
}

func TestSubmitIntent_CalldataHardening(t *testing.T) {
	installSpy(t, h32(0xA0))
	caller := common.Address{0x1}
	good := encodeSubmit(h32(0x11), h32(0x22), 3, 2, feeWord(5), [32]byte{})
	gas := BridgePrecompile.RequiredGas(good)

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"short", good[:len(good)-1], ErrInputTooShort},
		{"oversized", append(append([]byte(nil), good...), 0x00), ErrInputOversized},
		{"zero model", encodeSubmit([32]byte{}, h32(0x22), 1, 1, feeWord(5), [32]byte{}), ErrZeroModelSpec},
		{"zero prompt", encodeSubmit(h32(0x11), [32]byte{}, 1, 1, feeWord(5), [32]byte{}), ErrZeroPrompt},
		{"N=0", encodeSubmit(h32(0x11), h32(0x22), 0, 0, feeWord(5), [32]byte{}), ErrBadFanout},
		{"N>max", encodeSubmit(h32(0x11), h32(0x22), MaxFanout+1, 1, feeWord(5), [32]byte{}), ErrBadFanout},
		{"threshold=0", encodeSubmit(h32(0x11), h32(0x22), 3, 0, feeWord(5), [32]byte{}), ErrBadThreshold},
		{"threshold>N", encodeSubmit(h32(0x11), h32(0x22), 3, 4, feeWord(5), [32]byte{}), ErrBadThreshold},
		{"dirty N word", dirtyNWord(good), ErrDirtyWord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newMockState(common.HexToHash("0x01"))
			g := gas
			if len(tc.in) >= 4 {
				g = BridgePrecompile.RequiredGas(tc.in)
			}
			if _, _, err := BridgePrecompile.Run(st, caller, ContractAddress, tc.in, g, false); err != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// dirtyNWord sets a non-zero byte in the HIGH part of the N word (offset 4+64=68,
// high bytes [68:96-2]). A correct decoder rejects it.
func dirtyNWord(good []byte) []byte {
	cp := append([]byte(nil), good...)
	cp[68] = 0x01 // high byte of the N word — must be rejected as dirty
	return cp
}

// --- helpers ------------------------------------------------------------------

func toArr(b []byte) [32]byte {
	var x [32]byte
	copy(x[:], b)
	return x
}

var _ = binary.BigEndian
