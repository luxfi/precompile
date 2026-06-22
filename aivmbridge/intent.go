// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// intent.go — the C->A inference INTENT and its deterministic id.
//
// THE SHARED WIRE SPEC (pinned byte-for-byte; Blue-B's chains/aivm importer MUST
// match; aivmbridge_wire_test.go asserts the golden vectors). intent_id is a PURE
// DETERMINISTIC FUNCTION of the calldata + the C tx identity — never of any A-Chain
// observation — so every validator executing the same C block derives the SAME id.
// That is the whole reason Pattern A is consensus-safe.
//
//	DOMAIN_INTENT = "lux/aivmbridge/intent/v1"   (raw utf8, no length prefix)
//
//	intent_id = keccak256(
//	    DOMAIN_INTENT
//	    || c_chain_id(32) || a_chain_id(32)
//	    || c_tx_hash(32)  || u32be(call_index)
//	    || caller(20)
//	    || model_spec_hash(32) || prompt_hash(32)
//	    || u16be(N) || u16be(threshold)
//	    || u256be(fee, 32)
//	)
//
// Every component is fixed width, so the concatenation is unambiguous (no
// length-prefix needed). c_chain_id / a_chain_id scope the id to exactly one C<->A
// rail (an intent minted on one network/chain pair can never alias another);
// c_tx_hash + call_index make it injective per C tx call; caller + model + prompt +
// N + threshold + fee bind the economic payload so the id cannot be reused for a
// different request.

package aivmbridge

import (
	"encoding/binary"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// DomainIntent is the keccak domain separator for intent-id derivation. Raw utf8
// bytes (no length prefix) — pinned by the shared wire spec.
const DomainIntent = "lux/aivmbridge/intent/v1"

// InferenceIntent is the full C->A inference job intent a Pattern-A call records.
// Identity (Caller) is bound from the C tx caller, so two callers requesting the
// same prompt get DISTINCT intent ids — no cross-caller collision, no replay across
// callers. The realized result settles on A under A consensus and is later verified
// on C via Pattern B; it is NEVER folded into C state synchronously.
type InferenceIntent struct {
	// CChainID is the C-Chain (this EVM chain) id — sourced from the host atomic
	// capability (AtomicState.CChainID()). Bound into the id so an intent is scoped
	// to its source chain.
	CChainID [32]byte
	// AChainID is the A-Chain (aivm) peer id the intent targets. The bridge holds it
	// as committed configuration (the on-ramp's declared peer); bound into the id so
	// an intent is scoped to exactly one C<->A rail.
	AChainID [32]byte
	// CTxHash is the originating C tx hash (StateDB.TxHash()). Durable +
	// consensus-shared, so a re-executed / reorged tx maps to the SAME intent_id
	// (idempotent) and two genuinely distinct txs get distinct ids.
	CTxHash [32]byte
	// CallIndex is this precompile invocation's index within the C tx
	// (AtomicState.CallIndex(), else 0 when the atomic capability is absent —
	// documented). Disambiguates two bridge calls in one tx.
	CallIndex uint32
	// Caller is the C tx caller — the requesting account, bound into the id so the
	// intent (and its eventual settlement) is attributable + distinct per caller.
	Caller common.Address
	// ModelSpecHash is the model identity (weight-commitment hash). ONE model
	// identity shared by C and A.
	ModelSpecHash [32]byte
	// PromptHash is the commitment to the prompt/input. The large prompt body lives
	// off-chain (the operator fetches it by hash); the hash binds the request.
	ModelPromptHash [32]byte
	// N is the number of independent provider executions requested (fan-out).
	N uint16
	// Threshold is the M of M-of-N agreement required to finalize (1 <= M <= N).
	Threshold uint16
	// Fee is the reward offered to the winning provider(s), as a 256-bit big-endian
	// value. Recorded in the committed intent; the A settlement layer pays it.
	Fee [32]byte
}

// DeriveIntentID computes the deterministic, injective intent id per the pinned
// shared wire spec (keccak256 over the fixed-width preimage above). It binds the
// FULL identity so the same intent in a re-executed/reorged tx derives the SAME id
// (idempotent), and any change to chain/tx/call/caller/model/prompt/N/threshold/fee
// derives a DISTINCT id. NO A-Chain input enters the preimage.
func DeriveIntentID(in InferenceIntent) [32]byte {
	// Preimage width: domain + 32+32 + 32+4 + 20 + 32+32 + 2+2 + 32.
	buf := make([]byte, 0, len(DomainIntent)+32+32+32+4+20+32+32+2+2+32)
	buf = append(buf, []byte(DomainIntent)...)
	buf = append(buf, in.CChainID[:]...)
	buf = append(buf, in.AChainID[:]...)
	buf = append(buf, in.CTxHash[:]...)
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], in.CallIndex)
	buf = append(buf, u4[:]...)
	buf = append(buf, in.Caller.Bytes()...) // common.Address.Bytes() is exactly 20 bytes
	buf = append(buf, in.ModelSpecHash[:]...)
	buf = append(buf, in.ModelPromptHash[:]...)
	var u2 [2]byte
	binary.BigEndian.PutUint16(u2[:], in.N)
	buf = append(buf, u2[:]...)
	binary.BigEndian.PutUint16(u2[:], in.Threshold)
	buf = append(buf, u2[:]...)
	buf = append(buf, in.Fee[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out
}
