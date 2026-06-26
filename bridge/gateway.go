// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"encoding/binary"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"

	"github.com/luxfi/precompile/contract"
)

// BridgeGateway is the bridge completion authority. Its request lifecycle and
// signer committee live entirely in StateDB (request_state.go / committee_state.go)
// so they survive reorg/restart and revert atomically with the settling
// transaction. The struct itself holds only the supported-chain configuration
// (a deterministic mirror of the on-chain registry, NOT value state); every
// money-path method takes (state, gwAddr) and reads/writes StateDB.
//
// Completion is authorized by a ⅔-weight quorum of the state-resident committee
// over the canonical CompletionDigest — never by a length check, never against a
// key supplied in calldata.
type BridgeGateway struct {
	// SupportedChains is the chain-id set this gateway recognizes. It is benign
	// configuration (no balances, no requests) seeded from the registry; it is
	// NOT the fund-bearing request state, which lives in StateDB.
	SupportedChains map[uint32]bool
}

// completionDomain domain-separates the completion digest and is bound as the
// ML-DSA-65 signing context. A signature over a completion can never be replayed
// as any other message kind, and a classical recover is bound to the same bytes.
const completionDomain = "lux.bridge.complete.v1"

// NewBridgeGateway builds a gateway with the default ecosystem chain set.
func NewBridgeGateway() *BridgeGateway {
	gw := &BridgeGateway{SupportedChains: make(map[uint32]bool)}
	gw.initSupportedChains()
	return gw
}

// NewBridgeGatewayWithRegistry builds a gateway whose supported-chain set mirrors
// r at construction time. Used in tests and on networks that pin the set to a
// curated registry rather than the hard-coded defaults.
func NewBridgeGatewayWithRegistry(r Registry) *BridgeGateway {
	gw := &BridgeGateway{SupportedChains: make(map[uint32]bool)}
	for _, c := range r.All() {
		gw.SupportedChains[uint32(c.ID)] = true
	}
	return gw
}

// Supports reports whether id is in the gateway's supported-chain set.
func (gw *BridgeGateway) Supports(id uint32) bool {
	return gw.SupportedChains[id]
}

func (gw *BridgeGateway) initSupportedChains() {
	for _, id := range []uint32{
		ChainLux, ChainLuxTest,
		ChainHanzo, ChainHanzoTest,
		ChainZoo, ChainZooTest,
		ChainSPC, ChainSPCTest,
		ChainEthereum, ChainArbitrum, ChainOptimism,
		ChainBase, ChainPolygon, ChainBSC, ChainAvalanche,
	} {
		gw.SupportedChains[id] = true
	}
}

// CompletionDigest is the canonical 32-byte message the MPC committee attests to
// authorize a bridge completion. It binds the LIVE chain identity (networkID +
// chainID) and EVERY value-affecting field of the request, so a digest is valid
// on exactly one chain and for exactly one request — no cross-chain, cross-asset,
// or amount substitution is possible. The off-chain signer MUST produce the same
// 207-byte preimage:
//
//	"lux.bridge.complete.v1"(22) | version=0x01(1) |
//	networkID(u32) | chainID(32) |
//	srcNetwork(u32) | srcChain(u32) | destNetwork(u32) | destChain(u32) |
//	requestID(32) | sourceAsset(32) | amount(uint256 BE 32) |
//	recipient(20) | deadline(u64) | nonce(u64)
//
// sourceAsset uses the SAME canonical asset id the DEX uses (the token address
// left-padded into 32 bytes; native == all-zero), so it agrees with the signed
// intent's SourceAsset.
func CompletionDigest(networkID uint32, chainID ids.ID, r *BridgeRequest) [32]byte {
	buf := make([]byte, 0, 207)
	buf = append(buf, []byte(completionDomain)...)
	buf = append(buf, 0x01)
	buf = appendU32(buf, networkID)
	buf = append(buf, chainID[:]...)
	buf = appendU32(buf, r.SourceNetwork)
	buf = appendU32(buf, r.SourceChain)
	buf = appendU32(buf, r.DestNetwork)
	buf = appendU32(buf, r.DestChain)
	buf = append(buf, r.ID[:]...)
	buf = append(buf, sourceAssetID(r.Token)...)
	buf = appendAmount32(buf, r.Amount)
	buf = append(buf, r.Recipient.Bytes()...)
	buf = appendU64(buf, r.Deadline)
	buf = appendU64(buf, r.Nonce)

	var d [32]byte
	copy(d[:], crypto.Keccak256(buf))
	return d
}

// RecordInbound records a quorum-attested inbound as Pending. The committee must
// sign the request's CompletionDigest, so an attacker cannot plant a fake Pending
// record: the same quorum that authorizes completion authorizes recording. It
// refuses to overwrite an existing record (a recorded id is immutable) and
// validates the amount fits the storage word.
//
// This is the host/relayer INGEST path (B-Chain MPC -> StateDB), the analog of
// SeedCommittee/SeedGovernance; the DEX consumer never calls it.
func RecordInbound(
	state contract.StateDB,
	gwAddr common.Address,
	networkID uint32,
	chainID ids.ID,
	r *BridgeRequest,
	signers []SignerSig,
) error {
	if r == nil || r.Amount == nil || r.Amount.Sign() <= 0 || r.Amount.BitLen() > 256 {
		return ErrInvalidRequest
	}
	if _, err := ReadRequest(state, gwAddr, r.ID); err == nil {
		return ErrRequestExists
	} else if err != ErrRequestNotFound {
		return err
	}
	if err := VerifyCompletionQuorum(state, gwAddr, CompletionDigest(networkID, chainID, r), signers); err != nil {
		return err
	}
	r.CreatedAt = 0 // createdAt is set by an attested record path if needed; not on the verify path
	writeRequest(state, gwAddr, r)
	return nil
}

// GetRequest returns the StateDB-resident request, or ErrRequestNotFound when no
// record exists at requestID.
func (gw *BridgeGateway) GetRequest(state contract.StateDB, gwAddr common.Address, requestID [32]byte) (*BridgeRequest, error) {
	return ReadRequest(state, gwAddr, requestID)
}

// VerifyCompletion runs every completion precondition WITHOUT mutating state: the
// request exists and is Pending, the block time is within the deadline, and a
// ⅔-weight quorum of the state-resident committee signed the CompletionDigest. It
// is the read-only half of CompleteBridge, exposed so a composite (the DEX intent
// settlement) can verify a proof up front, perform its atomic swap, and consume
// the request via CompleteBridge ONLY on success — one verification, one place.
func (gw *BridgeGateway) VerifyCompletion(
	state contract.StateDB,
	gwAddr common.Address,
	networkID uint32,
	chainID ids.ID,
	blockTime uint64,
	requestID [32]byte,
	signers []SignerSig,
) error {
	r, err := ReadRequest(state, gwAddr, requestID)
	if err != nil {
		return err
	}
	if r.Status != StatusPending {
		return ErrRequestAlreadyDone
	}
	if r.Deadline > 0 && blockTime > r.Deadline {
		return ErrRequestExpired
	}
	return VerifyCompletionQuorum(state, gwAddr, CompletionDigest(networkID, chainID, r), signers)
}

// CompleteBridge consumes a Pending request: it re-runs the full VerifyCompletion
// check (DRY) and then, only on success, flips the on-state status Pending ->
// Completed. This status flip is the LAST mutation of a settling transaction, so
// a StateDB revert un-flips it — the request is consumed IFF the surrounding work
// committed.
func (gw *BridgeGateway) CompleteBridge(
	state contract.StateDB,
	gwAddr common.Address,
	networkID uint32,
	chainID ids.ID,
	blockTime uint64,
	requestID [32]byte,
	signers []SignerSig,
) error {
	if err := gw.VerifyCompletion(state, gwAddr, networkID, chainID, blockTime, requestID, signers); err != nil {
		return err
	}
	setRequestStatus(state, gwAddr, requestID, StatusCompleted, blockTime)
	return nil
}

// Refund releases a Pending request, flipping Pending -> Refunded. A consumed
// (terminal) request can never be refunded. Expiry is judged by blockTime — never
// wall clock — so every validator agrees.
//
// Authorization (closes red finding 9): the inbound's recipient (its owner) may
// refund ANYTIME; anyone else may refund only AFTER a real deadline has passed
// (deadline > 0 && blockTime > deadline). So a third party can never refund a
// no-deadline inbound out from under a quorum-valid completion (the deadline==0
// liveness grief), while the owner's recovery path stays immediate — one rule,
// both needs met.
func (gw *BridgeGateway) Refund(
	state contract.StateDB,
	gwAddr common.Address,
	caller common.Address,
	blockTime uint64,
	requestID [32]byte,
) error {
	r, err := ReadRequest(state, gwAddr, requestID)
	if err != nil {
		return err
	}
	if r.Status != StatusPending {
		return ErrRequestAlreadyDone
	}
	if caller != r.Recipient && (r.Deadline == 0 || blockTime <= r.Deadline) {
		return ErrRequestNotExpired
	}
	setRequestStatus(state, gwAddr, requestID, StatusRefunded, 0)
	return nil
}

// sourceAssetID maps a token address to the DEX canonical 32-byte asset id (the
// 20-byte address left-padded with 12 zero bytes; native == all-zero). It MUST
// match dex.assetID so the completion digest's sourceAsset equals the signed
// intent's SourceAsset.
func sourceAssetID(token common.Address) []byte {
	id := make([]byte, 32)
	copy(id[12:], token.Bytes())
	return id
}

// appendU32 / appendU64 append a big-endian fixed-width integer to the digest
// preimage; appendAmount32 appends a non-negative amount as a 32-byte big-endian
// uint256 (allocation-bounded, never panics for an in-range amount).
func appendU32(b []byte, v uint32) []byte {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	return append(b, x[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

func appendAmount32(b []byte, amount *big.Int) []byte {
	var x [32]byte
	if amount != nil && amount.Sign() > 0 {
		ab := amount.Bytes()
		if len(ab) <= 32 {
			copy(x[32-len(ab):], ab)
		} else {
			copy(x[:], ab[len(ab)-32:])
		}
	}
	return append(b, x[:]...)
}
