// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"encoding/binary"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/precompile/contract"
)

// committee_state.go holds the bridge completion committee as a StateDB snapshot
// under the gateway address. The completion verifier (signer.go) reads this
// snapshot and NOTHING ELSE — the committee public keys never come from calldata,
// so an attacker who controls a transaction cannot substitute their own keys.
//
// This is the StateDB analog of the registrar's governance set (registrar.go
// loadGovernance/SeedGovernance) but keyed by an epoch so a rotation writes a new
// snapshot at a new epoch and the live pointer is flipped atomically. The
// PRODUCER of new epochs is a consensus/warp-attested rotation path (out of scope
// here); the verifier is orthogonal — it only READS the current snapshot.
//
// Storage layout (all keccak-derived, Solidity-style base + integer offset):
//
//	cmteEpochSlot                 -> word: currentEpoch (u64 BE @24:32)
//	baseE = keccak("lux.bridge.cmte" || u64BE(epoch))
//	  baseE + 0                   -> header word:
//	      totalWeight (u128 BE @0:16) | memberCount (u32 @16:20) |
//	      quorumNum   (u16 @20:22)    | quorumDen   (u16 @22:24) |
//	      epoch       (u64 @24:32)
//	  baseE + 1 + i               -> member i descriptor word:
//	      scheme (byte0) | weight (u64 @1:9) | pkWords (u16 @9:11) |
//	      keyID  (20 @12:32)
//	pkBase = keccak("lux.bridge.cmte.pk" || u64BE(epoch) || u16BE(i))
//	  pkBase + 0 .. + (pkWords-1) -> ML-DSA-65 public key blob (1952 bytes = 61 words)
//
// secp256k1 members store NO pubkey blob (keyID is the EVM address; the key is
// recovered from the signature). ML-DSA-65 members store the full 1952-byte key.
var (
	cmteNS      = []byte("lux.bridge.cmte")
	cmteEpochNS = []byte("lux.bridge.cmte.epoch")
	cmtePKNS    = []byte("lux.bridge.cmte.pk")
)

// cmteEpochSlot is the fixed slot holding the live committee epoch.
func cmteEpochSlot() common.Hash {
	return common.BytesToHash(crypto.Keccak256(cmteEpochNS))
}

// cmteBaseE is the base slot for the committee snapshot at epoch.
func cmteBaseE(epoch uint64) common.Hash {
	return common.BytesToHash(crypto.Keccak256(cmteNS, u64BE(epoch)))
}

// cmtePKBase is the base slot for member i's ML-DSA-65 public key blob at epoch.
func cmtePKBase(epoch uint64, idx uint16) common.Hash {
	return common.BytesToHash(crypto.Keccak256(cmtePKNS, u64BE(epoch), u16BE(idx)))
}

// addOffset returns base + n as a 256-bit big-endian integer (Solidity slot
// arithmetic), wrapping mod 2^256. Allocation-free, carry-propagating; used to
// walk the contiguous slots of a committee snapshot or a request record.
func addOffset(base common.Hash, n uint64) common.Hash {
	out := base
	for i := 31; i >= 0 && n > 0; i-- {
		sum := uint64(out[i]) + (n & 0xff)
		out[i] = byte(sum)
		n = (n >> 8) + (sum >> 8)
	}
	return out
}

func u64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func u16BE(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// committeeHeader is the decoded committee snapshot header.
type committeeHeader struct {
	totalWeight *big.Int
	memberCount uint32
	quorumNum   uint16
	quorumDen   uint16
	epoch       uint64
	baseE       common.Hash
}

// SeedCommittee writes the completion committee snapshot to state at gwAddr for
// the given epoch and flips the live-epoch pointer to it. It mirrors
// SeedGovernance: intended to run once at genesis from the configurator, though
// the same write path is what a consensus/warp-attested rotation would use to
// publish a new epoch.
//
// It REJECTS a committee whose total weight is zero (and any zero-weight member,
// any empty set, and any malformed quorum fraction) so loadCommitteeHeader can
// treat totalWeight==0 as "unset" and fail closed — a seeded committee always has
// a positive total weight, so the verifier can never be tricked into a threshold
// of one.
func SeedCommittee(
	state contract.StateDB,
	gwAddr common.Address,
	epoch uint64,
	members []CommitteeMember,
	quorumNum, quorumDen uint16,
) error {
	if len(members) == 0 || len(members) > maxCommitteeMembers {
		return ErrInvalidCommittee
	}
	if quorumNum == 0 || quorumDen == 0 || quorumNum > quorumDen {
		return ErrInvalidCommittee
	}

	total := new(big.Int)
	seenKey := make(map[[20]byte]bool, len(members))
	for i := range members {
		m := &members[i]
		if m.Weight == 0 {
			return ErrInvalidCommittee
		}
		// KeyID must be unique across the committee. Quorum is ⅔ of distinct
		// KEYS; a duplicate KeyID would let one physical key sign at multiple
		// indices and reach threshold alone (value fabrication via a mis-seed).
		if seenKey[m.KeyID] {
			return ErrInvalidCommittee
		}
		seenKey[m.KeyID] = true
		switch m.Scheme {
		case SchemeSecp256k1:
			// keyID is the EVM address; no pubkey blob.
		case SchemeMLDSA65:
			if len(m.PubKey) != mldsa.MLDSA65PublicKeySize {
				return ErrInvalidCommittee
			}
		default:
			return ErrInvalidScheme
		}
		total.Add(total, new(big.Int).SetUint64(m.Weight))
	}
	if total.Sign() == 0 { // defensive: every weight was > 0, so this cannot trip
		return ErrInvalidCommittee
	}

	baseE := cmteBaseE(epoch)

	var hdr common.Hash
	total.FillBytes(hdr[0:16]) // u128 BE; total < 2^128 (<= maxMembers * maxU64)
	binary.BigEndian.PutUint32(hdr[16:20], uint32(len(members)))
	binary.BigEndian.PutUint16(hdr[20:22], quorumNum)
	binary.BigEndian.PutUint16(hdr[22:24], quorumDen)
	binary.BigEndian.PutUint64(hdr[24:32], epoch)
	state.SetState(gwAddr, baseE, hdr)

	for i := range members {
		m := &members[i]
		var d common.Hash
		d[0] = m.Scheme
		binary.BigEndian.PutUint64(d[1:9], m.Weight)
		if m.Scheme == SchemeMLDSA65 {
			binary.BigEndian.PutUint16(d[9:11], uint16((len(m.PubKey)+31)/32))
		}
		copy(d[12:32], m.KeyID[:])
		state.SetState(gwAddr, addOffset(baseE, uint64(1+i)), d)

		if m.Scheme == SchemeMLDSA65 {
			writePubKeyBlob(state, gwAddr, epoch, uint16(i), m.PubKey)
		}
	}

	var ep common.Hash
	binary.BigEndian.PutUint64(ep[24:32], epoch)
	state.SetState(gwAddr, cmteEpochSlot(), ep)
	return nil
}

// maxCommitteeMembers bounds the set so member indices fit a uint16 (SignerSig.Index).
const maxCommitteeMembers = 1<<16 - 1

// loadCommitteeHeader reads the live committee snapshot header, FAILING CLOSED
// with ErrCommitteeUnset when no committee is set (the epoch pointer or the
// header is absent, i.e. totalWeight==0 or memberCount==0). It NEVER returns a
// usable header with zero weight — so the verifier can never fall through to a
// threshold of one.
func loadCommitteeHeader(state contract.StateDB, gwAddr common.Address) (committeeHeader, error) {
	ep := state.GetState(gwAddr, cmteEpochSlot())
	epoch := binary.BigEndian.Uint64(ep[24:32])
	baseE := cmteBaseE(epoch)
	w := state.GetState(gwAddr, baseE)

	h := committeeHeader{
		totalWeight: new(big.Int).SetBytes(w[0:16]),
		memberCount: binary.BigEndian.Uint32(w[16:20]),
		quorumNum:   binary.BigEndian.Uint16(w[20:22]),
		quorumDen:   binary.BigEndian.Uint16(w[22:24]),
		epoch:       binary.BigEndian.Uint64(w[24:32]),
		baseE:       baseE,
	}
	if h.totalWeight.Sign() == 0 || h.memberCount == 0 || h.quorumNum == 0 || h.quorumDen == 0 {
		return committeeHeader{}, ErrCommitteeUnset
	}
	return h, nil
}

// loadMember reads member idx of the snapshot described by h, including its
// ML-DSA-65 public key blob from STATE when the member is post-quantum.
func loadMember(state contract.StateDB, gwAddr common.Address, h committeeHeader, idx uint16) (CommitteeMember, error) {
	if uint32(idx) >= h.memberCount {
		return CommitteeMember{}, ErrSignerIndexRange
	}
	d := state.GetState(gwAddr, addOffset(h.baseE, uint64(1+idx)))
	m := CommitteeMember{
		Scheme: d[0],
		Weight: binary.BigEndian.Uint64(d[1:9]),
	}
	copy(m.KeyID[:], d[12:32])
	if m.Scheme == SchemeMLDSA65 {
		m.PubKey = loadPubKeyBlob(state, gwAddr, h.epoch, idx, binary.BigEndian.Uint16(d[9:11]))
	}
	return m, nil
}

// writePubKeyBlob stores an ML-DSA-65 public key across ceil(len/32) words.
func writePubKeyBlob(state contract.StateDB, gwAddr common.Address, epoch uint64, idx uint16, pk []byte) {
	base := cmtePKBase(epoch, idx)
	for w := 0; w*32 < len(pk); w++ {
		var word common.Hash
		copy(word[:], pk[w*32:]) // copy clamps to the available tail for the last word
		state.SetState(gwAddr, addOffset(base, uint64(w)), word)
	}
}

// loadPubKeyBlob reassembles an ML-DSA-65 public key from pkWords state words and
// trims to the exact key size so the verifier receives a well-formed key.
func loadPubKeyBlob(state contract.StateDB, gwAddr common.Address, epoch uint64, idx uint16, pkWords uint16) []byte {
	base := cmtePKBase(epoch, idx)
	out := make([]byte, int(pkWords)*32)
	for w := 0; w < int(pkWords); w++ {
		word := state.GetState(gwAddr, addOffset(base, uint64(w)))
		copy(out[w*32:], word[:])
	}
	if len(out) >= mldsa.MLDSA65PublicKeySize {
		return out[:mldsa.MLDSA65PublicKeySize]
	}
	return out
}
