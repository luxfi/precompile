// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"bytes"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/precompile/contract"
)

// signer.go is the completion-quorum verifier: it decides whether a set of member
// signatures over a completion digest meets the committee's ⅔-weight threshold.
// It reads the committee EXCLUSIVELY from StateDB (committee_state.go) — public
// keys are never taken from the relayer's calldata — and it FAILS CLOSED when no
// committee is set. There is exactly one verification path; the old in-memory
// length-only stub (which accepted any non-empty byte slice) is gone.

// VerifyCompletionQuorum reports nil iff a ⅔-weight quorum of distinct, valid
// committee members signed digest. Each signer references a committee index; the
// member (scheme, weight, key) is loaded from STATE at that index and the
// signature is checked against the stored key. The weight rule is exact 256-bit
// integer cross-multiplication (no division, no rounding):
//
//	Σ weight(distinct valid signer) * quorumDen  >=  totalWeight * quorumNum
//
// with (quorumNum, quorumDen) = (2, 3) for a ⅔ threshold.
//
// Fail-closed properties:
//   - no committee set            -> ErrCommitteeUnset (loadCommitteeHeader)
//   - signer index out of range   -> ErrSignerIndexRange
//   - duplicate signer index      -> ErrDuplicateSigner (no double-counting weight)
//   - an invalid signature        -> does not count toward the weight
//   - valid weight below quorum    -> ErrSignatureThreshold
//
// A junk proof (e.g. a single 1-byte signature) contributes zero valid weight and
// is rejected by the threshold check; an empty/absent committee is rejected before
// any signature is examined.
func VerifyCompletionQuorum(
	state contract.StateDB,
	gwAddr common.Address,
	digest [32]byte,
	signers []SignerSig,
) error {
	h, err := loadCommitteeHeader(state, gwAddr)
	if err != nil {
		return err // ErrCommitteeUnset — fail closed, never a threshold of one
	}

	seen := make(map[uint16]bool, len(signers))
	seenKey := make(map[[20]byte]bool, len(signers))
	sumWeight := new(big.Int)
	for _, s := range signers {
		if seen[s.Index] {
			return ErrDuplicateSignerIndex
		}
		seen[s.Index] = true

		m, err := loadMember(state, gwAddr, h, s.Index)
		if err != nil {
			return err // ErrSignerIndexRange — a member that does not exist
		}
		if verifyMemberSig(m, digest, s.Sig) {
			// A physical key counts ONCE toward quorum, even if the committee
			// was (mis)seeded with the same KeyID at multiple indices. Quorum is
			// ⅔ of distinct KEYS, not ⅔ of distinct indices — otherwise one key
			// signing at N duplicate slots could reach threshold alone. Defense
			// in depth: SeedCommittee also rejects duplicate KeyIDs at construction.
			if seenKey[m.KeyID] {
				continue
			}
			seenKey[m.KeyID] = true
			sumWeight.Add(sumWeight, new(big.Int).SetUint64(m.Weight))
		}
		// An invalid signature simply does not count — only valid distinct
		// members add weight (so a 1-byte junk signature reaches no quorum).
	}

	lhs := new(big.Int).Mul(sumWeight, new(big.Int).SetUint64(uint64(h.quorumDen)))
	rhs := new(big.Int).Mul(h.totalWeight, new(big.Int).SetUint64(uint64(h.quorumNum)))
	if lhs.Cmp(rhs) < 0 {
		return ErrSignatureThreshold
	}
	return nil
}

// verifyMemberSig verifies one member's signature over digest against the key the
// committee was seeded with. secp256k1 recovers the EVM address and compares it to
// the member's keyID; ML-DSA-65 verifies against the state-resident public key
// with the completion domain bound as the FIPS 204 context.
func verifyMemberSig(m CommitteeMember, digest [32]byte, sig []byte) bool {
	switch m.Scheme {
	case SchemeSecp256k1:
		if len(sig) != 65 {
			return false
		}
		pub, err := crypto.Ecrecover(digest[:], sig)
		if err != nil || len(pub) != 65 {
			return false
		}
		// Drop the 0x04 prefix, keccak the 64-byte key, take the low 20 bytes.
		addr := crypto.Keccak256(pub[1:])[12:]
		return bytes.Equal(addr, m.KeyID[:])

	case SchemeMLDSA65:
		pk, err := mldsa.PublicKeyFromBytes(m.PubKey, mldsa.MLDSA65)
		if err != nil {
			return false
		}
		return pk.VerifySignatureCtx(digest[:], sig, []byte(completionDomain))

	default:
		return false
	}
}
