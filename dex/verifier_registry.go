// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/geth/common"
)

// verifier_registry.go is the CERT-TYPE UPGRADE SEAM. The on-chain V4 ABI never
// changes; 0x9999 dispatches certificate verification by certType through this
// registry, so the cert scheme can move BLS -> Quasar -> post-quantum -> ZK with
// no ABI change and no new precompile address. Day-1 implements BLS only; the
// registry holds the active D-validator set(s) and the certType each set certifies
// under.
//
// The registry is DURABLE, consensus-shared StateDB state keyed by
// (dChainID, validatorSetID). It is populated at genesis activation and rotated by
// governance (protocolFeeController-gated, same authority as halt) — NEVER by a
// live query. Resolving a validator set during swap verification is therefore a
// deterministic StateDB read, safe in Run().

// VerifierStatus is the lifecycle of a registry entry.
type VerifierStatus uint8

const (
	VerifierInactive VerifierStatus = 0 // absent / retired set — its certs are refused
	VerifierActive   VerifierStatus = 1 // live set — certs at/after activationHeight accepted
)

// Validator is one member of a D-validator set: its BLS public key (48-byte
// compressed G1) and its stake weight (for the quorum fraction). The canonical
// ORDER of the slice fixes the bitmap index meaning; it MUST match the order the
// D-Chain signer uses when it assembles the aggregate.
type Validator struct {
	PublicKey *bls.PublicKey
	Weight    uint64
}

// ValidatorSet is the active set at a given dHeight, resolved from the registry.
type ValidatorSet struct {
	DChainID       [32]byte
	ValidatorSetID [32]byte
	CertType       CertType
	ActivationHeight uint64
	Status         VerifierStatus
	Validators     []Validator
	TotalWeight    uint64
}

var (
	ErrVerifierNotFound   = errors.New("dex: no verifier registry entry for (dChainID, validatorSetID)")
	ErrVerifierInactive   = errors.New("dex: verifier registry entry is not active")
	ErrVerifierCertType   = errors.New("dex: receipt certType does not match the registered verifier")
	ErrVerifierTooEarly   = errors.New("dex: receipt dHeight precedes the verifier activation height")
	ErrVerifierBadEntry   = errors.New("dex: verifier registry entry is malformed")
	ErrVerifierBadKey     = errors.New("dex: verifier registry entry has an invalid validator public key")
	ErrUnsupportedCertType = errors.New("dex: certType not supported at this height (staged)")
)

// Registry storage layout (under poolManagerAddr9999):
//
//	meta slot      = key("vr.meta", dChainID ‖ validatorSetID)
//	                 -> [status(1) certType(1) activationHeight(8) count(4) totalWeight(8)]
//	validator i    = key("vr.val", dChainID ‖ validatorSetID ‖ i_le4) gives the FIRST
//	                 32 bytes of the 48-byte compressed pubkey; the remaining 16 bytes
//	                 live in the adjacent slot key("vr.val2", ...). weight lives in
//	                 key("vr.valw", ...).
//
// A 48-byte BLS pubkey does not fit one 32-byte word, so each validator occupies
// three derived slots (pk[0:32], pk[32:48]+weight share). We keep it explicit and
// fixed so the read is unambiguous and bounds-checked.
var (
	vrMetaPrefix = []byte(settleStateNamespace + "vr.meta")
	vrPkAPrefix  = []byte(settleStateNamespace + "vr.pkA") // pubkey bytes [0:32]
	vrPkBPrefix  = []byte(settleStateNamespace + "vr.pkB") // pubkey bytes [32:48] in high 16
	vrWtPrefix   = []byte(settleStateNamespace + "vr.wt")  // weight in low 8 bytes
)

// vrMetaKey derives the meta slot for a (dChainID, validatorSetID).
func vrMetaKey(dChainID, validatorSetID [32]byte) common.Hash {
	id := make([]byte, 0, 64)
	id = append(id, dChainID[:]...)
	id = append(id, validatorSetID[:]...)
	return makeStorageKey(vrMetaPrefix, id)
}

// vrValKey derives a per-validator slot for prefix p at index i.
func vrValKey(p []byte, dChainID, validatorSetID [32]byte, i uint32) common.Hash {
	id := make([]byte, 0, 68)
	id = append(id, dChainID[:]...)
	id = append(id, validatorSetID[:]...)
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], i)
	id = append(id, ib[:]...)
	return makeStorageKey(p, id)
}

// maxValidatorsPerSet bounds a set so a malformed/huge count cannot make the
// read loop unbounded. 1<<16 validators is far above any real D-Chain set.
const maxValidatorsPerSet = 1 << 16

// PutValidatorSet writes a validator set into the registry. Called at genesis
// activation and by governance rotation (the caller enforces authority). It is
// the only writer of registry state; verification only reads.
func PutValidatorSet(stateDB stateKV, vs *ValidatorSet) error {
	if len(vs.Validators) == 0 || len(vs.Validators) > maxValidatorsPerSet {
		return ErrVerifierBadEntry
	}
	var meta common.Hash
	meta[0] = byte(vs.Status)
	meta[1] = byte(vs.CertType)
	binary.BigEndian.PutUint64(meta[2:10], vs.ActivationHeight)
	binary.BigEndian.PutUint32(meta[10:14], uint32(len(vs.Validators)))
	var total uint64
	for i, v := range vs.Validators {
		if v.PublicKey == nil {
			return ErrVerifierBadKey
		}
		pk := bls.PublicKeyToCompressedBytes(v.PublicKey) // 48 bytes
		if len(pk) != bls.PublicKeyLen {
			return ErrVerifierBadKey
		}
		var a common.Hash
		copy(a[:], pk[0:32])
		stateDB.SetState(poolManagerAddr9999, vrValKey(vrPkAPrefix, vs.DChainID, vs.ValidatorSetID, uint32(i)), a)
		var b common.Hash
		copy(b[0:16], pk[32:48])
		stateDB.SetState(poolManagerAddr9999, vrValKey(vrPkBPrefix, vs.DChainID, vs.ValidatorSetID, uint32(i)), b)
		var w common.Hash
		binary.BigEndian.PutUint64(w[24:32], v.Weight)
		stateDB.SetState(poolManagerAddr9999, vrValKey(vrWtPrefix, vs.DChainID, vs.ValidatorSetID, uint32(i)), w)
		total += v.Weight
	}
	binary.BigEndian.PutUint64(meta[14:22], total)
	stateDB.SetState(poolManagerAddr9999, vrMetaKey(vs.DChainID, vs.ValidatorSetID), meta)
	return nil
}

// ResolveValidatorSet reads the validator set active for (dChainID, validatorSetID)
// from StateDB and checks it certifies the given certType at the given dHeight.
// PURE read — every validator computes the identical set. This is what makes the
// downstream cert verify safe in Run().
func ResolveValidatorSet(stateDB stateKV, dChainID, validatorSetID [32]byte, certType CertType, dHeight uint64) (*ValidatorSet, error) {
	meta := stateDB.GetState(poolManagerAddr9999, vrMetaKey(dChainID, validatorSetID))
	status := VerifierStatus(meta[0])
	if status == VerifierInactive {
		// An all-zero meta slot (never written) reads as inactive => not found.
		if (meta == common.Hash{}) {
			return nil, ErrVerifierNotFound
		}
		return nil, ErrVerifierInactive
	}
	entryCertType := CertType(meta[1])
	if entryCertType != certType {
		return nil, ErrVerifierCertType
	}
	activation := binary.BigEndian.Uint64(meta[2:10])
	if dHeight < activation {
		return nil, ErrVerifierTooEarly
	}
	count := binary.BigEndian.Uint32(meta[10:14])
	if count == 0 || count > maxValidatorsPerSet {
		return nil, ErrVerifierBadEntry
	}
	storedTotal := binary.BigEndian.Uint64(meta[14:22])

	vs := &ValidatorSet{
		DChainID:         dChainID,
		ValidatorSetID:   validatorSetID,
		CertType:         entryCertType,
		ActivationHeight: activation,
		Status:           status,
		Validators:       make([]Validator, 0, count),
	}
	var total uint64
	for i := uint32(0); i < count; i++ {
		a := stateDB.GetState(poolManagerAddr9999, vrValKey(vrPkAPrefix, dChainID, validatorSetID, i))
		b := stateDB.GetState(poolManagerAddr9999, vrValKey(vrPkBPrefix, dChainID, validatorSetID, i))
		w := stateDB.GetState(poolManagerAddr9999, vrValKey(vrWtPrefix, dChainID, validatorSetID, i))
		pkBytes := make([]byte, bls.PublicKeyLen)
		copy(pkBytes[0:32], a[:])
		copy(pkBytes[32:48], b[0:16])
		pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
		if err != nil || pk == nil {
			return nil, ErrVerifierBadKey
		}
		weight := binary.BigEndian.Uint64(w[24:32])
		vs.Validators = append(vs.Validators, Validator{PublicKey: pk, Weight: weight})
		total += weight
	}
	// The stored total must equal the recomputed total (tamper / corruption guard).
	if total != storedTotal {
		return nil, ErrVerifierBadEntry
	}
	vs.TotalWeight = total
	return vs, nil
}

// verifyCert is the certType dispatch: it resolves the validator set and routes
// to the scheme verifier. Day-1 only BLS_FAST_PATH is implemented; the other arms
// return ErrUnsupportedCertType so a receipt claiming a staged certType cleanly
// reverts (never silently accepts an unverified fill). receiptRoot is the value
// the cert signed over (day-1 == receiptID; P3 == the block's fill-Merkle root).
func verifyCert(stateDB stateKV, r *DFillReceiptV1, receiptRoot [32]byte, cert *BLSCert) error {
	vs, err := ResolveValidatorSet(stateDB, r.DChainID, cert.ValidatorSetID, r.CertType, r.DHeight)
	if err != nil {
		return err
	}
	switch r.CertType {
	case CertTypeBLSFastPath:
		return VerifyBLSCert(cert, r, receiptRoot, vs)
	case CertTypeQ, CertTypeQPQ, CertTypeZK:
		// Staged (P5). The registry entry and dispatch arm exist; the verifier is
		// not yet wired, so refuse rather than accept an unverifiable certificate.
		return ErrUnsupportedCertType
	default:
		return ErrUnsupportedCertType
	}
}
