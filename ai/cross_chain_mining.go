// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// cross_chain_mining.go — atomic AI-mining claims for the 'AI'/'BLG' economy. Any L1/L2
// produces AI work (TEE-attested compute) or a PII-free data contribution off-chain,
// signs it with a post-quantum ML-DSA key, and submits it (directly or relayed via Warp).
// These methods ATOMICALLY verify the attestation, prevent double-spend, compute the
// reward, and mark the work spent — in one call, so a contract mints in a single step
// without the check-then-act race a multi-call (isSpent → calculateReward → markSpent)
// orchestration would expose to front-running/replay.
//
// They compose only already-verified primitives (VerifyMLDSA, CalculateReward,
// ComputeWorkId, IsSpent/MarkSpent, privacyMultipliers) — no new crypto. The chainId is
// part of the work id, so the same work can't be minted on two chains (the WorkContext
// is bound at attestation time). The PII-free guarantee is asserted by the attesting
// signer (a recognized scrub service / TEE); a future variant verifies a ZK/FHE proof
// (zk 0x0900 / fhe 0x0700) inline for trustless anonymization.

package ai

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/zeebo/blake3"

	"github.com/luxfi/precompile/contract"
)

// Gas: the fused cost of the primitives each method composes. A mint now also
// verifies a TEE attestation certificate chain (GasVerifyTEE) — the X.509 work
// that proves the signing key belongs to a real device — so the cost is metered.
const (
	GasVerifyAndMintWork uint64 = GasVerifyMLDSA + GasVerifyTEE + GasCalculateReward + GasMarkSpent
	GasVerifyAndMintData uint64 = GasVerifyMLDSA + GasVerifyTEE + GasCalculateReward + GasMarkSpent
)

// ErrInputTooShort is returned when calldata is truncated.
var ErrInputTooShort = fmt.Errorf("input too short")

// blobs decodes count length-prefixed blobs from the front of input and reports the offset
// just past the last one:
//
//	[4]len0 | blob0 | [4]len1 | blob1 | ...
//
// Every length is widened to int before it is used. Computing the bound in uint32 — as
// `uint32(len(input)) < 4+n+4` — wraps for n near 2^32, so the check passes and the slice
// expression that follows panics with "slice bounds out of range". A panic inside a
// precompile is not recovered anywhere on the execution path, so it takes down every
// validator that processed the transaction; eight bytes of calldata were enough. int is
// wide enough on 64-bit, and the n < 0 test covers a 32-bit build where int(uint32) can go
// negative.
func blobs(input []byte, count int) ([][]byte, int, error) {
	out := make([][]byte, 0, count)
	off := 0
	for range count {
		if off+4 > len(input) {
			return nil, 0, ErrInputTooShort
		}
		n := int(binary.BigEndian.Uint32(input[off : off+4]))
		off += 4
		if n < 0 || off+n > len(input) {
			return nil, 0, ErrInputTooShort
		}
		out = append(out, input[off:off+n])
		off += n
	}
	return out, off, nil
}

// parseTriple decodes three length-prefixed blobs followed by a uint64 chainId:
//
//	[4]lenA | A | [4]lenB | B | [4]lenC | C | [8]chainId
func parseTriple(input []byte) (a, b, c []byte, chainId uint64, err error) {
	parts, off, err := blobs(input, 3)
	if err != nil {
		return
	}
	if off+8 > len(input) {
		err = ErrInputTooShort
		return
	}
	return parts[0], parts[1], parts[2], binary.BigEndian.Uint64(input[off : off+8]), nil
}

// mintWork atomically settles an attested compute work-proof: workId is bound to
// (deviceId, nonce, chainId); if unspent, the reward is computed and the work is marked
// spent. Returns the reward; the caller mints it. (The ML-DSA attestation is verified by
// the Run wrapper before this is called.)
func mintWork(stateDB StateDB, workProof []byte, chainId uint64) (*big.Int, error) {
	if len(workProof) < WorkProofMinSize {
		return nil, ErrInvalidWorkProof
	}
	var deviceId, nonce [32]byte
	copy(deviceId[:], workProof[0:32])
	copy(nonce[:], workProof[32:64])

	workId := ComputeWorkId(deviceId, nonce, chainId)
	if IsSpent(stateDB, workId) {
		return nil, ErrWorkAlreadySpent
	}
	reward, err := CalculateReward(workProof, chainId)
	if err != nil {
		return nil, err
	}
	if err := MarkSpent(stateDB, workId); err != nil {
		return nil, err
	}
	return reward, nil
}

// mintData atomically settles a PII-free data contribution. descriptor =
// dataHash(32) | dataSize(uint64,8) | privacyLevel(uint16,2). The contribution id binds
// all of these to the chain, so the same dataset can't be double-claimed. Reward scales
// with data size and the privacy multiplier (the same schedule as compute mining).
func mintData(stateDB StateDB, descriptor []byte, chainId uint64) (*big.Int, error) {
	if len(descriptor) < DataContributionSize {
		return nil, ErrInvalidWorkProof
	}
	var dataHash [32]byte
	copy(dataHash[:], descriptor[0:32])
	dataSize := binary.BigEndian.Uint64(descriptor[32:40])
	privacyLevel := binary.BigEndian.Uint16(descriptor[40:42])

	multiplier, ok := privacyMultipliers[privacyLevel]
	if !ok {
		return nil, ErrInvalidPrivacyLevel
	}

	// contributionId = ComputeWorkId(dataHash, size||privacy, chainId) — unique per
	// (dataset, size, privacy, chain), preventing double-claim of the same data.
	var nonce [32]byte
	binary.BigEndian.PutUint64(nonce[0:8], dataSize)
	binary.BigEndian.PutUint16(nonce[8:10], privacyLevel)
	contributionId := ComputeWorkId(dataHash, nonce, chainId)
	if IsSpent(stateDB, contributionId) {
		return nil, ErrWorkAlreadySpent
	}

	reward := new(big.Int).Set(baseRewardPerMinute)
	reward.Mul(reward, new(big.Int).SetUint64(dataSize))
	reward.Mul(reward, big.NewInt(int64(multiplier)))
	reward.Div(reward, big.NewInt(10000))

	if err := MarkSpent(stateDB, contributionId); err != nil {
		return nil, err
	}
	return reward, nil
}

// verifyDeviceBinding is the trust gate that makes a mint impossible without a
// chain-trusted signature. The attestation envelope appended to a work proof /
// data descriptor is:
//
//	envelope = [4]sigLen | teeSig | receipt
//	receipt  = report(48) | certChainDER     (report = deviceID(32)|ts(8)|nonce(8))
//
// It establishes, in order: (1) the certificate chain in the receipt terminates
// at an embedded vendor root (a genuine TEE device), checked at the report's own
// timestamp so every validator agrees; (2) teeSig is the device leaf's signature
// over the 48-byte report; and (3) the attested deviceID equals BLAKE3(pubkey) —
// so the trust runs embedded-root → device leaf → this exact ML-DSA key. A miner
// that presents a self-generated key with no embedded-root-anchored quote is
// rejected: the signing key is vouched for on chain, never asserted in calldata.
//
// roots is threaded explicitly (production passes teeRootPool(); tests pass a
// generated PKI) so the gate carries no hidden global state.
func verifyDeviceBinding(pubkey, envelope []byte, roots *x509.CertPool) error {
	if len(envelope) < 4 {
		return ErrInvalidTEEReceipt
	}
	sigLen := uint64(binary.BigEndian.Uint32(envelope[0:4]))
	if sigLen == 0 || 4+sigLen > uint64(len(envelope)) {
		return ErrInvalidTEEReceipt
	}
	teeSig := envelope[4 : 4+sigLen]
	receipt := envelope[4+sigLen:]

	ok, err := verifyAttestation(receipt, teeSig, roots)
	if err != nil {
		return err
	}
	if !ok {
		return ErrTEESignatureInvalid
	}
	// receipt is guaranteed >= teeReportLen here (verifyAttestation enforced it),
	// so receipt[0:32] (the attested deviceID) is safe to read.
	var attestedDevice [32]byte
	copy(attestedDevice[:], receipt[:32])
	if attestedDevice != blake3.Sum256(pubkey) {
		return ErrDeviceKeyMismatch
	}
	return nil
}

func (c *AIMiningContract) runVerifyAndMintWork(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	return c.verifyAndMintWork(accessibleState, input, suppliedGas, readOnly, teeRootPool())
}

// verifyAndMintWork is runVerifyAndMintWork with the trust-anchor pool injected.
func (c *AIMiningContract) verifyAndMintWork(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
	roots *x509.CertPool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot mint in read-only mode")
	}
	if suppliedGas < GasVerifyAndMintWork {
		return nil, 0, fmt.Errorf("out of gas")
	}
	remaining := suppliedGas - GasVerifyAndMintWork

	workProof, pubkey, signature, chainId, err := parseTriple(input)
	if err != nil {
		return nil, remaining, err
	}
	// 1. The post-quantum key signed THIS exact work claim.
	valid, err := VerifyMLDSA(pubkey, workProof, signature)
	if err != nil {
		return nil, remaining, err
	}
	if !valid {
		return nil, remaining, fmt.Errorf("ml-dsa attestation invalid")
	}
	// 2. A TEE quote binds that key to a real, embedded-root-certified device.
	if len(workProof) <= WorkProofTEEQuoteOffset {
		return nil, remaining, ErrMissingAttestation
	}
	if err := verifyDeviceBinding(pubkey, workProof[WorkProofTEEQuoteOffset:], roots); err != nil {
		return nil, remaining, err
	}
	// 3. The work proof's own deviceID must equal the attested key identity, so
	//    the settled workId is scoped to the chain-trusted device, not a value
	//    the attacker grinds freely.
	if [32]byte(workProof[:32]) != blake3.Sum256(pubkey) {
		return nil, remaining, ErrDeviceKeyMismatch
	}

	stateDB := accessibleState.GetStateDB()
	reward, err := mintWork(&stateDBAdapter{stateDB, ContractAddress}, workProof, chainId)
	if err != nil {
		return nil, remaining, err
	}
	result := make([]byte, 32)
	reward.FillBytes(result)
	return result, remaining, nil
}

func (c *AIMiningContract) runVerifyAndMintData(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	return c.verifyAndMintData(accessibleState, input, suppliedGas, readOnly, teeRootPool())
}

// verifyAndMintData is runVerifyAndMintData with the trust-anchor pool injected.
func (c *AIMiningContract) verifyAndMintData(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
	roots *x509.CertPool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot mint in read-only mode")
	}
	if suppliedGas < GasVerifyAndMintData {
		return nil, 0, fmt.Errorf("out of gas")
	}
	remaining := suppliedGas - GasVerifyAndMintData

	descriptor, pubkey, signature, chainId, err := parseTriple(input)
	if err != nil {
		return nil, remaining, err
	}
	// 1. The post-quantum key signed THIS exact data descriptor.
	valid, err := VerifyMLDSA(pubkey, descriptor, signature)
	if err != nil {
		return nil, remaining, err
	}
	if !valid {
		return nil, remaining, fmt.Errorf("ml-dsa attestation invalid")
	}
	// 2. A TEE quote (appended after the 42-byte descriptor) binds that key to a
	//    real, embedded-root-certified device (the scrub service's enclave).
	if len(descriptor) <= DataContributionSize {
		return nil, remaining, ErrMissingAttestation
	}
	if err := verifyDeviceBinding(pubkey, descriptor[DataContributionSize:], roots); err != nil {
		return nil, remaining, err
	}

	stateDB := accessibleState.GetStateDB()
	reward, err := mintData(&stateDBAdapter{stateDB, ContractAddress}, descriptor, chainId)
	if err != nil {
		return nil, remaining, err
	}
	result := make([]byte, 32)
	reward.FillBytes(result)
	return result, remaining, nil
}
