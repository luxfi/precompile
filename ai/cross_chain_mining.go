// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
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
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/luxfi/precompile/contract"
)

// Gas: the fused cost of the primitives each method composes.
const (
	GasVerifyAndMintWork uint64 = GasVerifyMLDSA + GasCalculateReward + GasMarkSpent
	GasVerifyAndMintData uint64 = GasVerifyMLDSA + GasCalculateReward + GasMarkSpent
)

// ErrInputTooShort is returned when calldata is truncated.
var ErrInputTooShort = fmt.Errorf("input too short")

// parseTriple decodes three length-prefixed blobs followed by a uint64 chainId:
//
//	[4]lenA | A | [4]lenB | B | [4]lenC | C | [8]chainId
func parseTriple(input []byte) (a, b, c []byte, chainId uint64, err error) {
	off := 0
	readBlob := func() ([]byte, error) {
		if off+4 > len(input) {
			return nil, ErrInputTooShort
		}
		n := int(binary.BigEndian.Uint32(input[off : off+4]))
		off += 4
		if n < 0 || off+n > len(input) {
			return nil, ErrInputTooShort
		}
		blob := input[off : off+n]
		off += n
		return blob, nil
	}
	if a, err = readBlob(); err != nil {
		return
	}
	if b, err = readBlob(); err != nil {
		return
	}
	if c, err = readBlob(); err != nil {
		return
	}
	if off+8 > len(input) {
		err = ErrInputTooShort
		return
	}
	chainId = binary.BigEndian.Uint64(input[off : off+8])
	return
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
	if len(descriptor) < 42 {
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

func (c *AIMiningContract) runVerifyAndMintWork(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
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
	valid, err := VerifyMLDSA(pubkey, workProof, signature)
	if err != nil {
		return nil, remaining, err
	}
	if !valid {
		return nil, remaining, fmt.Errorf("ml-dsa attestation invalid")
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
	valid, err := VerifyMLDSA(pubkey, descriptor, signature)
	if err != nil {
		return nil, remaining, err
	}
	if !valid {
		return nil, remaining, fmt.Errorf("ml-dsa attestation invalid")
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
