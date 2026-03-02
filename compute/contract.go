// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package compute implements the AI compute marketplace precompile.
// Address: 0x0300000000000000000000000000000000000010 (AI range)
//
// Operations:
//   - 0x01: RegisterProvider(gpuType, teeAttestation) -> providerID (hash of caller + nonce)
//   - 0x02: SubmitJob(modelHash, inputHash, maxPrice) -> jobID
//   - 0x03: ClaimReward(jobID, outputHash) -> bool
//   - 0x04: VerifyCompute(jobID, attestation) -> bool
//   - 0x05: GetPrice(modelHash, inputSize) -> price in wei
//
// Storage layout (all keyed under ContractAddress):
//   keccak256("provider", providerID)       -> gpuType (32 bytes)
//   keccak256("provider.owner", providerID) -> owner address
//   keccak256("job", jobID)                 -> modelHash
//   keccak256("job.provider", jobID)        -> provider address
//   keccak256("job.price", jobID)           -> maxPrice
//   keccak256("job.status", jobID)          -> status (0=open, 1=claimed, 2=verified)
//   keccak256("job.output", jobID)          -> outputHash
//   keccak256("nonce", address)             -> provider nonce
//
// Gas: 25,000 register, 10,000 submit, 50,000 verify, 5,000 claim/getPrice
package compute

import (
	"errors"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000010")

	Precompile = &computeMarketPrecompile{}

	_ contract.StatefulPrecompiledContract = Precompile

	ErrInvalidInput      = errors.New("invalid compute input")
	ErrUnknownOp         = errors.New("unknown compute operation")
	ErrNotProvider       = errors.New("caller is not registered provider")
	ErrJobNotFound       = errors.New("job not found")
	ErrJobAlreadyClaimed = errors.New("job already claimed")
	ErrReadOnlyState     = errors.New("state modification in read-only context")
)

const (
	OpRegisterProvider = 0x01
	OpSubmitJob        = 0x02
	OpClaimReward      = 0x03
	OpVerifyCompute    = 0x04
	OpGetPrice         = 0x05

	GasRegister = 25000
	GasSubmit   = 10000
	GasClaim    = 5000
	GasVerify   = 50000
	GasGetPrice = 5000

	StatusOpen     = 0
	StatusClaimed  = 1
	StatusVerified = 2
)

type computeMarketPrecompile struct{}

func (p *computeMarketPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 1 {
		return nil, suppliedGas, ErrInvalidInput
	}

	op := input[0]
	data := input[1:]

	switch op {
	case OpRegisterProvider:
		if readOnly {
			return nil, suppliedGas, ErrReadOnlyState
		}
		gas, err := contract.DeductGas(suppliedGas, GasRegister)
		if err != nil {
			return nil, 0, err
		}
		return registerProvider(accessibleState, caller, data, gas)

	case OpSubmitJob:
		if readOnly {
			return nil, suppliedGas, ErrReadOnlyState
		}
		gas, err := contract.DeductGas(suppliedGas, GasSubmit)
		if err != nil {
			return nil, 0, err
		}
		return submitJob(accessibleState, caller, data, gas)

	case OpClaimReward:
		if readOnly {
			return nil, suppliedGas, ErrReadOnlyState
		}
		gas, err := contract.DeductGas(suppliedGas, GasClaim)
		if err != nil {
			return nil, 0, err
		}
		return claimReward(accessibleState, caller, data, gas)

	case OpVerifyCompute:
		gas, err := contract.DeductGas(suppliedGas, GasVerify)
		if err != nil {
			return nil, 0, err
		}
		return verifyCompute(accessibleState, data, gas)

	case OpGetPrice:
		gas, err := contract.DeductGas(suppliedGas, GasGetPrice)
		if err != nil {
			return nil, 0, err
		}
		return getPrice(data, gas)

	default:
		return nil, suppliedGas, ErrUnknownOp
	}
}

// registerProvider: data = [gpuType (32 bytes)] [teeAttestation (32 bytes)]
// Returns: providerID (32 bytes)
func registerProvider(state contract.AccessibleState, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	gpuType := common.BytesToHash(data[:32])
	// teeAttestation is data[32:64], stored as part of the provider record

	stateDB := state.GetStateDB()

	// Get and increment caller nonce
	nonceSlot := storageSlot("nonce", caller.Bytes())
	nonce := stateDB.GetState(ContractAddress, nonceSlot)
	nonceInt := new(big.Int).SetBytes(nonce.Bytes())

	// providerID = keccak256(caller, nonce)
	providerID := common.BytesToHash(crypto.Keccak256(caller.Bytes(), nonce.Bytes()))

	// Store provider data
	stateDB.SetState(ContractAddress, storageSlot("provider", providerID.Bytes()), gpuType)
	stateDB.SetState(ContractAddress, storageSlot("provider.owner", providerID.Bytes()), common.BytesToHash(caller.Bytes()))
	stateDB.SetState(ContractAddress, storageSlot("provider.tee", providerID.Bytes()), common.BytesToHash(data[32:64]))

	// Increment nonce
	nonceInt.Add(nonceInt, big.NewInt(1))
	stateDB.SetState(ContractAddress, nonceSlot, common.BytesToHash(padTo32(nonceInt.Bytes())))

	return providerID.Bytes(), gas, nil
}

// submitJob: data = [modelHash (32)] [inputHash (32)] [maxPrice (32)]
// Returns: jobID (32 bytes)
func submitJob(state contract.AccessibleState, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 96 {
		return nil, gas, ErrInvalidInput
	}
	modelHash := common.BytesToHash(data[:32])
	maxPrice := common.BytesToHash(data[64:96])

	stateDB := state.GetStateDB()

	// Get and increment caller nonce for unique jobID
	nonceSlot := storageSlot("job.nonce", caller.Bytes())
	nonce := stateDB.GetState(ContractAddress, nonceSlot)
	nonceInt := new(big.Int).SetBytes(nonce.Bytes())

	// jobID = keccak256(caller, nonce)
	jobID := common.BytesToHash(crypto.Keccak256(caller.Bytes(), nonce.Bytes()))

	// Store job data
	stateDB.SetState(ContractAddress, storageSlot("job", jobID.Bytes()), modelHash)
	stateDB.SetState(ContractAddress, storageSlot("job.submitter", jobID.Bytes()), common.BytesToHash(caller.Bytes()))
	stateDB.SetState(ContractAddress, storageSlot("job.price", jobID.Bytes()), maxPrice)
	stateDB.SetState(ContractAddress, storageSlot("job.input", jobID.Bytes()), common.BytesToHash(data[32:64]))
	// status = 0 (open) is default zero value

	// Increment nonce
	nonceInt.Add(nonceInt, big.NewInt(1))
	stateDB.SetState(ContractAddress, nonceSlot, common.BytesToHash(padTo32(nonceInt.Bytes())))

	return jobID.Bytes(), gas, nil
}

// claimReward: data = [jobID (32)] [outputHash (32)]
// Returns: 1 on success
func claimReward(state contract.AccessibleState, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	jobID := common.BytesToHash(data[:32])
	outputHash := common.BytesToHash(data[32:64])

	stateDB := state.GetStateDB()

	// Check job exists
	modelHash := stateDB.GetState(ContractAddress, storageSlot("job", jobID.Bytes()))
	if modelHash == (common.Hash{}) {
		return nil, gas, ErrJobNotFound
	}

	// Check status is open
	status := stateDB.GetState(ContractAddress, storageSlot("job.status", jobID.Bytes()))
	if status != (common.Hash{}) {
		return nil, gas, ErrJobAlreadyClaimed
	}

	// Check caller is a registered provider (nonzero nonce means they registered)
	callerNonce := stateDB.GetState(ContractAddress, storageSlot("nonce", caller.Bytes()))
	if callerNonce == (common.Hash{}) {
		return nil, gas, ErrNotProvider
	}

	// Set status to claimed, record output and provider
	stateDB.SetState(ContractAddress, storageSlot("job.status", jobID.Bytes()), common.BytesToHash([]byte{StatusClaimed}))
	stateDB.SetState(ContractAddress, storageSlot("job.output", jobID.Bytes()), outputHash)
	stateDB.SetState(ContractAddress, storageSlot("job.provider", jobID.Bytes()), common.BytesToHash(caller.Bytes()))

	result := make([]byte, 32)
	result[31] = 1
	return result, gas, nil
}

// verifyCompute: data = [jobID (32)] [attestation (32)]
// Returns: 1 if verified, 0 otherwise
func verifyCompute(state contract.AccessibleState, data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	jobID := common.BytesToHash(data[:32])
	attestation := common.BytesToHash(data[32:64])

	stateDB := state.GetStateDB()

	// Check job exists and is claimed
	status := stateDB.GetState(ContractAddress, storageSlot("job.status", jobID.Bytes()))
	if status != common.BytesToHash([]byte{StatusClaimed}) {
		result := make([]byte, 32)
		return result, gas, nil
	}

	// Verify attestation: check that keccak256(jobID, outputHash) matches attestation
	outputHash := stateDB.GetState(ContractAddress, storageSlot("job.output", jobID.Bytes()))
	expected := common.BytesToHash(crypto.Keccak256(jobID.Bytes(), outputHash.Bytes()))
	if attestation != expected {
		result := make([]byte, 32)
		return result, gas, nil
	}

	// Mark as verified
	stateDB.SetState(ContractAddress, storageSlot("job.status", jobID.Bytes()), common.BytesToHash([]byte{StatusVerified}))

	result := make([]byte, 32)
	result[31] = 1
	return result, gas, nil
}

// getPrice: data = [modelHash (32)] [inputSize (32)]
// Returns: price in wei (32 bytes)
// Base price = 1000 wei per input byte, scaled by model complexity
func getPrice(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	inputSize := new(big.Int).SetBytes(data[32:64])

	// Price = inputSize * 1000 (base rate per byte)
	price := new(big.Int).Mul(inputSize, big.NewInt(1000))
	return padTo32(price.Bytes()), gas, nil
}

// storageSlot computes keccak256(prefix, key) for deterministic storage mapping.
func storageSlot(prefix string, key []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256([]byte(prefix), key))
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
