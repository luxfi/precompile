// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package modelregistry

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// State key derivation (the precompile owns its storage at ContractAddress). Internal
// storage keys (not consensus-visible ABI), so any deterministic hash works; stdlib
// sha256 avoids an external dep.
func stateKey(prefix string, data []byte) common.Hash {
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write(data)
	return common.BytesToHash(h.Sum(nil))
}

func adminKey(a common.Address) common.Hash  { return stateKey("adm", a.Bytes()) }
func weightKey(name common.Hash) common.Hash { return stateKey("mw", name.Bytes()) }
func verKey(name common.Hash) common.Hash    { return stateKey("mv", name.Bytes()) }

var enabledHash = common.Hash{31: 1}

func setAdminState(state contract.StateDB, a common.Address, enabled bool) {
	if enabled {
		state.SetState(ContractAddress, adminKey(a), enabledHash)
	} else {
		state.SetState(ContractAddress, adminKey(a), common.Hash{})
	}
}

// IsAdmin reports whether addr may adopt models / manage admins.
func IsAdmin(state contract.StateDB, a common.Address) bool {
	return state.GetState(ContractAddress, adminKey(a)) != (common.Hash{})
}

// GetApproved returns the currently-adopted (version, weight-commitment) for a model
// name. This is what the inference precompile / off-chain provisioners read to know
// which weights are the chain's canonical brain. weight == zero means none adopted yet.
func GetApproved(state contract.StateDB, name common.Hash) (version uint64, weight common.Hash) {
	v := state.GetState(ContractAddress, verKey(name))
	weight = state.GetState(ContractAddress, weightKey(name))
	version = binary.BigEndian.Uint64(v[24:32])
	return version, weight
}

// ModelRegistryContract — the governance-adopted, versioned model commitment.
type ModelRegistryContract struct{}

func (c *ModelRegistryContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasGetApproved
	}
	switch binary.BigEndian.Uint32(input[:4]) {
	case SelectorAdopt:
		return GasAdopt
	case SelectorGetApproved:
		return GasGetApproved
	case SelectorIsAdmin:
		return GasIsAdmin
	case SelectorSetAdmin:
		return GasSetAdmin
	default:
		return GasGetApproved
	}
}

func boolWord(b bool) []byte {
	out := make([]byte, 32)
	if b {
		out[31] = 1
	}
	return out
}

func (c *ModelRegistryContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	gas := c.RequiredGas(input)
	if suppliedGas < gas {
		return nil, 0, fmt.Errorf("out of gas: need %d have %d", gas, suppliedGas)
	}
	remainingGas = suppliedGas - gas
	if len(input) < 4 {
		return nil, remainingGas, fmt.Errorf("input too short")
	}
	selector := binary.BigEndian.Uint32(input[:4])
	data := input[4:]
	state := accessibleState.GetStateDB()

	switch selector {
	case SelectorAdopt: // adopt(bytes32 name, uint256 version, bytes32 weightHash)
		if readOnly {
			return nil, remainingGas, fmt.Errorf("cannot adopt in read-only mode")
		}
		if !IsAdmin(state, caller) {
			return nil, remainingGas, fmt.Errorf("caller %s is not an admin", caller)
		}
		if len(data) < 96 {
			return nil, remainingGas, fmt.Errorf("adopt: input too short")
		}
		name := common.BytesToHash(data[0:32])
		version := common.BytesToHash(data[32:64])
		weight := common.BytesToHash(data[64:96])
		state.SetState(ContractAddress, verKey(name), version)
		state.SetState(ContractAddress, weightKey(name), weight)
		return boolWord(true), remainingGas, nil

	case SelectorGetApproved: // getApproved(bytes32 name) -> (uint256 version, bytes32 weightHash)
		if len(data) < 32 {
			return nil, remainingGas, fmt.Errorf("getApproved: input too short")
		}
		name := common.BytesToHash(data[0:32])
		ver := state.GetState(ContractAddress, verKey(name))
		weight := state.GetState(ContractAddress, weightKey(name))
		out := make([]byte, 64)
		copy(out[0:32], ver[:])
		copy(out[32:64], weight[:])
		return out, remainingGas, nil

	case SelectorIsAdmin: // isAdmin(address) -> bool
		if len(data) < 32 {
			return nil, remainingGas, fmt.Errorf("isAdmin: input too short")
		}
		return boolWord(IsAdmin(state, common.BytesToAddress(data[12:32]))), remainingGas, nil

	case SelectorSetAdmin: // setAdmin(address, bool enabled) -> bool
		if readOnly {
			return nil, remainingGas, fmt.Errorf("cannot setAdmin in read-only mode")
		}
		if !IsAdmin(state, caller) {
			return nil, remainingGas, fmt.Errorf("caller %s is not an admin", caller)
		}
		if len(data) < 64 {
			return nil, remainingGas, fmt.Errorf("setAdmin: input too short")
		}
		a := common.BytesToAddress(data[12:32])
		enabled := common.BytesToHash(data[32:64]) != (common.Hash{})
		setAdminState(state, a, enabled)
		return boolWord(true), remainingGas, nil

	default:
		return nil, remainingGas, fmt.Errorf("unknown selector %#x", selector)
	}
}
