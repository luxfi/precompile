// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/accounts/abi"
)

// Shared error sentinels for all precompiles.
var (
	ErrOutOfGas     = errors.New("out of gas")
	ErrInvalidInput = errors.New("invalid input")
	ErrInvalidOp    = errors.New("invalid operation")
)

// Gas costs for stateful precompiles
const (
	WriteGasCostPerSlot = 20_000
	ReadGasCostPerSlot  = 5_000

	// Per LOG operation.
	LogGas uint64 = 375 // from params/protocol_params.go
	// Gas cost of single topic of the LOG. Should be multiplied by the number of topics.
	LogTopicGas uint64 = 375 // from params/protocol_params.go
	// Per byte cost in a LOG operation's data. Should be multiplied by the byte size of the data.
	LogDataGas uint64 = 8 // from params/protocol_params.go
)

// functionSignatureRegex matches a whole canonical Solidity signature and
// nothing else. The anchors are load-bearing: keccak hashes the entire string,
// so a signature carrying stray whitespace or a copy-paste artefact would pass
// an unanchored check and yield a selector no caller will ever send. The panic
// below exists to catch exactly that at boot.
var functionSignatureRegex = regexp.MustCompile(`^\w+\((\w*|(\w+,)+\w+)\)$`)

// CalculateFunctionSelector returns the 4 byte function selector that results from [functionSignature]
// Ex. the function setBalance(addr address, balance uint256) should be passed in as the string:
// "setBalance(address,uint256)"
//
// Panics on a signature that is not exactly one canonical Solidity signature.
// Every caller is a package-level initialiser over a string literal, so the
// panic is a boot failure on a constant, never reachable from calldata.
func CalculateFunctionSelector(functionSignature string) []byte {
	if !functionSignatureRegex.MatchString(functionSignature) {
		panic(fmt.Errorf("invalid function signature: %q", functionSignature))
	}
	hash := crypto.Keccak256([]byte(functionSignature))
	return hash[:4]
}

// DeductGas checks if [suppliedGas] is sufficient against [requiredGas] and deducts [requiredGas] from [suppliedGas].
func DeductGas(suppliedGas uint64, requiredGas uint64) (uint64, error) {
	if suppliedGas < requiredGas {
		return 0, ErrOutOfGas
	}
	return suppliedGas - requiredGas, nil
}

// ParseABI parses the given ABI string and returns the parsed ABI.
// If the ABI is invalid, it panics.
func ParseABI(rawABI string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(rawABI))
	if err != nil {
		panic(err)
	}

	return parsed
}
