// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"fmt"
	"strings"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/accounts/abi"
	"github.com/luxfi/geth/common"
)

// ExtendedABI wraps the standard ABI and adds PackOutput, UnpackInput, and PackEvent methods
type ExtendedABI struct {
	abi.ABI
}

// ParseABI parses the raw ABI JSON and returns an ExtendedABI
func ParseABI(rawABI string) ExtendedABI {
	parsed, err := abi.JSON(strings.NewReader(rawABI))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ABI: %v", err))
	}
	return ExtendedABI{ABI: parsed}
}

// PackOutput packs the given args as the output of given method name to conform the ABI.
// This does not include method ID.
func (e ExtendedABI) PackOutput(name string, args ...interface{}) ([]byte, error) {
	method, exist := e.Methods[name]
	if !exist {
		return nil, fmt.Errorf("method '%s' not found", name)
	}
	return method.Outputs.Pack(args...)
}

// UnpackInput unpacks the input according to the ABI specification.
// useStrictMode indicates whether to check the input data length strictly.
func (e ExtendedABI) UnpackInput(name string, data []byte, useStrictMode bool) ([]interface{}, error) {
	method, exist := e.Methods[name]
	if !exist {
		return nil, fmt.Errorf("method '%s' not found", name)
	}
	if useStrictMode && len(data)%32 != 0 {
		return nil, fmt.Errorf("abi: improperly formatted input: %s", string(data))
	}
	return method.Inputs.Unpack(data)
}

// PackEvent packs the given event name and arguments to conform the ABI.
// Returns the topics for the event and the packed data of non-indexed args.
func (e ExtendedABI) PackEvent(name string, args ...interface{}) ([]common.Hash, []byte, error) {
	event, exist := e.Events[name]
	if !exist {
		return nil, nil, fmt.Errorf("event '%s' not found", name)
	}
	if len(args) != len(event.Inputs) {
		return nil, nil, fmt.Errorf("event '%s' unexpected number of inputs %d", name, len(args))
	}

	var (
		nonIndexedInputs = make([]interface{}, 0)
		indexedInputs    = make([]interface{}, 0)
		nonIndexedArgs   abi.Arguments
		indexedArgs      abi.Arguments
	)

	for i, arg := range event.Inputs {
		if arg.Indexed {
			indexedArgs = append(indexedArgs, arg)
			indexedInputs = append(indexedInputs, args[i])
		} else {
			nonIndexedArgs = append(nonIndexedArgs, arg)
			nonIndexedInputs = append(nonIndexedInputs, args[i])
		}
	}

	packedArguments, err := nonIndexedArgs.Pack(nonIndexedInputs...)
	if err != nil {
		return nil, nil, err
	}

	topics := make([]common.Hash, 0, len(indexedArgs)+1)
	if !event.Anonymous {
		topics = append(topics, event.ID)
	}

	// Pack indexed topics
	for _, input := range indexedInputs {
		topic, err := packTopic(input)
		if err != nil {
			return nil, nil, err
		}
		topics = append(topics, topic)
	}

	return topics, packedArguments, nil
}

// packTopic packs a single indexed argument into a topic hash
func packTopic(value interface{}) (common.Hash, error) {
	switch v := value.(type) {
	case common.Address:
		return common.BytesToHash(v.Bytes()), nil
	case common.Hash:
		return v, nil
	case []byte:
		return common.BytesToHash(crypto.Keccak256(v)), nil
	case string:
		return common.BytesToHash(crypto.Keccak256([]byte(v))), nil
	default:
		// For other types, try to ABI encode and hash
		return common.Hash{}, fmt.Errorf("unsupported indexed type: %T", value)
	}
}
