// Package main exports all Lux precompiles as a C shared library.
//
// Build:
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libluxprecompile.so ./bindings/cabi/
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libluxprecompile.dylib ./bindings/cabi/  # macOS
//
// This produces libluxprecompile.{so,dylib} + libluxprecompile.h
// Rust (hanzod), Python, and TypeScript can bind to it.
//
// The dispatch pattern: one Run function handles all registered precompiles.
// Precompile lookup is by 20-byte hex address via the module registry.
package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"unsafe"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"

	// Blank imports trigger init() → RegisterModule for every precompile.
	_ "github.com/luxfi/precompile/ai"
	_ "github.com/luxfi/precompile/blake3"
	_ "github.com/luxfi/precompile/cggmp21"
	_ "github.com/luxfi/precompile/dead"
	_ "github.com/luxfi/precompile/dex"
	// REMOVED: ecies — secret keys in calldata are public on-chain
	_ "github.com/luxfi/precompile/fhe"
	_ "github.com/luxfi/precompile/frost"
	_ "github.com/luxfi/precompile/graph"
	_ "github.com/luxfi/precompile/hpke"
	_ "github.com/luxfi/precompile/mldsa"
	_ "github.com/luxfi/precompile/mlkem"
	_ "github.com/luxfi/precompile/pqcrypto"
	_ "github.com/luxfi/precompile/ring"
	_ "github.com/luxfi/precompile/ringtail"
	_ "github.com/luxfi/precompile/slhdsa"
	_ "github.com/luxfi/precompile/sr25519"
	_ "github.com/luxfi/precompile/zk"
)

// gasEstimator is the optional interface for precompiles that expose RequiredGas.
type gasEstimator interface {
	RequiredGas(input []byte) uint64
}

// parseAddress decodes a hex address string (with or without 0x prefix) into common.Address.
func parseAddress(addrPtr *C.char, addrLen C.int) (common.Address, bool) {
	raw := C.GoStringN(addrPtr, addrLen)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if len(raw) != 40 {
		return common.Address{}, false
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return common.Address{}, false
	}
	return common.BytesToAddress(b), true
}

// lux_precompile_run dispatches a precompile call by address.
//
// Returns 0 on success, -1 if address not found, -2 on execution error.
// On success, output is written to the output buffer and outputLen is set.
// remainingGas is updated with gas left after execution.
//
//export lux_precompile_run
func lux_precompile_run(
	address *C.char, addrLen C.int,
	input *C.char, inputLen C.int,
	gas C.uint64_t,
	output *C.char, outputLen *C.int,
	remainingGas *C.uint64_t,
) C.int {
	addr, ok := parseAddress(address, addrLen)
	if !ok {
		return -1
	}

	mod, found := modules.GetPrecompileModuleByAddress(addr)
	if !found {
		return -1
	}

	inputBytes := C.GoBytes(unsafe.Pointer(input), inputLen)
	suppliedGas := uint64(gas)

	// Run with nil AccessibleState + zero caller/addr for stateless precompiles.
	// Precompiles that need state (DEX, AI mining, dead) will panic on nil state;
	// recover and return -3 (needs state) to distinguish from execution errors.
	var (
		ret     []byte
		gasLeft uint64
		runErr  error
		panicked bool
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		ret, gasLeft, runErr = mod.Contract.Run(nil, common.Address{}, addr, inputBytes, suppliedGas, true)
	}()
	if panicked {
		return -3 // precompile requires EVM state
	}
	if runErr != nil {
		return -2
	}

	*outputLen = C.int(len(ret))
	*remainingGas = C.uint64_t(gasLeft)
	if len(ret) > 0 {
		C.memcpy(unsafe.Pointer(output), unsafe.Pointer(&ret[0]), C.size_t(len(ret)))
	}

	return 0
}

// precompileEntry is the JSON structure for lux_precompile_list.
type precompileEntry struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

// lux_precompile_list writes a JSON array of {address, name} for all registered precompiles.
//
// Returns 0 on success, -1 if buffer too small (bufLen is set to required size).
//
//export lux_precompile_list
func lux_precompile_list(buf *C.char, bufLen *C.int) C.int {
	mods := modules.RegisteredModules()
	entries := make([]precompileEntry, len(mods))
	for i, m := range mods {
		entries[i] = precompileEntry{
			Address: m.Address.Hex(),
			Name:    m.ConfigKey,
		}
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return -2
	}

	needed := C.int(len(data))
	if *bufLen < needed {
		*bufLen = needed
		return -1
	}

	*bufLen = needed
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	return 0
}

// lux_precompile_required_gas returns the gas cost estimate for a precompile call.
//
// Returns the gas cost, or 0 if the precompile is not found or does not implement RequiredGas.
//
//export lux_precompile_required_gas
func lux_precompile_required_gas(
	address *C.char, addrLen C.int,
	input *C.char, inputLen C.int,
) C.uint64_t {
	addr, ok := parseAddress(address, addrLen)
	if !ok {
		return 0
	}

	mod, found := modules.GetPrecompileModuleByAddress(addr)
	if !found {
		return 0
	}

	estimator, ok := mod.Contract.(gasEstimator)
	if !ok {
		return 0
	}

	inputBytes := C.GoBytes(unsafe.Pointer(input), inputLen)
	return C.uint64_t(estimator.RequiredGas(inputBytes))
}

func main() {}
