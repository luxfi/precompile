// Package harness provides a lightweight test runner for Lux EVM precompiles.
//
// Instead of spinning up a geth dev node (heavy: RPC, networking, block production),
// we call StatefulPrecompiledContract.Run directly. This gives us:
//   - Sub-microsecond dispatch (no RPC overhead)
//   - Deterministic execution (no block timing variance)
//   - Full gas accounting (returned by Run)
//   - Race-detector compatibility (no background goroutines)
//
// For scenarios that need on-chain state (bridge, anchor, compute, DEX), we inject
// a mock StateDB via a mock AccessibleState. For pure-compute precompiles (crypto,
// ZK, hashing), accessibleState is nil — they never touch state.
package harness

import (
	"fmt"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

const DefaultGas = 50_000_000

// Call invokes a precompile directly (no EVM, no RPC).
// Returns output, gas consumed, and any error.
func Call(
	p contract.StatefulPrecompiledContract,
	addr common.Address,
	input []byte,
	readOnly bool,
) (output []byte, gasUsed uint64, err error) {
	return CallWithGas(p, addr, input, DefaultGas, readOnly)
}

// CallWithGas invokes a precompile with a specific gas budget.
func CallWithGas(
	p contract.StatefulPrecompiledContract,
	addr common.Address,
	input []byte,
	gas uint64,
	readOnly bool,
) (output []byte, gasUsed uint64, err error) {
	out, remaining, err := p.Run(nil, common.Address{}, addr, input, gas, readOnly)
	return out, gas - remaining, err
}

// CallStateful invokes a precompile with mock state for write operations.
func CallStateful(
	p contract.StatefulPrecompiledContract,
	state contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	readOnly bool,
) (output []byte, gasUsed uint64, err error) {
	return CallStatefulWithGas(p, state, caller, addr, input, DefaultGas, readOnly)
}

// CallStatefulWithGas invokes a precompile with mock state and specific gas.
func CallStatefulWithGas(
	p contract.StatefulPrecompiledContract,
	state contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	gas uint64,
	readOnly bool,
) (output []byte, gasUsed uint64, err error) {
	out, remaining, err := p.Run(state, caller, addr, input, gas, readOnly)
	return out, gas - remaining, err
}

// MustCall calls a precompile and fails the test on error.
func MustCall(t *testing.T, p contract.StatefulPrecompiledContract, addr common.Address, input []byte, readOnly bool) ([]byte, uint64) {
	t.Helper()
	out, gas, err := Call(p, addr, input, readOnly)
	if err != nil {
		t.Fatalf("precompile call failed: %v", err)
	}
	return out, gas
}

// MustCallStateful calls a stateful precompile and fails the test on error.
func MustCallStateful(
	t *testing.T,
	p contract.StatefulPrecompiledContract,
	state contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	readOnly bool,
) ([]byte, uint64) {
	t.Helper()
	out, gas, err := CallStateful(p, state, caller, addr, input, readOnly)
	if err != nil {
		t.Fatalf("stateful precompile call failed: %v", err)
	}
	return out, gas
}

// AssertSuccess checks that a precompile call succeeded and the last byte of
// a 32-byte return is 1 (the standard "true" encoding).
func AssertSuccess(t *testing.T, out []byte, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("[%s] call error: %v", label, err)
	}
	if len(out) < 32 {
		t.Fatalf("[%s] output too short: %d bytes", label, len(out))
	}
	if out[31] != 1 {
		t.Fatalf("[%s] expected success (last byte = 1), got %d", label, out[31])
	}
}

// PadLeft pads b to n bytes with leading zeros.
func PadLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// Uint32BE encodes v as 4 bytes big-endian.
func Uint32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// Uint256 encodes v as a 32-byte big-endian uint256.
func Uint256(v uint64) []byte {
	b := make([]byte, 32)
	for i := 0; i < 8; i++ {
		b[31-i] = byte(v >> (8 * i))
	}
	return b
}

// GasReport logs gas usage for a precompile operation.
func GasReport(t *testing.T, label string, gasUsed uint64) {
	t.Helper()
	t.Logf("  gas [%s]: %d", label, gasUsed)
}

// FormatGas returns a human-readable gas string.
func FormatGas(gas uint64) string {
	if gas >= 1_000_000 {
		return fmt.Sprintf("%.2fM", float64(gas)/1_000_000)
	}
	if gas >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(gas)/1_000)
	}
	return fmt.Sprintf("%d", gas)
}
