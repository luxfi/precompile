// Package examples provides demo programs for all 33 Lux EVM precompiles.
//
// This is a separate Go module to avoid polluting the main precompile module
// with demo-only dependencies. Each subdirectory exercises one precompile
// family and can be run standalone or via the cmd/demo orchestrator.
package examples

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/luxfi/geth/common"
)

// Result captures a single precompile demo execution.
type Result struct {
	Name     string // Human name (e.g. "BLS12-381 G1Add")
	Address  common.Address
	Calldata []byte
	Output   []byte
	GasUsed  uint64
	Pass     bool
	Error    error
}

// Print renders a Result to stdout.
func (r *Result) Print() {
	status := "PASS"
	if !r.Pass {
		status = "FAIL"
	}
	addrShort := strings.TrimLeft(r.Address.Hex(), "0x0")
	if addrShort == "" {
		addrShort = "0"
	}
	fmt.Printf("  [%s] %-35s addr=0x%s  gas=%d\n", status, r.Name, addrShort, r.GasUsed)
	if r.Error != nil {
		fmt.Printf("         error: %v\n", r.Error)
	}
}

// Demo is the interface each precompile demo implements.
type Demo interface {
	// Name returns the category (e.g. "curves", "pq").
	Name() string
	// Run executes all demos in this category and returns results.
	Run() []Result
}

// HexDecode is a helper that panics on invalid hex (test vectors only).
func HexDecode(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad hex: %s: %v", s, err))
	}
	return b
}

// PadLeft pads b to n bytes on the left with zeros.
func PadLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// Uint256 encodes a uint64 as a 32-byte big-endian uint256.
func Uint256(v uint64) []byte {
	return PadLeft(new(big.Int).SetUint64(v).Bytes(), 32)
}

// Uint32BE encodes a uint32 as 4 bytes big-endian.
func Uint32BE(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	return b
}

// Uint16BE encodes a uint16 as 2 bytes big-endian.
func Uint16BE(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

// IsNonZero returns true if any byte in b is non-zero.
func IsNonZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}

// LastByte32IsOne checks if the last byte of a 32-byte result is 1 (common success pattern).
func LastByte32IsOne(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	for i := 0; i < 31; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[31] == 1
}
