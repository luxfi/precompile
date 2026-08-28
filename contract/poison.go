// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

// Poisoned returns b with spare capacity behind it, filled with a
// recognisable pattern. It is the one definition of what a precompile's input
// actually looks like, and every refusal test in this repository submits one.
//
// The EVM hands a precompile the two-index slice Memory.GetPtr returns
// (instructions.go opCall and its three siblings), and nothing on the path to
// Run copies it. So len is the size the caller declared and paid gas for,
// while cap is the rest of EVM memory — memory that same caller filled with
// MSTORE before making the call.
//
// A fixture built with append also carries spare capacity, but zeroed or
// stale. An over-read into it looks like a harmless run of zeros, and a test
// over such a fixture passes whether or not the bound it means to exercise is
// present. Chosen bytes are what make an over-read visible as an over-read,
// and what make the test's subject the parser rather than the allocator.
//
// It lives in non-test source because nine packages' tests need the same
// definition, and two definitions of the adversary is one too many. Nothing
// in a Run path calls it.
func Poisoned(b []byte, spare int) []byte {
	full := make([]byte, len(b)+spare)
	for i := range full {
		full[i] = 0xA5
	}
	copy(full, b)
	return full[:len(b)]
}
