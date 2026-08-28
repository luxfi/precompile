// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// This file is package contract_test rather than contract because it imports
// geth's core/vm, which imports contract. An external test package is how that
// cycle is broken, and importing the real VM is the point: the claim under
// test is about what geth actually hands a precompile, so reading it from the
// VM beats restating it in a comment.
package contract_test

import (
	"testing"

	"github.com/luxfi/geth/core/vm"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestCalldataCarriesCallerChosenSpareCapacity is the measurement the Cursor
// is designed against, taken from the VM rather than asserted.
//
// The CALL opcode builds a precompile's input with Memory.GetPtr, which
// returns the two-index slice m.store[offset : offset+size]. So cap is the
// rest of EVM memory, and EVM memory is whatever the caller MSTOREd. A parser
// that reads past its declared input does not panic and does not halt a
// validator — it reads bytes the caller chose and returns a verdict over them.
//
// If geth ever copies the input on the way in, this test fails, and the
// reasoning in cursor.go needs rewriting rather than trusting.
func TestCalldataCarriesCallerChosenSpareCapacity(t *testing.T) {
	m := vm.NewMemory()
	m.Resize(256)
	chosen := make([]byte, 256)
	for i := range chosen {
		chosen[i] = 0xA5
	}
	m.Set(0, 256, chosen) // the attacker's MSTOREs

	// instructions.go opCall, verbatim:
	//   args := scope.Memory.GetPtr(inOffset.Uint64(), inSize.Uint64())
	args := m.GetPtr(0, 8)

	require.Len(t, args, 8, "len is the size the caller declared and paid for")
	require.Greater(t, cap(args), len(args),
		"a precompile's input carries spare capacity — re-read the threat model in cursor.go")
	require.Equal(t, byte(0xA5), args[:16][8],
		"and reading past the declared end yields bytes the caller chose")

	// Poisoned reproduces exactly that shape for use as a fixture.
	fixture := contract.Poisoned(make([]byte, 8), 8)
	require.Len(t, fixture, 8)
	require.Greater(t, cap(fixture), len(fixture))
	require.Equal(t, byte(0xA5), fixture[:16][8])

	// And the cursor refuses what the slice expression allows.
	_, err := contract.Read(args).Bytes(16)
	require.ErrorIs(t, err, contract.ErrShort)
}
