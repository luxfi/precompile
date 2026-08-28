// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"errors"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// spy records whether the underlying function ran and what it was handed.
type spy struct {
	calls    int
	input    []byte
	readOnly bool
	gas      uint64
	caller   common.Address
	addr     common.Address
}

func (s *spy) fn() RunStatefulPrecompileFunc {
	return func(_ AccessibleState, caller, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) ([]byte, uint64, error) {
		s.calls++
		s.input = input
		s.readOnly = readOnly
		s.gas = suppliedGas
		s.caller = caller
		s.addr = addr
		return []byte("ok"), suppliedGas, nil
	}
}

func dispatchState() AccessibleState {
	return NewMockAccessibleState(NewMockStateDB(), NewMockBlockContext(1, 1000))
}

// ---------------------------------------------------------------------------
// Refusal is what burns the gas
// ---------------------------------------------------------------------------

// TestRefusalPathsAlwaysReturnAnError is the property that makes an unknown
// selector cost the caller everything rather than nothing.
//
// Run hands back the FULL suppliedGas on every refusal. That is not a refund:
// the EVM host discards remainingGas and sets gas = 0 whenever a stateful
// precompile returns any error other than ErrExecutionReverted
// (geth core/vm/evm.go, Call and StaticCall). The error is therefore the only
// thing standing between a bad selector and a free call. A refusal path that
// ever returns a nil error would hand the caller its whole gas back AND run
// nothing — this test is what catches that.
func TestRefusalPathsAlwaysReturnAnError(t *testing.T) {
	sel := []byte{0x01, 0x02, 0x03, 0x04}
	var s spy
	fn := NewStatefulPrecompileFunction(sel, s.fn())

	off := NewStatefulPrecompileFunctionWithActivator(
		[]byte{0x09, 0x09, 0x09, 0x09}, s.fn(), func(AccessibleState) bool { return false },
	)

	c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{fn, off})
	require.NoError(t, err)

	cases := []struct {
		name  string
		input []byte
	}{
		{"empty input, no fallback", []byte{}},
		{"nil input, no fallback", nil},
		{"one byte", []byte{0x01}},
		{"three bytes, a prefix of a real selector", sel[:3]},
		{"unknown selector", []byte{0xff, 0xff, 0xff, 0xff}},
		{"unknown selector with payload", []byte{0xff, 0xff, 0xff, 0xff, 0xde, 0xad}},
		{"deactivated selector", []byte{0x09, 0x09, 0x09, 0x09}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := s.calls
			ret, remaining, err := c.Run(dispatchState(), testCaller, testAddr, tc.input, 1000, false)

			require.Error(t, err, "a refusal MUST return an error — a nil error here is a free call")
			require.Nil(t, ret)
			require.Equal(t, uint64(1000), remaining,
				"Run reports gas unspent; the host zeroes it because err != nil")
			require.Equal(t, before, s.calls, "no underlying function may run on a refusal")
		})
	}
}

// ---------------------------------------------------------------------------
// Selector framing
// ---------------------------------------------------------------------------

func TestSelectorIsExactlyFourBytesAndInputIsTheRemainder(t *testing.T) {
	sel := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	var s spy
	c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, s.fn()),
	})
	require.NoError(t, err)

	payload := []byte{0x01, 0x02, 0x03}
	_, _, err = c.Run(dispatchState(), testCaller, testAddr, append(append([]byte{}, sel...), payload...), 1000, false)
	require.NoError(t, err)
	require.Equal(t, 1, s.calls)
	// An off-by-one in input[:SelectorLen] / input[SelectorLen:] shifts every
	// ABI argument by a byte — every decoded value would be wrong, silently.
	require.Equal(t, payload, s.input)
}

func TestSelectorExactlyFourBytesGivesEmptyInput(t *testing.T) {
	sel := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	var s spy
	c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, s.fn()),
	})
	require.NoError(t, err)

	_, _, err = c.Run(dispatchState(), testCaller, testAddr, sel, 1000, false)
	require.NoError(t, err)
	require.Equal(t, 1, s.calls)
	require.Empty(t, s.input)
}

func TestSelectorMatchIsExactNotPrefix(t *testing.T) {
	// A 5th byte belongs to the arguments, never to the selector; and a 3-byte
	// truncation of a real selector must not dispatch to it.
	sel := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	var s spy
	c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, s.fn()),
	})
	require.NoError(t, err)

	_, _, err = c.Run(dispatchState(), testCaller, testAddr, []byte{0xaa, 0xbb, 0xcc}, 1000, false)
	require.Error(t, err)
	require.Zero(t, s.calls)

	// Two selectors sharing three bytes must stay distinct.
	near := []byte{0xaa, 0xbb, 0xcc, 0xde}
	var s2 spy
	c2, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, s.fn()),
		NewStatefulPrecompileFunction(near, s2.fn()),
	})
	require.NoError(t, err)

	_, _, err = c2.Run(dispatchState(), testCaller, testAddr, near, 1000, false)
	require.NoError(t, err)
	require.Equal(t, 1, s2.calls)
	require.Zero(t, s.calls, "the near-miss selector must not reach the other function")
}

// ---------------------------------------------------------------------------
// Fallback
// ---------------------------------------------------------------------------

func TestFallbackOnlyRunsOnEmptyInput(t *testing.T) {
	var fb, fn spy
	sel := []byte{0x01, 0x02, 0x03, 0x04}
	c, err := NewStatefulPrecompileContract(fb.fn(), []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, fn.fn()),
	})
	require.NoError(t, err)

	// Non-empty input never reaches the fallback, even when the selector misses.
	_, _, err = c.Run(dispatchState(), testCaller, testAddr, []byte{0xff, 0xff, 0xff, 0xff}, 1000, false)
	require.Error(t, err)
	require.Zero(t, fb.calls, "an unknown selector must not silently fall back")

	// Short input never reaches the fallback either.
	_, _, err = c.Run(dispatchState(), testCaller, testAddr, []byte{0x01}, 1000, false)
	require.Error(t, err)
	require.Zero(t, fb.calls)

	// Empty input does.
	_, _, err = c.Run(dispatchState(), testCaller, testAddr, nil, 1000, false)
	require.NoError(t, err)
	require.Equal(t, 1, fb.calls)
	require.Nil(t, fb.input, "the fallback is handed nil, not the empty selector")
	require.Zero(t, fn.calls)
}

// ---------------------------------------------------------------------------
// readOnly must survive dispatch
// ---------------------------------------------------------------------------

func TestReadOnlyAndCallIdentityReachTheFunction(t *testing.T) {
	// A precompile can only refuse a write in a STATICCALL if the flag actually
	// arrives. Dropping readOnly in dispatch would let every precompile write
	// from a static context while each one's own guard still looks correct.
	sel := []byte{0x01, 0x02, 0x03, 0x04}
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	self := common.HexToAddress("0x2222222222222222222222222222222222222222")

	for _, readOnly := range []bool{true, false} {
		var s spy
		c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
			NewStatefulPrecompileFunction(sel, s.fn()),
		})
		require.NoError(t, err)

		_, _, err = c.Run(dispatchState(), caller, self, sel, 4242, readOnly)
		require.NoError(t, err)
		require.Equal(t, readOnly, s.readOnly)
		require.Equal(t, uint64(4242), s.gas)
		require.Equal(t, caller, s.caller)
		require.Equal(t, self, s.addr)
	}
}

func TestFallbackAlsoReceivesReadOnly(t *testing.T) {
	for _, readOnly := range []bool{true, false} {
		var fb spy
		c, err := NewStatefulPrecompileContract(fb.fn(), nil)
		require.NoError(t, err)
		_, _, err = c.Run(dispatchState(), testCaller, testAddr, nil, 77, readOnly)
		require.NoError(t, err)
		require.Equal(t, readOnly, fb.readOnly)
		require.Equal(t, uint64(77), fb.gas)
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestDuplicateSelectorRejectedRegardlessOfActivation(t *testing.T) {
	// Two functions on one selector is ambiguous dispatch. An activator does not
	// disambiguate it — activation is evaluated after the map lookup, so the
	// loser would simply never be reachable.
	sel := []byte{0x07, 0x07, 0x07, 0x07}
	var a, b spy
	_, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, a.fn()),
		NewStatefulPrecompileFunctionWithActivator(sel, b.fn(), func(AccessibleState) bool { return false }),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicated function selector")
}

func TestActivationIsConsultedOnEveryCallNotCached(t *testing.T) {
	// Activation can flip with chain state. Caching the first answer would keep
	// a precompile alive after it was meant to go dark.
	sel := []byte{0x01, 0x02, 0x03, 0x04}
	active := false
	var s spy
	c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunctionWithActivator(sel, s.fn(), func(AccessibleState) bool { return active }),
	})
	require.NoError(t, err)

	_, _, err = c.Run(dispatchState(), testCaller, testAddr, sel, 1000, false)
	require.Error(t, err)

	active = true
	_, _, err = c.Run(dispatchState(), testCaller, testAddr, sel, 1000, false)
	require.NoError(t, err)
	require.Equal(t, 1, s.calls)

	active = false
	_, _, err = c.Run(dispatchState(), testCaller, testAddr, sel, 1000, false)
	require.Error(t, err)
	require.Equal(t, 1, s.calls)
}

func TestExecuteErrorReachesTheCallerUnwrapped(t *testing.T) {
	// A precompile's own sentinel must survive dispatch, or callers cannot tell
	// out-of-gas from invalid-input.
	sel := []byte{0x01, 0x02, 0x03, 0x04}
	sentinel := errors.New("precompile said no")
	c, err := NewStatefulPrecompileContract(nil, []*StatefulPrecompileFunction{
		NewStatefulPrecompileFunction(sel, func(AccessibleState, common.Address, common.Address, []byte, uint64, bool) ([]byte, uint64, error) {
			return nil, 5, sentinel
		}),
	})
	require.NoError(t, err)

	_, remaining, err := c.Run(dispatchState(), testCaller, testAddr, sel, 1000, false)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, uint64(5), remaining, "dispatch must not rewrite the function's gas accounting")
}

// ---------------------------------------------------------------------------
// The two panics in utils.go
// ---------------------------------------------------------------------------

// TestPanickingHelpersAreInitTimeOnly documents why the panics in
// CalculateFunctionSelector and ParseABI are correct rather than a chain-halt
// hazard.
//
// Neither helper is called anywhere in this module outside tests (verified by
// call-site search), and every downstream call site is a package-level
// initialiser over a string literal:
//
//	var setAdminSignature = contract.CalculateFunctionSelector("setAdmin(address)")
//	var WarpABI           = contract.ParseABI(WarpRawABI)
//
// Those run at init(), before the first block, on constants fixed at compile
// time. A malformed signature is therefore a boot failure — loud and immediate,
// which is what you want — and cannot be reached from calldata. The tests below
// pin that they DO panic, because a helper that silently returned a wrong
// selector would mis-dispatch every call to that precompile forever.
func TestPanickingHelpersAreInitTimeOnly(t *testing.T) {
	require.Panics(t, func() { CalculateFunctionSelector("not a signature") })
	require.Panics(t, func() { ParseABI("{not json}") })

	// And they do not panic on the shapes an init-time constant actually takes.
	require.Len(t, CalculateFunctionSelector("setAdmin(address)"), SelectorLen)
	parsed := ParseABI(`[{"type":"function","name":"setAdmin","inputs":[{"name":"a","type":"address"}]}]`)
	_, ok := parsed.Methods["setAdmin"]
	require.True(t, ok, "ParseABI must produce a usable ABI, not just avoid panicking")
}

func TestCalculateFunctionSelectorRejectsSignaturesThatWouldMisDispatch(t *testing.T) {
	// The regex is the only thing stopping a typo'd signature from producing a
	// plausible-looking 4-byte selector that matches nothing on the Solidity
	// side. Each of these differs from a valid signature by one character.
	for _, bad := range []string{
		"transfer(address,)",
		"transfer(,address)",
		"transfer(address,,uint256)",
		"transfer address,uint256)",
		"",
	} {
		require.Panics(t, func() { CalculateFunctionSelector(bad) }, "%q must be refused", bad)
	}
}

func TestCalculateFunctionSelectorRejectsAnythingAroundTheSignature(t *testing.T) {
	// keccak hashes the WHOLE string. A signature with junk attached produces a
	// selector no Solidity caller will ever send, and the precompile is dead on
	// arrival with no error anywhere. The validator must therefore match the
	// entire input, not merely contain a signature.
	valid := "transfer(address,uint256)"
	require.Len(t, CalculateFunctionSelector(valid), SelectorLen)

	for _, bad := range []string{
		" " + valid,
		valid + " ",
		"JUNK " + valid,
		valid + " // trailing comment",
		"\n" + valid + "\n",
		"\t" + valid,
		"a(b) c(d)",
		valid + valid,
	} {
		require.Panics(t, func() { CalculateFunctionSelector(bad) },
			"%q contains a signature but is not one", bad)
	}
}

func TestCalculateFunctionSelectorIgnoresNothingItAccepts(t *testing.T) {
	// Whatever the validator accepts is hashed verbatim, so acceptance and
	// hashing must agree on the same bytes: two accepted strings that differ at
	// all must produce different selectors.
	a := CalculateFunctionSelector("transfer(address,uint256)")
	b := CalculateFunctionSelector("transfer(uint256,address)")
	c := CalculateFunctionSelector("Transfer(address,uint256)")
	require.NotEqual(t, a, b, "argument order must change the selector")
	require.NotEqual(t, a, c, "case must change the selector")
}
