// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// 0x9996 (PositionManager) composes the 0x9999 kernel, whose LP-commit ERC-20 leg
// moves token value with the PRECOMPILE ITSELF as msg.sender. geth binds the running
// contract as `addr`, and only DELEGATECALL makes addr differ from 0x9996 — CALL and
// CALLCODE both pass self. So the `addr != positionManagerAddr` check is the guard
// that stops a delegatecalling contract committing liquidity as the wrong
// msg.sender, which would break the same custody-conservation invariant 0x9999 rests
// on. It is tested here as the authorization control it is.

// pgSelectors is every 0x9996 selector, grouped by what it does, so the guards below
// can be asserted across the WHOLE surface rather than one representative.
func pgSelectors() (lifecycle map[string]uint32, reads map[string]uint32) {
	lifecycle = map[string]uint32{
		"mint":              SelectorPMMint,
		"openPosition":      SelectorPMOpenPosition,
		"increaseLiquidity": SelectorPMIncreaseLiquidity,
		"placeLimit":        SelectorPMPlaceLimit,
		"decreaseLiquidity": SelectorPMDecreaseLiquidity,
		"burn":              SelectorPMBurn,
		"closePosition":     SelectorPMClosePosition,
		"cancelLimit":       SelectorPMCancelLimit,
		"modifyPosition":    SelectorPMModifyPosition,
		"collect":           SelectorPMCollect,
	}
	reads = map[string]uint32{
		"positionsOf":  SelectorPMPositionsOf,
		"positionInfo": SelectorPMPositionInfo,
	}
	return
}

// pgLifecycleBody builds the shared 320-byte lifecycle calldata.
func pgLifecycleBody(key PoolKey, lower, upper int32, delta *big.Int, salt byte, side byte) []byte {
	out := make([]byte, 0, 320)
	out = append(out, EncodePoolKeyABI(key)...)
	out = append(out, encodeInt24Word(lower)...)
	out = append(out, encodeInt24Word(upper)...)

	d := make([]byte, 32)
	if delta.Sign() < 0 {
		// two's-complement sign extension for a negative int256
		mod := new(big.Int).Lsh(big.NewInt(1), 256)
		new(big.Int).Add(mod, delta).FillBytes(d)
	} else {
		delta.FillBytes(d)
	}
	out = append(out, d...)

	s := make([]byte, 32)
	s[31] = salt
	out = append(out, s...)

	sd := make([]byte, 32)
	sd[31] = side
	return append(out, sd...)
}

// TestPositionManagerRefusesDelegatecall is the guard's own test: every selector,
// lifecycle and read alike, must refuse when `addr` is not 0x9996. A single selector
// that slipped through would run the 0x9999 commit leg under a foreign identity.
func TestPositionManagerRefusesDelegatecall(t *testing.T) {
	h := newSettleHarness(t)
	before := fingerprint(h.state.stateDB)
	pm := &PositionManagerContract{}

	// Addresses a DELEGATECALL would present: the caller's own contract, another
	// precompile, and the zero address.
	foreign := []common.Address{
		common.HexToAddress("0xDEADBEEF00000000000000000000000000000001"),
		common.HexToAddress(DEXPoolManagerAddress),
		common.HexToAddress(DEXQuoterAddress),
		{},
	}

	lifecycle, reads := pgSelectors()
	body := pgLifecycleBody(h.key, -60, 60, big.NewInt(1000), 1, 0)

	for _, addr := range foreign {
		for name, sel := range lifecycle {
			_, _, err := pm.Run(h.state, h.caller, addr, append(selectorBytes(sel), body...), 10_000_000, false)
			require.ErrorIsf(t, err, ErrSettleWrongContext,
				"%s at addr %s must be refused: only a self CALL may run 0x9996", name, addr.Hex())
		}
		for name, sel := range reads {
			_, _, err := pm.Run(h.state, h.caller, addr, append(selectorBytes(sel), make([]byte, 64)...), 10_000_000, true)
			require.ErrorIsf(t, err, ErrSettleWrongContext,
				"read %s at addr %s must be refused too", name, addr.Hex())
		}
	}

	require.Equal(t, before, fingerprint(h.state.stateDB),
		"a delegatecall-shaped call must not mutate state before being refused")

	// The guard is an equality on the module's own address, so the canonical address
	// must be ACCEPTED past this point (it may still fail later for other reasons,
	// but never with ErrSettleWrongContext).
	self := common.HexToAddress(DEXPositionManagerAddress)
	for name, sel := range lifecycle {
		_, _, err := pm.Run(h.state, h.caller, self, append(selectorBytes(sel), body...), 10_000_000, false)
		if err != nil {
			require.NotErrorIsf(t, err, ErrSettleWrongContext,
				"%s at the canonical address must pass the context guard", name)
		}
	}
}

// TestPositionManagerRefusesMalformedInput walks the refusal surface: no selector,
// an unknown selector, and every truncation of the shared lifecycle body. None may
// panic — 0x9996 composes the always-on money path.
func TestPositionManagerRefusesMalformedInput(t *testing.T) {
	h := newSettleHarness(t)
	pm := &PositionManagerContract{}
	self := common.HexToAddress(DEXPositionManagerAddress)

	t.Run("shorter than a selector", func(t *testing.T) {
		for n := range 4 {
			_, _, err := pm.Run(h.state, h.caller, self, make([]byte, n), 10_000_000, false)
			require.Errorf(t, err, "a %d-byte input carries no selector", n)
		}
	})

	t.Run("unknown selector", func(t *testing.T) {
		for _, sel := range []uint32{0x00000000, 0xffffffff, 0x12345678} {
			_, _, err := pm.Run(h.state, h.caller, self,
				append(selectorBytes(sel), make([]byte, 320)...), 10_000_000, false)
			require.Errorf(t, err, "selector %#x must be refused", sel)
		}
	})

	t.Run("every truncation of the lifecycle body", func(t *testing.T) {
		lifecycle, _ := pgSelectors()
		body := pgLifecycleBody(h.key, -60, 60, big.NewInt(1000), 1, 0)
		for name, sel := range lifecycle {
			in := append(selectorBytes(sel), body...)
			for cut := 4; cut < len(in); cut += 7 { // stride keeps this quick but dense
				require.NotPanicsf(t, func() {
					_, _, _ = pm.Run(h.state, h.caller, self, in[:cut], 10_000_000, false)
				}, "%s truncated to %d bytes must not panic", name, cut)
			}
		}
	})

	t.Run("zero gas", func(t *testing.T) {
		lifecycle, reads := pgSelectors()
		body := pgLifecycleBody(h.key, -60, 60, big.NewInt(1000), 1, 0)
		for name, sel := range lifecycle {
			require.NotPanicsf(t, func() {
				_, _, err := pm.Run(h.state, h.caller, self, append(selectorBytes(sel), body...), 0, false)
				require.Errorf(t, err, "%s with zero gas must be refused", name)
			}, "%s with zero gas must not panic", name)
		}
		for name, sel := range reads {
			require.NotPanicsf(t, func() {
				_, _, _ = pm.Run(h.state, h.caller, self, append(selectorBytes(sel), make([]byte, 64)...), 0, true)
			}, "read %s with zero gas must not panic", name)
		}
	})
}

// TestPositionManagerLifecycleRefusesReadOnly: the lifecycle selectors move value
// through the 0x9999 kernel, so a static call must be refused. The two reads must
// still work under readOnly — a view that refused in a static call would be useless.
func TestPositionManagerLifecycleRefusesReadOnly(t *testing.T) {
	h := newSettleHarness(t)
	before := fingerprint(h.state.stateDB)
	pm := &PositionManagerContract{}
	self := common.HexToAddress(DEXPositionManagerAddress)

	lifecycle, reads := pgSelectors()
	body := pgLifecycleBody(h.key, -60, 60, big.NewInt(1000), 1, 0)

	for name, sel := range lifecycle {
		_, _, err := pm.Run(h.state, h.caller, self, append(selectorBytes(sel), body...), 10_000_000, true)
		require.Errorf(t, err, "%s must be refused in a read-only call", name)
	}
	require.Equal(t, before, fingerprint(h.state.stateDB),
		"a read-only lifecycle call must not mutate state")

	for name, sel := range reads {
		owner := make([]byte, 32)
		copy(owner[12:], h.caller.Bytes())
		require.NotPanicsf(t, func() {
			_, _, _ = pm.Run(h.state, h.caller, self, append(selectorBytes(sel), owner...), 10_000_000, true)
		}, "read %s must work under readOnly", name)
	}
}

// TestDecodePMLifecycleBoundsAndSigns: the shared lifecycle decoder must refuse
// anything below its fixed 320-byte layout, and must sign-extend the tick and delta
// fields correctly. A delta whose sign is misread turns a burn into a mint.
func TestDecodePMLifecycleBoundsAndSigns(t *testing.T) {
	h := newSettleHarness(t)

	// Below the fixed width: refused, never partially decoded.
	for cut := 0; cut < 320; cut += 11 {
		require.NotPanicsf(t, func() {
			_, err := decodePMLifecycle(make([]byte, cut))
			require.Errorf(t, err, "a %d-byte lifecycle body must be refused", cut)
		}, "a %d-byte body must not panic", cut)
	}

	// A positive delta decodes positive; a negative delta decodes negative with the
	// same magnitude. This is the add-vs-remove decision for real liquidity.
	pos, err := decodePMLifecycle(pgLifecycleBody(h.key, -60, 60, big.NewInt(1_000_000), 7, 0))
	require.NoError(t, err)
	require.Positive(t, pos.delta.Sign(), "a positive delta must decode positive")
	require.Equal(t, int64(1_000_000), pos.delta.Int64())
	require.Equal(t, int32(-60), int32(pos.tickLower), "a negative tick must sign-extend")
	require.Equal(t, int32(60), int32(pos.tickUpper))
	require.Equal(t, byte(7), pos.salt[31])

	neg, err := decodePMLifecycle(pgLifecycleBody(h.key, -120, 120, big.NewInt(-1_000_000), 9, 1))
	require.NoError(t, err)
	require.Negative(t, neg.delta.Sign(), "a negative delta must decode NEGATIVE, not as a huge positive")
	require.Equal(t, int64(-1_000_000), neg.delta.Int64())
	require.Equal(t, int32(-120), int32(neg.tickLower))

	// A zero delta is a no-op request and must decode as exactly zero, not as either
	// sign — the sign is what routes it to add or remove.
	zero, err := decodePMLifecycle(pgLifecycleBody(h.key, 0, 60, big.NewInt(0), 0, 0))
	require.NoError(t, err)
	require.Zero(t, zero.delta.Sign())
}

// TestEncodeSigned256RoundTrip: the signed encoder is how a position delta crosses
// the ABI. Both signs and zero must survive, and a negative must be two's complement
// so a Solidity int256 reads the same number.
func TestEncodeSigned256RoundTrip(t *testing.T) {
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	for _, v := range []int64{0, 1, -1, 1_000_000, -1_000_000, 1 << 40, -(1 << 40)} {
		enc := encodeSigned256(big.NewInt(v))
		require.Len(t, enc, 32, "a signed value is exactly one ABI word")

		got := new(big.Int).SetBytes(enc)
		if v < 0 {
			got.Sub(got, mod) // interpret as two's complement
		}
		require.Equalf(t, v, got.Int64(), "signed %d must survive the round trip", v)
	}
	// A negative value must have its high bit set — that is what makes Solidity read
	// it as negative rather than as an enormous positive.
	require.Equal(t, byte(0xff), encodeSigned256(big.NewInt(-1))[0])
	require.Equal(t, byte(0x00), encodeSigned256(big.NewInt(1))[0])
}

// TestCheckERC20Return pins SafeERC20 return semantics. A token `transfer` may
// return a bool, return nothing at all (the pre-EIP-20 tokens), or return false.
// Only the revert, the false, and the malformed short word are failures. Reading
// "no return data" as failure would break real tokens; reading "false" as success
// would credit a transfer that never moved anything.
func TestCheckERC20Return(t *testing.T) {
	// A revert is a failed transfer, and the underlying error stays wrapped so a
	// caller's errors.Is still reaches it.
	boom := errors.New("execution reverted")
	err := checkERC20Return(nil, boom)
	require.Error(t, err, "a reverted token call must be a failed transfer")
	require.ErrorIs(t, err, boom, "the revert must stay wrapped, not be flattened")

	// Empty return data: legacy tokens that return nothing on success.
	require.NoError(t, checkERC20Return(nil, nil), "no return data must be read as success")
	require.NoError(t, checkERC20Return([]byte{}, nil), "empty return data must be read as success")

	// A 32-byte word of 1 is an explicit true.
	trueWord := make([]byte, 32)
	trueWord[31] = 1
	require.NoError(t, checkERC20Return(trueWord, nil), "an explicit true must be success")

	// A 32-byte zero word is an explicit FALSE and must be a failure — this is the
	// token that "succeeds" without moving anything.
	require.Error(t, checkERC20Return(make([]byte, 32), nil), "an explicit false must be a failure")

	// Any non-zero byte anywhere in the word is truthy, matching Solidity's own
	// non-zero-is-true decoding.
	odd := make([]byte, 32)
	odd[0] = 1
	require.NoError(t, checkERC20Return(odd, nil))

	// Short return data is malformed, not "false" and not "no data": a token that
	// answers with a truncated word is refused rather than guessed at. The whole
	// range 1..31 is refused, so no length can slip through as success.
	for n := 1; n < 32; n++ {
		short := make([]byte, n)
		for i := range short {
			short[i] = 0xff
		}
		require.Errorf(t, checkERC20Return(short, nil),
			"a %d-byte return is malformed and must be refused even though its bytes are non-zero", n)
	}
	// A revert outranks the return data: even a well-formed `true` word alongside an
	// error is a failure.
	require.Error(t, checkERC20Return(trueWord, boom), "a revert wins over a true return word")
}
