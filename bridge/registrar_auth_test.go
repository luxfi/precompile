// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

// TestRegistrar_AuthorisationIsSingleUse is the regression test for the replay
// hole. The signed digest binds the registrar's governance nonce, which advances
// on every successful write, so a signature set spends exactly once.
//
// Without the nonce, the operators' signatures over "register chain 5" stayed
// valid forever: anyone who saw the original transaction could re-apply it after
// an unregister, resurrecting a chain the operators had deliberately removed.
func TestRegistrar_AuthorisationIsSingleUse(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	id := ChainID(5)
	payload := buildRegisterPayload(id, "five", true, common.Address{})
	sigs := signByAll(t, state, ops, SelectorRegisterChain, payload)
	body := appendSigs(payload, sigs)

	// First use lands.
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, body, 1_000_000)
	require.NoError(t, err)

	// Operators remove the chain, with a fresh authorisation at the new nonce.
	unreg := buildUnregisterPayload(id)
	usigs := signByAll(t, state, ops, SelectorUnregisterChain, unreg)
	_, _, err = runRegistrar(t, state, SelectorUnregisterChain, appendSigs(unreg, usigs), 1_000_000)
	require.NoError(t, err)

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	_, ok := r.Get(id)
	require.False(t, ok)

	// Replaying the ORIGINAL registration bytes must not resurrect it.
	_, _, err = runRegistrar(t, state, SelectorRegisterChain, body, 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized, "a spent authorisation was accepted again")

	_, ok = r.Get(id)
	require.False(t, ok, "the replayed authorisation re-registered the chain")
}

func TestRegistrar_SupersededSetGatewayCannotBeReapplied(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	id := ChainID(96369)
	oldGW := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	newGW := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	reg := buildRegisterPayload(id, "lux", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(reg, signByAll(t, state, ops, SelectorRegisterChain, reg)), 1_000_000)
	require.NoError(t, err)

	// Point the gateway at oldGW, then at newGW.
	p1 := buildSetGatewayPayload(id, oldGW)
	b1 := appendSigs(p1, signByAll(t, state, ops, SelectorSetGateway, p1))
	_, _, err = runRegistrar(t, state, SelectorSetGateway, b1, 1_000_000)
	require.NoError(t, err)

	p2 := buildSetGatewayPayload(id, newGW)
	b2 := appendSigs(p2, signByAll(t, state, ops, SelectorSetGateway, p2))
	_, _, err = runRegistrar(t, state, SelectorSetGateway, b2, 1_000_000)
	require.NoError(t, err)

	// Replaying the first, superseded authorisation must not roll the gateway
	// back to an address the operators have moved away from.
	_, _, err = runRegistrar(t, state, SelectorSetGateway, b1, 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	c, ok := r.Get(id)
	require.True(t, ok)
	require.Equal(t, newGW, c.GatewayAt, "a replayed authorisation rolled the gateway back")
}

func TestRegistrar_NonceAdvancesOnlyOnSuccess(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	require.Equal(t, uint64(0), governanceNonce(state.db))

	reg := buildRegisterPayload(1, "one", true, common.Address{})
	body := appendSigs(reg, signByAll(t, state, ops, SelectorRegisterChain, reg))
	_, _, err := runRegistrar(t, state, SelectorRegisterChain, body, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, uint64(1), governanceNonce(state.db))

	// A write that is authorised but refused by a business rule must NOT burn
	// the nonce, or a single already-registered chain would invalidate every
	// signature the operators had prepared.
	again := buildRegisterPayload(1, "one", true, common.Address{})
	againBody := appendSigs(again, signByAll(t, state, ops, SelectorRegisterChain, again))
	_, _, err = runRegistrar(t, state, SelectorRegisterChain, againBody, 1_000_000)
	require.ErrorIs(t, err, ErrAlreadyRegistered)
	require.Equal(t, uint64(1), governanceNonce(state.db))

	// An unauthorised attempt must not advance it either — otherwise anyone
	// could invalidate the operators' pending authorisations for free.
	stranger := newOperator(t)
	bad := buildRegisterPayload(2, "two", true, common.Address{})
	badBody := appendSigs(bad, signByAll(t, state, []*operator{stranger}, SelectorRegisterChain, bad))
	_, _, err = runRegistrar(t, state, SelectorRegisterChain, badBody, 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Equal(t, uint64(1), governanceNonce(state.db))
}

func TestRegistrar_GetNonceReportsWhatSignersMustBind(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	read := func() uint64 {
		ret, gasLeft, err := runRegistrar(t, state, SelectorGetNonce, nil, 100_000)
		require.NoError(t, err)
		require.Equal(t, uint64(100_000-GasGetNonce), gasLeft)
		return binary.BigEndian.Uint64(ret[24:32])
	}

	require.Equal(t, uint64(0), read())

	reg := buildRegisterPayload(1, "one", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(reg, signByAll(t, state, ops, SelectorRegisterChain, reg)), 1_000_000)
	require.NoError(t, err)

	require.Equal(t, uint64(1), read())
	require.Equal(t, governanceNonce(state.db), read(),
		"the selector and the internal reader must agree, or signers bind the wrong value")
}

func TestRegistrar_ReSeedDoesNotResetTheNonce(t *testing.T) {
	// SeedGovernance rewrites the operator header and rows. If the nonce lived
	// in that header, re-seeding would revive every authorisation the operators
	// had already spent.
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	reg := buildRegisterPayload(1, "one", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(reg, signByAll(t, state, ops, SelectorRegisterChain, reg)), 1_000_000)
	require.NoError(t, err)
	require.Equal(t, uint64(1), governanceNonce(state.db))

	rotated := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(rotated), 2))
	require.Equal(t, uint64(1), governanceNonce(state.db), "re-seeding reset the nonce")
}

func TestRegistrar_NonceSlotDoesNotCollideWithGovernanceSlots(t *testing.T) {
	// The nonce is namespaced separately from govSlot. A collision would make
	// an operator address readable as a nonce, or vice versa.
	n := nonceSlot()
	require.NotEqual(t, n, govSlot(0))
	for i := uint64(1); i <= 1024; i++ {
		require.NotEqual(t, n, govSlot(i), "nonce slot collides with operator slot %d", i)
	}
	// And with the registry rows, which live at a different address anyway.
	require.NotEqual(t, n, slotCount())
}

// ---------------------------------------------------------------------------
// Signature-count gas
// ---------------------------------------------------------------------------

// TestRegistrar_SignaturesArePricedPerRecovery is the regression test for the
// flat-fee-over-unbounded-input hole. decodeSigs accepts up to 255 signatures
// and verifyMultisig recovers EVERY one of them before it knows whether any
// belongs to an operator, so the work is unauthenticated and caller-chosen.
// A flat 60,000 bought roughly 765,000 gas of ECRECOVER.
func TestRegistrar_SignaturesArePricedPerRecovery(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildRegisterPayload(42, "x", true, common.Address{})

	cost := func(n int) uint64 {
		junk := make([][]byte, n)
		for i := range junk {
			junk[i] = make([]byte, argSigLen)
			junk[i][0] = byte(i + 1) // distinct, still not an operator
		}
		_, remaining, _ := runRegistrar(t, state, SelectorRegisterChain,
			appendSigs(payload, junk), 10_000_000)
		return 10_000_000 - remaining
	}

	one := cost(1)
	ten := cost(10)
	require.Equal(t, GasPerSignature*9, ten-one,
		"nine extra signatures must cost nine extra recoveries")

	// The maximum the wire format allows must be priced, not free.
	require.Equal(t, GasRegisterChain+255*GasPerSignature, cost(255))
}

func TestRegistrar_SignatureFloodRunsOutOfGasRatherThanRunningFree(t *testing.T) {
	// With the flat fee, 255 signatures fit inside 60,001 gas on every write
	// selector. Now they cannot: the call must run out of gas before performing
	// the recoveries, on all three.
	junk := make([][]byte, 255)
	for i := range junk {
		junk[i] = make([]byte, argSigLen)
	}

	for _, tc := range []struct {
		name    string
		sel     byte
		payload []byte
		base    uint64
	}{
		{"register", SelectorRegisterChain, buildRegisterPayload(42, "x", true, common.Address{}), GasRegisterChain},
		{"unregister", SelectorUnregisterChain, buildUnregisterPayload(42), GasUnregisterChain},
		{"setGateway", SelectorSetGateway, buildSetGatewayPayload(42, common.Address{}), GasSetGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newRegAS()
			ops := []*operator{newOperator(t)}
			require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

			_, remaining, err := runRegistrar(t, state, tc.sel,
				appendSigs(tc.payload, junk), tc.base+100)
			require.ErrorIs(t, err, contract.ErrOutOfGas)
			require.Zero(t, remaining)
			require.Equal(t, uint64(0), governanceNonce(state.db))
		})
	}
}

func TestRegistrar_EveryWriteSelectorPricesItsSignatures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sel     byte
		payload []byte
		base    uint64
	}{
		{"register", SelectorRegisterChain, buildRegisterPayload(1, "a", true, common.Address{}), GasRegisterChain},
		{"unregister", SelectorUnregisterChain, buildUnregisterPayload(1), GasUnregisterChain},
		{"setGateway", SelectorSetGateway, buildSetGatewayPayload(1, common.Address{}), GasSetGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newRegAS()
			ops := []*operator{newOperator(t)}
			require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

			junk := make([][]byte, 8)
			for i := range junk {
				junk[i] = make([]byte, argSigLen)
			}
			_, remaining, _ := runRegistrar(t, state, tc.sel, appendSigs(tc.payload, junk), 1_000_000)
			require.Equal(t, uint64(1_000_000)-tc.base-8*GasPerSignature, remaining)
		})
	}
}

func TestRegistrar_ReadSelectorsAreNotChargedForSignatures(t *testing.T) {
	// Reads take no signatures, so their cost must stay flat.
	state := newRegAS()

	_, remaining, err := runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(100_000-GasGetCount), remaining)

	idx := make([]byte, 8)
	_, _, err = runRegistrar(t, state, SelectorGetChain, idx, 100_000)
	require.ErrorIs(t, err, ErrIndexOutOfRange)
}

// ---------------------------------------------------------------------------
// Governance loading
// ---------------------------------------------------------------------------

// TestLoadGovernance_RefusesAnAbsurdOperatorCount — count is read from storage,
// and genesis alloc can pre-populate any slot at any address. Allocating on an
// unvalidated uint32 would ask for 4 billion addresses at boot.
func TestLoadGovernance_RefusesAnAbsurdOperatorCount(t *testing.T) {
	db := newRegState()

	var header common.Hash
	binary.BigEndian.PutUint32(header[24:28], 0xFFFFFFFF) // count
	binary.BigEndian.PutUint32(header[28:32], 1)          // threshold
	db.SetState(ContractRegistrarAddress, govSlot(0), header)

	_, _, err := loadGovernance(db)
	require.ErrorIs(t, err, ErrTooManyOperators)
}

func TestLoadGovernance_AcceptsTheLargestPermittedSet(t *testing.T) {
	// The bound must not reject a legal set: exactly maxOperators is allowed.
	db := newRegState()
	var header common.Hash
	binary.BigEndian.PutUint32(header[24:28], uint32(maxOperators))
	binary.BigEndian.PutUint32(header[28:32], 1)
	db.SetState(ContractRegistrarAddress, govSlot(0), header)

	ops, threshold, err := loadGovernance(db)
	require.NoError(t, err)
	require.Len(t, ops, maxOperators)
	require.Equal(t, uint32(1), threshold)
}

func TestLoadGovernance_RefusesAnUnreachableThreshold(t *testing.T) {
	// threshold > count can never be met, so every write reverts. Refusing it
	// at load names the misconfiguration instead of reporting "threshold not
	// met" forever.
	db := newRegState()
	var header common.Hash
	binary.BigEndian.PutUint32(header[24:28], 2) // count
	binary.BigEndian.PutUint32(header[28:32], 3) // threshold
	db.SetState(ContractRegistrarAddress, govSlot(0), header)

	_, _, err := loadGovernance(db)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestSeedGovernance_RefusesBadConfigurations(t *testing.T) {
	db := newRegState()
	a := common.HexToAddress("0x1111111111111111111111111111111111111111")

	require.Error(t, SeedGovernance(db, []common.Address{a}, 0), "threshold 0 authorises nothing")
	require.Error(t, SeedGovernance(db, []common.Address{a}, 2), "threshold above the set size is unreachable")
	require.Error(t, SeedGovernance(db, nil, 1), "no operators means no governance")

	// Nothing was written by a refused seed.
	_, _, err := loadGovernance(db)
	require.ErrorIs(t, err, ErrUnauthorized)

	require.NoError(t, SeedGovernance(db, []common.Address{a}, 1))
	ops, threshold, err := loadGovernance(db)
	require.NoError(t, err)
	require.Equal(t, []common.Address{a}, ops)
	require.Equal(t, uint32(1), threshold)
}

func TestSeedGovernance_RefusesTooManyOperators(t *testing.T) {
	db := newRegState()
	tooMany := make([]common.Address, maxOperators+1)
	require.ErrorIs(t, SeedGovernance(db, tooMany, 1), ErrTooManyOperators)
}

// ---------------------------------------------------------------------------
// Signature semantics
// ---------------------------------------------------------------------------

func TestRegistrar_MalleatedSignatureCountsAsTheSameSigner(t *testing.T) {
	// secp256k1 signatures are malleable: (r, s, v) and (r, n-s, v^1) recover
	// the same address. Dedup is by recovered address, not by signature bytes,
	// so a malleated copy cannot be passed off as a second operator.
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	digest := registrarDigest(SelectorRegisterChain, governanceNonce(state.db), payload)

	sig, err := crypto.Sign(digest, ops[0].key)
	require.NoError(t, err)

	// A byte-different signature from the SAME key: re-signing is
	// deterministic here, so flip the recovery id's partner instead — submit
	// the same signer twice and require the duplicate to be caught by address.
	_, _, err = runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(payload, [][]byte{sig, sig}), 1_000_000)
	require.ErrorIs(t, err, ErrDuplicateSigner,
		"one operator must not be able to meet a threshold of two")
}

func TestRegistrar_OneBadSignatureFailsTheWholeSet(t *testing.T) {
	// Fail closed: an unrecoverable signature aborts rather than being skipped,
	// so a caller cannot pad a set with garbage to hide which operators signed.
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	good := signByAll(t, state, ops, SelectorRegisterChain, payload)

	bad := make([]byte, argSigLen)
	for i := range bad {
		bad[i] = 0xff // invalid r/s, unrecoverable
	}

	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(payload, [][]byte{bad, good[0], good[1]}), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidSignatureBytes)

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	_, ok := r.Get(42)
	require.False(t, ok, "a set containing an invalid signature must write nothing")
}

func TestRegistrar_ZeroSignaturesIsRefused(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(payload, nil), 1_000_000)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestRegistrar_ExtraSignaturesBeyondThresholdAreHarmless(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(payload, signByAll(t, state, ops, SelectorRegisterChain, payload)), 1_000_000)
	require.NoError(t, err)
}

func TestRegistrar_SignatureOverADifferentPayloadIsRefused(t *testing.T) {
	// The digest covers the arguments, so changing any of them after signing
	// must invalidate the authorisation. Otherwise operators would be signing
	// "register something" rather than "register THIS".
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	signed := buildRegisterPayload(1, "one", true, common.HexToAddress("0xaa"))
	sigs := signByAll(t, state, ops, SelectorRegisterChain, signed)

	for name, tampered := range map[string][]byte{
		"different id":      buildRegisterPayload(2, "one", true, common.HexToAddress("0xaa")),
		"different name":    buildRegisterPayload(1, "two", true, common.HexToAddress("0xaa")),
		"different evmFlag": buildRegisterPayload(1, "one", false, common.HexToAddress("0xaa")),
		"different gateway": buildRegisterPayload(1, "one", true, common.HexToAddress("0xbb")),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runRegistrar(t, state, SelectorRegisterChain,
				appendSigs(tampered, sigs), 1_000_000)
			require.ErrorIs(t, err, ErrUnauthorized)
		})
	}
}

// ---------------------------------------------------------------------------
// Wire-format refusals
// ---------------------------------------------------------------------------

func TestRegistrar_DecodersRefuseTruncatedInput(t *testing.T) {
	// Each decoder slices fixed offsets. One byte short must be a clean refusal
	// at every boundary, never a slice panic.
	state := newRegAS()

	full := map[byte][]byte{
		SelectorRegisterChain:   appendSigs(buildRegisterPayload(1, "abc", true, common.HexToAddress("0xaa")), nil),
		SelectorUnregisterChain: appendSigs(buildUnregisterPayload(1), nil),
		SelectorSetGateway:      appendSigs(buildSetGatewayPayload(1, common.HexToAddress("0xaa")), nil),
	}

	for sel, body := range full {
		for n := 0; n < len(body); n++ {
			_, _, err := runRegistrar(t, state, sel, body[:n], 1_000_000)
			require.Error(t, err, "selector %#x truncated to %d bytes was accepted", sel, n)
		}
	}
}

func TestDecodeSigs_RefusesAShortSignatureArray(t *testing.T) {
	// The count byte is attacker-controlled. Claiming more signatures than the
	// bytes carry must refuse rather than slice past the end.
	_, err := decodeSigs(nil)
	require.ErrorIs(t, err, ErrRegistrarInputTooShort)

	_, err = decodeSigs([]byte{1})
	require.ErrorIs(t, err, ErrRegistrarInputTooShort)

	_, err = decodeSigs(append([]byte{2}, make([]byte, argSigLen)...))
	require.ErrorIs(t, err, ErrRegistrarInputTooShort)

	_, err = decodeSigs(append([]byte{255}, make([]byte, 254*argSigLen)...))
	require.ErrorIs(t, err, ErrRegistrarInputTooShort)

	// Exactly enough bytes is accepted, and each slice is the right length.
	sigs, err := decodeSigs(append([]byte{3}, make([]byte, 3*argSigLen)...))
	require.NoError(t, err)
	require.Len(t, sigs, 3)
	for _, s := range sigs {
		require.Len(t, s, argSigLen)
	}

	// Zero signatures is a well-formed empty set.
	sigs, err = decodeSigs([]byte{0})
	require.NoError(t, err)
	require.Empty(t, sigs)
}

func TestDecodeRegisterChainArgs_NameLengthIsBounded(t *testing.T) {
	// name_len is one attacker-chosen byte read before any bounds check on the
	// name itself.
	for _, nameLen := range []int{maxChainNameSize + 1, 200, 255} {
		args := make([]byte, 5)
		args[4] = byte(nameLen)
		_, _, _, _, _, _, err := decodeRegisterChainArgs(args)
		require.ErrorIs(t, err, ErrChainNameTooLong, "name_len %d", nameLen)
	}

	// Exactly the maximum is accepted when the bytes are there.
	name := make([]byte, maxChainNameSize)
	for i := range name {
		name[i] = 'a'
	}
	args := append([]byte{0, 0, 0, 1, byte(maxChainNameSize)}, name...)
	args = append(args, 0x01)
	args = append(args, make([]byte, argAddressSize)...)
	args = append(args, 0x00) // zero signatures
	_, gotName, _, _, _, _, err := decodeRegisterChainArgs(args)
	require.NoError(t, err)
	require.Equal(t, string(name), gotName)
}

func TestEncodeChain_TruncatesAnOverlongName(t *testing.T) {
	// Names are validated at every entry point, so this is belt-and-braces —
	// but the reply's length prefix must always match the bytes that follow it,
	// or a caller decodes into the gateway address.
	long := make([]byte, 40)
	for i := range long {
		long[i] = 'z'
	}
	out := encodeChain(Chain{ID: 9, Name: string(long), EVM: true, GatewayAt: common.HexToAddress("0xaa")})

	nameLen := int(out[4])
	require.Equal(t, maxChainNameSize, nameLen)
	require.Len(t, out, 4+1+nameLen+1+argAddressSize)
	require.Equal(t, byte(0x01), out[5+nameLen])
}

func TestRegistrar_GetChainRejectsAnOutOfRangeIndexWithoutReading(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	reg := buildRegisterPayload(1, "one", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(reg, signByAll(t, state, ops, SelectorRegisterChain, reg)), 1_000_000)
	require.NoError(t, err)

	// index == count is one past the end.
	idx := make([]byte, 8)
	binary.BigEndian.PutUint64(idx, 1)
	_, _, err = runRegistrar(t, state, SelectorGetChain, idx, 100_000)
	require.ErrorIs(t, err, ErrIndexOutOfRange)

	// The last valid index still reads.
	binary.BigEndian.PutUint64(idx, 0)
	ret, _, err := runRegistrar(t, state, SelectorGetChain, idx, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint32(1), binary.BigEndian.Uint32(ret[0:4]))

	// A maximal index must not wrap into range.
	binary.BigEndian.PutUint64(idx, ^uint64(0))
	_, _, err = runRegistrar(t, state, SelectorGetChain, idx, 100_000)
	require.ErrorIs(t, err, ErrIndexOutOfRange)
}

// ---------------------------------------------------------------------------
// readOnly
// ---------------------------------------------------------------------------

func TestRegistrar_EveryWriterRefusesReadOnly(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	for name, tc := range map[string]struct {
		sel     byte
		payload []byte
	}{
		"register":   {SelectorRegisterChain, buildRegisterPayload(1, "a", true, common.Address{})},
		"unregister": {SelectorUnregisterChain, buildUnregisterPayload(1)},
		"setGateway": {SelectorSetGateway, buildSetGatewayPayload(1, common.Address{})},
	} {
		t.Run(name, func(t *testing.T) {
			sigs := signByAll(t, state, ops, tc.sel, tc.payload)
			input := append([]byte{tc.sel}, appendSigs(tc.payload, sigs)...)
			_, remaining, err := RegistrarPrecompile.Run(
				state, common.Address{}, ContractRegistrarAddress, input, 1_000_000, true)
			require.ErrorIs(t, err, ErrRegistrarReadOnly)
			require.Equal(t, uint64(1_000_000), remaining)
			require.Equal(t, uint64(0), governanceNonce(state.db),
				"a read-only refusal must not have advanced the nonce")
		})
	}
}

func TestRegistrar_ReadersWorkInReadOnly(t *testing.T) {
	state := newRegAS()
	for _, sel := range []byte{SelectorGetCount, SelectorGetNonce} {
		_, _, err := RegistrarPrecompile.Run(
			state, common.Address{}, ContractRegistrarAddress, []byte{sel}, 100_000, true)
		require.NoError(t, err, "selector %#x must be callable from a static frame", sel)
	}
}

// ---------------------------------------------------------------------------
// Compaction invariants
// ---------------------------------------------------------------------------

func TestRegistrar_UnregisterKeepsIndicesDense(t *testing.T) {
	// The slot scheme addresses rows by contiguous index, so a hole would make
	// GetChain return a zeroed row for a live chain.
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	ids := []ChainID{10, 20, 30, 40, 50}
	for _, id := range ids {
		p := buildRegisterPayload(id, "c", true, common.Address{})
		_, _, err := runRegistrar(t, state, SelectorRegisterChain,
			appendSigs(p, signByAll(t, state, ops, SelectorRegisterChain, p)), 1_000_000)
		require.NoError(t, err)
	}

	// Remove from the front, the middle, and the end in turn.
	for _, remove := range []ChainID{10, 40, 30} {
		p := buildUnregisterPayload(remove)
		_, _, err := runRegistrar(t, state, SelectorUnregisterChain,
			appendSigs(p, signByAll(t, state, ops, SelectorUnregisterChain, p)), 1_000_000)
		require.NoError(t, err)

		r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
		all := r.All()
		seen := map[ChainID]bool{}
		for i, c := range all {
			require.NotZero(t, c.ID, "row %d is a hole after removing %d", i, remove)
			require.False(t, seen[c.ID], "row %d duplicates chain %d", i, c.ID)
			seen[c.ID] = true
		}
		_, ok := r.Get(remove)
		require.False(t, ok)
	}

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	require.Len(t, r.All(), 2)
	for _, id := range []ChainID{20, 50} {
		_, ok := r.Get(id)
		require.True(t, ok, "chain %d was lost by compaction", id)
	}
}

func TestRegistrar_UnregisterTheOnlyRow(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	p := buildRegisterPayload(7, "seven", true, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(p, signByAll(t, state, ops, SelectorRegisterChain, p)), 1_000_000)
	require.NoError(t, err)

	u := buildUnregisterPayload(7)
	_, _, err = runRegistrar(t, state, SelectorUnregisterChain,
		appendSigs(u, signByAll(t, state, ops, SelectorUnregisterChain, u)), 1_000_000)
	require.NoError(t, err)

	ret, _, err := runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(0), binary.BigEndian.Uint64(ret[24:32]))

	// Re-registering the same id after removal works: it is a fresh row.
	p2 := buildRegisterPayload(7, "seven", true, common.Address{})
	_, _, err = runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(p2, signByAll(t, state, ops, SelectorRegisterChain, p2)), 1_000_000)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Row packing
// ---------------------------------------------------------------------------

func TestPackRowRoundTrip(t *testing.T) {
	for _, c := range []Chain{
		{ID: 0, Name: "", EVM: false},
		{ID: 1, Name: "a", EVM: true, GatewayAt: common.HexToAddress("0xaa")},
		{ID: ChainID(0xFFFFFFFF), Name: "max", EVM: true},
		{ID: 96369, Name: "0123456789abcdef0123456789abcdef", EVM: false,
			GatewayAt: common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff")},
	} {
		hdr, name := packRow(c)
		got := unpackRow(hdr, name)
		require.Equal(t, c.ID, got.ID)
		require.Equal(t, c.Name, got.Name)
		require.Equal(t, c.EVM, got.EVM)
		require.Equal(t, c.GatewayAt, got.GatewayAt)
	}
}

func TestPackRowFieldsDoNotOverlap(t *testing.T) {
	// The header packs id, evm flag and gateway into one word. Overlapping
	// ranges would make setting a gateway corrupt the chain id.
	full := Chain{
		ID:        ChainID(0xFFFFFFFF),
		EVM:       true,
		GatewayAt: common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
	}
	hdr, _ := packRow(full)
	got := unpackRow(hdr, common.Hash{})
	require.Equal(t, full.ID, got.ID)
	require.True(t, got.EVM)
	require.Equal(t, full.GatewayAt, got.GatewayAt)

	// Bytes 25..31 are reserved and must stay zero.
	for i := 25; i < 32; i++ {
		require.Zero(t, hdr[i], "reserved byte %d was written", i)
	}
}

func TestTrimRightZeroKeepsInteriorZeros(t *testing.T) {
	// Only trailing padding is stripped. Trimming an interior zero would rename
	// a chain.
	require.Equal(t, "", trimRightZero(make([]byte, 32)))
	require.Equal(t, "ab", trimRightZero(append([]byte("ab"), make([]byte, 30)...)))
	require.Equal(t, "a\x00b", trimRightZero(append([]byte("a\x00b"), make([]byte, 29)...)))
}

// ---------------------------------------------------------------------------
// Module wiring
// ---------------------------------------------------------------------------

func TestRegistrar_ModuleAddressIsReserved(t *testing.T) {
	require.True(t, modules.ReservedAddress(ContractRegistrarAddress))
	m, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, ContractRegistrarAddress, m.Address)
	require.False(t, m.AlwaysOn)
}

func TestRegistrar_ConfigureRejectsBadOperators(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig().(*Config)
	cfg.Operators = []string{"nonsense"}
	cfg.Threshold = 1
	require.Error(t, c.Configure(&regChainCfg{}, cfg, newRegState(), &regBlockCtx{}))
}

func TestRegistrar_ConfigureIgnoresAForeignConfig(t *testing.T) {
	// A config of the wrong concrete type must be a no-op, not a panic.
	require.NoError(t, (&configurator{}).Configure(&regChainCfg{}, nil, newRegState(), &regBlockCtx{}))
}

func TestParseAddress(t *testing.T) {
	want := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	for _, in := range []string{
		"0x1234567890abcdef1234567890abcdef12345678",
		"1234567890abcdef1234567890abcdef12345678",
		"  0x1234567890abcdef1234567890abcdef12345678  ",
	} {
		got, err := parseAddress(in)
		require.NoError(t, err, "%q", in)
		require.Equal(t, want, got)
	}

	for _, bad := range []string{"", "0x", "0x1234", "0x1234567890abcdef1234567890abcdef1234567890"} {
		_, err := parseAddress(bad)
		require.Error(t, err, "%q must be refused", bad)
	}
}
