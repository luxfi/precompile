// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// secp256k1N is the curve order; s and n-s are the two halves of a malleable
// signature pair.
var secp256k1N, _ = new(big.Int).SetString(
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

// malleate flips a signature to its equally-valid twin: (r, s, v) → (r, n-s, v^1).
func malleate(sig []byte) []byte {
	out := make([]byte, len(sig))
	copy(out, sig)
	s := new(big.Int).SetBytes(sig[32:64])
	flipped := new(big.Int).Sub(secp256k1N, s)
	copy(out[32:64], common.LeftPadBytes(flipped.Bytes(), 32))
	out[64] ^= 1
	return out
}

// TestRegistrar_MalleatedSignatureCannotForgeASecondSigner is the real
// malleability check: secp256k1 admits two signatures per (key, digest), so a
// caller can always produce a byte-different copy of an operator's signature.
// Deduplication is by RECOVERED ADDRESS, not by signature bytes, so the twin
// must either be rejected outright or counted as the same signer — never as a
// second operator meeting a threshold of two.
func TestRegistrar_MalleatedSignatureCannotForgeASecondSigner(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t), newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 2))

	payload := buildRegisterPayload(42, "x", true, common.Address{})
	digest := registrarDigest(SelectorRegisterChain, governanceNonce(state.db), payload)

	sig, err := crypto.Sign(digest, ops[0].key)
	require.NoError(t, err)
	twin := malleate(sig)
	require.NotEqual(t, sig, twin, "the twin must be byte-different or this test proves nothing")

	_, _, err = runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(payload, [][]byte{sig, twin}), 1_000_000)
	require.Error(t, err, "one operator met a threshold of two using a malleated copy")
	require.True(t,
		err == ErrDuplicateSigner || err == ErrUnauthorized || err == ErrInvalidSignatureBytes,
		"unexpected error for a malleated pair: %v", err)

	// Whatever the reason, nothing was written.
	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	_, ok := r.Get(42)
	require.False(t, ok)
	require.Equal(t, uint64(0), governanceNonce(state.db))
}

func TestRegistrar_DedupIsByRecoveredAddressNotSignatureBytes(t *testing.T) {
	// Direct check on verifyMultisig: two byte-different signatures that recover
	// to one operator must not both count.
	db := newRegState()
	present := newOperator(t)
	absent := newOperator(t)
	require.NoError(t, SeedGovernance(db, []common.Address{present.addr, absent.addr}, 2))

	payload := []byte{1, 2, 3}
	digest := registrarDigest(SelectorRegisterChain, 0, payload)
	sig, err := crypto.Sign(digest, present.key)
	require.NoError(t, err)

	// Only ONE of the two operators signed. Its malleated twin must not stand in
	// for the operator who did not.
	err = verifyMultisig(db, SelectorRegisterChain, payload, [][]byte{sig, malleate(sig)})
	require.Error(t, err, "a single key must never satisfy a threshold of two")
}

// TestVerifyMultisig_RefusesAWrongLengthSignature covers the internal guard that
// Run's decoder can never trip: decodeSigs only ever emits 65-byte slices, so
// this is reachable only by a direct caller — and it must still fail closed
// rather than hand a short buffer to Ecrecover.
func TestVerifyMultisig_RefusesAWrongLengthSignature(t *testing.T) {
	db := newRegState()
	op := newOperator(t)
	require.NoError(t, SeedGovernance(db, []common.Address{op.addr}, 1))

	for _, n := range []int{0, 1, argSigLen - 1, argSigLen + 1, 200} {
		err := verifyMultisig(db, SelectorRegisterChain, []byte{1}, [][]byte{make([]byte, n)})
		require.ErrorIs(t, err, ErrInvalidSignatureBytes, "%d-byte signature", n)
	}
}

func TestVerifyMultisig_RefusesWhenGovernanceIsUnseeded(t *testing.T) {
	db := newRegState()
	op := newOperator(t)
	digest := registrarDigest(SelectorRegisterChain, 0, []byte{1})
	sig, err := crypto.Sign(digest, op.key)
	require.NoError(t, err)

	require.ErrorIs(t,
		verifyMultisig(db, SelectorRegisterChain, []byte{1}, [][]byte{sig}),
		ErrUnauthorized)
}

// ---------------------------------------------------------------------------
// Out of gas on every selector
// ---------------------------------------------------------------------------

func TestRegistrar_EverySelectorRefusesInsufficientGas(t *testing.T) {
	cases := []struct {
		name string
		sel  byte
		body []byte
		fee  uint64
	}{
		{"register", SelectorRegisterChain,
			appendSigs(buildRegisterPayload(1, "a", true, common.Address{}), nil), GasRegisterChain},
		{"unregister", SelectorUnregisterChain,
			appendSigs(buildUnregisterPayload(1), nil), GasUnregisterChain},
		{"setGateway", SelectorSetGateway,
			appendSigs(buildSetGatewayPayload(1, common.Address{}), nil), GasSetGateway},
		{"getCount", SelectorGetCount, nil, GasGetCount},
		{"getChain", SelectorGetChain, make([]byte, 8), GasGetChain},
		{"getNonce", SelectorGetNonce, nil, GasGetNonce},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := newRegAS()
			ops := []*operator{newOperator(t)}
			require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

			_, remaining, err := runRegistrar(t, state, c.sel, c.body, c.fee-1)
			require.ErrorIs(t, err, contract.ErrOutOfGas)
			require.Zero(t, remaining, "an out-of-gas refusal must report no gas left")

			// Zero gas is the same refusal, never a free call.
			_, remaining, err = runRegistrar(t, state, c.sel, c.body, 0)
			require.ErrorIs(t, err, contract.ErrOutOfGas)
			require.Zero(t, remaining)

			// Exactly the fee gets past the gas check.
			_, _, err = runRegistrar(t, state, c.sel, c.body, c.fee)
			require.NotErrorIs(t, err, contract.ErrOutOfGas)
		})
	}
}

func TestRegistrar_OutOfGasWritesNothing(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	payload := buildRegisterPayload(1, "one", true, common.Address{})
	body := appendSigs(payload, signByAll(t, state, ops, SelectorRegisterChain, payload))

	_, _, err := runRegistrar(t, state, SelectorRegisterChain, body, GasRegisterChain-1)
	require.ErrorIs(t, err, contract.ErrOutOfGas)

	ret, _, err := runRegistrar(t, state, SelectorGetCount, nil, 100_000)
	require.NoError(t, err)
	require.Equal(t, uint64(0), binary.BigEndian.Uint64(ret[24:32]))
	require.Equal(t, uint64(0), governanceNonce(state.db))
}

// ---------------------------------------------------------------------------
// encodeChain / row shape
// ---------------------------------------------------------------------------

func TestEncodeChain_EncodesTheVirtualFlag(t *testing.T) {
	// A virtual (non-EVM) chain must encode 0x00, not "anything falsy". The
	// caller reads this byte to decide whether an eth_chainId exists.
	virtual := encodeChain(Chain{ID: 900001, Name: "solana", EVM: false,
		GatewayAt: common.HexToAddress("0xaa")})
	nameLen := int(virtual[4])
	require.Equal(t, byte(0x00), virtual[5+nameLen])

	native := encodeChain(Chain{ID: 1, Name: "ethereum", EVM: true})
	nameLen = int(native[4])
	require.Equal(t, byte(0x01), native[5+nameLen])
}

func TestEncodeChain_EmptyName(t *testing.T) {
	out := encodeChain(Chain{ID: 3, Name: "", EVM: true, GatewayAt: common.HexToAddress("0xbb")})
	require.Equal(t, byte(0), out[4])
	require.Len(t, out, 4+1+0+1+argAddressSize)
	require.Equal(t, uint32(3), binary.BigEndian.Uint32(out[0:4]))
	require.Equal(t, common.HexToAddress("0xbb"), common.BytesToAddress(out[6:26]))
}

func TestRegistrar_GetChainRoundTripsAVirtualChain(t *testing.T) {
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	p := buildRegisterPayload(900002, "bitcoin", false, common.Address{})
	_, _, err := runRegistrar(t, state, SelectorRegisterChain,
		appendSigs(p, signByAll(t, state, ops, SelectorRegisterChain, p)), 1_000_000)
	require.NoError(t, err)

	idx := make([]byte, 8)
	ret, _, err := runRegistrar(t, state, SelectorGetChain, idx, 100_000)
	require.NoError(t, err)

	require.Equal(t, uint32(900002), binary.BigEndian.Uint32(ret[0:4]))
	nameLen := int(ret[4])
	require.Equal(t, "bitcoin", string(ret[5:5+nameLen]))
	require.Equal(t, byte(0x00), ret[5+nameLen], "a virtual chain must not report EVM")
}

// ---------------------------------------------------------------------------
// Storage layout
// ---------------------------------------------------------------------------

// TestSlotRow_StrideIsThreeWords pins the on-disk row stride. It is a consensus
// constant: every registered chain's rows move if it changes, so a node built
// with a different stride reads garbage for chains a peer reads correctly. The
// third word is reserved and currently only written (zeroed) on unregister,
// which is why an arithmetic slip here is otherwise invisible.
func TestSlotRow_StrideIsThreeWords(t *testing.T) {
	for i := uint64(0); i < 4; i++ {
		hdr, name, res := slotRow(i)
		require.Equal(t, registrySlot(1+i*3+0), hdr)
		require.Equal(t, registrySlot(1+i*3+1), name)
		require.Equal(t, registrySlot(1+i*3+2), res)
	}

	// Row 0 starts immediately after the count word.
	hdr, _, _ := slotRow(0)
	require.Equal(t, registrySlot(1), hdr)
	require.NotEqual(t, slotCount(), hdr)
}

func TestSlotRow_RowsNeverOverlap(t *testing.T) {
	// All three words of every row must be distinct from all three words of
	// every other row, and from the count word. A stride smaller than the row
	// width makes one row's reserved slot the next row's header.
	owner := map[common.Hash]string{slotCount(): "count"}
	for i := uint64(0); i < 64; i++ {
		hdr, name, res := slotRow(i)
		for label, s := range map[string]common.Hash{"header": hdr, "name": name, "reserved": res} {
			key := label
			if prev, dup := owner[s]; dup {
				t.Fatalf("row %d %s collides with %s at slot %s", i, key, prev, s.Hex())
			}
			owner[s] = "row " + string(rune('0'+i%10)) + " " + key
		}
	}
}

func TestUnregister_DoesNotDisturbNeighbouringRows(t *testing.T) {
	// Unregister zeroes all three words of the trailing row, including the
	// reserved one. If the stride were too small, that zeroing would land on the
	// next row's header and erase a live chain.
	state := newRegAS()
	ops := []*operator{newOperator(t)}
	require.NoError(t, SeedGovernance(state.db, operatorAddrs(ops), 1))

	ids := []ChainID{11, 22, 33}
	for _, id := range ids {
		p := buildRegisterPayload(id, "c", true, common.HexToAddress("0xaa"))
		_, _, err := runRegistrar(t, state, SelectorRegisterChain,
			appendSigs(p, signByAll(t, state, ops, SelectorRegisterChain, p)), 1_000_000)
		require.NoError(t, err)
	}

	// Snapshot every word of row 0 before removing row 1.
	hdr0, name0, res0 := slotRow(0)
	before := []common.Hash{
		state.db.GetState(BridgeGatewayCanonicalAddress, hdr0),
		state.db.GetState(BridgeGatewayCanonicalAddress, name0),
		state.db.GetState(BridgeGatewayCanonicalAddress, res0),
	}

	u := buildUnregisterPayload(22)
	_, _, err := runRegistrar(t, state, SelectorUnregisterChain,
		appendSigs(u, signByAll(t, state, ops, SelectorUnregisterChain, u)), 1_000_000)
	require.NoError(t, err)

	require.Equal(t, before[0], state.db.GetState(BridgeGatewayCanonicalAddress, hdr0))
	require.Equal(t, before[1], state.db.GetState(BridgeGatewayCanonicalAddress, name0))
	require.Equal(t, before[2], state.db.GetState(BridgeGatewayCanonicalAddress, res0))

	r := NewStateRegistry(state.db, BridgeGatewayCanonicalAddress)
	for _, id := range []ChainID{11, 33} {
		_, ok := r.Get(id)
		require.True(t, ok, "chain %d was lost", id)
	}
}

func TestRegistryAndGovernanceNamespacesAreDisjoint(t *testing.T) {
	// The two prefixes are 24 bytes each and must not produce a shared slot,
	// or an operator address would be readable as a registry row.
	used := map[common.Hash]string{}
	for i := uint64(0); i < 256; i++ {
		used[registrySlot(i)] = "registry"
	}
	for i := uint64(0); i < 256; i++ {
		s := govSlot(i)
		require.NotContains(t, used, s, "govSlot(%d) collides with a registry slot", i)
	}
	require.NotContains(t, used, nonceSlot())
}

// ---------------------------------------------------------------------------
// Config.Equal
// ---------------------------------------------------------------------------

func TestConfig_EqualCoversEveryField(t *testing.T) {
	ts := uint64(10)
	other := uint64(11)
	base := func() *Config {
		return &Config{
			Upgrade:   precompileconfig.Upgrade{BlockTimestamp: &ts},
			Operators: []string{"0x1111111111111111111111111111111111111111"},
			Threshold: 1,
		}
	}

	require.True(t, base().Equal(base()))

	differing := map[string]*Config{
		"timestamp": {
			Upgrade:   precompileconfig.Upgrade{BlockTimestamp: &other},
			Operators: base().Operators, Threshold: 1,
		},
		"disable": {
			Upgrade:   precompileconfig.Upgrade{BlockTimestamp: &ts, Disable: true},
			Operators: base().Operators, Threshold: 1,
		},
		"threshold": {
			Upgrade:   precompileconfig.Upgrade{BlockTimestamp: &ts},
			Operators: base().Operators, Threshold: 2,
		},
		"operator count": {
			Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts},
			Operators: []string{
				"0x1111111111111111111111111111111111111111",
				"0x2222222222222222222222222222222222222222",
			},
			Threshold: 1,
		},
		"operator identity": {
			Upgrade:   precompileconfig.Upgrade{BlockTimestamp: &ts},
			Operators: []string{"0x2222222222222222222222222222222222222222"},
			Threshold: 1,
		},
	}
	for name, cfg := range differing {
		require.False(t, base().Equal(cfg), "Equal ignored a difference in %s", name)
		require.False(t, cfg.Equal(base()), "Equal is not symmetric for %s", name)
	}

	// Operator ORDER is part of identity here, so a reordering is not equal.
	reordered := &Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts},
		Operators: []string{
			"0x2222222222222222222222222222222222222222",
			"0x1111111111111111111111111111111111111111",
		},
		Threshold: 1,
	}
	pair := &Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts},
		Operators: []string{
			"0x1111111111111111111111111111111111111111",
			"0x2222222222222222222222222222222222222222",
		},
		Threshold: 1,
	}
	require.False(t, pair.Equal(reordered))
}

func TestConfig_EqualRejectsAForeignType(t *testing.T) {
	require.False(t, (&Config{}).Equal(otherPrecompileConfig{}),
		"Equal must reject a different precompile's config by type")
	require.False(t, (&Config{}).Equal(nil))
}

type otherPrecompileConfig struct{}

func (otherPrecompileConfig) Key() string                               { return "other" }
func (otherPrecompileConfig) Timestamp() *uint64                        { return nil }
func (otherPrecompileConfig) IsDisabled() bool                          { return false }
func (otherPrecompileConfig) Equal(precompileconfig.Config) bool        { return false }
func (otherPrecompileConfig) Verify(precompileconfig.ChainConfig) error { return nil }
