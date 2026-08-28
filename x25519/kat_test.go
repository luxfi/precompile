// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package x25519

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func kat(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	require.Len(tb, b, 32)
	return b
}

func call(tb testing.TB, op byte, args ...[]byte) ([]byte, uint64, error) {
	tb.Helper()
	in := []byte{op}
	for _, a := range args {
		in = append(in, a...)
	}
	return X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, 1<<20, true)
}

// basepointU is the Curve25519 base point u = 9 (RFC 7748 section 4.1).
const basepointU = "0900000000000000000000000000000000000000000000000000000000000000"

// TestKAT_RFC7748_ScalarMult pins the two scalar-multiplication vectors from
// RFC 7748 section 5.2. Both were reproduced with an independent Montgomery
// ladder before being written here.
func TestKAT_RFC7748_ScalarMult(t *testing.T) {
	for _, v := range []struct{ name, scalar, u, want string }{
		{
			name:   "vector 1",
			scalar: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			u:      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			want:   "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		},
		{
			name:   "vector 2",
			scalar: "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			u:      "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			want:   "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			out, _, err := call(t, OpScalarMult, kat(t, v.scalar), kat(t, v.u))
			require.NoError(t, err)
			require.Equal(t, kat(t, v.want), out)
		})
	}
}

// TestKAT_RFC7748_DiffieHellman pins section 6.1: both public keys and the
// shared secret are published constants, so both directions are covered.
func TestKAT_RFC7748_DiffieHellman(t *testing.T) {
	const (
		alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
		alicePub  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
		bobPriv   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
		bobPub    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
		shared    = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	)

	ap, _, err := call(t, OpBasepoint, kat(t, alicePriv))
	require.NoError(t, err)
	require.Equal(t, kat(t, alicePub), ap, "Alice's published public key")

	bp, _, err := call(t, OpBasepoint, kat(t, bobPriv))
	require.NoError(t, err)
	require.Equal(t, kat(t, bobPub), bp, "Bob's published public key")

	// Basepoint must be exactly ScalarMult against u = 9: two code paths, one
	// answer. A divergence here is a silent key-agreement failure.
	viaMult, _, err := call(t, OpScalarMult, kat(t, alicePriv), kat(t, basepointU))
	require.NoError(t, err)
	require.Equal(t, ap, viaMult)

	sa, _, err := call(t, OpScalarMult, kat(t, alicePriv), kat(t, bobPub))
	require.NoError(t, err)
	sb, _, err := call(t, OpScalarMult, kat(t, bobPriv), kat(t, alicePub))
	require.NoError(t, err)
	require.Equal(t, kat(t, shared), sa, "published shared secret")
	require.Equal(t, sa, sb, "Diffie-Hellman must commute")
}

// TestKAT_RFC7748_Iterated runs the section 5.2 iteration. The value after one
// round is published; running a thousand rounds and matching the published
// thousand-round value exercises the ladder across a thousand distinct scalars
// and points, which no single vector can.
func TestKAT_RFC7748_Iterated(t *testing.T) {
	k := kat(t, basepointU)
	u := kat(t, basepointU)

	for i := 1; i <= 1000; i++ {
		out, _, err := call(t, OpScalarMult, k, u)
		require.NoError(t, err, "iteration %d", i)
		u, k = k, out
		switch i {
		case 1:
			require.Equal(t,
				kat(t, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), k,
				"RFC 7748 iteration 1")
		case 1000:
			require.Equal(t,
				kat(t, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), k,
				"RFC 7748 iteration 1000")
		}
	}
}

// lowOrderU lists every u-coordinate whose X25519 output is all zeros for any
// clamped scalar: the seven canonical ones from RFC 7748 section 6.1's security
// note plus the five that differ only in the ignored high bit. Each was checked
// against an independent ladder.
var lowOrderU = []string{
	"0000000000000000000000000000000000000000000000000000000000000000", // 0
	"0100000000000000000000000000000000000000000000000000000000000000", // 1
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 4
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p-1
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p+1
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", // high bit set
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// TestRefusal_LowOrderPoint is the contributory-behaviour refusal. A peer who
// sends one of these forces the shared secret to zero no matter what scalar the
// caller holds, so accepting it would let anyone fix both sides of a key
// agreement. Returning zero bytes and no error would be worse than useless:
// the caller would key a cipher with a constant.
func TestRefusal_LowOrderPoint(t *testing.T) {
	scalar := kat(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	for _, u := range lowOrderU {
		t.Run(u[:12], func(t *testing.T) {
			out, gas, err := call(t, OpScalarMult, scalar, kat(t, u))
			require.ErrorIs(t, err, ErrDHFailed, "low-order point must be refused")
			require.Nil(t, out)
			require.Equal(t, uint64(1<<20-GasScalarMult), gas, "gas is charged before the check")
		})
	}

	// Every one of them is also refused as a basepoint scalar? No: the scalar is
	// clamped, so any 32 bytes are a legal scalar. Basepoint must succeed.
	for _, u := range lowOrderU {
		out, _, err := call(t, OpBasepoint, kat(t, u))
		require.NoError(t, err, "any 32 bytes is a valid scalar once clamped")
		require.Len(t, out, 32)
	}
}

// TestRefusal_Length covers short, empty and nil for both operations, and pins
// that trailing bytes past the fixed operand width are ignored rather than
// refused -- so calldata is NOT a unique identifier for a call. A caller
// deduplicating by calldata hash must trim first.
func TestRefusal_Length(t *testing.T) {
	scalar := kat(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	u := kat(t, basepointU)

	for _, tc := range []struct {
		name string
		in   []byte
		err  error
	}{
		{"nil", nil, ErrInvalidInput},
		{"empty", []byte{}, ErrInvalidInput},
		{"scalarmult op only", []byte{OpScalarMult}, ErrInvalidInput},
		{"basepoint op only", []byte{OpBasepoint}, ErrInvalidInput},
		{"scalarmult one short", append([]byte{OpScalarMult}, append(append([]byte{}, scalar...), u[:31]...)...), ErrInvalidInput},
		{"basepoint one short", append([]byte{OpBasepoint}, scalar[:31]...), ErrInvalidInput},
		{"unknown op 0x00", []byte{0x00, 1, 2, 3}, ErrInvalidOp},
		{"unknown op 0x03", []byte{0x03, 1, 2, 3}, ErrInvalidOp},
		{"unknown op 0xff", []byte{0xFF}, ErrInvalidOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := X25519Precompile.Run(nil, common.Address{}, ContractAddress, tc.in, 1<<20, true)
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, out)
		})
	}

	// Trailing data is ignored, not refused: two encodings, one result.
	short, _, err := call(t, OpBasepoint, scalar)
	require.NoError(t, err)
	long, _, err := call(t, OpBasepoint, scalar, make([]byte, 97))
	require.NoError(t, err)
	require.Equal(t, short, long, "trailing bytes are ignored by design")

	shortM, _, err := call(t, OpScalarMult, scalar, u)
	require.NoError(t, err)
	longM, _, err := call(t, OpScalarMult, scalar, u, []byte{0xAA})
	require.NoError(t, err)
	require.Equal(t, shortM, longM)
}

// TestGas_Schedule covers every arm of RequiredGas and the deduction in Run.
// The zero-gas arm is only safe because the matching Run arm refuses: a call
// that costs nothing must also do nothing.
func TestGas_Schedule(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"scalarmult", []byte{OpScalarMult}, GasScalarMult},
		{"basepoint", []byte{OpBasepoint}, GasBasepoint},
		{"unknown 0x00", []byte{0x00}, 0},
		{"unknown 0x03", []byte{0x03}, 0},
		{"unknown 0xff", []byte{0xFF}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, X25519Precompile.RequiredGas(tc.in))
		})
	}

	// Work is a fixed-size ladder, so the price must not move with input size.
	long := append([]byte{OpScalarMult}, make([]byte, 1<<16)...)
	require.Equal(t, uint64(GasScalarMult), X25519Precompile.RequiredGas(long))

	// Every zero-priced input must refuse in Run: no work is bought for free.
	for _, in := range [][]byte{nil, {}, {0x00}, {0x03}, {0xFF}, {0x00, 1, 2}} {
		require.Zero(t, X25519Precompile.RequiredGas(in))
		out, _, err := X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.Error(t, err, "a zero-gas input must not execute")
		require.Nil(t, out)
	}
}

func TestGas_Deduction(t *testing.T) {
	scalar := kat(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	in := append([]byte{OpBasepoint}, scalar...)

	_, left, err := X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBasepoint+13, true)
	require.NoError(t, err)
	require.Equal(t, uint64(13), left)

	_, left, err = X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBasepoint, true)
	require.NoError(t, err)
	require.Zero(t, left)

	_, left, err = X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBasepoint-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, left)

	_, _, err = X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

// TestReadOnlyIsIrrelevant: the precompile touches no state, so the readOnly
// flag and the caller address must not change the answer.
func TestReadOnlyIsIrrelevant(t *testing.T) {
	scalar := kat(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	in := append([]byte{OpBasepoint}, scalar...)

	ro, _, err := X25519Precompile.Run(nil, common.Address{}, ContractAddress, in, 1<<20, true)
	require.NoError(t, err)
	rw, _, err := X25519Precompile.Run(nil, common.HexToAddress("0xdead"), common.Address{}, in, 1<<20, false)
	require.NoError(t, err)
	require.Equal(t, ro, rw)
}

// --- module + config ----------------------------------------------------

func TestModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, X25519Precompile, Module.Contract)
	require.NotNil(t, Module.Configurator)
	require.Equal(t,
		common.HexToAddress("0x0000000000000000000000000000000000009203"),
		ContractAddress)
}

func TestConfigurator_Surface(t *testing.T) {
	c := &configurator{}
	require.IsType(t, &Config{}, c.MakeConfig())
	require.NoError(t, c.Configure(nil, nil, nil, nil))
}

func TestConfig_Surface(t *testing.T) {
	c := &Config{}
	require.Equal(t, ConfigKey, c.Key())
	require.Nil(t, c.Timestamp())
	require.False(t, c.IsDisabled())
	require.NoError(t, c.Verify(nil))

	ts := uint64(7)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(8)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil))
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module),
		"a second registration must be refused, which is what init() panics on")
}
