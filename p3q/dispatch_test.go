// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// exact returns a copy of b whose capacity equals its length.
//
// This matters more than it looks. A Go slice expression s[a:b] panics
// only when b exceeds cap(s), not len(s) — so an input assembled with
// append, which leaves spare capacity, lets a MISSING bounds check
// read uninitialised bytes and carry on. The test then passes while
// the guard it was meant to exercise is absent. Calldata handed to a
// precompile by the EVM has no spare capacity, so the same input
// panics in production, and a panic in geth's precompile dispatch has
// no recover: it halts every validator processing the transaction.
//
// Every refusal test below therefore submits an exact-capacity slice.
func exact(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// verdictExact is verdict() over an exact-capacity input, and it
// requires that no input can panic the precompile.
func verdictExact(t *testing.T, input []byte) bool {
	t.Helper()
	in := exact(input)
	var out bool
	require.NotPanics(t, func() { out = verdict(t, in) },
		"a %d-byte input must be refused, never panic", len(in))
	return out
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// wire assembles the P3Q calldata from parts without re-deriving any
// length, so a test can declare a length that disagrees with the bytes
// it supplies.
func wire(kind, mode uint8, sigLen uint32, sig []byte, pkLen uint32, pk, hash []byte) []byte {
	out := []byte{kind, mode}
	out = append(out, be32(sigLen)...)
	out = append(out, sig...)
	out = append(out, be32(pkLen)...)
	out = append(out, pk...)
	out = append(out, hash...)
	return exact(out)
}

// TestNoInputPanicsTheVerifier sweeps every truncation of a fully
// valid call, at exact capacity. Each prefix must produce a verdict,
// never a panic — this is the property that keeps a malformed
// transaction from halting the chain.
func TestNoInputPanicsTheVerifier(t *testing.T) {
	k := katSets()[0]
	full := exact(EncodeInput(k.mode, mustHex(t, k.sig), mustHex(t, k.pub), mustHex(t, k.msgHexVar)))
	require.True(t, verdictExact(t, full), "control: the whole input verifies")

	// Every prefix: the boundaries between fields are where an
	// off-by-one lives, and there is no reason to guess which.
	for n := 0; n <= len(full); n++ {
		in := exact(full[:n])
		require.NotPanics(t, func() {
			out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress,
				in, P3QVerifyPrecompile.RequiredGas(in), true)
			require.NoError(t, err)
			require.Len(t, out, 32)
			if n < len(full) {
				require.Equal(t, byte(0), out[31], "prefix of length %d must not verify", n)
			}
		}, "prefix of length %d panicked", n)
	}
}

// TestKindDispatchIsBinding is the test the reserved-kind branches
// actually need. Checking that a reserved kind rejects GARBAGE proves
// nothing — garbage rejects under every kind. The question is whether
// the kind byte is load-bearing, so submit material that WOULD verify
// under KindPulsar and require that it does not verify under any other
// kind.
//
// If the dispatch fell through, a rollup could present a Pulsar
// signature as a Corona or Magnetar attestation, and a consumer
// switching on the kind byte would be told a lattice-threshold
// signature had been checked by a verifier that never ran.
func TestKindDispatchIsBinding(t *testing.T) {
	k := katSets()[1] // ML-DSA-65
	sig, pk, msg := mustHex(t, k.sig), mustHex(t, k.pub), mustHex(t, k.msgHexVar)

	require.True(t, verdictExact(t, EncodeInputKind(KindPulsar, k.mode, sig, pk, msg)),
		"control: this material verifies under KindPulsar")

	for _, kind := range []uint8{KindCorona, KindMagnetar} {
		require.False(t, verdictExact(t, EncodeInputKind(kind, k.mode, sig, pk, msg)),
			"kind 0x%02x is reserved: valid Pulsar material must not verify under it", kind)
	}

	// And every byte that names no kind at all.
	named := map[uint8]bool{KindPulsar: true, KindCorona: true, KindMagnetar: true}
	for b := 0; b < 256; b++ {
		if named[uint8(b)] {
			continue
		}
		require.False(t, verdictExact(t, EncodeInputKind(uint8(b), k.mode, sig, pk, msg)),
			"unknown kind 0x%02x must not verify valid Pulsar material", b)
	}
}

// TestModeDispatchIsBinding is the same argument one field along. A
// mode byte outside {0x44, 0x65, 0x87} must refuse material that
// verifies under its true mode — never silently fall back to a default
// parameter set that happens to fit.
func TestModeDispatchIsBinding(t *testing.T) {
	k := katSets()[1] // ML-DSA-65, the set a careless default would pick
	sig, pk, msg := mustHex(t, k.sig), mustHex(t, k.pub), mustHex(t, k.msgHexVar)

	require.True(t, verdictExact(t, EncodeInput(k.mode, sig, pk, msg)), "control")

	known := map[uint8]bool{ModeMLDSA44: true, ModeMLDSA65: true, ModeMLDSA87: true}
	for b := 0; b < 256; b++ {
		if known[uint8(b)] {
			continue
		}
		require.False(t, verdictExact(t, EncodeInput(uint8(b), sig, pk, msg)),
			"mode 0x%02x names no parameter set: ML-DSA-65 material must not verify under it", b)
	}
}

// TestDeclaredLengthsMustBeExact pins that both length fields are
// checked for equality, not merely for fitting. A parser that accepted
// "at least the right size" would let a caller pad a field and shift
// every later offset, so the bytes the verifier sees are chosen by the
// length field rather than by the layout.
func TestDeclaredLengthsMustBeExact(t *testing.T) {
	k := katSets()[0] // ML-DSA-44
	sig, pk, msg := mustHex(t, k.sig), mustHex(t, k.pub), mustHex(t, k.msgHexVar)
	sz, pkSz := uint32(k.sigSize), uint32(k.pkSize)

	require.True(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, pkSz, pk, msg)), "control")

	// Signature length declared larger than the parameter set allows,
	// with the bytes to back it up.
	over := append(append([]byte{}, sig...), 0x00)
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz+1, over, pkSz, pk, msg)),
		"an oversized declared signature length must be refused")

	// ...and smaller, likewise backed by bytes.
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz-1, sig[:k.sigSize-1], pkSz, pk, msg)),
		"an undersized declared signature length must be refused")

	// Public key length declared larger, with bytes present.
	overPK := append(append([]byte{}, pk...), 0x00)
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, pkSz+1, overPK, msg)),
		"an oversized declared public key length must be refused")

	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, pkSz-1, pk[:k.pkSize-1], msg)),
		"an undersized declared public key length must be refused")

	// Zero-length declarations, structurally padded out to clear
	// MinInputLength.
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, 0, nil, pkSz, pk, msg)))
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, 0, nil, msg)))
}

// TestDeclaredLengthsCannotOverrun pins the bounds half: a length
// field that claims more bytes than the calldata holds must be
// refused before the slice is taken. Exact capacity is what makes this
// test meaningful.
func TestDeclaredLengthsCannotOverrun(t *testing.T) {
	k := katSets()[0]
	sig, pk, msg := mustHex(t, k.sig), mustHex(t, k.pub), mustHex(t, k.msgHexVar)
	sz, pkSz := uint32(k.sigSize), uint32(k.pkSize)

	for _, claim := range []uint32{sz + 1, sz + 1000, 1 << 30, ^uint32(0)} {
		require.False(t, verdictExact(t, wire(KindPulsar, k.mode, claim, sig, pkSz, pk, msg)),
			"declared signature length %d exceeds the calldata", claim)
	}
	for _, claim := range []uint32{pkSz + 1, 1 << 30, ^uint32(0)} {
		require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, claim, pk, msg)),
			"declared public key length %d exceeds the calldata", claim)
	}

	// Too few bytes left to hold the public-key length field at all.
	short := []byte{KindPulsar, k.mode}
	short = append(short, be32(sz)...)
	short = append(short, sig...)
	short = append(short, 0x00, 0x00, 0x00) // three bytes: one short of the field
	require.GreaterOrEqual(t, len(short), MinInputLength)
	require.False(t, verdictExact(t, short))

	// Message hash truncated to 31 bytes, and absent entirely.
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, pkSz, pk, msg[:31])))
	require.False(t, verdictExact(t, wire(KindPulsar, k.mode, sz, sig, pkSz, pk, nil)))
}

// TestOutputWordIsFreshEachCall pins the documented promise that a
// caller may mutate the returned slice. If the true and false words
// were package-level singletons, one caller scribbling on a verdict
// would corrupt every later caller's — a verification result flipping
// underneath consumers that never touched the verifier.
func TestOutputWordIsFreshEachCall(t *testing.T) {
	k := katSets()[1]
	good := exact(EncodeInput(k.mode, mustHex(t, k.sig), mustHex(t, k.pub), mustHex(t, k.msgHexVar)))
	bad := exact(EncodeInput(k.mode, make([]byte, k.sigSize), mustHex(t, k.pub), mustHex(t, k.msgHexVar)))

	call := func(in []byte) []byte {
		out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress,
			in, P3QVerifyPrecompile.RequiredGas(in), true)
		require.NoError(t, err)
		return out
	}

	first := call(good)
	require.Equal(t, byte(1), first[31])
	for i := range first {
		first[i] = 0xAA
	}
	require.Equal(t, byte(1), call(good)[31], "a mutated result must not affect the next call")

	firstFalse := call(bad)
	require.Equal(t, byte(0), firstFalse[31])
	for i := range firstFalse {
		firstFalse[i] = 0xAA
	}
	require.Equal(t, byte(0), call(bad)[31])
	require.Equal(t, byte(1), call(good)[31])
}

// TestVerifyNamesTheFieldItRefused pins that the standalone entry
// point reports WHICH precondition failed. Run collapses every failure
// into a false word by design, so Verify's typed errors are the only
// place a caller can learn that a size was wrong rather than a
// signature — and the only place a test can tell a real size check
// from an incidental downstream rejection.
func TestVerifyNamesTheFieldItRefused(t *testing.T) {
	k := katSets()[1]
	pk, sig, msg := mustHex(t, k.pub), mustHex(t, k.sig), mustHex(t, k.msgHexVar)
	require.NoError(t, Verify(k.mode, pk, sig, msg), "control")

	require.EqualError(t, Verify(k.mode, pk[:k.pkSize-1], sig, msg), "p3q: groupPubKey size mismatch")
	require.EqualError(t, Verify(k.mode, append(pk, 0), sig, msg), "p3q: groupPubKey size mismatch")

	require.EqualError(t, Verify(k.mode, pk, sig[:k.sigSize-1], msg), "p3q: pulsarSig size mismatch")
	require.EqualError(t, Verify(k.mode, pk, append(sig, 0), msg), "p3q: pulsarSig size mismatch")

	require.EqualError(t, Verify(k.mode, pk, sig, msg[:31]), "p3q: messageHash must be 32 bytes")
	require.EqualError(t, Verify(k.mode, pk, sig, append(msg, 0)), "p3q: messageHash must be 32 bytes")

	// A genuine cryptographic rejection must be distinguishable from
	// all of the above.
	require.EqualError(t, Verify(k.mode, pk, make([]byte, k.sigSize), msg),
		"p3q: FIPS 204 ML-DSA verify rejected")
}
