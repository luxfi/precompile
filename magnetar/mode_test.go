// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/stretchr/testify/require"
)

// allModes is every FIPS 205 parameter set the precompile accepts, in wire
// order. Any mode byte outside this set is unsupported.
var allModes = []uint8{
	ModeSHA2_128s, ModeSHA2_128f,
	ModeSHA2_192s, ModeSHA2_192f,
	ModeSHA2_256s, ModeSHA2_256f,
	ModeSHAKE_128s, ModeSHAKE_128f,
	ModeSHAKE_192s, ModeSHAKE_192f,
	ModeSHAKE_256s, ModeSHAKE_256f,
}

// TestModeParams_AgreeWithLibrary is the one that matters: for every parameter
// set, the sizes the precompile's own table hands to the frame decoder must be
// the sizes the FIPS 205 implementation it dispatches into actually uses, and
// the slhdsa.Mode it selects must be the one the mode byte names. A single
// mis-copied line in the switch -- SHAKE-192s routed to slhdsa.SHAKE_192f, say
// -- would let a frame decode cleanly and then be verified under the wrong
// hash family or the wrong tree height.
func TestModeParams_AgreeWithLibrary(t *testing.T) {
	want := map[uint8]slhdsa.Mode{
		ModeSHA2_128s: slhdsa.SHA2_128s, ModeSHA2_128f: slhdsa.SHA2_128f,
		ModeSHA2_192s: slhdsa.SHA2_192s, ModeSHA2_192f: slhdsa.SHA2_192f,
		ModeSHA2_256s: slhdsa.SHA2_256s, ModeSHA2_256f: slhdsa.SHA2_256f,
		ModeSHAKE_128s: slhdsa.SHAKE_128s, ModeSHAKE_128f: slhdsa.SHAKE_128f,
		ModeSHAKE_192s: slhdsa.SHAKE_192s, ModeSHAKE_192f: slhdsa.SHAKE_192f,
		ModeSHAKE_256s: slhdsa.SHAKE_256s, ModeSHAKE_256f: slhdsa.SHAKE_256f,
	}
	require.Len(t, want, len(allModes))

	seen := map[slhdsa.Mode]uint8{}
	for _, mode := range allModes {
		pkSize, sigSize, baseGas, m, err := getModeParams(mode)
		require.NoError(t, err, "mode=0x%02x", mode)

		require.Equal(t, want[mode], m, "mode=0x%02x routes to the wrong slhdsa parameter set", mode)
		require.Equal(t, slhdsa.GetPublicKeySize(m), pkSize, "mode=0x%02x pubkey size", mode)
		require.Equal(t, slhdsa.GetSignatureSize(m), sigSize, "mode=0x%02x signature size", mode)
		require.Positive(t, baseGas, "mode=0x%02x", mode)

		prev, dup := seen[m]
		require.False(t, dup, "modes 0x%02x and 0x%02x both route to the same parameter set", prev, mode)
		seen[m] = mode
	}
	require.Len(t, seen, len(allModes), "the twelve mode bytes must cover twelve distinct parameter sets")
}

// TestModeParams_RejectsUnknown sweeps all 256 byte values. Every byte that is
// not one of the twelve parameter sets must fall through to the default arm
// with ErrUnsupportedMode and zeroed sizes -- a non-zero size on an unknown
// mode would let the frame decoder compute offsets for a set that does not
// exist.
func TestModeParams_RejectsUnknown(t *testing.T) {
	known := map[uint8]bool{}
	for _, m := range allModes {
		known[m] = true
	}

	for b := 0; b < 256; b++ {
		mode := uint8(b)
		pkSize, sigSize, baseGas, _, err := getModeParams(mode)
		if known[mode] {
			require.NoError(t, err, "mode=0x%02x", mode)
			continue
		}
		require.ErrorIs(t, err, ErrUnsupportedMode, "mode=0x%02x", mode)
		require.Zero(t, pkSize, "mode=0x%02x", mode)
		require.Zero(t, sigSize, "mode=0x%02x", mode)
		require.Zero(t, baseGas, "mode=0x%02x", mode)
	}
}

// TestModeParams_SizeOrdering pins the shape of the FIPS 205 catalogue the
// table encodes: key size grows with the security level and is shared by the
// two hash families; the fast variant of a level always has the larger
// signature; and signature size grows with the security level.
func TestModeParams_SizeOrdering(t *testing.T) {
	size := func(mode uint8) (int, int) {
		pk, sig, _, _, err := getModeParams(mode)
		require.NoError(t, err)
		return pk, sig
	}

	for _, lvl := range []struct {
		name           string
		sha2S, sha2F   uint8
		shakeS, shakeF uint8
		wantPubKeySize int
	}{
		{"128", ModeSHA2_128s, ModeSHA2_128f, ModeSHAKE_128s, ModeSHAKE_128f, SLH128PublicKeySize},
		{"192", ModeSHA2_192s, ModeSHA2_192f, ModeSHAKE_192s, ModeSHAKE_192f, SLH192PublicKeySize},
		{"256", ModeSHA2_256s, ModeSHA2_256f, ModeSHAKE_256s, ModeSHAKE_256f, SLH256PublicKeySize},
	} {
		t.Run(lvl.name, func(t *testing.T) {
			pkS, sigS := size(lvl.sha2S)
			pkF, sigF := size(lvl.sha2F)
			pkKS, sigKS := size(lvl.shakeS)
			pkKF, sigKF := size(lvl.shakeF)

			require.Equal(t, lvl.wantPubKeySize, pkS)
			require.Equal(t, []int{pkS, pkS, pkS}, []int{pkF, pkKS, pkKF},
				"one key size per security level, shared by both hash families")
			require.Equal(t, sigS, sigKS, "SHA2 and SHAKE share a signature size")
			require.Equal(t, sigF, sigKF, "SHA2 and SHAKE share a signature size")
			require.Less(t, sigS, sigF, "the fast variant has the larger signature")
		})
	}

	// Signature size is monotone in the security level, within each variant.
	for _, chain := range [][]uint8{
		{ModeSHA2_128s, ModeSHA2_192s, ModeSHA2_256s},
		{ModeSHA2_128f, ModeSHA2_192f, ModeSHA2_256f},
		{ModeSHAKE_128s, ModeSHAKE_192s, ModeSHAKE_256s},
		{ModeSHAKE_128f, ModeSHAKE_192f, ModeSHAKE_256f},
	} {
		for i := 1; i < len(chain); i++ {
			_, prev := size(chain[i-1])
			_, cur := size(chain[i])
			require.Less(t, prev, cur,
				"%s signature must be smaller than %s", ModeName(chain[i-1]), ModeName(chain[i]))
		}
	}
}

// TestModeName covers every parameter set plus the default arm. The names are
// what on-chain accounting and validator dashboards attribute verifies by, so
// a copy-paste duplicate in the switch would silently merge two parameter sets
// in every report: the test asserts each known mode has a name that is neither
// "unknown" nor shared with any other mode, and it asserts the name spells out
// the hash family and the variant the mode actually selects.
func TestModeName(t *testing.T) {
	want := map[uint8]string{
		ModeSHA2_128s: "Magnetar-SHA2-128s", ModeSHA2_128f: "Magnetar-SHA2-128f",
		ModeSHA2_192s: "Magnetar-SHA2-192s", ModeSHA2_192f: "Magnetar-SHA2-192f",
		ModeSHA2_256s: "Magnetar-SHA2-256s", ModeSHA2_256f: "Magnetar-SHA2-256f",
		ModeSHAKE_128s: "Magnetar-SHAKE-128s", ModeSHAKE_128f: "Magnetar-SHAKE-128f",
		ModeSHAKE_192s: "Magnetar-SHAKE-192s", ModeSHAKE_192f: "Magnetar-SHAKE-192f",
		ModeSHAKE_256s: "Magnetar-SHAKE-256s", ModeSHAKE_256f: "Magnetar-SHAKE-256f",
	}
	require.Len(t, want, len(allModes))

	seen := map[string]uint8{}
	for _, mode := range allModes {
		name := ModeName(mode)
		require.NotEqual(t, "unknown", name, "mode=0x%02x is a supported parameter set", mode)
		require.Equal(t, want[mode], name, "mode=0x%02x", mode)

		prev, dup := seen[name]
		require.False(t, dup, "modes 0x%02x and 0x%02x share the name %q", prev, mode, name)
		seen[name] = mode
	}
	require.Len(t, seen, len(allModes), "the twelve mode bytes must have twelve distinct names")

	// Every byte outside the catalogue is "unknown", including the bytes that
	// sit immediately either side of each nibble range.
	known := map[uint8]bool{}
	for _, m := range allModes {
		known[m] = true
	}
	for b := 0; b < 256; b++ {
		if known[uint8(b)] {
			continue
		}
		require.Equal(t, "unknown", ModeName(uint8(b)), "mode=0x%02x", b)
	}
}
