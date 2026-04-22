// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompileconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func u64ptr(v uint64) *uint64 {
	return &v
}

// ============================================================================
// Upgrade.Timestamp / Upgrade.IsDisabled
// ============================================================================

func TestUpgrade_Timestamp(t *testing.T) {
	t.Run("nil timestamp means never enabled", func(t *testing.T) {
		u := &Upgrade{BlockTimestamp: nil}
		require.Nil(t, u.Timestamp())
	})

	t.Run("zero timestamp means enabled from genesis", func(t *testing.T) {
		u := &Upgrade{BlockTimestamp: u64ptr(0)}
		ts := u.Timestamp()
		require.NotNil(t, ts)
		require.Equal(t, uint64(0), *ts)
	})

	t.Run("nonzero timestamp is returned verbatim", func(t *testing.T) {
		u := &Upgrade{BlockTimestamp: u64ptr(1_700_000_000)}
		ts := u.Timestamp()
		require.NotNil(t, ts)
		require.Equal(t, uint64(1_700_000_000), *ts)
	})

	t.Run("returned pointer aliases the underlying field", func(t *testing.T) {
		// Document the current aliasing behavior so any future change to return
		// a copy is an intentional break.
		u := &Upgrade{BlockTimestamp: u64ptr(42)}
		require.Equal(t, u.BlockTimestamp, u.Timestamp())
	})
}

func TestUpgrade_IsDisabled(t *testing.T) {
	require.False(t, (&Upgrade{}).IsDisabled())
	require.False(t, (&Upgrade{Disable: false}).IsDisabled())
	require.True(t, (&Upgrade{Disable: true}).IsDisabled())

	// Disable is independent of BlockTimestamp.
	require.True(t, (&Upgrade{BlockTimestamp: nil, Disable: true}).IsDisabled())
	require.True(t, (&Upgrade{BlockTimestamp: u64ptr(0), Disable: true}).IsDisabled())
	require.True(t, (&Upgrade{BlockTimestamp: u64ptr(1000), Disable: true}).IsDisabled())
}

// ============================================================================
// Upgrade.Equal — systematic edge cases
// ============================================================================

func TestUpgrade_Equal(t *testing.T) {
	tests := []struct {
		name string
		a    *Upgrade
		b    *Upgrade
		want bool
	}{
		{
			name: "both nil-timestamp, both enabled",
			a:    &Upgrade{BlockTimestamp: nil, Disable: false},
			b:    &Upgrade{BlockTimestamp: nil, Disable: false},
			want: true,
		},
		{
			name: "both nil-timestamp, both disabled",
			a:    &Upgrade{BlockTimestamp: nil, Disable: true},
			b:    &Upgrade{BlockTimestamp: nil, Disable: true},
			want: true,
		},
		{
			name: "nil-timestamp disable mismatch",
			a:    &Upgrade{BlockTimestamp: nil, Disable: false},
			b:    &Upgrade{BlockTimestamp: nil, Disable: true},
			want: false,
		},
		{
			name: "same zero timestamp, both enabled",
			a:    &Upgrade{BlockTimestamp: u64ptr(0), Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(0), Disable: false},
			want: true,
		},
		{
			name: "zero timestamp vs nil timestamp (one-sided nil)",
			a:    &Upgrade{BlockTimestamp: u64ptr(0), Disable: false},
			b:    &Upgrade{BlockTimestamp: nil, Disable: false},
			want: false,
		},
		{
			name: "nil timestamp vs zero timestamp (symmetry)",
			a:    &Upgrade{BlockTimestamp: nil, Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(0), Disable: false},
			want: false,
		},
		{
			name: "same nonzero timestamp, both enabled",
			a:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
			want: true,
		},
		{
			name: "same timestamp, different pointer identity",
			a:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
			want: true,
		},
		{
			name: "different nonzero timestamps",
			a:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_001), Disable: false},
			want: false,
		},
		{
			name: "same timestamp, disable mismatch",
			a:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(1_700_000_000), Disable: true},
			want: false,
		},
		{
			name: "max uint64 timestamp",
			a:    &Upgrade{BlockTimestamp: u64ptr(^uint64(0)), Disable: false},
			b:    &Upgrade{BlockTimestamp: u64ptr(^uint64(0)), Disable: false},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.a.Equal(tt.b))
			// Equal must be symmetric for every well-formed comparison.
			require.Equal(t, tt.want, tt.b.Equal(tt.a), "Equal is not symmetric")
		})
	}
}

func TestUpgrade_Equal_OtherNilReturnsFalse(t *testing.T) {
	// Document the nil-receiver-side behavior: Equal(nil) is always false, even
	// when the receiver itself is the zero Upgrade{}. This protects callers
	// that pass a potentially-unset upgrade pointer into comparisons.
	cases := []*Upgrade{
		{},
		{BlockTimestamp: nil, Disable: false},
		{BlockTimestamp: nil, Disable: true},
		{BlockTimestamp: u64ptr(0), Disable: false},
		{BlockTimestamp: u64ptr(1_700_000_000), Disable: true},
	}
	for _, u := range cases {
		require.False(t, u.Equal(nil))
	}
}

func TestUpgrade_Equal_Reflexive(t *testing.T) {
	// Reflexivity: u.Equal(u) must always be true for any well-formed Upgrade.
	cases := []*Upgrade{
		{BlockTimestamp: nil, Disable: false},
		{BlockTimestamp: nil, Disable: true},
		{BlockTimestamp: u64ptr(0), Disable: false},
		{BlockTimestamp: u64ptr(1_700_000_000), Disable: false},
		{BlockTimestamp: u64ptr(^uint64(0)), Disable: true},
	}
	for _, u := range cases {
		require.True(t, u.Equal(u), "Upgrade is not reflexive-equal to itself: %+v", u)
	}
}

// ============================================================================
// uint64PtrEqual (package-private, exercised directly for coverage)
// ============================================================================

func TestUint64PtrEqual(t *testing.T) {
	require.True(t, uint64PtrEqual(nil, nil))
	require.False(t, uint64PtrEqual(u64ptr(0), nil))
	require.False(t, uint64PtrEqual(nil, u64ptr(0)))
	require.True(t, uint64PtrEqual(u64ptr(0), u64ptr(0)))
	require.True(t, uint64PtrEqual(u64ptr(1_700_000_000), u64ptr(1_700_000_000)))
	require.False(t, uint64PtrEqual(u64ptr(1_700_000_000), u64ptr(1_700_000_001)))
	require.True(t, uint64PtrEqual(u64ptr(^uint64(0)), u64ptr(^uint64(0))))

	// Different pointers, same value — equal.
	a, b := u64ptr(42), u64ptr(42)
	require.NotSame(t, a, b)
	require.True(t, uint64PtrEqual(a, b))
}
