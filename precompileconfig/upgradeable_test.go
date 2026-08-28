// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompileconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func ptr(v uint64) *uint64 { return &v }

// ---------------------------------------------------------------------------
// Timestamp / IsDisabled
// ---------------------------------------------------------------------------

func TestUpgradeTimestamp(t *testing.T) {
	// nil means "never enabled" — distinct from 0, which means "from genesis".
	require.Nil(t, (&Upgrade{}).Timestamp())

	var zero Upgrade
	zero.BlockTimestamp = ptr(0)
	require.NotNil(t, zero.Timestamp())
	require.Equal(t, uint64(0), *zero.Timestamp())

	at := Upgrade{BlockTimestamp: ptr(1_700_000_000)}
	require.Equal(t, uint64(1_700_000_000), *at.Timestamp())
}

func TestUpgradeIsDisabled(t *testing.T) {
	require.False(t, (&Upgrade{}).IsDisabled())
	require.True(t, (&Upgrade{Disable: true}).IsDisabled())
	// Disable is independent of the timestamp: a disable at a future block is a
	// legitimate upgrade, not a contradiction.
	require.True(t, (&Upgrade{BlockTimestamp: ptr(99), Disable: true}).IsDisabled())
}

// ---------------------------------------------------------------------------
// Equal
// ---------------------------------------------------------------------------

func TestUpgradeEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b *Upgrade
		want bool
	}{
		{"both zero", &Upgrade{}, &Upgrade{}, true},
		{"nil other", &Upgrade{}, nil, false},
		{"same timestamp", &Upgrade{BlockTimestamp: ptr(7)}, &Upgrade{BlockTimestamp: ptr(7)}, true},
		{"different timestamp", &Upgrade{BlockTimestamp: ptr(7)}, &Upgrade{BlockTimestamp: ptr(8)}, false},
		{"nil vs set", &Upgrade{}, &Upgrade{BlockTimestamp: ptr(0)}, false},
		{"set vs nil", &Upgrade{BlockTimestamp: ptr(0)}, &Upgrade{}, false},
		{"disable differs", &Upgrade{Disable: true}, &Upgrade{}, false},
		{"disable matches", &Upgrade{Disable: true}, &Upgrade{Disable: true}, true},
		{
			"same timestamp, disable differs",
			&Upgrade{BlockTimestamp: ptr(7), Disable: true},
			&Upgrade{BlockTimestamp: ptr(7)},
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, c.a.Equal(c.b))
			if c.b != nil {
				require.Equal(t, c.want, c.b.Equal(c.a), "Equal must be symmetric")
			}
		})
	}
}

func TestUpgradeEqualComparesValuesNotPointers(t *testing.T) {
	// Two distinct *uint64 holding the same value must compare equal. Pointer
	// identity would make an upgrade config never equal to its own reload from
	// JSON, and the host uses Equal to detect an upgrade re-declaration.
	a := &Upgrade{BlockTimestamp: ptr(1234)}
	b := &Upgrade{BlockTimestamp: ptr(1234)}
	require.NotSame(t, a.BlockTimestamp, b.BlockTimestamp)
	require.True(t, a.Equal(b))
}

func TestUpgradeEqualIsReflexive(t *testing.T) {
	for _, u := range []*Upgrade{
		{},
		{BlockTimestamp: ptr(0)},
		{BlockTimestamp: ptr(1), Disable: true},
	} {
		require.True(t, u.Equal(u))
	}
}

// ---------------------------------------------------------------------------
// JSON — the on-disk upgrade.json shape is a compatibility surface
// ---------------------------------------------------------------------------

func TestUpgradeJSONRoundTrip(t *testing.T) {
	for _, src := range []Upgrade{
		{},
		{BlockTimestamp: ptr(0)},
		{BlockTimestamp: ptr(1_700_000_000)},
		{BlockTimestamp: ptr(42), Disable: true},
		{Disable: true},
	} {
		b, err := json.Marshal(src)
		require.NoError(t, err)

		var got Upgrade
		require.NoError(t, json.Unmarshal(b, &got))
		require.True(t, src.Equal(&got), "round trip lost information: %s", b)
	}
}

func TestUpgradeJSONFieldNames(t *testing.T) {
	// The key names ARE the file format. A rename silently ignores every
	// operator's existing upgrade.json — it unmarshals clean into a nil
	// timestamp, which means "never enabled".
	b, err := json.Marshal(Upgrade{BlockTimestamp: ptr(9), Disable: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"blockTimestamp":9,"disable":true}`, string(b))

	// disable is omitempty; blockTimestamp is not, so "never enabled" is
	// explicit on the wire rather than an absent key.
	b, err = json.Marshal(Upgrade{})
	require.NoError(t, err)
	require.JSONEq(t, `{"blockTimestamp":null}`, string(b))
}

func TestUpgradeJSONUnknownKeyIsIgnoredButTimestampIsNot(t *testing.T) {
	var u Upgrade
	require.NoError(t, json.Unmarshal([]byte(`{"blockTimestamp":5,"disable":false,"bogus":1}`), &u))
	require.Equal(t, uint64(5), *u.Timestamp())
	require.False(t, u.IsDisabled())

	// Key matching is case-insensitive, so a capitalisation slip still lands.
	var caseSlip Upgrade
	require.NoError(t, json.Unmarshal([]byte(`{"blockTimeStamp":5}`), &caseSlip))
	require.Equal(t, uint64(5), *caseSlip.Timestamp())

	// A genuinely misspelled key leaves the field nil — "never enabled" — with
	// no error at all. Pinned so the silence is a documented property rather
	// than a surprise on an operator's upgrade.json.
	var typo Upgrade
	require.NoError(t, json.Unmarshal([]byte(`{"blockTime":5}`), &typo))
	require.Nil(t, typo.Timestamp())
}

// ---------------------------------------------------------------------------
// Config interface shape
// ---------------------------------------------------------------------------

// upgradeOnly embeds Upgrade and supplies the rest of Config, proving that
// Upgrade's Timestamp/IsDisabled signatures actually satisfy the interface a
// precompile config must implement. A signature drift breaks the build here
// rather than in twenty precompile packages. Note the pointer receiver:
// Upgrade's methods are declared on *Upgrade, so only *upgradeOnly is a Config.
type upgradeOnly struct{ Upgrade }

func (*upgradeOnly) Key() string              { return "test" }
func (*upgradeOnly) Verify(ChainConfig) error { return nil }
func (u *upgradeOnly) Equal(other Config) bool {
	o, ok := other.(*upgradeOnly)
	return ok && u.Upgrade.Equal(&o.Upgrade)
}

var _ Config = (*upgradeOnly)(nil)

func TestConfigInterfaceSatisfiedByUpgrade(t *testing.T) {
	var c Config = &upgradeOnly{Upgrade{BlockTimestamp: ptr(3)}}
	require.Equal(t, "test", c.Key())
	require.Equal(t, uint64(3), *c.Timestamp())
	require.False(t, c.IsDisabled())
	require.NoError(t, c.Verify(nil))
	require.True(t, c.Equal(&upgradeOnly{Upgrade{BlockTimestamp: ptr(3)}}))
	require.False(t, c.Equal(&upgradeOnly{Upgrade{BlockTimestamp: ptr(4)}}))

	// Equal against a different concrete Config type is false, never a panic.
	require.False(t, c.Equal(otherConfig{}))
}

// otherConfig is a second, unrelated Config implementation. Equal must reject
// it by type rather than by comparing fields it does not have.
type otherConfig struct{}

func (otherConfig) Key() string              { return "other" }
func (otherConfig) Timestamp() *uint64       { return nil }
func (otherConfig) IsDisabled() bool         { return false }
func (otherConfig) Equal(Config) bool        { return false }
func (otherConfig) Verify(ChainConfig) error { return nil }

func TestChainConfigAdmitsAnythingIncludingNil(t *testing.T) {
	// ChainConfig is a bare interface{} on purpose: under activate-all-implicitly
	// there are no upgrade gates to ask about, and hosts that DO have something
	// to say implement a narrower interface that a precompile feature-detects
	// (see contract.FeeConfigReporter). The consequence is that Verify's
	// parameter is unchecked — nil and a wrong-typed value are both accepted.
	// Pinned so the looseness is a decision, not an accident.
	var c Config = &upgradeOnly{}
	require.NoError(t, c.Verify(nil))
	require.NoError(t, c.Verify(struct{ Unrelated int }{1}))
	require.NoError(t, c.Verify("not a chain config"))
}
