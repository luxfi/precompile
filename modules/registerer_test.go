// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package modules

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixtures
//
// registeredModules is process-global consensus-critical state. Every test that
// registers must restore it, or a later test observes a registry the production
// binary would never have.
// ---------------------------------------------------------------------------

// isolate replaces the global registry with an empty one for the duration of
// the test and restores the original afterwards.
func isolate(t *testing.T) {
	t.Helper()
	saved := registeredModules
	registeredModules = make([]Module, 0)
	t.Cleanup(func() { registeredModules = saved })
}

// stub is a do-nothing StatefulPrecompiledContract. Registration must not care
// what the contract does, only where it lives.
type stub struct{}

func (stub) Run(contract.AccessibleState, common.Address, common.Address, []byte, uint64, bool) ([]byte, uint64, error) {
	return nil, 0, nil
}

func mod(key string, addr common.Address) Module {
	return Module{ConfigKey: key, Address: addr, Contract: stub{}}
}

// addr builds a 20-byte address from a big.Int, so tests can walk a range
// boundary by ±1 in the full 160-bit address space.
func addr(n *big.Int) common.Address {
	var a common.Address
	b := n.Bytes()
	if len(b) > common.AddressLength {
		b = b[len(b)-common.AddressLength:]
	}
	copy(a[common.AddressLength-len(b):], b)
	return a
}

func toInt(a common.Address) *big.Int { return new(big.Int).SetBytes(a[:]) }

// unionContains is an independent reimplementation of the allowlist predicate:
// it answers "is addr in ANY reserved range" without calling ReservedAddress,
// so a boundary test compares two implementations instead of one against itself.
func unionContains(a common.Address) bool {
	n := toInt(a)
	for _, r := range reservedRanges {
		if n.Cmp(toInt(r.Start)) >= 0 && n.Cmp(toInt(r.End)) <= 0 {
			return true
		}
	}
	return false
}

// maxAddr is 0xff..ff, above every reserved range's End.
var maxAddr = common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff")

// ---------------------------------------------------------------------------
// AddressRange.Contains
// ---------------------------------------------------------------------------

func TestAddressRangeContainsBoundaries(t *testing.T) {
	r := AddressRange{
		Start: common.HexToAddress("0x0000000000000000000000000000000000001000"),
		End:   common.HexToAddress("0x0000000000000000000000000000000000001fff"),
	}

	// Inclusive on BOTH ends. `>` instead of `>=` (or `<` instead of `<=`) in
	// Contains is the classic off-by-one and is caught here.
	require.True(t, r.Contains(r.Start), "Start must be inside its own range")
	require.True(t, r.Contains(r.End), "End must be inside its own range")
	require.True(t, r.Contains(common.HexToAddress("0x0000000000000000000000000000000000001800")))

	// One below Start, one above End.
	require.False(t, r.Contains(addr(new(big.Int).Sub(toInt(r.Start), big.NewInt(1)))))
	require.False(t, r.Contains(addr(new(big.Int).Add(toInt(r.End), big.NewInt(1)))))
}

func TestAddressRangeContainsIsUnsignedByteOrder(t *testing.T) {
	// A signed-comparison bug shows up at the 0x7f→0x80 high-bit crossing: a
	// signed compare would place 0x80.. BELOW 0x00.. and the range would invert.
	r := AddressRange{
		Start: common.HexToAddress("0x7f00000000000000000000000000000000000000"),
		End:   common.HexToAddress("0x8100000000000000000000000000000000000000"),
	}
	require.True(t, r.Contains(common.HexToAddress("0x8000000000000000000000000000000000000000")))
	require.False(t, r.Contains(common.HexToAddress("0x7effffffffffffffffffffffffffffffffffffff")))
	require.False(t, r.Contains(common.HexToAddress("0x8100000000000000000000000000000000000001")))
}

func TestAddressRangeSingleAddress(t *testing.T) {
	only := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	r := AddressRange{Start: only, End: only}
	require.True(t, r.Contains(only))
	require.False(t, r.Contains(addr(new(big.Int).Sub(toInt(only), big.NewInt(1)))))
	require.False(t, r.Contains(addr(new(big.Int).Add(toInt(only), big.NewInt(1)))))
}

// ---------------------------------------------------------------------------
// ReservedAddress — every declared range, at both edges
// ---------------------------------------------------------------------------

func TestReservedAddressEveryRangeBoundary(t *testing.T) {
	require.NotEmpty(t, reservedRanges)

	for i, r := range reservedRanges {
		t.Run(fmt.Sprintf("range%02d_%s", i, r.Start.Hex()), func(t *testing.T) {
			require.True(t, ReservedAddress(r.Start), "first address of range must be reserved")
			require.True(t, ReservedAddress(r.End), "last address of range must be reserved")

			// A midpoint is reserved too.
			mid := addr(new(big.Int).Rsh(new(big.Int).Add(toInt(r.Start), toInt(r.End)), 1))
			require.True(t, ReservedAddress(mid), "midpoint %s must be reserved", mid.Hex())

			// One outside each edge is reserved only if a DIFFERENT range covers
			// it. Cross-checked against the independent union predicate so an
			// inverted comparison in Contains cannot hide.
			below := addr(new(big.Int).Sub(toInt(r.Start), big.NewInt(1)))
			if toInt(r.Start).Sign() > 0 {
				require.Equal(t, unionContains(below), ReservedAddress(below),
					"below-Start %s disagrees with the union", below.Hex())
			}
			above := addr(new(big.Int).Add(toInt(r.End), big.NewInt(1)))
			require.Equal(t, unionContains(above), ReservedAddress(above),
				"above-End %s disagrees with the union", above.Hex())
		})
	}
}

func TestReservedAddressAgreesWithUnionOnProbeGrid(t *testing.T) {
	// Walk a grid across the whole 160-bit space plus every range edge ±1 and
	// require ReservedAddress to agree with the independent union predicate.
	var probes []common.Address
	for _, r := range reservedRanges {
		for _, d := range []int64{-1, 0, 1} {
			probes = append(probes,
				addr(new(big.Int).Add(toInt(r.Start), big.NewInt(d))),
				addr(new(big.Int).Add(toInt(r.End), big.NewInt(d))),
			)
		}
	}
	for i := 0; i < 256; i++ {
		var a common.Address
		a[0] = byte(i)
		a[19] = byte(i)
		probes = append(probes, a)
	}
	for _, p := range probes {
		require.Equal(t, unionContains(p), ReservedAddress(p), "disagreement at %s", p.Hex())
	}
}

func TestReservedAddressRejectsOutside(t *testing.T) {
	// Addresses that no range covers. Each is asserted against the union too, so
	// this test cannot rot if a range is widened.
	for _, a := range []common.Address{
		maxAddr,
		common.HexToAddress("0x1000000000000000000000000000000000000000"),
		common.HexToAddress("0x0c00000000000000000000000000000000000000"),
		common.HexToAddress("0x0000000000000000000000000000000000000200"),
		common.HexToAddress("0x000000000000000000000000000000000000c000"),
	} {
		require.False(t, unionContains(a), "fixture %s is no longer outside every range", a.Hex())
		require.False(t, ReservedAddress(a), "%s must not be reserved", a.Hex())
	}
}

func TestReservedRangesAreWellFormed(t *testing.T) {
	seen := make(map[string]int, len(reservedRanges))
	for i, r := range reservedRanges {
		require.LessOrEqual(t, bytes.Compare(r.Start[:], r.End[:]), 0,
			"range %d is inverted: Start %s > End %s", i, r.Start.Hex(), r.End.Hex())

		// An exact duplicate range is dead weight: the first entry always wins
		// the linear scan, so the second can never change an answer.
		k := r.Start.Hex() + "-" + r.End.Hex()
		if prev, dup := seen[k]; dup {
			t.Fatalf("range %d duplicates range %d (%s); one of them is dead", i, prev, k)
		}
		seen[k] = i
	}
}

// ---------------------------------------------------------------------------
// RegisterModule — the collision gate
// ---------------------------------------------------------------------------

func TestRegisterModuleAcceptsReservedAddress(t *testing.T) {
	isolate(t)
	a := common.HexToAddress("0x0000000000000000000000000000000000002000")
	require.NoError(t, RegisterModule(mod("k", a)))

	got, ok := GetPrecompileModuleByAddress(a)
	require.True(t, ok)
	require.Equal(t, "k", got.ConfigKey)
}

func TestRegisterModuleRejectsBlackhole(t *testing.T) {
	isolate(t)
	err := RegisterModule(mod("blackhole", BlackholeAddr))
	require.Error(t, err)
	require.Contains(t, err.Error(), "blackhole")

	// And nothing was recorded — a refused registration must not half-commit.
	_, ok := GetPrecompileModuleByAddress(BlackholeAddr)
	require.False(t, ok)
	require.Empty(t, RegisteredModules())
}

func TestBlackholeIsTheWarpRangeStart(t *testing.T) {
	// BlackholeAddr sits on the first address of the Warp/Teleport range, so the
	// blackhole check is the ONLY thing keeping a precompile off it. If the
	// blackhole guard is removed, ReservedAddress would happily admit it.
	require.True(t, ReservedAddress(BlackholeAddr),
		"blackhole is inside a reserved range — the explicit guard is load-bearing")
}

func TestRegisterModuleRejectsUnreservedAddress(t *testing.T) {
	isolate(t)
	err := RegisterModule(mod("stray", maxAddr))
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in a reserved range")
	require.Empty(t, RegisteredModules())
}

func TestRegisterModuleRejectsZeroAddressIsNotRejected(t *testing.T) {
	isolate(t)
	// The zero address IS a declared reserved range (LP-0150 dead/burn), so the
	// gate admits it. Pinned deliberately: if the dead-address ranges are ever
	// removed this flips, and that is a consensus-visible change that must be
	// made on purpose.
	require.True(t, ReservedAddress(common.Address{}))
	require.NoError(t, RegisterModule(mod("zero", common.Address{})))
}

func TestRegisterModuleRejectsDuplicateAddress(t *testing.T) {
	isolate(t)
	a := common.HexToAddress("0x0000000000000000000000000000000000003001")
	require.NoError(t, RegisterModule(mod("first", a)))

	err := RegisterModule(mod("second", a))
	require.Error(t, err)
	require.Contains(t, err.Error(), "address collision")

	// The winner is untouched: a rejected duplicate must not overwrite.
	got, ok := GetPrecompileModuleByAddress(a)
	require.True(t, ok)
	require.Equal(t, "first", got.ConfigKey)
	require.Len(t, RegisteredModules(), 1)
}

func TestRegisterModuleRejectsDuplicateConfigKey(t *testing.T) {
	isolate(t)
	a := common.HexToAddress("0x0000000000000000000000000000000000003002")
	b := common.HexToAddress("0x0000000000000000000000000000000000003003")
	require.NoError(t, RegisterModule(mod("shared", a)))

	err := RegisterModule(mod("shared", b))
	require.Error(t, err)
	require.Contains(t, err.Error(), "config key collision")

	_, ok := GetPrecompileModuleByAddress(b)
	require.False(t, ok, "the rejected module must not be reachable by address")
	require.Len(t, RegisteredModules(), 1)
}

func TestRegisterModuleCollisionIsOrderIndependent(t *testing.T) {
	// Whichever import order the linker picks, a colliding pair must fail. Not
	// "the second one wins" and not "it depends".
	a := common.HexToAddress("0x0000000000000000000000000000000000003004")

	for _, order := range [][2]Module{
		{mod("x", a), mod("y", a)},
		{mod("y", a), mod("x", a)},
	} {
		func() {
			isolate(t)
			require.NoError(t, RegisterModule(order[0]))
			require.Error(t, RegisterModule(order[1]))
		}()
	}
}

func TestRegisterModuleAtEveryRangeEdge(t *testing.T) {
	// Registering exactly on the first and last address of every reserved range
	// must be accepted. This is the gate-level restatement of the boundary test:
	// an off-by-one in Contains would reject a legitimate precompile address.
	for i, r := range reservedRanges {
		for name, a := range map[string]common.Address{"start": r.Start, "end": r.End} {
			t.Run(fmt.Sprintf("range%02d_%s", i, name), func(t *testing.T) {
				isolate(t)
				err := RegisterModule(mod("edge", a))
				if a == BlackholeAddr {
					require.Error(t, err, "blackhole must stay refused even on a range edge")
					return
				}
				require.NoError(t, err, "edge address %s must be registrable", a.Hex())
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

func TestGetPrecompileModuleByAddress(t *testing.T) {
	isolate(t)
	a := common.HexToAddress("0x0000000000000000000000000000000000004001")
	require.NoError(t, RegisterModule(mod("hit", a)))

	got, ok := GetPrecompileModuleByAddress(a)
	require.True(t, ok)
	require.Equal(t, a, got.Address)

	miss, ok := GetPrecompileModuleByAddress(common.HexToAddress("0x0000000000000000000000000000000000004002"))
	require.False(t, ok)
	require.Equal(t, Module{}, miss, "a miss must return the zero Module, never a neighbour")
}

func TestGetPrecompileModuleByKey(t *testing.T) {
	isolate(t)
	a := common.HexToAddress("0x0000000000000000000000000000000000004003")
	require.NoError(t, RegisterModule(mod("theKey", a)))

	got, ok := GetPrecompileModule("theKey")
	require.True(t, ok)
	require.Equal(t, a, got.Address)

	_, ok = GetPrecompileModule("nope")
	require.False(t, ok)

	// Key lookup is exact, not prefix or case-insensitive.
	_, ok = GetPrecompileModule("theKe")
	require.False(t, ok)
	_, ok = GetPrecompileModule("THEKEY")
	require.False(t, ok)
}

// ---------------------------------------------------------------------------
// Determinism — nothing consensus-reachable may depend on registration order
// ---------------------------------------------------------------------------

func TestRegisteredModulesSortedByAddress(t *testing.T) {
	isolate(t)
	addrs := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000005003"),
		common.HexToAddress("0x0000000000000000000000000000000000005001"),
		common.HexToAddress("0x0a00000000000000000000000000000000000000"),
		common.HexToAddress("0x0000000000000000000000000000000000005002"),
		common.HexToAddress("0x0200000000000000000000000000000000000000"),
	}
	for i, a := range addrs {
		require.NoError(t, RegisterModule(mod(fmt.Sprintf("k%d", i), a)))
	}

	got := RegisteredModules()
	require.Len(t, got, len(addrs))
	for i := 1; i < len(got); i++ {
		require.Negative(t, bytes.Compare(got[i-1].Address[:], got[i].Address[:]),
			"registry must be strictly ascending by address")
	}
}

func TestRegisteredModulesOrderIsIndependentOfRegistrationOrder(t *testing.T) {
	// The host iterates RegisteredModules() to build the per-block precompile
	// set. If that order tracked import order (or map iteration), two nodes with
	// the same code could disagree. Every permutation must produce one order.
	addrs := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000006001"),
		common.HexToAddress("0x0000000000000000000000000000000000006002"),
		common.HexToAddress("0x0000000000000000000000000000000000006003"),
		common.HexToAddress("0x0000000000000000000000000000000000006004"),
	}

	var want []common.Address
	for _, perm := range permutations(len(addrs)) {
		var got []common.Address
		func() {
			isolate(t)
			for _, i := range perm {
				require.NoError(t, RegisterModule(mod(fmt.Sprintf("k%d", i), addrs[i])))
			}
			for _, m := range RegisteredModules() {
				got = append(got, m.Address)
			}
		}()
		if want == nil {
			want = got
			continue
		}
		require.Equal(t, want, got, "permutation %v produced a different order", perm)
	}
}

func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, sub := range permutations(n - 1) {
		for pos := 0; pos <= len(sub); pos++ {
			p := make([]int, 0, n)
			p = append(p, sub[:pos]...)
			p = append(p, n-1)
			p = append(p, sub[pos:]...)
			out = append(out, p)
		}
	}
	return out
}

func TestRegisteredModulesCannotBeMutatedByCallers(t *testing.T) {
	// The returned slice must not alias the registry. A consumer that sorts or
	// truncates its copy would otherwise permanently reorder the consensus set
	// for every later block — silently, with no error anywhere.
	isolate(t)
	lo := common.HexToAddress("0x0000000000000000000000000000000000007001")
	hi := common.HexToAddress("0x0000000000000000000000000000000000007002")
	require.NoError(t, RegisterModule(mod("lo", lo)))
	require.NoError(t, RegisterModule(mod("hi", hi)))

	caller := RegisteredModules()
	caller[0], caller[1] = caller[1], caller[0]
	caller[0].ConfigKey = "clobbered"

	fresh := RegisteredModules()
	require.Equal(t, lo, fresh[0].Address, "caller mutation leaked into the registry")
	require.Equal(t, "lo", fresh[0].ConfigKey)
	require.Equal(t, hi, fresh[1].Address)
}

// ---------------------------------------------------------------------------
// AlwaysOnModules
// ---------------------------------------------------------------------------

func TestAlwaysOnModulesFiltersAndKeepsOrder(t *testing.T) {
	isolate(t)
	type spec struct {
		addr     common.Address
		alwaysOn bool
	}
	specs := []spec{
		{common.HexToAddress("0x0000000000000000000000000000000000009003"), true},
		{common.HexToAddress("0x0000000000000000000000000000000000009001"), false},
		{common.HexToAddress("0x0000000000000000000000000000000000009002"), true},
		{common.HexToAddress("0x0000000000000000000000000000000000009004"), false},
	}
	for i, s := range specs {
		m := mod(fmt.Sprintf("k%d", i), s.addr)
		m.AlwaysOn = s.alwaysOn
		require.NoError(t, RegisterModule(m))
	}

	on := AlwaysOnModules()
	require.Len(t, on, 2)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000009002"), on[0].Address)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000009003"), on[1].Address)
	for _, m := range on {
		require.True(t, m.AlwaysOn)
	}
}

func TestAlwaysOnModulesEmptyWhenNoneMarked(t *testing.T) {
	isolate(t)
	require.NoError(t, RegisterModule(mod("plain", common.HexToAddress("0x0000000000000000000000000000000000009005"))))
	require.Empty(t, AlwaysOnModules())
}

func TestAlwaysOnIsASubsetOfRegistered(t *testing.T) {
	// Holds for the REAL registry too, whatever packages the test binary links.
	all := make(map[common.Address]Module, len(RegisteredModules()))
	for _, m := range RegisteredModules() {
		all[m.Address] = m
	}
	for _, m := range AlwaysOnModules() {
		got, ok := all[m.Address]
		require.True(t, ok, "%s is always-on but not registered", m.Address.Hex())
		require.Equal(t, got.ConfigKey, m.ConfigKey)
	}
}
