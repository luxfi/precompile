// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// module_config_test.go — the 0x0303 module surface: registration, the upgrade Config,
// the gas schedule, and every refusal Run can issue. These assert relationships and
// refusals, never the constants themselves: a test that restates GasBaseInference
// proves nothing, while "one more token costs more" and "the clamped price always
// reverts" are properties a broken implementation cannot satisfy.

package inference

import (
	"encoding/binary"
	"math"
	"reflect"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// surplus is handed over and above RequiredGas so a refusal is never an out-of-gas
// refusal, and so the gas actually charged is observable in the return value.
const surplus uint64 = 4321

// call runs the precompile with exactly RequiredGas+surplus.
func call(input []byte) ([]byte, uint64, error) {
	gas := InferencePrecompile.RequiredGas(input) + surplus
	return InferencePrecompile.Run(nil, common.Address{}, common.Address{}, input, gas, false)
}

// refuse asserts the precompile rejects input, produces nothing, and still charges
// the full reserved price — otherwise the ABI could be probed for free.
func refuse(t *testing.T, input []byte, want string) {
	t.Helper()
	ret, rem, err := call(input)
	require.ErrorContains(t, err, want)
	require.Nil(t, ret, "a refusal must produce no output")
	require.Equal(t, surplus, rem, "a refusal must still charge exactly RequiredGas")
}

func decode(b []byte) []uint32 {
	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.BigEndian.Uint32(b[i*4:])
	}
	return out
}

func gasFor(nNew uint32, prompt []uint32) uint64 {
	return InferencePrecompile.RequiredGas(encodeGenerate(nNew, prompt))
}

func tokens(n int, vocab uint32) []uint32 {
	p := make([]uint32, n)
	for i := range p {
		p[i] = uint32(i) % vocab
	}
	return p
}

// ---- Run: every refusal ------------------------------------------------------------

func TestRunRefusals(t *testing.T) {
	vocab := fixtureModel().Cfg.Vocab
	selectorOnly := make([]byte, 4)
	binary.BigEndian.PutUint32(selectorOnly, SelectorGenerate)

	for _, c := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"no input at all", nil, "input too short"},
		{"one byte short of a selector", []byte{0, 0, 0}, "input too short"},
		{"unknown selector", []byte{0xde, 0xad, 0xbe, 0xef}, "unknown selector"},
		{"selector with nothing after it", selectorOnly, "input too short for generate"},
		{"token count but no prompt", encodeGenerate(1, nil), "input too short for generate"},
		{"one byte short of a token", append(encodeGenerate(1, nil), 0, 0, 0), "input too short for generate"},
		{"prompt is one byte past a token", append(encodeGenerate(0, []uint32{1}), 0), "not a multiple of 4"},
		{"prompt is half a token past a token", append(encodeGenerate(0, []uint32{1}), 0, 0), "not a multiple of 4"},
		{"prompt is three bytes past a token", append(encodeGenerate(0, []uint32{1}), 0, 0, 0), "not a multiple of 4"},
		{"one token past the generation limit", encodeGenerate(MaxNewTokens+1, []uint32{1}), "nNew 65 exceeds max"},
		{"generation limit at the uint32 ceiling", encodeGenerate(math.MaxUint32, []uint32{1}), "nNew 4294967295 exceeds max"},
		{"one token past the sequence limit", encodeGenerate(0, tokens(MaxSeqLen+1, vocab)), "sequence 257 exceeds max"},
		{"prompt plus generation past the sequence limit", encodeGenerate(MaxNewTokens, tokens(MaxSeqLen-int(MaxNewTokens)+1, vocab)), "sequence 257 exceeds max"},
		{"token id at the vocab ceiling", encodeGenerate(0, []uint32{1, vocab}), "token 48 out of vocab"},
		{"token id far past the vocab", encodeGenerate(0, []uint32{math.MaxUint32}), "token 4294967295 out of vocab"},
	} {
		t.Run(c.name, func(t *testing.T) { refuse(t, c.input, c.want) })
	}
}

// TestRunAcceptsTheLastLegalToken pins the other side of the vocab bound: the check is
// >= vocab, so vocab-1 must still decode.
func TestRunAcceptsTheLastLegalToken(t *testing.T) {
	vocab := fixtureModel().Cfg.Vocab
	ret, _, err := call(encodeGenerate(0, []uint32{vocab - 1}))
	require.NoError(t, err)
	require.Equal(t, []uint32{vocab - 1}, decode(ret))
}

// TestRunChargesBeforeItParses: the gas check must come first, or a caller could
// discover the ABI's refusals without paying for them.
func TestRunChargesBeforeItParses(t *testing.T) {
	ret, rem, err := InferencePrecompile.Run(nil, common.Address{}, common.Address{}, []byte{0xde, 0xad, 0xbe, 0xef}, 0, false)
	require.ErrorContains(t, err, "out of gas")
	require.Nil(t, ret)
	require.Zero(t, rem)
}

// TestRunGasBoundary: one gas short reverts, exactly enough succeeds and leaves nothing.
func TestRunGasBoundary(t *testing.T) {
	input := encodeGenerate(1, []uint32{1})
	need := InferencePrecompile.RequiredGas(input)

	ret, rem, err := InferencePrecompile.Run(nil, common.Address{}, common.Address{}, input, need-1, false)
	require.ErrorContains(t, err, "out of gas")
	require.Nil(t, ret)
	require.Zero(t, rem, "an out-of-gas revert refunds nothing")

	ret, rem, err = InferencePrecompile.Run(nil, common.Address{}, common.Address{}, input, need, false)
	require.NoError(t, err)
	require.NotEmpty(t, ret)
	require.Zero(t, rem)
}

// ---- the gas schedule --------------------------------------------------------------

// TestRequiredGasMonotonic: one more requested token always costs more, and a longer
// prompt is never cheaper. The price ignores the prompt today, so the second half holds
// as an equality; it is written as an inequality so it still holds if the schedule
// starts charging for the prompt, which is quadratic work the price does not yet see.
func TestRequiredGasMonotonic(t *testing.T) {
	prompt := []uint32{1}
	prev := gasFor(0, prompt)
	require.Equal(t, InferencePrecompile.RequiredGas(nil), prev,
		"zero new tokens must cost the same as an unparseable input: the base is the floor")

	for n := uint32(1); n <= MaxNewTokens; n++ {
		g := gasFor(n, prompt)
		require.Greater(t, g, prev, "asking for one more token must cost more")
		prev = g
	}

	for _, n := range []uint32{0, 1, MaxNewTokens} {
		require.GreaterOrEqual(t, gasFor(n, tokens(200, 48)), gasFor(n, prompt),
			"a longer prompt must never be cheaper than a short one")
	}
}

// TestRequiredGasFloorsAtTheBase: anything too short to carry a token count is priced
// at the base, and that base is the cheapest the precompile ever is.
func TestRequiredGasFloorsAtTheBase(t *testing.T) {
	base := InferencePrecompile.RequiredGas(nil)
	for n := 0; n < 8; n++ {
		require.Equal(t, base, InferencePrecompile.RequiredGas(make([]byte, n)),
			"input with no readable token count must be priced at the base")
	}
	require.Equal(t, base, gasFor(0, []uint32{1}))
	for n := uint32(0); n <= MaxNewTokens; n++ {
		require.GreaterOrEqual(t, gasFor(n, []uint32{1}), base)
	}
}

// TestRequiredGasSaturates: past the generation limit the price stops growing, so an
// absurd token count cannot be used to reserve an absurd amount of gas.
func TestRequiredGasSaturates(t *testing.T) {
	atMax := gasFor(MaxNewTokens, []uint32{1})
	for _, n := range []uint32{MaxNewTokens + 1, MaxNewTokens + 2, 1000, math.MaxUint32 / 2, math.MaxUint32} {
		require.Equal(t, atMax, gasFor(n, []uint32{1}), "price must saturate at the generation limit")
	}
}

// TestClampedPriceAlwaysReverts is the invariant that keeps the price and the work
// honest. RequiredGas CLAMPS nNew to MaxNewTokens; Run REJECTS it. Those two must
// never disagree — every request that receives the clamped price must revert, so a
// caller can never be quoted for 64 tokens and served more.
func TestClampedPriceAlwaysReverts(t *testing.T) {
	prompt := []uint32{1}
	atMax := gasFor(MaxNewTokens, prompt)

	for _, n := range []uint32{MaxNewTokens + 1, MaxNewTokens + 2, 100, 1000, math.MaxUint32} {
		input := encodeGenerate(n, prompt)
		require.Equal(t, atMax, InferencePrecompile.RequiredGas(input), "the price is clamped here")
		ret, _, err := call(input)
		require.Error(t, err, "a clamped price must buy no work")
		require.Nil(t, ret)
	}

	// The boundary itself is not clamped and not rejected: nNew == MaxNewTokens clears
	// the generation gate and fails later, on the vocab check.
	refuse(t, encodeGenerate(MaxNewTokens, []uint32{fixtureModel().Cfg.Vocab}), "out of vocab")
}

// ---- Run: the successful shape -----------------------------------------------------

// TestRunReturnsPromptThenGeneration: the reply is the prompt verbatim followed by the
// requested tokens, so a caller can locate the generated span without re-encoding.
func TestRunReturnsPromptThenGeneration(t *testing.T) {
	prompt := []uint32{1, 7, 13, 2}

	ret, _, err := call(encodeGenerate(0, prompt))
	require.NoError(t, err)
	require.Equal(t, prompt, decode(ret), "zero new tokens echoes the prompt untouched")

	ret, _, err = call(encodeGenerate(2, prompt))
	require.NoError(t, err)
	got := decode(ret)
	require.Len(t, got, len(prompt)+2)
	require.Equal(t, prompt, got[:len(prompt)], "the prompt prefix must survive generation")
}

// TestRunAtTheSequenceLimit: a prompt that exactly fills the window is accepted, one
// token more is not.
func TestRunAtTheSequenceLimit(t *testing.T) {
	vocab := fixtureModel().Cfg.Vocab
	full := tokens(MaxSeqLen, vocab)

	ret, _, err := call(encodeGenerate(0, full))
	require.NoError(t, err)
	require.Equal(t, full, decode(ret))

	refuse(t, encodeGenerate(0, tokens(MaxSeqLen+1, vocab)), "sequence 257 exceeds max")
}

// TestRunIsByteIdentical: the precompile is on the consensus path, so repeated
// invocations of the same input must not differ by a single byte or a single gas.
func TestRunIsByteIdentical(t *testing.T) {
	input := encodeGenerate(3, []uint32{1, 7, 13, 2})
	first, rem, err := call(input)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	for i := 0; i < 3; i++ {
		again, rem2, err2 := call(input)
		require.NoError(t, err2)
		require.Equal(t, first, again, "the consensus path must be byte-identical across invocations")
		require.Equal(t, rem, rem2, "and must charge identically")
	}
}

// ---- module + config ---------------------------------------------------------------

func TestModuleWiring(t *testing.T) {
	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractAddress)
	require.True(t, ok, "init must have registered the module")
	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok, "the config key must resolve to the same module")
	require.Equal(t, byAddr.Address, byKey.Address)
	require.Equal(t, byAddr.ConfigKey, byKey.ConfigKey)
	require.Same(t, InferencePrecompile, byAddr.Contract, "the registry must hold the singleton")
	require.Equal(t, byAddr.ConfigKey, byAddr.Configurator.MakeConfig().Key(),
		"the configurator must mint configs under the key the registry indexes by")

	// init panics if registration fails; prove the collision it guards against is real.
	require.Error(t, modules.RegisterModule(Module), "a second registration at this address must be refused")
}

// TestMakeConfigIsFreshAndUnset: every call hands back its own unscheduled config. A
// shared value would leak one chain's upgrade into the next.
func TestMakeConfigIsFreshAndUnset(t *testing.T) {
	first, ok := Module.Configurator.MakeConfig().(*Config)
	require.True(t, ok, "MakeConfig must mint this precompile's config type")
	require.Nil(t, first.Timestamp(), "a fresh config is not scheduled")
	require.False(t, first.IsDisabled())
	require.NoError(t, first.Verify(nil))

	first.Upgrade = precompileconfig.Upgrade{BlockTimestamp: ptr(9), Disable: true}
	second := Module.Configurator.MakeConfig()
	require.Nil(t, second.Timestamp(), "a later config must not inherit an earlier one")
	require.False(t, second.IsDisabled())
	require.True(t, second.Equal(Module.Configurator.MakeConfig()), "two fresh configs are equal")
}

// TestConfigReportsTheUpgradeItHolds: Key, Timestamp and IsDisabled must read the
// embedded upgrade rather than answer from a constant.
func TestConfigReportsTheUpgradeItHolds(t *testing.T) {
	c := new(Config)
	require.Equal(t, Module.ConfigKey, c.Key())
	require.Nil(t, c.Timestamp())
	require.False(t, c.IsDisabled())

	for _, at := range []uint64{0, 7, 1_700_000_000} {
		c.Upgrade.BlockTimestamp = ptr(at)
		require.Equal(t, at, *c.Timestamp())
	}

	c.Upgrade.Disable = true
	require.True(t, c.IsDisabled())
	require.NoError(t, c.Verify(nil), "a disabled upgrade still verifies")
	require.Equal(t, Module.ConfigKey, c.Key(), "the key does not move with the upgrade")
}

// TestConfigEqualComparesEveryField mutates one field at a time and requires equality
// to break in both directions.
func TestConfigEqualComparesEveryField(t *testing.T) {
	// Equal forwards the whole embedded upgrade, so the exhaustiveness claim below is
	// only true for these shapes. A new field must teach Equal about itself.
	require.Equal(t, 1, reflect.TypeOf(Config{}).NumField(), "new Config field: teach Equal about it")
	require.Equal(t, 2, reflect.TypeOf(precompileconfig.Upgrade{}).NumField(), "new Upgrade field: teach Equal about it")

	base := func() *Config { return &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(100)}} }
	// Distinct pointers holding the same instant: Equal compares values, not addresses.
	require.True(t, base().Equal(base()))

	for _, c := range []struct {
		name  string
		other *Config
	}{
		{"timestamp differs", &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(101)}}},
		{"timestamp unset", &Config{}},
		{"disable differs", &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(100), Disable: true}}},
		{"both differ", &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			require.False(t, base().Equal(c.other))
			require.False(t, c.other.Equal(base()), "Equal must be symmetric")
		})
	}
}

// TestConfigEqualRejectsAForeignConfig: the foreign config carries an identical
// upgrade, so only the type can tell the two apart.
func TestConfigEqualRejectsAForeignConfig(t *testing.T) {
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(100)}}
	require.False(t, c.Equal(nil), "a missing config is not this config")
	require.False(t, c.Equal(&foreign{Upgrade: c.Upgrade}), "another precompile's config is not this config")
	require.True(t, c.Equal(&Config{Upgrade: c.Upgrade}), "but the same config still is")
}

// TestConfigureTouchesNoState: this precompile is pure compute. Any StateDB or block
// call would reach the embedded nil interface and panic.
func TestConfigureTouchesNoState(t *testing.T) {
	cfg := Module.Configurator.MakeConfig()
	require.NoError(t, Module.Configurator.Configure(nil, cfg, deadState{}, deadBlock{}))
}

// ---- helpers -----------------------------------------------------------------------

func ptr(v uint64) *uint64 { return &v }

// foreign is another precompile's config: a different type carrying the same upgrade.
type foreign struct{ precompileconfig.Upgrade }

func (*foreign) Key() string                               { return "someOtherPrecompileConfig" }
func (*foreign) Verify(precompileconfig.ChainConfig) error { return nil }
func (*foreign) Equal(cfg precompileconfig.Config) bool    { _, ok := cfg.(*foreign); return ok }

// deadState and deadBlock panic on any use: they hold a nil interface.
type deadState struct{ contract.StateDB }

type deadBlock struct {
	contract.ConfigurationBlockContext
}
