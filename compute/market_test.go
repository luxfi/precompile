// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package compute

import (
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

var caller3 = common.HexToAddress("0x3333333333333333333333333333333333333333")

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func run(t *testing.T, st contract.AccessibleState, from common.Address, op byte, body []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	t.Helper()
	return Precompile.Run(st, from, ContractAddress, append([]byte{op}, body...), gas, readOnly)
}

func register(t *testing.T, st contract.AccessibleState, from common.Address) []byte {
	t.Helper()
	body := make([]byte, 64)
	copy(body[:32], padTo32([]byte("H100")))
	id, _, err := run(t, st, from, OpRegisterProvider, body, 1_000_000, false)
	require.NoError(t, err)
	return id
}

func submit(t *testing.T, st contract.AccessibleState, from common.Address, model string) []byte {
	t.Helper()
	body := make([]byte, 96)
	copy(body[:32], padTo32([]byte(model)))
	copy(body[32:64], padTo32([]byte("input")))
	copy(body[64:96], padTo32(big.NewInt(500).Bytes()))
	id, _, err := run(t, st, from, OpSubmitJob, body, 1_000_000, false)
	require.NoError(t, err)
	return id
}

func claim(t *testing.T, st contract.AccessibleState, from common.Address, jobID, outputHash []byte) error {
	t.Helper()
	body := make([]byte, 0, 64)
	body = append(body, jobID...)
	body = append(body, outputHash...)
	_, _, err := run(t, st, from, OpClaimReward, body, 1_000_000, false)
	return err
}

// ---------------------------------------------------------------------------
// readOnly: every state-mutating op must refuse a static frame
// ---------------------------------------------------------------------------

// TestEveryWriterRefusesReadOnly covers all four mutating opcodes. Before this
// test, OpVerifyCompute had no readOnly check and wrote job.status from a
// STATICCALL — a state change inside a frame the EVM promises is inert.
func TestEveryWriterRefusesReadOnly(t *testing.T) {
	writers := []struct {
		name string
		op   byte
		body []byte
	}{
		{"registerProvider", OpRegisterProvider, make([]byte, 64)},
		{"submitJob", OpSubmitJob, make([]byte, 96)},
		{"claimReward", OpClaimReward, make([]byte, 64)},
		{"verifyCompute", OpVerifyCompute, make([]byte, 64)},
	}

	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			st := newMockState()
			_, remaining, err := run(t, st, caller1, w.op, w.body, 1_000_000, true)
			require.ErrorIs(t, err, ErrReadOnlyState)
			require.Equal(t, uint64(1_000_000), remaining)
		})
	}
}

// TestReadOnlyVerifyLeavesStateUntouched is the assertion that matters: the
// refusal must happen BEFORE any SetState, not merely be reported afterwards.
func TestReadOnlyVerifyLeavesStateUntouched(t *testing.T) {
	st := newMockState()

	register(t, st, caller2)
	jobID := submit(t, st, caller1, "model")
	outputHash := crypto.Keccak256([]byte("the output"))
	require.NoError(t, claim(t, st, caller2, jobID, outputHash))

	db := st.GetStateDB()
	statusSlot := storageSlot("job.status", jobID)
	before := db.GetState(ContractAddress, statusSlot)
	require.Equal(t, common.BytesToHash([]byte{StatusClaimed}), before)

	// A correct attestation, submitted from a static frame.
	att := crypto.Keccak256(jobID, outputHash)
	_, _, err := run(t, st, caller1, OpVerifyCompute, append(append([]byte{}, jobID...), att...), 1_000_000, true)
	require.ErrorIs(t, err, ErrReadOnlyState)

	require.Equal(t, before, db.GetState(ContractAddress, statusSlot),
		"a read-only call must not have advanced the job status")
}

// TestGetPriceIsAllowedReadOnly — a pure quote has no business being refused in
// a static frame; the readOnly gate must be on the writers only.
func TestGetPriceIsAllowedReadOnly(t *testing.T) {
	st := newMockState()
	body := make([]byte, 64)
	copy(body[32:64], padTo32(big.NewInt(7).Bytes()))
	ret, _, err := run(t, st, caller1, OpGetPrice, body, 100_000, true)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(7000), new(big.Int).SetBytes(ret))
}

// ---------------------------------------------------------------------------
// getPrice arithmetic
// ---------------------------------------------------------------------------

func TestGetPriceRefusesOverflowInsteadOfWrapping(t *testing.T) {
	// inputSize is 256 bits of attacker-chosen calldata. Multiplying by 1000
	// overflows, and truncating to the low 32 bytes quotes a price modulo
	// 2^256 — for the value below, a price of ZERO for a maximal input.
	st := newMockState()
	twoTo256 := new(big.Int).Lsh(big.NewInt(1), 256)

	// 1000 = 2^3 * 125, so 2^253 * 1000 = 125 * 2^256, which is exactly zero
	// modulo 2^256. Truncating to the low 32 bytes therefore quotes a price of
	// ZERO for an input of 2^253 bytes. This is the fixture that proves the
	// wrap is exploitable, not merely inaccurate.
	wrapToZero := new(big.Int).Lsh(big.NewInt(1), 253)
	require.Zero(t,
		new(big.Int).Mod(new(big.Int).Mul(wrapToZero, big.NewInt(pricePerByte)), twoTo256).Sign(),
		"fixture must wrap to exactly zero")

	for name, inputSize := range map[string]*big.Int{
		"exact wrap to zero": wrapToZero,
		"max uint256":        new(big.Int).Sub(twoTo256, big.NewInt(1)),
		"one past the limit": new(big.Int).Add(new(big.Int).Div(new(big.Int).Sub(twoTo256, big.NewInt(1)), big.NewInt(pricePerByte)), big.NewInt(1)),
	} {
		t.Run(name, func(t *testing.T) {
			body := make([]byte, 64)
			copy(body[32:64], padTo32(inputSize.Bytes()))
			ret, _, err := run(t, st, caller1, OpGetPrice, body, 100_000, false)
			require.ErrorIs(t, err, ErrPriceOverflow,
				"an unrepresentable price must be refused, never wrapped")
			require.Nil(t, ret)
		})
	}
}

func TestGetPriceAcceptsTheLargestRepresentablePrice(t *testing.T) {
	// One below the overflow point must still quote. An off-by-one in the
	// BitLen check would reject legitimate large jobs.
	st := newMockState()
	twoTo256 := new(big.Int).Lsh(big.NewInt(1), 256)
	maxInput := new(big.Int).Div(new(big.Int).Sub(twoTo256, big.NewInt(1)), big.NewInt(pricePerByte))

	body := make([]byte, 64)
	copy(body[32:64], padTo32(maxInput.Bytes()))
	ret, _, err := run(t, st, caller1, OpGetPrice, body, 100_000, false)
	require.NoError(t, err)

	want := new(big.Int).Mul(maxInput, big.NewInt(pricePerByte))
	require.Equal(t, want, new(big.Int).SetBytes(ret))
	require.LessOrEqual(t, want.BitLen(), 256)
}

func TestGetPriceIsLinearAndZeroAtZero(t *testing.T) {
	st := newMockState()
	quote := func(n int64) *big.Int {
		body := make([]byte, 64)
		copy(body[32:64], padTo32(big.NewInt(n).Bytes()))
		ret, _, err := run(t, st, caller1, OpGetPrice, body, 100_000, false)
		require.NoError(t, err)
		return new(big.Int).SetBytes(ret)
	}
	require.Zero(t, quote(0).Sign(), "zero bytes must quote zero")
	require.Zero(t, quote(1).Cmp(big.NewInt(pricePerByte)))
	require.Zero(t, quote(2).Cmp(big.NewInt(2*pricePerByte)))
	// Doubling the input doubles the price — a rate constant folded into the
	// wrong place would break this while leaving quote(1) correct.
	require.Zero(t, quote(2000).Cmp(new(big.Int).Mul(quote(1000), big.NewInt(2))))
}

func TestGetPriceIgnoresModelHash(t *testing.T) {
	// The quote is documented as inputSize * rate. If a model term were ever
	// added, this test says so rather than the price silently changing.
	st := newMockState()
	price := func(model string) *big.Int {
		body := make([]byte, 64)
		copy(body[:32], padTo32([]byte(model)))
		copy(body[32:64], padTo32(big.NewInt(42).Bytes()))
		ret, _, err := run(t, st, caller1, OpGetPrice, body, 100_000, false)
		require.NoError(t, err)
		return new(big.Int).SetBytes(ret)
	}
	require.Equal(t, price("llama"), price("gpt"))
}

// ---------------------------------------------------------------------------
// Input length refusals
// ---------------------------------------------------------------------------

func TestEveryOpRefusesShortInput(t *testing.T) {
	// Each handler slices fixed offsets out of data. One byte short must be a
	// clean refusal, never a slice panic and never a zero-filled read.
	cases := []struct {
		name string
		op   byte
		need int
	}{
		{"registerProvider", OpRegisterProvider, 64},
		{"submitJob", OpSubmitJob, 96},
		{"claimReward", OpClaimReward, 64},
		{"verifyCompute", OpVerifyCompute, 64},
		{"getPrice", OpGetPrice, 64},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := newMockState()
			for _, n := range []int{0, 1, c.need / 2, c.need - 1} {
				_, _, err := run(t, st, caller1, c.op, make([]byte, n), 1_000_000, false)
				require.ErrorIs(t, err, ErrInvalidInput, "%d bytes must be refused", n)
			}
			// Exactly the required length is accepted (or fails for a reason
			// other than length).
			_, _, err := run(t, st, caller1, c.op, make([]byte, c.need), 1_000_000, false)
			require.NotErrorIs(t, err, ErrInvalidInput, "exactly %d bytes must not be a length error", c.need)
		})
	}
}

func TestExtraTrailingBytesAreIgnored(t *testing.T) {
	// Handlers read a prefix. Trailing bytes must not change the outcome, or
	// two encodings of one call would produce two different jobs.
	st := newMockState()
	body := make([]byte, 96)
	copy(body[:32], padTo32([]byte("model")))
	copy(body[64:96], padTo32(big.NewInt(1).Bytes()))

	a, _, err := run(t, st, caller1, OpSubmitJob, body, 1_000_000, false)
	require.NoError(t, err)

	st2 := newMockState()
	b, _, err := run(t, st2, caller1, OpSubmitJob, append(body, 0xde, 0xad, 0xbe, 0xef), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, a, b, "trailing bytes changed the jobID")
}

func TestEmptyInputAndUnknownOp(t *testing.T) {
	st := newMockState()

	_, remaining, err := Precompile.Run(st, caller1, ContractAddress, nil, 500, false)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Equal(t, uint64(500), remaining)

	for _, op := range []byte{0x00, 0x06, 0x7f, 0xff} {
		_, _, err := run(t, st, caller1, op, make([]byte, 96), 1_000_000, false)
		require.ErrorIs(t, err, ErrUnknownOp, "op %#x must be unknown", op)
	}
}

// ---------------------------------------------------------------------------
// Gas
// ---------------------------------------------------------------------------

func TestEveryOpChargesItsFeeAndRefusesBelowIt(t *testing.T) {
	cases := []struct {
		name string
		op   byte
		need int
		fee  uint64
	}{
		{"registerProvider", OpRegisterProvider, 64, GasRegister},
		{"submitJob", OpSubmitJob, 96, GasSubmit},
		{"claimReward", OpClaimReward, 64, GasClaim},
		{"verifyCompute", OpVerifyCompute, 64, GasVerify},
		{"getPrice", OpGetPrice, 64, GasGetPrice},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := newMockState()

			// One gas short of the fee is out-of-gas with nothing left.
			_, remaining, err := run(t, st, caller1, c.op, make([]byte, c.need), c.fee-1, false)
			require.ErrorIs(t, err, contract.ErrOutOfGas)
			require.Zero(t, remaining, "an out-of-gas refusal must not report gas remaining")

			// Exactly the fee is enough, and it is all consumed.
			_, remaining, _ = run(t, st, caller1, c.op, make([]byte, c.need), c.fee, false)
			require.Zero(t, remaining)

			// A surplus is returned intact.
			_, remaining, _ = run(t, st, caller1, c.op, make([]byte, c.need), c.fee+777, false)
			require.Equal(t, uint64(777), remaining)
		})
	}
}

func TestGasIsCheckedBeforeAnyWork(t *testing.T) {
	// An op that cannot pay must leave no trace, even with otherwise valid
	// arguments — otherwise a caller gets a free registration by underpaying.
	st := newMockState()
	body := make([]byte, 64)
	copy(body[:32], padTo32([]byte("H100")))

	_, _, err := run(t, st, caller1, OpRegisterProvider, body, GasRegister-1, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)

	db := st.GetStateDB()
	require.Equal(t, common.Hash{}, db.GetState(ContractAddress, storageSlot("nonce", caller1.Bytes())),
		"an unpaid call incremented the caller's nonce")
}

// ---------------------------------------------------------------------------
// Job lifecycle refusals
// ---------------------------------------------------------------------------

func TestClaimRefusesUnknownJob(t *testing.T) {
	st := newMockState()
	register(t, st, caller2)
	err := claim(t, st, caller2, crypto.Keccak256([]byte("no such job")), crypto.Keccak256([]byte("out")))
	require.ErrorIs(t, err, ErrJobNotFound)
}

func TestClaimRefusesUnregisteredProvider(t *testing.T) {
	// caller3 never registered, so it has no provider nonce.
	st := newMockState()
	jobID := submit(t, st, caller1, "model")
	err := claim(t, st, caller3, jobID, crypto.Keccak256([]byte("out")))
	require.ErrorIs(t, err, ErrNotProvider)

	// And the job is untouched — a refused claim must not record an output.
	db := st.GetStateDB()
	require.Equal(t, common.Hash{}, db.GetState(ContractAddress, storageSlot("job.output", jobID)))
	require.Equal(t, common.Hash{}, db.GetState(ContractAddress, storageSlot("job.status", jobID)))
}

func TestClaimRefusesSecondClaim(t *testing.T) {
	st := newMockState()
	register(t, st, caller2)
	register(t, st, caller3)
	jobID := submit(t, st, caller1, "model")

	require.NoError(t, claim(t, st, caller2, jobID, crypto.Keccak256([]byte("first"))))

	// A different registered provider cannot take the job away.
	require.ErrorIs(t, claim(t, st, caller3, jobID, crypto.Keccak256([]byte("second"))), ErrJobAlreadyClaimed)

	db := st.GetStateDB()
	require.Equal(t, common.BytesToHash(caller2.Bytes()),
		db.GetState(ContractAddress, storageSlot("job.provider", jobID)),
		"the second claim overwrote the provider")
	require.Equal(t, common.BytesToHash(crypto.Keccak256([]byte("first"))),
		db.GetState(ContractAddress, storageSlot("job.output", jobID)))
}

func TestVerifyRefusesUnclaimedJobWithoutWriting(t *testing.T) {
	st := newMockState()
	jobID := submit(t, st, caller1, "model")

	// An open job cannot be verified: the result is a zero word, not an error,
	// and nothing is written.
	att := crypto.Keccak256(jobID, make([]byte, 32))
	ret, _, err := run(t, st, caller1, OpVerifyCompute, append(append([]byte{}, jobID...), att...), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), ret)

	db := st.GetStateDB()
	require.Equal(t, common.Hash{}, db.GetState(ContractAddress, storageSlot("job.status", jobID)))
}

func TestVerifyRefusesWrongAttestationWithoutWriting(t *testing.T) {
	st := newMockState()
	register(t, st, caller2)
	jobID := submit(t, st, caller1, "model")
	outputHash := crypto.Keccak256([]byte("real output"))
	require.NoError(t, claim(t, st, caller2, jobID, outputHash))

	db := st.GetStateDB()
	for _, wrong := range [][]byte{
		make([]byte, 32),
		crypto.Keccak256([]byte("guess")),
		crypto.Keccak256(outputHash, jobID), // arguments transposed
		crypto.Keccak256(jobID),             // outputHash omitted
	} {
		ret, _, err := run(t, st, caller1, OpVerifyCompute,
			append(append([]byte{}, jobID...), wrong...), 1_000_000, false)
		require.NoError(t, err)
		require.Equal(t, make([]byte, 32), ret, "a wrong attestation must report failure")
		require.Equal(t, common.BytesToHash([]byte{StatusClaimed}),
			db.GetState(ContractAddress, storageSlot("job.status", jobID)),
			"a wrong attestation advanced the status")
	}
}

func TestVerifyIsNotReplayable(t *testing.T) {
	// Once verified, the same call must not re-verify: status is no longer
	// StatusClaimed, so the guard short-circuits.
	st := newMockState()
	register(t, st, caller2)
	jobID := submit(t, st, caller1, "model")
	outputHash := crypto.Keccak256([]byte("out"))
	require.NoError(t, claim(t, st, caller2, jobID, outputHash))

	body := append(append([]byte{}, jobID...), crypto.Keccak256(jobID, outputHash)...)
	ret, _, err := run(t, st, caller1, OpVerifyCompute, body, 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])

	ret, _, err = run(t, st, caller1, OpVerifyCompute, body, 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), ret, "a verified job must not verify twice")
}

// ---------------------------------------------------------------------------
// Identifier derivation
// ---------------------------------------------------------------------------

func TestProviderAndJobIdsAreUniquePerCallerAndNonce(t *testing.T) {
	st := newMockState()

	// Same caller, successive registrations → different ids.
	a := register(t, st, caller1)
	b := register(t, st, caller1)
	require.NotEqual(t, a, b, "a second registration reused the first providerID")

	// Different callers at the same nonce → different ids.
	c := register(t, st, caller2)
	require.NotEqual(t, a, c)

	// Job ids come from a separate nonce space, so a caller's first job id is
	// not its first provider id.
	j1 := submit(t, st, caller1, "m")
	j2 := submit(t, st, caller1, "m")
	require.NotEqual(t, j1, j2)
}

func TestProviderAndJobNoncesAreIndependent(t *testing.T) {
	// Sharing one nonce would make a submit change the next providerID, so two
	// callers interleaving the two ops could collide.
	st := newMockState()
	register(t, st, caller1)
	providerNonce := st.GetStateDB().GetState(ContractAddress, storageSlot("nonce", caller1.Bytes()))
	submit(t, st, caller1, "m")
	require.Equal(t, providerNonce,
		st.GetStateDB().GetState(ContractAddress, storageSlot("nonce", caller1.Bytes())),
		"submitJob advanced the provider nonce")
}

func TestStorageSlotsAreDomainSeparated(t *testing.T) {
	// Every record for one id lives under a distinct prefix. Two prefixes
	// hashing to one slot would make a job's price overwrite its status.
	id := crypto.Keccak256([]byte("id"))
	seen := map[common.Hash]string{}
	for _, prefix := range []string{
		"provider", "provider.owner", "provider.tee",
		"job", "job.submitter", "job.price", "job.input",
		"job.status", "job.output", "job.provider",
		"nonce", "job.nonce",
	} {
		s := storageSlot(prefix, id)
		if prev, dup := seen[s]; dup {
			t.Fatalf("prefixes %q and %q collide at slot %s", prev, prefix, s.Hex())
		}
		seen[s] = prefix
	}

	// And the same prefix with different ids does not collide.
	require.NotEqual(t,
		storageSlot("job", crypto.Keccak256([]byte("a"))),
		storageSlot("job", crypto.Keccak256([]byte("b"))))
}

// ---------------------------------------------------------------------------
// KNOWN GAP — reported, awaiting a design decision
// ---------------------------------------------------------------------------

// TestVerifyComputeAttestationIsDerivableFromPublicState pins a security gap
// rather than a desired behaviour.
//
// The "attestation" verifyCompute checks is keccak256(jobID, outputHash). jobID
// is supplied by the caller and outputHash is read straight out of public
// contract storage, so ANY address can compute a passing attestation for ANY
// claimed job without having run the computation and without any relationship
// to the job. verifyCompute also takes no caller argument, so there is no
// access control on who may finalise a job.
//
// Nothing of value moves inside this precompile (maxPrice is recorded and never
// transferred), so the damage is confined to contracts that read job.status and
// believe it means "a TEE attested this result". The fix is a design decision —
// bind the check to a real TEE quote (attestation.VerifyCompute already does
// exactly this) and restrict finalisation to the job's submitter — so it is
// reported rather than changed here.
//
// When that fix lands, this test must be replaced by its inverse.
func TestVerifyComputeAttestationIsDerivableFromPublicState(t *testing.T) {
	st := newMockState()
	register(t, st, caller2)
	jobID := submit(t, st, caller1, "model")
	outputHash := crypto.Keccak256([]byte("provider output"))
	require.NoError(t, claim(t, st, caller2, jobID, outputHash))

	// caller3 is a stranger: not the submitter, not the provider, not even a
	// registered provider. It reads outputHash from public storage.
	publicOutput := st.GetStateDB().GetState(ContractAddress, storageSlot("job.output", jobID))
	forged := crypto.Keccak256(jobID, publicOutput.Bytes())

	ret, _, err := run(t, st, caller3, OpVerifyCompute,
		append(append([]byte{}, jobID...), forged...), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31],
		"KNOWN GAP: a stranger finalised a job using only public state")
	require.Equal(t, common.BytesToHash([]byte{StatusVerified}),
		st.GetStateDB().GetState(ContractAddress, storageSlot("job.status", jobID)))
}

// ---------------------------------------------------------------------------
// Module registration and config
// ---------------------------------------------------------------------------

func TestModuleIsRegisteredAtItsAddress(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, Precompile, Module.Contract)

	m, ok := modules.GetPrecompileModuleByAddress(ContractAddress)
	require.True(t, ok, "init() must have registered the compute precompile")
	require.Equal(t, ConfigKey, m.ConfigKey)

	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, ContractAddress, byKey.Address)

	require.True(t, modules.ReservedAddress(ContractAddress),
		"the compute address must sit in a reserved range")
	require.False(t, Module.AlwaysOn, "compute activates by config, not at genesis")
}

func TestConfigLifecycle(t *testing.T) {
	c := &configurator{}

	cfg, ok := c.MakeConfig().(*Config)
	require.True(t, ok, "MakeConfig must produce this package's Config")
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(nil))

	ts := uint64(1_700_000_000)
	at := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, ts, *at.Timestamp())

	off := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, off.IsDisabled())
}

func TestConfigEqual(t *testing.T) {
	ts := uint64(5)
	other := uint64(6)

	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	b := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.True(t, a.Equal(b))
	require.True(t, b.Equal(a))

	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(&Config{}))
	require.False(t, a.Equal(nil), "Equal against nil must be false, not a panic")

	// A config of a different precompile is never equal, whatever its fields.
	require.False(t, a.Equal(foreignConfig{}))
}

type foreignConfig struct{}

func (foreignConfig) Key() string                               { return "other" }
func (foreignConfig) Timestamp() *uint64                        { return nil }
func (foreignConfig) IsDisabled() bool                          { return false }
func (foreignConfig) Equal(precompileconfig.Config) bool        { return false }
func (foreignConfig) Verify(precompileconfig.ChainConfig) error { return nil }

func TestConfigureIsANoOpButSucceeds(t *testing.T) {
	// compute keeps no genesis state, so Configure writes nothing. Assert that
	// explicitly: a Configure that silently wrote would corrupt genesis.
	st := newMockState()
	db := st.GetStateDB().(*mockStateDB)
	before := len(db.storage)

	require.NoError(t, (&configurator{}).Configure(nil, &Config{}, db, nil))
	require.Equal(t, before, len(db.storage))
}
