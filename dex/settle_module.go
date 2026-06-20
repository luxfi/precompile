// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// settle_module.go registers 0x9999 — THE production DEX settlement precompile —
// as its own module (orthogonal: a new primitive at its own address, not bolted
// onto 0x9010). 0x9999 is the SOLE money path. It exposes:
//
//   - swap(...)  (V4 selector 0xF3CD914C): receipt-settlement (SettleSwap). The V4
//     ABI is byte-for-byte unchanged; web/mobile change only the config address.
//   - the existing custody/admin selectors (deposit/withdraw/balanceOf, pause/
//     freeze) so a node serving 0x9999 has the full surface in one place.
//   - settlement governance: register a validator set, set halt layers (gated on
//     the same protocolFeeController authority as the existing pause controls).
//
// 0x9010 (the deprecated V4 PoolManager) FORWARDS its swap to SettleSwap and
// reverts other value-moving calls with PRECOMPILE_MOVED — one money path, one
// replay namespace (dex.precompile.v1.9999.*), never two.

var settleConfigKey = "dexSettleConfig"

// SettleContract is the 0x9999 stateful precompile. It holds the same
// protocolFeeController authority value as the 0x9010 contract (set at Configure)
// so halt/registry governance is gated identically.
type SettleContract struct {
	protocolFeeController common.Address
}

var _ contract.StatefulPrecompiledContract = (*SettleContract)(nil)

// SettlePrecompile is the singleton 0x9999 contract.
var SettlePrecompile = &SettleContract{}

// Governance selectors (computed in init via keccak4).
var (
	SelectorRegisterValidatorSet uint32 // registerValidatorSet(...) — governance
	SelectorSetHaltGlobal        uint32 // setHaltGlobal(bool)
	SelectorSetHaltMarket        uint32 // setHaltMarket(bytes32,bool)
	SelectorSetHaltAsset         uint32 // setHaltAsset(bytes32,bool)
	SelectorSetHaltReceiptType   uint32 // setHaltReceiptType(uint8,bool)
	SelectorSetHaltValidatorSet  uint32 // setHaltValidatorSet(bytes32,bool)
)

// SettleModule registers the 0x9999 precompile.
var SettleModule = modules.Module{
	ConfigKey:    settleConfigKey,
	Address:      poolManagerAddr9999,
	Contract:     SettlePrecompile,
	Configurator: &settleConfigurator{},
}

type settleConfigurator struct{}

func init() {
	SelectorSetHaltGlobal = keccak4("setHaltGlobal(bool)")
	SelectorSetHaltMarket = keccak4("setHaltMarket(bytes32,bool)")
	SelectorSetHaltAsset = keccak4("setHaltAsset(bytes32,bool)")
	SelectorSetHaltReceiptType = keccak4("setHaltReceiptType(uint8,bool)")
	SelectorSetHaltValidatorSet = keccak4("setHaltValidatorSet(bytes32,bool)")
	SelectorRegisterValidatorSet = keccak4("registerValidatorSet(bytes)")

	if err := modules.RegisterModule(SettleModule); err != nil {
		panic(err)
	}
}

func (*settleConfigurator) MakeConfig() precompileconfig.Config { return &SettleConfig{} }

func (s *settleConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	config, ok := cfg.(*SettleConfig)
	if !ok {
		return errors.New("dex: 0x9999 expected *SettleConfig")
	}
	// Same authority discipline as 0x9010: a missing/zero controller would leave
	// halt + registry governance open. Refuse activation.
	if config.ProtocolFeeController == (common.Address{}) {
		return ErrDEXNoProtocolFeeController
	}
	if _, bad := compromisedDevControllers[config.ProtocolFeeController]; bad {
		return ErrDEXCompromisedController
	}
	SettlePrecompile.protocolFeeController = config.ProtocolFeeController
	// Persist the chain identity receipts must bind to (durable, consensus-shared).
	kv := kvAdapter{db: state}
	SetSettleChainIdentity(kv, config.NetworkID, config.CChainID)
	// Seed the genesis validator set(s), if any.
	for i := range config.ValidatorSets {
		if err := PutValidatorSet(kv, &config.ValidatorSets[i]); err != nil {
			return err
		}
	}
	return nil
}

// SettleConfig is the 0x9999 genesis/upgrade config.
type SettleConfig struct {
	precompileconfig.Upgrade
	ProtocolFeeController common.Address `json:"protocolFeeController,omitempty"`
	NetworkID             uint32         `json:"networkID,omitempty"`
	CChainID              [32]byte       `json:"cChainID,omitempty"`
	// ValidatorSets seeds the verifier registry at genesis (the day-1 D-validator
	// BLS set). Governance rotates it later via registerValidatorSet.
	ValidatorSets []ValidatorSet `json:"-"`
}

func (c *SettleConfig) Key() string        { return settleConfigKey }
func (c *SettleConfig) Timestamp() *uint64 { return c.Upgrade.Timestamp() }
func (c *SettleConfig) IsDisabled() bool   { return c.Upgrade.Disable }
func (c *SettleConfig) Verify(_ precompileconfig.ChainConfig) error {
	if c.ProtocolFeeController == (common.Address{}) {
		return ErrDEXNoProtocolFeeController
	}
	return nil
}
func (c *SettleConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*SettleConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade) &&
		c.ProtocolFeeController == other.ProtocolFeeController &&
		c.NetworkID == other.NetworkID &&
		c.CChainID == other.CChainID
}

// Run dispatches the 0x9999 surface. The swap selector is the money path
// (SettleSwap); custody/admin selectors reuse the 0x9010 handlers via the shared
// pool manager; governance selectors gate on protocolFeeController.
func (s *SettleContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 4 {
		return nil, suppliedGas, errors.New("dex: input too short")
	}
	if accessibleState.GetBlockContext() == nil {
		return nil, suppliedGas, errors.New("dex: block context unavailable")
	}
	selector := binary.BigEndian.Uint32(input[:4])
	data := input[4:]

	switch selector {
	case SelectorSwap:
		// THE money path: receipt-settlement (deterministic BLS verify, no matcher).
		return SettleSwap(accessibleState, caller, data, suppliedGas, readOnly)

	// Market creation — C-AUTHORITATIVE registry (settle_market.go). Computes the
	// tick deterministically ON C; any D OpenMarket is best-effort + discarded.
	case SelectorInitialize:
		return s.runSettleInitialize(accessibleState, caller, data, suppliedGas, readOnly)

	// Maker / resting-order path — pure reserve lock/unlock, NO matching
	// (settle_maker.go). 0x9996 PositionManager routes its lifecycle ops here.
	case SelectorModifyLiquidity:
		return s.runSettleModifyLiquidity(accessibleState, caller, data, suppliedGas, readOnly)

	// donate is explicitly UNSUPPORTED in the receipt model (settle_views9999.go):
	// LP fee growth is D-authoritative, so a safe C-only donate cannot exist.
	case SelectorDonate:
		return s.runSettleDonate(accessibleState, caller, data, suppliedGas, readOnly)

	// Raw slot reads of 0x9999's own storage (read-only; harmless).
	case SelectorExtsload:
		return s.runSettleExtsload(accessibleState, data, suppliedGas)
	case SelectorExtsloadArray:
		return s.runSettleExtsloadArray(accessibleState, data, suppliedGas)

	// Vault funds-in / funds-out / balance — the 0x9999 receipt-settlement RESERVE
	// (settle_custody.go), NOT the deprecated 0x9010 ZAP-custody ledger. These are
	// NOT gated by the swap halt so funds can always exit even when new swaps are
	// halted (safe default: never strand funds).
	case SelectorDeposit:
		return s.runSettleDeposit(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorWithdraw:
		return s.runSettleWithdraw(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorBalanceOf:
		return s.runSettleBalanceOf(accessibleState, data, suppliedGas)

	// Validator-set rotation (protocolFeeController-gated, PoP-verified). The SAME
	// trusted authority as halt governance; replaces the genesis-only seam.
	case SelectorRegisterValidatorSet:
		return s.runRegisterValidatorSet(accessibleState, caller, data, suppliedGas, readOnly)

	// Settlement governance (protocolFeeController-gated).
	case SelectorSetHaltGlobal:
		return s.runSetHaltGlobal(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSetHaltMarket:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltMarket)
	case SelectorSetHaltAsset:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltAsset)
	case SelectorSetHaltValidatorSet:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltValidatorSet)
	case SelectorSetHaltReceiptType:
		return s.runSetHaltReceiptType(accessibleState, caller, data, suppliedGas, readOnly)

	default:
		return nil, suppliedGas, errors.New("dex: unknown 0x9999 selector")
	}
}

const gasHaltAdmin uint64 = 25_000

// runSetHaltGlobal toggles the global halt (governance only).
func (s *SettleContract) runSetHaltGlobal(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot halt in read-only mode")
	}
	if gas < gasHaltAdmin {
		return nil, 0, errors.New("dex: out of gas")
	}
	if caller != s.protocolFeeController {
		return nil, gas - gasHaltAdmin, ErrUnauthorized
	}
	if len(data) < 32 {
		return nil, gas - gasHaltAdmin, errors.New("dex: setHaltGlobal needs a bool")
	}
	on := data[31] != 0
	SetHaltGlobal(newPoolStateAdapter(state), on)
	return nil, gas - gasHaltAdmin, nil
}

// runSetHaltScoped toggles a [32]byte-scoped halt (market/asset/validatorSet).
func (s *SettleContract) runSetHaltScoped(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
	apply func(stateKV, [32]byte, bool),
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot halt in read-only mode")
	}
	if gas < gasHaltAdmin {
		return nil, 0, errors.New("dex: out of gas")
	}
	if caller != s.protocolFeeController {
		return nil, gas - gasHaltAdmin, ErrUnauthorized
	}
	if len(data) < 64 {
		return nil, gas - gasHaltAdmin, errors.New("dex: setHalt(bytes32,bool) needs 2 words")
	}
	var id [32]byte
	copy(id[:], data[0:32])
	on := data[63] != 0
	apply(newPoolStateAdapter(state), id, on)
	return nil, gas - gasHaltAdmin, nil
}

// runSetHaltReceiptType toggles a certType halt.
func (s *SettleContract) runSetHaltReceiptType(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot halt in read-only mode")
	}
	if gas < gasHaltAdmin {
		return nil, 0, errors.New("dex: out of gas")
	}
	if caller != s.protocolFeeController {
		return nil, gas - gasHaltAdmin, ErrUnauthorized
	}
	if len(data) < 64 {
		return nil, gas - gasHaltAdmin, errors.New("dex: setHaltReceiptType(uint8,bool) needs 2 words")
	}
	ct := CertType(data[31])
	on := data[63] != 0
	SetHaltReceiptType(newPoolStateAdapter(state), ct, on)
	return nil, gas - gasHaltAdmin, nil
}

// gasRegisterValidatorSet is the base admin cost of a rotation; the per-validator
// PoP verify dominates, so charge proportionally to the decoded set size.
const (
	gasRegisterValidatorSetBase uint64 = 25_000
	gasRegisterValidatorSetPerV uint64 = 5_000 // 1 G1 decompress + 1 PoP pairing per member.
)

// runRegisterValidatorSet rotates the BLS D-validator set (governance only). It is
// the runtime twin of the genesis Configure seam, gated on the SAME
// protocolFeeController authority as halt. CRITICALLY it routes through the
// PoP-checked PutValidatorSet — so a rotation can NEVER register a rogue/aggregated
// key (the rogue-key forge the EUF-CMA reduction relies on being closed). This is
// where wiring carelessly would turn a non-bug into a real bug; PutValidatorSet
// verifies every member's proof-of-possession before any slot is written.
func (s *SettleContract) runRegisterValidatorSet(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot register a validator set in read-only mode")
	}
	if gas < gasRegisterValidatorSetBase {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - gasRegisterValidatorSetBase
	if caller != s.protocolFeeController {
		return nil, gasLeft, ErrUnauthorized
	}
	vs, err := DecodeValidatorSet(data)
	if err != nil {
		return nil, gasLeft, err
	}
	// Charge per-validator (the PoP pairing dominates) before verifying possession.
	cost := uint64(len(vs.Validators)) * gasRegisterValidatorSetPerV
	if gasLeft < cost {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft -= cost
	// PutValidatorSet enforces per-key PoP + zero-total-weight rejection; a malformed
	// or rogue set reverts here with nothing written (EVM revert rolls back any
	// partial slot writes regardless).
	if err := PutValidatorSet(newPoolStateAdapter(state), vs); err != nil {
		return nil, gasLeft, err
	}
	return nil, gasLeft, nil
}
