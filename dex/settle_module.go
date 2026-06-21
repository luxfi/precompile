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

// DefaultDAOTreasury is the built-in canonical governance address for 0x9999 — the
// Lux DAO treasury. It is the protocolFeeController that gates the settlement kill
// switches (setHaltGlobal/Market/Asset) and the operator-gated pot seeding
// (seedSeamReserve / creditPositionFee). It is hard-coded (NOT per-network config)
// because 0x9999 is always-on with zero per-net configuration and DEX governance is
// the same DAO across every Lux network. It is deliberately NOT one of the publicly-
// known compromised dev keys (compromisedDevControllers), so it is a safe default
// admin from genesis. Forward-perfect: one canonical governance authority, one way.
var DefaultDAOTreasury = common.HexToAddress("0x9011E888251AB053B7bD1cdB598Db4f9DEd94714")

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
// 0x9010 was removed; 0x9999 is the sole DEX precompile — one money path, one
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

// Governance selectors (computed in init via keccak4). The BLS-era
// registerValidatorSet / setHaltReceiptType / setHaltValidatorSet selectors are
// GONE with the cert value path — the native seam has no validator set and no cert
// scheme. Only the real kill switches remain.
var (
	SelectorSetHaltGlobal uint32 // setHaltGlobal(bool)
	SelectorSetHaltMarket uint32 // setHaltMarket(bytes32,bool)
	SelectorSetHaltAsset  uint32 // setHaltAsset(bytes32,bool)

	// SelectorCollectPosition is the LP rail's D->C collect/withdraw money path:
	// collectPosition(bytes32 outputID, address asset, uint256 amount, bytes32
	// positionID) consumes a D->C railLP object ONCE and credits the caller out of the
	// committedPositions pot, bounded by the named position record's backing. It is the
	// SOLE C-credit path for an LP (collect, decrease, burn, cancel all return funds
	// through here). Distinct selector, same orthogonal money-path discipline.
	SelectorCollectPosition uint32 // collectPosition(bytes32,address,uint256,bytes32)
)

// SettleModule registers the 0x9999 precompile as ALWAYS-ON: it is active on every
// chain that loads the EVM plugin, from genesis, with NO config entry (neither a
// genesis-inlined precompile nor a precompileUpgrades timestamp). This is the money
// path — it must be present + callable the instant a node boots, on every Lux network,
// with ZERO per-net configuration. There is exactly ONE activation way and this is it.
//
// All parameters 0x9999 needs are resolved at RUNTIME, not from config:
//   - protocolFeeController: the built-in DefaultDAOTreasury (set in init below).
//   - networkID / cChainID / dChainID: from the host's atomic capability
//     (contract.AtomicState, sourced from the consensus context — see
//     native_dchain_client.go). dChainID is the dexvm "D" alias resolved by the host;
//     a network with no dexvm yields ids.Empty and the seam stays safely closed.
//
// The Configurator below exists only to satisfy modules.Module; for an AlwaysOn module
// the host never invokes Configure (there is no activating config). MakeConfig returns
// an empty marker so any tooling that enumerates configs gets a valid, parameter-free
// value that always Verifies.
var SettleModule = modules.Module{
	ConfigKey:    settleConfigKey,
	Address:      poolManagerAddr9999,
	Contract:     SettlePrecompile,
	Configurator: &settleConfigurator{},
	AlwaysOn:     true,
}

type settleConfigurator struct{}

func init() {
	SelectorSetHaltGlobal = keccak4("setHaltGlobal(bool)")
	SelectorSetHaltMarket = keccak4("setHaltMarket(bytes32,bool)")
	SelectorSetHaltAsset = keccak4("setHaltAsset(bytes32,bool)")
	SelectorCollectPosition = keccak4("collectPosition(bytes32,address,uint256,bytes32)")
	SelectorSeedSeamReserve = keccak4("seedSeamReserve(address,uint256)")
	SelectorCreditPositionFee = keccak4("creditPositionFee(bytes32,address,uint256)")

	// The settlement governance authority is the built-in DAO treasury — fixed across
	// every network (always-on, zero per-net config). This is the SOLE source of
	// s.protocolFeeController; there is no Configure step that could set it from genesis.
	SettlePrecompile.protocolFeeController = DefaultDAOTreasury

	if err := modules.RegisterModule(SettleModule); err != nil {
		panic(err)
	}
}

func (*settleConfigurator) MakeConfig() precompileconfig.Config { return &SettleConfig{} }

// Configure is a no-op for the always-on 0x9999 precompile. It is never invoked by the
// host (an AlwaysOn module has no activating config), and 0x9999 takes no per-net
// parameters — protocolFeeController is the built-in DAO treasury (set in init) and the
// chain identity is resolved at runtime from the atomic capability. The method exists
// solely to satisfy the contract.Configurator interface. It validates the config type
// so a misuse surfaces loudly rather than silently.
func (s *settleConfigurator) Configure(
	_ precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	_ contract.StateDB,
	_ contract.ConfigurationBlockContext,
) error {
	if _, ok := cfg.(*SettleConfig); !ok {
		return errors.New("dex: 0x9999 expected *SettleConfig")
	}
	return nil
}

// SettleConfig is the 0x9999 config marker. It carries NO parameters: 0x9999 is
// always-on and resolves everything at runtime, so there is nothing to configure per
// network. It embeds Upgrade only so the precompile framework can represent it as a
// (parameter-free) genesis config when enumerated; it always Verifies.
type SettleConfig struct {
	precompileconfig.Upgrade
}

func (c *SettleConfig) Key() string                            { return settleConfigKey }
func (c *SettleConfig) Timestamp() *uint64                     { return c.Upgrade.Timestamp() }
func (c *SettleConfig) IsDisabled() bool                       { return c.Upgrade.Disable }
func (c *SettleConfig) Verify(_ precompileconfig.ChainConfig) error { return nil }
func (c *SettleConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*SettleConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
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
		// THE money path: native C<->D two-phase atomic settlement (no matcher, no
		// cert). Phase A locks input + creates a C->D object; Phase B consumes a D->C
		// object + credits. See settle9999.go SettleSwap.
		return SettleSwap(accessibleState, caller, data, suppliedGas, readOnly)

	// Market creation — C-AUTHORITATIVE registry (settle_market.go). Computes the
	// tick deterministically ON C; any D OpenMarket is best-effort + discarded.
	case SelectorInitialize:
		return s.runSettleInitialize(accessibleState, caller, data, suppliedGas, readOnly)

	// LP D-committed liquidity path (position_commit.go): ADD commits the LP's funds
	// to a D position via a C->D object; REMOVE requests a D->C withdraw. 0x9996
	// PositionManager routes its lifecycle ops here.
	case SelectorModifyLiquidity:
		return s.runSettleModifyLiquidity(accessibleState, caller, data, suppliedGas, readOnly)

	// LP D->C collect/withdraw money path (position_commit.go): consume a D->C atomic
	// object ONCE and credit the caller out of committedPositions. The SOLE C-credit
	// path for an LP — collect/decrease/burn/cancel all return funds through here.
	case SelectorCollectPosition:
		return s.runSettleCollectPosition(accessibleState, caller, data, suppliedGas, readOnly)

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

	// Settlement governance (protocolFeeController-gated). Only the real kill
	// switches remain (global / market / asset); the BLS-era validator-set rotation
	// and cert-type halt are gone with the cert value path.
	case SelectorSetHaltGlobal:
		return s.runSetHaltGlobal(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSetHaltMarket:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltMarket)
	case SelectorSetHaltAsset:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltAsset)

	// Operator funding of the settlement pots (protocolFeeController-gated). The swap
	// rail's seamReserve counterparty seed (FIX-4 liveness: a market's first matched
	// swap settles without manual state-poking) and the LP rail's per-owner fee credit.
	case SelectorSeedSeamReserve:
		return s.runSeedSeamReserve(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorCreditPositionFee:
		return s.runCreditPositionFee(accessibleState, caller, data, suppliedGas, readOnly)

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
