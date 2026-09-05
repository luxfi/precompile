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

// 0x9999 settlement governance (setHaltGlobal/Market/Asset, seedSeamReserve) is
// gated to the per-NETWORK DEX GOVERNANCE CONTROLLER, resolved
// at RUNTIME from contract.AtomicState.GovernanceController() (the SAME runtime seam
// networkID/cChainID/dChainID flow through) — see governanceController in halt9999.go.
//
// There is NO hardcoded governance address. A single hardcoded EOA (the prior
// DefaultDAOTreasury) was mnemonic-derivable, so anyone with that mnemonic could halt
// an asset (censor) or halt globally (DoS the whole DEX). The authority is now a
// per-network governance CONTRACT (Governor/Timelock/multisig), configured by the host
// from its deployment topology, NEVER a dev-mnemonic EOA. When a network has not
// configured a governance controller, the halt/seed ops are fail-closed (uncallable) —
// strictly safer than a default key, and permissionless/decentralized by construction.

// settle_module.go registers 0x9999 — THE production DEX settlement precompile —
// as its own module (orthogonal: a new primitive at its own address, not bolted
// onto 0x9010). 0x9999 is the SOLE money path. It exposes:
//
//   - swap(...)  (V4 selector 0xF3CD914C): receipt-settlement (SettleSwap). The V4
//     ABI is byte-for-byte unchanged; web/mobile change only the config address.
//   - the existing custody/admin selectors (deposit/withdraw/balanceOf, pause/
//     freeze) so a node serving 0x9999 has the full surface in one place.
//   - settlement governance: set halt layers + seed pots (gated on the per-network
//     DEX governance controller resolved from the runtime AtomicState, not a key).
//
// 0x9010 was removed; 0x9999 is the sole DEX precompile — one money path, one
// replay namespace (dex.precompile.v1.9999.*), never two.

var settleConfigKey = "dexSettleConfig"

// ErrSettleWrongContext rejects any invocation of 0x9999 whose self-address is not
// 0x9999 — in practice a DELEGATECALL into the settlement precompile from a delegating
// contract. The whole money path's correctness rests on ONE invariant: the ERC-20
// token leg (transferFrom / transfer) is made with 0x9999 as the token's msg.sender,
// so a deposit pulls against approve(0x9999, amount) and the vault holds the asset at
// 0x9999. geth derives the precompile self from the call opcode — CALL and CALLCODE
// both pass the TARGET (0x9999) as self (geth core/vm/evm.go Call/CallCode:
// NewPrecompileEnvironment(evm, caller, addr=target)), but DELEGATECALL passes the
// DELEGATING contract as self (DelegateCall: NewPrecompileEnvironment(evm,
// originCaller, caller) — self is the caller's context, not the target). Under
// DELEGATECALL the token's msg.sender would become the delegating contract, breaking
// the conservation invariant (realHolding == settleVault + makerLockedVault +
// custody) and stranding the caller's own funds. Pinning
// addr == 0x9999 at the top of Run rejects exactly DELEGATECALL while CALL and CALLCODE
// (both bind self = 0x9999) pass.
var ErrSettleWrongContext = errors.New("dex: 0x9999 must be entered with self == 0x9999 (CALL/CALLCODE); DELEGATECALL from a delegating contract is rejected")

// SettleContract is the 0x9999 stateful precompile. It is STATELESS with respect to
// the governance authority: halt/seed governance is gated to the per-network DEX
// governance controller resolved at RUNTIME from contract.AtomicState (see
// governanceController in halt9999.go), never a field set from config or a hardcoded
// key. So a single process-global SettlePrecompile serves every network correctly and
// no compromised default key exists on the struct.
type SettleContract struct{}

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

	// SelectorCollectPosition is a position's D->C money path: collectPosition(bytes32
	// claimID, address asset, uint256 amount, bytes32 positionID) consumes a D->C claim
	// ONCE and credits its beneficiary out of custody, then applies the collect to the
	// named C-side position record. It is the SOLE C-credit path for an LP (collect,
	// decrease, burn and cancel all return funds through here).
	SelectorCollectPosition uint32 // collectPosition(bytes32,address,uint256,bytes32)

)

// SettleModule registers the 0x9999 precompile as ALWAYS-ON: it is active on every
// chain that loads the EVM plugin, from genesis, with NO config entry (neither a
// genesis-inlined precompile nor a precompileUpgrades timestamp). This is the money
// path — it must be present + callable the instant a node boots, on every Lux network,
// with ZERO per-net configuration. There is exactly ONE activation way and this is it.
//
// All parameters 0x9999 needs are resolved at RUNTIME, not from config:
//   - governanceController: the per-network DEX governance CONTRACT, resolved from the
//     host's atomic capability (contract.AtomicState.GovernanceController()). There is
//     NO hardcoded default; an unconfigured network is fail-closed (halt/seed revert).
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

	// No governance authority is set here: it is NOT a hardcoded key. The settlement
	// governance authority is the per-network DEX governance controller, resolved at
	// runtime from contract.AtomicState.GovernanceController() (see governanceController
	// in halt9999.go). A single process-global SettlePrecompile thus serves every network
	// correctly, with no compromised default key on the struct.

	if err := modules.RegisterModule(SettleModule); err != nil {
		panic(err)
	}
}

func (*settleConfigurator) MakeConfig() precompileconfig.Config { return &SettleConfig{} }

// Configure is a no-op for the always-on 0x9999 precompile. It is never invoked by the
// host (an AlwaysOn module has no activating config), and 0x9999 takes no per-net
// parameters — the governance controller and chain identity are both resolved at runtime
// from the atomic capability (contract.AtomicState). The method exists solely to satisfy
// the contract.Configurator interface. It validates the config type so a misuse surfaces
// loudly rather than silently.
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

func (c *SettleConfig) Key() string                                 { return settleConfigKey }
func (c *SettleConfig) Timestamp() *uint64                          { return c.Upgrade.Timestamp() }
func (c *SettleConfig) IsDisabled() bool                            { return c.Upgrade.Disable }
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
// pool manager; governance selectors gate on the runtime governance controller.
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
	// CALL-only guard: 0x9999 must execute with itself as self (msg.sender of its
	// token sub-calls). geth passes the call opcode's self here as `addr`; only
	// DELEGATECALL makes addr != 0x9999 (CALL/CALLCODE both pass self = 0x9999), which
	// would pull/push ERC-20 value as the WRONG msg.sender and break conservation.
	// Reject it before any state is touched (no gas charged — a context error, like
	// the two checks above). See ErrSettleWrongContext.
	if addr != poolManagerAddr9999 {
		return nil, suppliedGas, ErrSettleWrongContext
	}
	selector := binary.BigEndian.Uint32(input[:4])
	data := input[4:]

	switch selector {
	case SelectorSwap:
		// THE money path — SETTLE-ONLY. 0x9999 NEVER matches on C. Every swap routes to the
		// native C<->D atomic seam (SettleSwap, settle9999.go), keyed on the hookData phase:
		//
		//   - UNTAGGED / opaque / DI01 hookData => PHASE A (ORDER): lock the taker's input on
		//     C and write a C->D atomic object. D imports it and matches under ITS OWN
		//     consensus. Phase A returns the order id — NOT a fill; no output is credited here.
		//   - DS02-tagged hookData => PHASE B (SETTLEMENT): consume a real D->C atomic object
		//     ONCE and credit the output. This is the ONLY path that credits C, and the credit
		//     is the RECORDED object's amount — never a caller-supplied fill value.
		//
		// There is NO in-trie CLOB/AMM router, NO synchronous on-chain matcher, NO "money lives
		// in the order book" maker custody. The embedded matcher (swap_sync / swap_custody) was
		// REMOVED: a live matcher inside C-Chain block execution forks consensus (each validator
		// observes independently-timed fills => divergent StateRoot). Deterministic consumption
		// of a committed D->C object is fork-safe INLINE. A swap with no valid D-committed object
		// cannot settle — that is the load-bearing "no-receipt-no-settle" invariant.
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
	// claim ONCE and credit its beneficiary out of custody. The SOLE C-credit
	// path for an LP — collect/decrease/burn/cancel all return funds through here.
	case SelectorCollectPosition:
		return s.runSettleCollectPosition(accessibleState, caller, data, suppliedGas, readOnly)

	// SWAP-rail deadline reclaim (settle9999.go): refund a stranded swap order's
	// remaining locked principal to the locker once its deadline has passed and D never
	// settled. The swap-rail analog of collectPosition's exit guarantee — locked swap
	// input can always exit. NOT gated by the swap halt (funds must exit even when
	// halted), exactly like deposit/withdraw.

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

	// Settlement governance (governance-controller-gated, resolved from runtime
	// AtomicState — never a hardcoded key). Only the real kill switches remain
	// (global / market / asset); the BLS-era validator-set rotation and cert-type
	// halt are gone with the cert value path.
	case SelectorSetHaltGlobal:
		return s.runSetHaltGlobal(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSetHaltMarket:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltMarket)
	case SelectorSetHaltAsset:
		return s.runSetHaltScoped(accessibleState, caller, data, suppliedGas, readOnly, SetHaltAsset)

	// Operator funding of the settlement pots (governance-controller-gated): the swap
	// custody counterparty seed (FIX-4 liveness — a market's first matched swap settles
	// without manual state-poking). It is the ONLY way value enters custody other than
	// a C->D export, which is what makes the custody identity in native_state.go hold.
	case SelectorSeedSeamReserve:
		return s.runSeedSeamReserve(accessibleState, caller, data, suppliedGas, readOnly)

	default:
		return nil, suppliedGas, errors.New("dex: unknown 0x9999 selector")
	}
}

const gasHaltAdmin uint64 = 25_000

// runSetHaltGlobal toggles the global halt. Authority is the per-network DEX
// governance controller resolved from the runtime AtomicState (governanceController),
// NOT a hardcoded key: only the configured Governor/Timelock/multisig CONTRACT may
// halt. Fail-closed when no governance controller is configured (ErrSettleNoGovernance).
func (s *SettleContract) runSetHaltGlobal(
	state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot halt in read-only mode")
	}
	if gas < gasHaltAdmin {
		return nil, 0, errors.New("dex: out of gas")
	}
	gov, gerr := governanceController(state)
	if gerr != nil {
		return nil, gas - gasHaltAdmin, gerr
	}
	if caller != gov {
		return nil, gas - gasHaltAdmin, ErrUnauthorized
	}
	if len(data) < 32 {
		return nil, gas - gasHaltAdmin, errors.New("dex: setHaltGlobal needs a bool")
	}
	on := data[31] != 0
	SetHaltGlobal(newPoolStateAdapter(state), on)
	return nil, gas - gasHaltAdmin, nil
}

// runSetHaltScoped toggles a [32]byte-scoped halt (market/asset). Authority is the
// per-network DEX governance controller (governanceController), never a hardcoded key
// — the same decentralized gate as the global halt; fail-closed when unset.
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
	gov, gerr := governanceController(state)
	if gerr != nil {
		return nil, gas - gasHaltAdmin, gerr
	}
	if caller != gov {
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
