// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
)

// asset_onchain_verifier.go is the C1 LIVE-STATE half of real-asset admission on the
// 0x9999 cEVM value path. The AssetResolver (asset_resolver.go) answers "is this id
// REGISTERED + ENABLED?" from the registry's boot-time snapshot; THIS verifier answers
// "does the token CONTRACT actually exist (have bytecode) in the state THIS block is
// mutating, right now?". Both gates run on every value-path market-open BEFORE any
// C-balance debit (dexcore.OpenMarketChecked), so a swap is admitted only over an asset
// that is both registered AND backed by live on-chain code.
//
// WHY THE LIVE CHECK IS NOT REDUNDANT WITH THE REGISTRY. The registry's own ChainVerifier
// proves code presence at REGISTER time (chains/dexvm/registry.Asset.VerifyOnChain →
// VerifyERC20 → code length > 0). But registration is a boot-time event; between boot and a
// swap a token contract can SELFDESTRUCT, or on a relaunched/forked chain the registry may
// carry an asset whose contract was never (re)deployed in the new state. A debit/credit
// against such a code-less "ERC-20" would move value against a phantom. The resolver alone
// cannot catch it — it has no view of live state. This verifier closes that window: it reads
// the EXTCODESIZE-equivalent for the token address in the executing StateDB and refuses an
// ERC-20 whose address has no code. Native LUX (the zero-address marker) is the chain's own
// coin, not a contract, so it needs no code and is always real.
//
// IDENTITY DISCIPLINE (the property the directive pins): an ERC-20's on-chain reference IS
// its 20-byte token ADDRESS, and that address MUST carry bytecode for the asset to trade.
// There is no path that admits a left-padded ASCII ticker (e.g. a32("LUSD")) as an ERC-20:
// the ASCII bytes form an address with no contract code, so the verifier refuses it BEFORE
// any debit. (A UTXO's reference is its real 32-byte source-chain assetID, proven at the
// registry against the X-Chain — not an EVM-state object, so the EVM verifier reports it
// real and defers to the registry's X-Chain proof.)

// codeStater is the OPTIONAL capability a StateDB exposes when it can report the size of
// the contract code at an address — the EXTCODESIZE primitive. It is kept as a SEPARATE,
// type-asserted capability (exactly like erc20Vault and txIdentified) so the core
// contract.StateDB interface — and every existing mock/adapter — stays unchanged. The
// production poolStateAdapter satisfies it by forwarding to the underlying geth StateDB's
// GetCodeSize (the same method EXTCODESIZE compiles to); a StateDB that does NOT implement
// it makes the value path fail closed (no verifier → ErrNoOnChainVerifier), never faking a
// reality proof.
type codeStater interface {
	// CodeSizeOf returns the byte length of the contract code deployed at addr (0 for an
	// account with no code — an EOA, a never-deployed address, or a self-destructed
	// contract). This is the EXTCODESIZE value the EVM itself reads.
	CodeSizeOf(addr common.Address) int
}

// codeSizeAssetVerifier is the precompile's concrete dexcore.OnChainAssetVerifier. It
// proves an ERC-20 has live code via the codeStater capability; native is always real;
// a UTXO is deferred to the registry's X-Chain proof. It holds the code-size reader, not
// the whole StateDB, so it is a thin, order-revealing adapter.
type codeSizeAssetVerifier struct {
	code codeStater
}

var _ dexcore.OnChainAssetVerifier = (*codeSizeAssetVerifier)(nil)

// onChainVerifierFor builds the value-path on-chain asset verifier from the swap's
// StateDB. It returns a verifier ONLY when the StateDB can report code size (the live
// EVM path); otherwise it returns nil, which dexcore.RequireRealOnChain maps to the
// fail-closed ErrNoOnChainVerifier — the value path refuses an asset it cannot prove is
// backed by live code rather than admitting it.
func onChainVerifierFor(stateDB StateDB) dexcore.OnChainAssetVerifier {
	if cs, ok := codeStaterFor(stateDB); ok {
		return &codeSizeAssetVerifier{code: cs}
	}
	return nil
}

// codeStaterFor resolves the code-size capability for a StateDB. The production
// poolStateAdapter itself implements codeStater (bridging the geth StateDB's GetCodeSize
// to CodeSizeOf), so the adapter is the code-size source on the live path; a test StateDB
// (contractStateDBWrapper) implements codeStater directly over an in-memory code-size map.
// A StateDB that implements neither has no code-size capability and the value path fails
// closed. The adapter's CodeSizeOf returns -1 when ITS underlying StateDB cannot report
// code size, so a code-incapable host is treated as "no verifier" (fail-closed), not as
// "every asset has zero code" (which would refuse even native).
func codeStaterFor(stateDB StateDB) (codeStater, bool) {
	if a, ok := stateDB.(*poolStateAdapter); ok {
		// The adapter is code-capable only when its underlying StateDB exposes GetCodeSize;
		// otherwise CodeSizeOf returns -1 and we report not-capable so the caller fails
		// closed rather than admit on a fabricated zero. On the live path the underlying is
		// the registry stateDBBridge, which forwards GetCodeSize to the geth StateDB.
		if a.CodeSizeOf(common.Address{}) >= 0 {
			return a, true
		}
		return nil, false
	}
	cs, ok := stateDB.(codeStater)
	return cs, ok
}

// VerifyOnChainAsset implements dexcore.OnChainAssetVerifier: ERC-20 requires non-empty
// code at its 20-byte address; EVM_NATIVE (the zero-address marker) is always real; UTXO is
// reported real (its reality is the registry's X-Chain proof, not an EVM-state fact). It
// reads the canonical reference shape from dexcore so an ill-formed ref is refused before
// the code read.
func (v *codeSizeAssetVerifier) VerifyOnChainAsset(kind dexcore.AssetKind, ref []byte) error {
	cref, err := dexcore.CanonicalRefFor(kind, ref)
	if err != nil {
		return err
	}
	switch kind {
	case dexcore.AssetKindEVMNative:
		return nil // the chain's own coin: not a contract, always real
	case dexcore.AssetKindUTXO:
		return nil // X-Chain asset: reality proven at the registry, not in EVM state
	case dexcore.AssetKindERC20:
		var addr common.Address
		copy(addr[:], cref) // cref is the 20-byte token address (validated by CanonicalRefFor)
		if v.code.CodeSizeOf(addr) <= 0 {
			return ErrERC20NoOnChainCode
		}
		return nil
	default:
		return dexcore.ErrInvalidKind
	}
}

// ErrERC20NoOnChainCode is the precompile-level cause joined under
// dexcore.ErrAssetNotOnChain when an ERC-20's address carries no contract code in the
// executing state (a self-destructed / never-deployed token, or an ASCII-ticker address
// masquerading as a token). The swap reverts before any debit.
var ErrERC20NoOnChainCode = errInvalidOnChainAsset("dex: ERC-20 token address has no contract code in the executing state (not a real on-chain token); refusing swap")

// errInvalidOnChainAsset is a tiny typed error constructor kept local so the cause is a
// distinct value tests can match with errors.Is.
func errInvalidOnChainAsset(msg string) error { return onChainAssetErr(msg) }

type onChainAssetErr string

func (e onChainAssetErr) Error() string { return string(e) }
