// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

// asset.go holds the asset-identity helper shared by the whole DEX precompile —
// the injective map from a 20-byte EVM currency address to its canonical 32-byte
// asset id. It is value-NEUTRAL (no balances, no chains) and is used by the native
// C<->D seam, custody, and market binding so every surface names the same asset.
//
// (Decomplected out of the deprecated engine_zap.go ZAP backend: assetID is a pure
// identity function with no dependency on the ZAP transport that was ripped from
// the value path. One asset-identity function, one place.)

// assetID maps a 20-byte EVM currency address to its canonical 32-byte asset id,
// the FULL key the ledger / atomic objects key value by — NOT a truncated handle.
// The map is INJECTIVE: the 20-byte address is left-padded into 32 bytes (12 zero
// bytes + the 20 address bytes), so two distinct token addresses — or a token vs
// native — ALWAYS produce distinct ids. Native LUX (address(0)) maps to the
// all-zero id; since no real ERC-20 has the zero address, native never collides
// with a token. The chains/dexvm atomic side keys the same value by the full
// 32-byte cross-chain ids.ID (native == ids.Empty == all-zero), so a native op
// agrees across both rails and an ERC-20 only enters via this precompile rail.
func assetID(c Currency) [32]byte {
	var id [32]byte
	copy(id[12:], c.Address.Bytes())
	return id
}
