// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pqcrypto

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/stretchr/testify/require"
)

// C-01: AES/ChaCha20 encrypt/decrypt precompiles must not exist.
//
// Vulnerability: The AES precompile (0x9210) and ChaCha20 precompile (0x9211)
// accepted symmetric encryption keys in calldata. Since calldata is public
// on-chain, any validator or block explorer can read the key and decrypt all
// data encrypted with that key. This is a catastrophic key exposure.
//
// Fix: Delete the AES and ChaCha20 precompile packages entirely. Symmetric
// encryption must be performed off-chain where keys remain private.
func TestC01_AESPrecompileNotRegistered(t *testing.T) {
	aesAddr := common.HexToAddress("0x9210")
	_, exists := modules.GetPrecompileModuleByAddress(aesAddr)
	require.False(t, exists,
		"AES precompile at 0x9210 must NOT be registered -- accepts keys in calldata")
}

func TestC01_ChaCha20PrecompileNotRegistered(t *testing.T) {
	chachaAddr := common.HexToAddress("0x9211")
	_, exists := modules.GetPrecompileModuleByAddress(chachaAddr)
	require.False(t, exists,
		"ChaCha20 precompile at 0x9211 must NOT be registered -- accepts keys in calldata")
}

// C-01: Verify no symmetric cipher precompiles exist in the 0x9210-0x921F range.
func TestC01_NoSymmetricCipherPrecompiles(t *testing.T) {
	// Scan the entire symmetric cipher range
	for i := 0; i <= 0xF; i++ {
		addr := common.HexToAddress("0x0000000000000000000000000000000000009210")
		addr[19] = byte(0x10 + i) // 0x9210 through 0x921F
		_, exists := modules.GetPrecompileModuleByAddress(addr)
		require.False(t, exists,
			"No symmetric cipher precompile should exist at %s", addr.Hex())
	}
}

// C-03: ECIES precompile must not exist.
//
// Vulnerability: The ECIES precompile (0x9201) had both encrypt and decrypt
// operations. Decrypt required the private key in calldata (public on-chain).
// Even encrypt was problematic because it was non-deterministic (used random
// nonce), breaking EVM consensus.
//
// Fix: Delete the ECIES package entirely.
func TestC03_ECIESPrecompileNotRegistered(t *testing.T) {
	eciesAddr := common.HexToAddress("0x9201")
	_, exists := modules.GetPrecompileModuleByAddress(eciesAddr)
	require.False(t, exists,
		"ECIES precompile at 0x9201 must NOT be registered -- decrypt accepts private key, encrypt is non-deterministic")
}

// M-11: ECIES encrypt non-deterministic -- must not exist.
//
// Vulnerability: ECIES Encrypt used randomized key derivation, producing
// different ciphertext for the same plaintext+key on every call. In EVM,
// all validators must produce identical state transitions. Non-deterministic
// output means validators disagree on the result, causing consensus failures.
//
// Fix: The ECIES precompile was deleted entirely. No on-chain encryption
// with random nonces.
func TestM11_ECIESNonDeterministicRemoved(t *testing.T) {
	eciesAddr := common.HexToAddress("0x9201")
	_, exists := modules.GetPrecompileModuleByAddress(eciesAddr)
	require.False(t, exists,
		"ECIES precompile must be removed -- encrypt is non-deterministic, breaks consensus")
}

// Verify the PQ crypto precompile at 0x9003 still exists (verify + encapsulate are fine).
func TestPQCryptoPrecompileStillRegistered(t *testing.T) {
	_, exists := modules.GetPrecompileModuleByAddress(ContractAddress)
	require.True(t, exists,
		"PQ crypto precompile at %s must still be registered", ContractAddress.Hex())
}
