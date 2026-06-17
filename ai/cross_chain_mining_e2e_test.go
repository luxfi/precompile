// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end tests for the atomic cross-chain mining methods through the precompile's
// Run entry point: real ML-DSA signature -> calldata decode -> verify -> reward ->
// mark-spent. Exercises the full consensus-economic path, not just the core helpers.

package ai

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// --- minimal contract.AccessibleState / StateDB mock (only GetState/SetState exercised) ---

type ccDB struct{ m map[common.Hash]common.Hash }

func newCCDB() *ccDB { return &ccDB{m: map[common.Hash]common.Hash{}} }

func (s *ccDB) GetState(_ common.Address, k common.Hash) common.Hash { return s.m[k] }
func (s *ccDB) SetState(_ common.Address, k, v common.Hash) common.Hash { o := s.m[k]; s.m[k] = v; return o }
func (s *ccDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason)                          {}
func (s *ccDB) GetNonce(common.Address) uint64                                                      { return 0 }
func (s *ccDB) GetBalance(common.Address) *uint256.Int                                              { return uint256.NewInt(0) }
func (s *ccDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int    { return uint256.Int{} }
func (s *ccDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int    { return uint256.Int{} }
func (s *ccDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int                            { return big.NewInt(0) }
func (s *ccDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)                           {}
func (s *ccDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)                           {}
func (s *ccDB) CreateAccount(common.Address)                                                        {}
func (s *ccDB) Exist(common.Address) bool                                                           { return false }
func (s *ccDB) AddLog(*ethtypes.Log)                                                                {}
func (s *ccDB) Logs() []*ethtypes.Log                                                               { return nil }
func (s *ccDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool)                         { return nil, false }
func (s *ccDB) TxHash() common.Hash                                                                 { return common.Hash{} }
func (s *ccDB) Snapshot() int                                                                       { return 0 }
func (s *ccDB) RevertToSnapshot(int)                                                                {}

type ccAcc struct{ s contract.StateDB }

func (a ccAcc) GetStateDB() contract.StateDB                     { return a.s }
func (a ccAcc) GetBlockContext() contract.BlockContext           { return nil }
func (a ccAcc) GetConsensusContext() context.Context            { return nil }
func (a ccAcc) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (a ccAcc) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

func tripleCalldata(sel uint32, blobs [][]byte, chainId uint64) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, sel)
	for _, b := range blobs {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		out = append(out, l[:]...)
		out = append(out, b...)
	}
	var cid [8]byte
	binary.BigEndian.PutUint64(cid[:], chainId)
	return append(out, cid[:]...)
}

func mldsaKeyAndSig(t *testing.T, msg []byte) (pub, sig []byte) {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub, err = pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sig = make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, true, sig); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return pub, sig
}

func TestVerifyAndMintWork_E2E(t *testing.T) {
	const chainId = uint64(420420) // Beluga
	proof := makeWorkProof(3, 60)  // confidential, 60 compute-minutes
	pub, sig := mldsaKeyAndSig(t, proof)
	cd := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{proof, pub, sig}, chainId)
	acc := ccAcc{s: newCCDB()}
	gas := AIMiningPrecompile.RequiredGas(cd)

	ret, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, gas, false)
	if err != nil {
		t.Fatalf("verifyAndMintWork: %v", err)
	}
	if new(big.Int).SetBytes(ret).Sign() <= 0 {
		t.Fatalf("reward must be positive, got %s", new(big.Int).SetBytes(ret))
	}

	// double-spend: same work id again -> rejected
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, gas, false); err == nil {
		t.Fatal("expected double-spend rejection")
	}

	// read-only: writes not allowed
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, gas, true); err == nil {
		t.Fatal("expected read-only rejection")
	}

	// invalid signature: fresh (unspent) work id, corrupted sig -> rejected on verify
	fresh := makeWorkProof(3, 60)
	fresh[63] = 0xCC // different nonce -> different workId (unspent)
	pub2, sig2 := mldsaKeyAndSig(t, fresh)
	sig2[0] ^= 0xFF
	bad := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{fresh, pub2, sig2}, chainId)
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, bad, AIMiningPrecompile.RequiredGas(bad), false); err == nil {
		t.Fatal("expected invalid-signature rejection")
	}
}

func TestVerifyAndMintData_E2E(t *testing.T) {
	const chainId = uint64(420420)
	desc := make([]byte, 42)              // dataHash(32) | size(8) | privacy(2)
	desc[31] = 0xDD                       // dataHash
	binary.BigEndian.PutUint64(desc[32:40], 1000) // 1000 data units
	binary.BigEndian.PutUint16(desc[40:42], 3)    // confidential
	pub, sig := mldsaKeyAndSig(t, desc)
	cd := tripleCalldata(SelectorVerifyAndMintData, [][]byte{desc, pub, sig}, chainId)
	acc := ccAcc{s: newCCDB()}
	gas := AIMiningPrecompile.RequiredGas(cd)

	ret, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, gas, false)
	if err != nil {
		t.Fatalf("verifyAndMintData: %v", err)
	}
	if new(big.Int).SetBytes(ret).Sign() <= 0 {
		t.Fatal("data reward must be positive")
	}
	// same dataset -> double-claim rejected
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, gas, false); err == nil {
		t.Fatal("expected double-claim rejection")
	}
}
