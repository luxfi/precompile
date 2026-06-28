// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end tests for the atomic cross-chain mining methods. A mint is only
// honored for a post-quantum key that an embedded-root-certified TEE device has
// vouched for: the work proof must carry a TEE quote whose attested deviceID
// equals BLAKE3(pubkey). The happy path threads a generated test PKI through
// the roots-injected seam (verifyAndMint*); the forge path runs through the
// production Run entry point (embedded Intel root) where a self-signed key with
// no real device quote is rejected — that rejection is the proof the unbacked
// mint is closed.

package ai

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/holiman/uint256"
	"github.com/zeebo/blake3"

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
func (s *ccDB) SetState(_ common.Address, k, v common.Hash) common.Hash {
	o := s.m[k]
	s.m[k] = v
	return o
}
func (s *ccDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (s *ccDB) GetNonce(common.Address) uint64                             { return 0 }
func (s *ccDB) GetBalance(common.Address) *uint256.Int                     { return uint256.NewInt(0) }
func (s *ccDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (s *ccDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (s *ccDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int    { return big.NewInt(0) }
func (s *ccDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (s *ccDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)   {}
func (s *ccDB) CreateAccount(common.Address)                                {}
func (s *ccDB) Exist(common.Address) bool                                   { return false }
func (s *ccDB) AddLog(*ethtypes.Log)                                        {}
func (s *ccDB) Logs() []*ethtypes.Log                                       { return nil }
func (s *ccDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) { return nil, false }
func (s *ccDB) TxHash() common.Hash                                         { return common.Hash{} }
func (s *ccDB) Snapshot() int                                               { return 0 }
func (s *ccDB) RevertToSnapshot(int)                                        {}

type ccAcc struct{ s contract.StateDB }

func (a ccAcc) GetStateDB() contract.StateDB                     { return a.s }
func (a ccAcc) GetBlockContext() contract.BlockContext           { return nil }
func (a ccAcc) GetConsensusContext() context.Context             { return nil }
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

// --- ML-DSA + TEE-quote test fixtures ---------------------------------------

func genMLDSA(t *testing.T) ([]byte, *mldsa65.PrivateKey) {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pub, sk
}

func signMLDSA(t *testing.T, sk *mldsa65.PrivateKey, msg []byte) []byte {
	t.Helper()
	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, true, sig); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// reportWithDevice builds a 48-byte Lux attestation report carrying a full
// 32-byte deviceID.
func reportWithDevice(dev [32]byte, ts int64) []byte {
	r := make([]byte, teeReportLen)
	copy(r[:32], dev[:])
	binary.BigEndian.PutUint64(r[32:40], uint64(ts))
	binary.BigEndian.PutUint64(r[40:48], 0xCAFE)
	return r
}

// teeEnvelope frames a device-leaf signature and a receipt into the wire shape
// verifyDeviceBinding parses: [4]sigLen | teeSig | receipt.
func teeEnvelope(teeSig, receipt []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(teeSig)))
	out = append(out, teeSig...)
	return append(out, receipt...)
}

// attestedQuote returns the envelope binding deviceID = BLAKE3(pub) to the test
// PKI in tc, plus the deviceID itself.
func attestedQuote(t *testing.T, tc *teeChain, pub []byte) (env []byte, dev [32]byte) {
	t.Helper()
	dev = blake3.Sum256(pub)
	rep := reportWithDevice(dev, testAttestTime)
	receipt := tc.receiptFor(rep)
	teeSig := tc.signRaw(t, rep)
	return teeEnvelope(teeSig, receipt), dev
}

// --- happy path (generated PKI injected through the roots seam) -------------

func TestVerifyAndMintWork_E2E(t *testing.T) {
	const chainId = uint64(420420) // Beluga
	tc := newTEEChain(t, caNotAfter)
	pub, sk := genMLDSA(t)

	env, dev := attestedQuote(t, tc, pub)
	var nonce [32]byte
	nonce[31] = 0x01
	proof := BuildWorkProof(dev, nonce, uint64(testAttestTime), 3, 60, env) // confidential, 60 min
	sig := signMLDSA(t, sk, proof)
	cd := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{proof, pub, sig}, chainId)
	acc := ccAcc{s: newCCDB()}
	gas := AIMiningPrecompile.RequiredGas(cd)

	ret, _, err := AIMiningPrecompile.verifyAndMintWork(acc, cd[4:], gas, false, tc.roots)
	if err != nil {
		t.Fatalf("verifyAndMintWork: %v", err)
	}
	if new(big.Int).SetBytes(ret).Sign() <= 0 {
		t.Fatalf("reward must be positive, got %s", new(big.Int).SetBytes(ret))
	}

	// double-spend: same work id again -> rejected
	if _, _, err := AIMiningPrecompile.verifyAndMintWork(acc, cd[4:], gas, false, tc.roots); err == nil {
		t.Fatal("expected double-spend rejection")
	}

	// read-only: writes not allowed
	if _, _, err := AIMiningPrecompile.verifyAndMintWork(acc, cd[4:], gas, true, tc.roots); err == nil {
		t.Fatal("expected read-only rejection")
	}

	// invalid signature: fresh (unspent) work id, corrupted sig -> rejected on verify
	var nonce2 [32]byte
	nonce2[31] = 0x02
	fresh := BuildWorkProof(dev, nonce2, uint64(testAttestTime), 3, 60, env)
	badSig := signMLDSA(t, sk, fresh)
	badSig[0] ^= 0xFF
	bad := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{fresh, pub, badSig}, chainId)
	if _, _, err := AIMiningPrecompile.verifyAndMintWork(acc, bad[4:], AIMiningPrecompile.RequiredGas(bad), false, tc.roots); err == nil {
		t.Fatal("expected invalid-signature rejection")
	}

	// device-key mismatch: workProof deviceID != BLAKE3(pubkey) -> rejected even
	// though the TEE quote itself is well-formed (covers gate check #3).
	var nonce3 [32]byte
	nonce3[31] = 0x03
	var wrongDev [32]byte
	wrongDev[0] = 0xFF
	mismatch := BuildWorkProof(wrongDev, nonce3, uint64(testAttestTime), 3, 60, env)
	mSig := signMLDSA(t, sk, mismatch)
	mcd := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{mismatch, pub, mSig}, chainId)
	if _, _, err := AIMiningPrecompile.verifyAndMintWork(acc, mcd[4:], AIMiningPrecompile.RequiredGas(mcd), false, tc.roots); err != ErrDeviceKeyMismatch {
		t.Fatalf("deviceID mismatch: got %v, want ErrDeviceKeyMismatch", err)
	}
}

func TestVerifyAndMintData_E2E(t *testing.T) {
	const chainId = uint64(420420)
	tc := newTEEChain(t, caNotAfter)
	pub, sk := genMLDSA(t)
	env, _ := attestedQuote(t, tc, pub)

	desc := make([]byte, DataContributionSize)
	desc[31] = 0xDD                               // dataHash
	binary.BigEndian.PutUint64(desc[32:40], 1000) // 1000 data units
	binary.BigEndian.PutUint16(desc[40:42], 3)    // confidential
	desc = append(desc, env...)
	sig := signMLDSA(t, sk, desc)
	cd := tripleCalldata(SelectorVerifyAndMintData, [][]byte{desc, pub, sig}, chainId)
	acc := ccAcc{s: newCCDB()}
	gas := AIMiningPrecompile.RequiredGas(cd)

	ret, _, err := AIMiningPrecompile.verifyAndMintData(acc, cd[4:], gas, false, tc.roots)
	if err != nil {
		t.Fatalf("verifyAndMintData: %v", err)
	}
	if new(big.Int).SetBytes(ret).Sign() <= 0 {
		t.Fatal("data reward must be positive")
	}
	// same dataset -> double-claim rejected
	if _, _, err := AIMiningPrecompile.verifyAndMintData(acc, cd[4:], gas, false, tc.roots); err == nil {
		t.Fatal("expected double-claim rejection")
	}
}

// --- forge rejection (production Run, embedded Intel root) ------------------

// TestVerifyAndMintWork_ForgeRejected is the proof that the unbacked-mint forge
// is closed: an attacker self-signs a work proof with their OWN ML-DSA key and
// submits it through the production entry point. Without an embedded-root TEE
// quote vouching for the key, the mint is rejected. The CRITICAL bug was that
// this calldata used to mint unlimited reward.
func TestVerifyAndMintWork_ForgeRejected(t *testing.T) {
	const chainId = uint64(420420)
	acc := ccAcc{s: newCCDB()}

	// (a) attacker key, no TEE quote at all -> rejected.
	pub, sk := genMLDSA(t)
	dev := blake3.Sum256(pub)
	var nonce [32]byte
	nonce[31] = 0x01
	bare := BuildWorkProof(dev, nonce, uint64(testAttestTime), 3, 60, nil)
	sig := signMLDSA(t, sk, bare)
	cd := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{bare, pub, sig}, chainId)
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, AIMiningPrecompile.RequiredGas(cd), false); err != ErrMissingAttestation {
		t.Fatalf("self-signed, no quote: got %v, want ErrMissingAttestation", err)
	}

	// (b) attacker key, well-formed quote that chains to the attacker's OWN test
	//     root (NOT the embedded vendor root) -> rejected by the real verifier.
	tc := newTEEChain(t, caNotAfter)
	env, dev2 := attestedQuote(t, tc, pub)
	var nonce2 [32]byte
	nonce2[31] = 0x02
	proof := BuildWorkProof(dev2, nonce2, uint64(testAttestTime), 3, 60, env)
	sig2 := signMLDSA(t, sk, proof)
	cd2 := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{proof, pub, sig2}, chainId)
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd2, AIMiningPrecompile.RequiredGas(cd2), false); err != ErrTEESignatureInvalid {
		t.Fatalf("self-rooted quote: got %v, want ErrTEESignatureInvalid", err)
	}
}

// TestVerifyAndMintData_ForgeRejected mirrors the work case for data
// contributions through the production entry point.
func TestVerifyAndMintData_ForgeRejected(t *testing.T) {
	const chainId = uint64(420420)
	acc := ccAcc{s: newCCDB()}
	pub, sk := genMLDSA(t)

	// no attestation appended -> rejected.
	desc := make([]byte, DataContributionSize)
	desc[31] = 0xDD
	binary.BigEndian.PutUint64(desc[32:40], 1000)
	binary.BigEndian.PutUint16(desc[40:42], 3)
	sig := signMLDSA(t, sk, desc)
	cd := tripleCalldata(SelectorVerifyAndMintData, [][]byte{desc, pub, sig}, chainId)
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd, AIMiningPrecompile.RequiredGas(cd), false); err != ErrMissingAttestation {
		t.Fatalf("self-signed data, no quote: got %v, want ErrMissingAttestation", err)
	}

	// attacker test-rooted quote -> rejected by the real verifier.
	tc := newTEEChain(t, caNotAfter)
	env, _ := attestedQuote(t, tc, pub)
	desc2 := append(append([]byte{}, desc...), env...)
	sig2 := signMLDSA(t, sk, desc2)
	cd2 := tripleCalldata(SelectorVerifyAndMintData, [][]byte{desc2, pub, sig2}, chainId)
	if _, _, err := AIMiningPrecompile.Run(acc, common.Address{}, ContractAddress, cd2, AIMiningPrecompile.RequiredGas(cd2), false); err != ErrTEESignatureInvalid {
		t.Fatalf("self-rooted data quote: got %v, want ErrTEESignatureInvalid", err)
	}
}
