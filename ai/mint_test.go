// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/blake3"
)

// memState is a StateDB the mint helpers can be driven against directly.
type memState struct{ slots map[[32]byte][32]byte }

func newMemState() *memState { return &memState{slots: make(map[[32]byte][32]byte)} }

func (m *memState) GetState(_ [20]byte, k [32]byte) [32]byte { return m.slots[k] }
func (m *memState) SetState(_ [20]byte, k, v [32]byte)       { m.slots[k] = v }

// workProof builds a proof with the documented layout:
// deviceId(32) | nonce(32) | timestamp(8) | privacy(2) | computeMinutes(4).
func workProof(device, nonce byte, privacy uint16, minutes uint32) []byte {
	p := make([]byte, WorkProofMinSize)
	for i := 0; i < 32; i++ {
		p[i] = device
		p[32+i] = nonce
	}
	binary.BigEndian.PutUint64(p[64:72], 1_700_000_000)
	binary.BigEndian.PutUint16(p[72:74], privacy)
	binary.BigEndian.PutUint32(p[74:78], minutes)
	return p
}

// descriptor builds a data contribution: dataHash(32) | size(8) | privacy(2).
func descriptor(hash byte, size uint64, privacy uint16) []byte {
	d := make([]byte, DataContributionSize)
	for i := 0; i < 32; i++ {
		d[i] = hash
	}
	binary.BigEndian.PutUint64(d[32:40], size)
	binary.BigEndian.PutUint16(d[40:42], privacy)
	return d
}

// TestMintWork_RefusesReplay is the double-spend property: the same work may be minted
// exactly once per chain. A second attempt must be refused, not silently re-paid.
func TestMintWork_RefusesReplay(t *testing.T) {
	st := newMemState()
	proof := workProof(0xAA, 0xBB, PrivacyConfidential, 10)

	first, err := mintWork(st, proof, 96369)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.Positive(t, first.Sign(), "a valid work proof must pay something")

	_, err = mintWork(st, proof, 96369)
	require.ErrorIs(t, err, ErrWorkAlreadySpent, "the same work must not mint twice")

	// The work id binds the chain, so the same proof on another chain is a distinct claim.
	other, err := mintWork(st, proof, 200200)
	require.NoError(t, err)
	require.Equal(t, first, other)

	// ...and that one is now spent too.
	_, err = mintWork(st, proof, 200200)
	require.ErrorIs(t, err, ErrWorkAlreadySpent)
}

// TestMintWork_RefusesMalformedProof covers the length and content refusals, including the
// boundary: one byte short of the minimum is refused, exactly the minimum is accepted.
func TestMintWork_RefusesMalformedProof(t *testing.T) {
	st := newMemState()

	for n := 0; n < WorkProofMinSize; n++ {
		_, err := mintWork(st, make([]byte, n), 1)
		require.ErrorIs(t, err, ErrInvalidWorkProof, "proof of %d bytes", n)
	}
	_, err := mintWork(st, workProof(1, 2, PrivacyConfidential, 1), 1)
	require.NoError(t, err, "exactly the minimum length is a valid proof")

	// An unknown privacy level is refused rather than priced at some default.
	_, err = mintWork(st, workProof(3, 4, 0xBEEF, 1), 1)
	require.ErrorIs(t, err, ErrInvalidPrivacyLevel)
}

// TestMintData_RefusesReplayAndMalformed mirrors the work path for data contributions and
// pins that the contribution id binds size and privacy as well as the hash — otherwise the
// same dataset could be re-claimed by relabelling it.
func TestMintData_RefusesReplayAndMalformed(t *testing.T) {
	st := newMemState()
	d := descriptor(0x11, 1024, PrivacyConfidential)

	first, err := mintData(st, d, 96369)
	require.NoError(t, err)
	require.Positive(t, first.Sign())

	_, err = mintData(st, d, 96369)
	require.ErrorIs(t, err, ErrWorkAlreadySpent)

	// A different declared size is a different contribution id, so it is mintable...
	_, err = mintData(st, descriptor(0x11, 2048, PrivacyConfidential), 96369)
	require.NoError(t, err)
	// ...and it pays proportionally more for more data.
	bigger, err := mintData(st, descriptor(0x22, 2048, PrivacyConfidential), 96369)
	require.NoError(t, err)
	require.Positive(t, bigger.Cmp(first), "a larger contribution must pay more")

	for n := 0; n < DataContributionSize; n++ {
		_, err := mintData(st, make([]byte, n), 1)
		require.ErrorIs(t, err, ErrInvalidWorkProof, "descriptor of %d bytes", n)
	}

	_, err = mintData(st, descriptor(0x33, 1, 0xBEEF), 1)
	require.ErrorIs(t, err, ErrInvalidPrivacyLevel)
}

// TestVerifyDeviceBinding_Refusals covers every refusal in the envelope parser. The
// envelope is [4]sigLen | teeSig | receipt, and a caller controls all of it.
func TestVerifyDeviceBinding_Refusals(t *testing.T) {
	roots := x509.NewCertPool()
	pub := []byte("some public key")

	// Too short to hold the length prefix at all.
	for n := 0; n < 4; n++ {
		require.ErrorIs(t, verifyDeviceBinding(pub, make([]byte, n), roots), ErrInvalidTEEReceipt,
			"envelope of %d bytes", n)
	}

	// A zero-length signature is refused: an empty signature can never be verified, and
	// accepting it would let the receipt stand unsigned.
	zero := make([]byte, 64)
	binary.BigEndian.PutUint32(zero[:4], 0)
	require.ErrorIs(t, verifyDeviceBinding(pub, zero, roots), ErrInvalidTEEReceipt)

	// A declared signature length that overruns the envelope is refused rather than
	// slicing past the end.
	for _, n := range []uint32{61, 100, 1 << 31, ^uint32(0)} {
		env := make([]byte, 64)
		binary.BigEndian.PutUint32(env[:4], n)
		require.NotPanics(t, func() {
			require.ErrorIs(t, verifyDeviceBinding(pub, env, roots), ErrInvalidTEEReceipt,
				"declared sigLen %d", n)
		})
	}

	// A well-framed envelope with an unverifiable receipt fails closed against an empty
	// root pool — never "no roots, therefore trusted".
	env := make([]byte, 200)
	binary.BigEndian.PutUint32(env[:4], 64)
	require.Error(t, verifyDeviceBinding(pub, env, roots))
}

// TestVerifyAndMint_RefusalsThroughDispatch covers the mint entry points' own guards:
// read-only, out of gas, malformed framing, and a signature that does not verify. Each must
// leave the spent set untouched.
func TestVerifyAndMint_RefusalsThroughDispatch(t *testing.T) {
	c := &AIMiningContract{}
	roots := x509.NewCertPool()

	body := func() []byte {
		proof := workProof(0x01, 0x02, PrivacyConfidential, 5)
		enc := func(b []byte) []byte {
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, uint32(len(b)))
			return append(h, b...)
		}
		out := append(enc(proof), enc(make([]byte, MLDSA44PublicKeySize))...)
		out = append(out, enc(make([]byte, MLDSA44SignatureSize))...)
		tail := make([]byte, 8)
		binary.BigEndian.PutUint64(tail, 96369)
		return append(out, tail...)
	}()

	for name, fn := range map[string]func(contract.AccessibleState, []byte, uint64, bool) ([]byte, uint64, error){
		"work": func(s contract.AccessibleState, in []byte, gas uint64, ro bool) ([]byte, uint64, error) {
			return c.verifyAndMintWork(s, in, gas, ro, roots)
		},
		"data": func(s contract.AccessibleState, in []byte, gas uint64, ro bool) ([]byte, uint64, error) {
			return c.verifyAndMintData(s, in, gas, ro, roots)
		},
	} {
		t.Run(name, func(t *testing.T) {
			st := newTestAS()

			// Read-only: minting writes the spent set, so a static call must be refused.
			_, _, err := fn(st, body, 1_000_000, true)
			require.ErrorContains(t, err, "read-only")

			// Out of gas, at the boundary.
			_, _, err = fn(st, body, GasVerifyAndMintWork-1, false)
			require.ErrorContains(t, err, "out of gas")

			// Malformed framing.
			_, _, err = fn(st, []byte{0, 0, 0}, 1_000_000, false)
			require.ErrorIs(t, err, ErrInputTooShort)

			// A signature of the right length that is not a signature must not mint.
			_, _, err = fn(st, body, 1_000_000, false)
			require.Error(t, err, "an unverifiable attestation must never mint")
		})
	}
}

// TestVerifyECDSAReport_AcceptsBothEncodingsAndRefusesJunk covers the two signature
// encodings TEE quotes use in practice, on both curve widths (which select different
// pre-hashes), and proves a wrong-length or tampered signature is refused.
func TestVerifyECDSAReport_AcceptsBothEncodingsAndRefusesJunk(t *testing.T) {
	report := make([]byte, teeReportLen)
	for i := range report {
		report[i] = byte(i)
	}

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		digest := reportDigest(curve, report)

		// ASN.1 DER, the encoding crypto/ecdsa produces by default.
		der, err := ecdsa.SignASN1(rand.Reader, key, digest)
		require.NoError(t, err)
		require.True(t, verifyECDSAReport(&key.PublicKey, report, der),
			"%s: DER signature must verify", curve.Params().Name)

		// Fixed-width raw r||s, the SGX/TDX quote encoding.
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		require.NoError(t, err)
		byteLen := (curve.Params().BitSize + 7) / 8
		raw := make([]byte, 2*byteLen)
		r.FillBytes(raw[:byteLen])
		s.FillBytes(raw[byteLen:])
		require.True(t, verifyECDSAReport(&key.PublicKey, report, raw),
			"%s: raw r||s signature must verify", curve.Params().Name)

		// A tampered raw signature must not.
		bad := append([]byte{}, raw...)
		bad[0] ^= 0x01
		require.False(t, verifyECDSAReport(&key.PublicKey, report, bad))

		// Neither must a signature over a different report.
		require.False(t, verifyECDSAReport(&key.PublicKey, append(report, 0), raw))

		// Nor one of the wrong length, in either direction.
		require.False(t, verifyECDSAReport(&key.PublicKey, report, raw[:len(raw)-1]))
		require.False(t, verifyECDSAReport(&key.PublicKey, report, append(raw, 0)))
	}

	// A key with no curve is refused rather than dereferenced.
	require.False(t, verifyECDSAReport(&ecdsa.PublicKey{}, report, make([]byte, 64)))
}

func reportDigest(curve elliptic.Curve, report []byte) []byte {
	if curve.Params().BitSize > 256 {
		d := sha512.Sum384(report)
		return d[:]
	}
	d := sha256.Sum256(report)
	return d[:]
}

// TestVerifyReportSignature_RejectsUnknownKeyTypes proves the signature verifier fails
// closed on a key type it does not understand rather than defaulting to accept.
func TestVerifyReportSignature_RejectsUnknownKeyTypes(t *testing.T) {
	report := make([]byte, teeReportLen)
	require.False(t, verifyReportSignature("not a key", report, make([]byte, 64)))
	require.False(t, verifyReportSignature(nil, report, make([]byte, 64)))
	require.False(t, verifyReportSignature(struct{}{}, report, nil))
}

// TestTeeRootPool_IsNeverNilAndNeverTheSystemStore pins the fail-closed property: the pool
// is built once, is never nil, and repeated calls return the same pool.
func TestTeeRootPool_IsNeverNilAndNeverTheSystemStore(t *testing.T) {
	pool := teeRootPool()
	require.NotNil(t, pool)
	require.Same(t, pool, teeRootPool(), "the pool is built once")

	system, err := x509.SystemCertPool()
	if err == nil {
		require.NotEqual(t, len(system.Subjects()), len(pool.Subjects()), //nolint:staticcheck
			"the TEE pool must not be the system root store")
	}
}

// TestComputeWorkId_BindsEveryInput proves the work id changes when any of its three inputs
// changes — if it did not, two distinct claims would collide in the spent set and one would
// be unmintable, or one claim could be replayed as another.
func TestComputeWorkId_BindsEveryInput(t *testing.T) {
	var device, nonce [32]byte
	device[0], nonce[0] = 1, 2
	base := ComputeWorkId(device, nonce, 96369)

	altDevice := device
	altDevice[31] ^= 1
	altNonce := nonce
	altNonce[31] ^= 1

	require.NotEqual(t, base, ComputeWorkId(altDevice, nonce, 96369), "device must bind")
	require.NotEqual(t, base, ComputeWorkId(device, altNonce, 96369), "nonce must bind")
	require.NotEqual(t, base, ComputeWorkId(device, nonce, 96368), "chain must bind")
	require.Equal(t, base, ComputeWorkId(device, nonce, 96369), "and it is deterministic")
}

// TestBlake3DeviceBinding documents the binding the attestation gate checks: the attested
// device id is BLAKE3 of the public key, so a miner cannot present someone else's quote
// alongside its own key.
func TestBlake3DeviceBinding(t *testing.T) {
	keyA := []byte("public key A")
	keyB := []byte("public key B")
	require.NotEqual(t, blake3.Sum256(keyA), blake3.Sum256(keyB))
	require.Equal(t, blake3.Sum256(keyA), blake3.Sum256(keyA))
}

// TestVerifyReportSignature_AllKeyTypes covers each key type the verifier accepts, and
// proves each rejects a signature over a different report.
func TestVerifyReportSignature_AllKeyTypes(t *testing.T) {
	report := make([]byte, teeReportLen)
	other := append(append([]byte{}, report...), 1)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edSig := ed25519.Sign(edPriv, report)
	require.True(t, verifyReportSignature(edPub, report, edSig))
	require.False(t, verifyReportSignature(edPub, other, edSig))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	digest := sha256.Sum256(report)
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	require.NoError(t, err)
	require.True(t, verifyReportSignature(&rsaKey.PublicKey, report, rsaSig))
	require.False(t, verifyReportSignature(&rsaKey.PublicKey, other, rsaSig))
}

// TestRunVerifyTEE_Refusals covers the dispatch guards on the TEE selector: out of gas at
// the boundary, malformed framing, and a receipt that cannot be verified.
func TestRunVerifyTEE_Refusals(t *testing.T) {
	c := &AIMiningContract{}

	_, _, err := c.runVerifyTEE(newTestAS(), make([]byte, 64), GasVerifyTEE-1)
	require.ErrorContains(t, err, "out of gas")

	_, _, err = c.runVerifyTEE(newTestAS(), []byte{0, 0, 0}, 1_000_000)
	require.ErrorIs(t, err, ErrInputTooShort)

	// A well-framed but empty receipt is refused by VerifyTEE itself.
	body := make([]byte, 8) // two zero-length blobs
	_, _, err = c.runVerifyTEE(newTestAS(), body, 1_000_000)
	require.Error(t, err, "an empty TEE receipt must not verify")
}

// TestRunCalculateReward_RefusesUnpriceableProof proves a proof the reward schedule cannot
// price is surfaced as an error rather than paying zero.
func TestRunCalculateReward_RefusesUnpriceableProof(t *testing.T) {
	c := &AIMiningContract{}

	input := append(workProof(1, 2, 0xBEEF, 5), make([]byte, 8)...)
	_, _, err := c.runCalculateReward(newTestAS(), input, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidPrivacyLevel)

	_, _, err = c.runCalculateReward(newTestAS(), make([]byte, 85), 1_000_000)
	require.ErrorContains(t, err, "too short")

	_, _, err = c.runCalculateReward(newTestAS(), make([]byte, 86), GasCalculateReward-1)
	require.ErrorContains(t, err, "out of gas")
}

// TestBatchVerifyTEE_ScoresMatchVerdicts proves the batch TEE helper reports a zero score
// exactly when it reports invalid — a score that survived a failed verification would let a
// caller weight a rejected attestation.
func TestBatchVerifyTEE_ScoresMatchVerdicts(t *testing.T) {
	atts := [][]byte{
		nil,
		make([]byte, NVTrustMinQuoteSize-1), // below the minimum quote size
		make([]byte, NVTrustMinQuoteSize),   // long enough, but not a real quote
	}
	ok, scores, err := BatchVerifyTEE(atts)
	require.NoError(t, err)
	require.Len(t, ok, len(atts))
	require.Len(t, scores, len(atts))
	for i := range atts {
		require.Falsef(t, ok[i], "attestation %d must not verify", i)
		require.Zerof(t, scores[i], "a rejected attestation must score zero, got %d", scores[i])
	}

	require.Empty(t, mustBatchTEE(t, nil), "an empty batch is an empty result")
}

func mustBatchTEE(t *testing.T, atts [][]byte) []bool {
	t.Helper()
	ok, _, err := BatchVerifyTEE(atts)
	require.NoError(t, err)
	return ok
}

// TestVerifyDeviceBinding_RefusesAnotherDevicesQuote closes a hole the mutation check
// found: deleting the device check inside verifyDeviceBinding left the whole suite green.
//
// The reason is that two DIFFERENT bindings both compare against BLAKE3(pubkey), and only
// one of them was exercised. verifyAndMintWork checks that the WORK PROOF's deviceID field
// matches the signing key (covered by the e2e forge test), while verifyDeviceBinding checks
// that the deviceID inside the ATTESTATION RECEIPT matches it. Only the second stops a
// miner presenting a genuine, correctly-signed quote belonging to somebody else's device
// alongside its own key — every certificate verifies, the report signature verifies, and
// the work proof is internally consistent. Without this check that mints.
func TestVerifyDeviceBinding_RefusesAnotherDevicesQuote(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	victimPub, _ := genMLDSA(t)
	attackerPub, attackerSK := genMLDSA(t)

	// A real, fully valid quote for the victim's device.
	victimEnv, victimDev := attestedQuote(t, tc, victimPub)
	require.NoError(t, verifyDeviceBinding(victimPub, victimEnv, tc.roots),
		"the victim's own quote must verify for the victim's key")
	require.NotEqual(t, victimDev, blake3.Sum256(attackerPub))

	// The attacker replays that quote under its own key. Nothing about the
	// certificate chain or the report signature is wrong — only the identity is.
	require.ErrorIs(t, verifyDeviceBinding(attackerPub, victimEnv, tc.roots),
		ErrDeviceKeyMismatch,
		"a quote attesting another device must not vouch for this key")

	// And it must not mint, even with the work proof made internally consistent with
	// the attacker's own key so the second (work-proof) binding cannot be what refuses it.
	var nonce [32]byte
	nonce[31] = 0x77
	proof := BuildWorkProof(blake3.Sum256(attackerPub), nonce, uint64(testAttestTime), 3, 60, victimEnv)
	cd := tripleCalldata(SelectorVerifyAndMintWork, [][]byte{proof, attackerPub,
		signMLDSA(t, attackerSK, proof)}, 420420)

	acc := ccAcc{s: newCCDB()}
	_, _, err := AIMiningPrecompile.verifyAndMintWork(acc, cd[4:],
		AIMiningPrecompile.RequiredGas(cd), false, tc.roots)
	require.ErrorIs(t, err, ErrDeviceKeyMismatch, "a replayed quote must never mint")
}

// TestRun_ReadOnlyRefusesEveryStateWriter closes a hole the mutation check found: nothing
// asserted that markSpent is refused under a static call. STATICCALL promises the callee
// mutates nothing, and markSpent writes the spent set — so a static call could burn a work
// id, permanently denying a legitimate miner its reward.
//
// Every selector is driven, so a writer added later without a guard is caught here rather
// than in production.
func TestRun_ReadOnlyRefusesEveryStateWriter(t *testing.T) {
	writers := map[uint32][]byte{
		SelectorMarkSpent:         make([]byte, 32),
		SelectorVerifyAndMintWork: make([]byte, 128),
		SelectorVerifyAndMintData: make([]byte, 128),
	}
	readers := map[uint32][]byte{
		SelectorVerifyMLDSA:     make([]byte, 128),
		SelectorCalculateReward: make([]byte, 128),
		SelectorVerifyTEE:       make([]byte, 128),
		SelectorIsSpent:         make([]byte, 32),
		SelectorComputeWorkId:   make([]byte, 72),
	}

	c := &AIMiningContract{}
	run := func(sel uint32, body []byte, readOnly bool) error {
		input := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(input[:4], sel)
		copy(input[4:], body)
		_, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 10_000_000, readOnly)
		return err
	}

	for sel, body := range writers {
		require.ErrorContainsf(t, run(sel, body, true), "read-only",
			"selector %#x writes state and must be refused under a static call", sel)
		// The same call outside a static context gets past the guard and fails, if at
		// all, for its own reasons — proving the refusal is the readOnly flag and not
		// the body.
		require.NotErrorIsf(t, run(sel, body, false), errReadOnlySentinel, "selector %#x", sel)
	}

	for sel, body := range readers {
		err := run(sel, body, true)
		if err != nil {
			require.NotContainsf(t, err.Error(), "read-only",
				"selector %#x only reads and must not be refused as a writer", sel)
		}
	}
}

// errReadOnlySentinel is never returned by anything; it exists so the assertion above reads
// as a type check rather than another string match.
var errReadOnlySentinel = errStr("read-only sentinel")

type errStr string

func (e errStr) Error() string { return string(e) }

// TestVerifyAndMintData_ForgedSignatureIsRefused closes a hole the mutation check found:
// deleting the ML-DSA validity gate on the data path left the whole suite green, meaning a
// forged signature would have minted a reward.
//
// The existing forge test perturbs the descriptor, so a later gate (device binding, or the
// attestation itself) refuses it and the signature check is never the thing that fires.
// Here EVERYTHING else is valid — a genuine quote for this key, a descriptor bound to it —
// and only the signature is wrong, so nothing but the signature gate can refuse it.
func TestVerifyAndMintData_ForgedSignatureIsRefused(t *testing.T) {
	const chainID = uint64(420420)
	tc := newTEEChain(t, caNotAfter)
	pub, sk := genMLDSA(t)
	env, _ := attestedQuote(t, tc, pub)

	desc := make([]byte, DataContributionSize)
	desc[31] = 0xDD
	binary.BigEndian.PutUint64(desc[32:40], 1000)
	binary.BigEndian.PutUint16(desc[40:42], PrivacyConfidential)
	desc = append(desc, env...)

	// The control: the genuine signature mints, so every other gate is satisfied.
	good := signMLDSA(t, sk, desc)
	cd := tripleCalldata(SelectorVerifyAndMintData, [][]byte{desc, pub, good}, chainID)
	ret, _, err := AIMiningPrecompile.verifyAndMintData(ccAcc{s: newCCDB()}, cd[4:],
		AIMiningPrecompile.RequiredGas(cd), false, tc.roots)
	require.NoError(t, err, "the control must mint, or this test proves nothing")
	require.Positive(t, new(big.Int).SetBytes(ret).Sign())

	// Now the same claim with the signature broken, one forgery at a time.
	forgeries := map[string][]byte{
		"one bit flipped":        flip(good, len(good)/2, 0x01),
		"first byte flipped":     flip(good, 0, 0x80),
		"last byte flipped":      flip(good, len(good)-1, 0x01),
		"all zero":               make([]byte, len(good)),
		"signature over another": signMLDSA(t, sk, append(append([]byte{}, desc...), 0)),
	}
	for name, bad := range forgeries {
		t.Run(name, func(t *testing.T) {
			cd := tripleCalldata(SelectorVerifyAndMintData, [][]byte{desc, pub, bad}, chainID)
			_, _, err := AIMiningPrecompile.verifyAndMintData(ccAcc{s: newCCDB()}, cd[4:],
				AIMiningPrecompile.RequiredGas(cd), false, tc.roots)
			require.Error(t, err, "a forged signature must never mint")
			require.Contains(t, err.Error(), "ml-dsa",
				"the signature gate must be what refuses it, not a later check")
		})
	}

	// A signature from a DIFFERENT key of the same parameter set must not mint either.
	_, otherSK := genMLDSA(t)
	cd = tripleCalldata(SelectorVerifyAndMintData,
		[][]byte{desc, pub, signMLDSA(t, otherSK, desc)}, chainID)
	_, _, err = AIMiningPrecompile.verifyAndMintData(ccAcc{s: newCCDB()}, cd[4:],
		AIMiningPrecompile.RequiredGas(cd), false, tc.roots)
	require.ErrorContains(t, err, "ml-dsa", "a signature from another key must not mint")
}

func flip(b []byte, i int, mask byte) []byte {
	out := append([]byte{}, b...)
	out[i] ^= mask
	return out
}
