// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// --- test PKI helpers -------------------------------------------------------

const (
	testAttestTime = int64(1_700_000_000) // within all test cert validity windows
	caNotBefore    = int64(1_600_000_000)
	caNotAfter     = int64(2_000_000_000)
)

func mkCert(t *testing.T, tmpl, parent *x509.Certificate, pub, signerKey interface{}) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func caTemplate(serial int64, cn string, notAfter int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(caNotBefore, 0),
		NotAfter:              time.Unix(notAfter, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
}

func leafTemplate(serial int64, cn string, notAfter int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(caNotBefore, 0),
		NotAfter:     time.Unix(notAfter, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// teeChain is a generated root -> intermediate -> leaf attestation PKI.
type teeChain struct {
	root    *x509.Certificate
	inter   *x509.Certificate
	leaf    *x509.Certificate
	leafKey crypto.Signer
	roots   *x509.CertPool
}

// newTEEChain builds a 3-level ECDSA chain. leafNotAfter lets a caller expire
// the leaf for the expiry negative case.
func newTEEChain(t *testing.T, leafNotAfter int64) *teeChain {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := mkCert(t, caTemplate(1, "Test TEE Root", caNotAfter), caTemplate(1, "Test TEE Root", caNotAfter), &rootKey.PublicKey, rootKey)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inter := mkCert(t, caTemplate(2, "Test TEE Intermediate", caNotAfter), root, &interKey.PublicKey, rootKey)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := mkCert(t, leafTemplate(3, "Test TEE Leaf", leafNotAfter), inter, &leafKey.PublicKey, interKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &teeChain{root: root, inter: inter, leaf: leaf, leafKey: leafKey, roots: roots}
}

func report(deviceID byte, ts int64) []byte {
	r := make([]byte, teeReportLen)
	r[0] = deviceID
	binary.BigEndian.PutUint64(r[32:40], uint64(ts))
	binary.BigEndian.PutUint64(r[40:48], 0xCAFE)
	return r
}

// receiptFor concatenates report || leaf.DER || intermediate.DER.
func (tc *teeChain) receiptFor(rep []byte) []byte {
	out := append([]byte{}, rep...)
	out = append(out, tc.leaf.Raw...)
	out = append(out, tc.inter.Raw...)
	return out
}

func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// signRaw signs the report with the leaf key, raw r‖s (64 bytes for P-256).
func (tc *teeChain) signRaw(t *testing.T, rep []byte) []byte {
	t.Helper()
	key := tc.leafKey.(*ecdsa.PrivateKey)
	digest := sha256.Sum256(rep)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return append(leftPad32(r.Bytes()), leftPad32(s.Bytes())...)
}

// --- happy path -------------------------------------------------------------

func TestTEEAttestationValid(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	rep := report(0x01, testAttestTime)
	receipt := tc.receiptFor(rep)
	sig := tc.signRaw(t, rep)

	ok, err := verifyAttestation(receipt, sig, tc.roots)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("known-good attestation must verify")
	}
}

func TestTEEAttestationValidASN1(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	rep := report(0x02, testAttestTime)
	receipt := tc.receiptFor(rep)

	// ASN.1 DER encoded ECDSA signature path.
	key := tc.leafKey.(*ecdsa.PrivateKey)
	digest := sha256.Sum256(rep)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign asn1: %v", err)
	}
	ok, err := verifyAttestation(receipt, sig, tc.roots)
	if err != nil || !ok {
		t.Fatalf("ASN.1 ECDSA attestation must verify, ok=%v err=%v", ok, err)
	}
}

func TestTEEAttestationValidEd25519(t *testing.T) {
	// Build a chain whose leaf carries an Ed25519 key.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := mkCert(t, caTemplate(1, "ed root", caNotAfter), caTemplate(1, "ed root", caNotAfter), &rootKey.PublicKey, rootKey)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	leaf := mkCert(t, leafTemplate(2, "ed leaf", caNotAfter), root, edPub, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	rep := report(0x03, testAttestTime)
	receipt := append(append([]byte{}, rep...), leaf.Raw...)
	sig := ed25519.Sign(edPriv, rep)

	ok, err := verifyAttestation(receipt, sig, roots)
	if err != nil || !ok {
		t.Fatalf("Ed25519 attestation must verify, ok=%v err=%v", ok, err)
	}
}

// --- negative / rejection cases --------------------------------------------

func TestTEEAttestationTamperedReport(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	rep := report(0x01, testAttestTime)
	sig := tc.signRaw(t, rep) // signature over the ORIGINAL report
	rep[0] ^= 0xFF            // tamper the device id after signing
	receipt := tc.receiptFor(rep)

	ok, err := verifyAttestation(receipt, sig, tc.roots)
	if ok {
		t.Fatal("tampered report must be REJECTED")
	}
	if err != nil {
		t.Fatalf("tampered report should fail closed (false,nil), got err %v", err)
	}
}

func TestTEEAttestationWrongSigner(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	rep := report(0x01, testAttestTime)
	receipt := tc.receiptFor(rep)

	// Sign with a key that is NOT the leaf key.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256(rep)
	r, s, _ := ecdsa.Sign(rand.Reader, other, digest[:])
	sig := append(leftPad32(r.Bytes()), leftPad32(s.Bytes())...)

	ok, _ := verifyAttestation(receipt, sig, tc.roots)
	if ok {
		t.Fatal("signature by a non-leaf key must be REJECTED")
	}
}

func TestTEEAttestationTruncatedChain(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	rep := report(0x01, testAttestTime)
	sig := tc.signRaw(t, rep)

	// Receipt with the leaf only (intermediate dropped) cannot reach the root.
	receipt := append(append([]byte{}, rep...), tc.leaf.Raw...)
	ok, _ := verifyAttestation(receipt, sig, tc.roots)
	if ok {
		t.Fatal("chain that cannot reach the root must be REJECTED")
	}
}

func TestTEEAttestationExpiredLeaf(t *testing.T) {
	// Leaf expires before the attestation timestamp.
	tc := newTEEChain(t, testAttestTime-1)
	rep := report(0x01, testAttestTime)
	receipt := tc.receiptFor(rep)
	sig := tc.signRaw(t, rep)

	ok, _ := verifyAttestation(receipt, sig, tc.roots)
	if ok {
		t.Fatal("expired leaf must be REJECTED at attestation time")
	}
}

func TestTEEAttestationEmptyRootsFailsClosed(t *testing.T) {
	tc := newTEEChain(t, caNotAfter)
	rep := report(0x01, testAttestTime)
	receipt := tc.receiptFor(rep)
	sig := tc.signRaw(t, rep)

	// No trust anchor at all -> nothing can verify.
	ok, _ := verifyAttestation(receipt, sig, x509.NewCertPool())
	if ok {
		t.Fatal("empty roots pool must fail closed")
	}
}

func TestTEEAttestationMalformedInputs(t *testing.T) {
	// Short receipt -> structural error.
	if ok, err := verifyAttestation(make([]byte, 10), make([]byte, 64), x509.NewCertPool()); ok || err != ErrInvalidTEEReceipt {
		t.Fatalf("short receipt: want (false, ErrInvalidTEEReceipt), got (%v, %v)", ok, err)
	}
	// Empty signature -> structural error.
	if ok, err := verifyAttestation(make([]byte, teeReportLen+4), nil, x509.NewCertPool()); ok || err != ErrTEESignatureInvalid {
		t.Fatalf("empty sig: want (false, ErrTEESignatureInvalid), got (%v, %v)", ok, err)
	}
	// No certificate chain after the header -> structural error.
	if ok, err := verifyAttestation(make([]byte, teeReportLen), make([]byte, 64), x509.NewCertPool()); ok || err != ErrInvalidTEEReceipt {
		t.Fatalf("no chain: want (false, ErrInvalidTEEReceipt), got (%v, %v)", ok, err)
	}
	// Unparseable certificate chain -> structural error.
	bad := append(make([]byte, teeReportLen), []byte("not-a-der-cert")...)
	if ok, err := verifyAttestation(bad, make([]byte, 64), x509.NewCertPool()); ok || err != ErrInvalidTEEReceipt {
		t.Fatalf("garbage chain: want (false, ErrInvalidTEEReceipt), got (%v, %v)", ok, err)
	}
}

// --- production trust anchor ------------------------------------------------

// TestProductionTEEPathFailsClosed proves the exported verifyTEESignature
// (which uses the embedded Intel-only root pool) rejects a chain that does not
// terminate at an embedded vendor root, and rejects obviously fake input.
func TestProductionTEEPathFailsClosed(t *testing.T) {
	tc := newTEEChain(t, caNotAfter) // chains to a TEST root, not Intel
	rep := report(0x01, testAttestTime)
	receipt := tc.receiptFor(rep)
	sig := tc.signRaw(t, rep)

	if ok, _ := verifyTEESignature(receipt, sig); ok {
		t.Fatal("a chain not anchored at an embedded vendor root must be REJECTED by the production path")
	}

	// A bare 48-byte receipt with a fake 64-byte signature (the old stub
	// accepted this) must now be rejected.
	if ok, _ := verifyTEESignature(report(0x01, testAttestTime), make([]byte, 64)); ok {
		t.Fatal("fake chainless receipt must be REJECTED by the production path")
	}
}

// TestEmbeddedIntelRootIsGenuine proves the compiled-in trust anchor is the
// real Intel SGX Root CA (by serial number), not a placeholder.
func TestEmbeddedIntelRootIsGenuine(t *testing.T) {
	block, _ := pem.Decode([]byte(intelSGXRootCAPEM))
	if block == nil {
		t.Fatal("embedded Intel root PEM does not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("embedded Intel root does not parse: %v", err)
	}
	wantSerial, _ := new(big.Int).SetString("22650CD65A9D3489F383B49552BF501B392706AC", 16)
	if cert.SerialNumber.Cmp(wantSerial) != 0 {
		t.Fatalf("embedded root serial mismatch: got %X", cert.SerialNumber)
	}
	if cert.Subject.CommonName != "Intel SGX Root CA" {
		t.Fatalf("embedded root CN mismatch: %q", cert.Subject.CommonName)
	}
	// The pool must contain it (anchor actually loaded).
	if teeRootPool() == nil || len(teeRootPool().Subjects()) == 0 { //nolint:staticcheck // Subjects ok for test assertion
		t.Fatal("teeRootPool did not load the embedded anchor")
	}
}
