// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// --- helpers ----------------------------------------------------------------

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// selfRootedQuote builds a structurally valid TEE quote signed by a leaf that
// chains to the attacker's OWN root — NOT the embedded vendor root. The real
// verifier (ai.VerifyTEE) must reject it. This is a "forge any GPU" attempt.
func selfRootedQuote(t *testing.T) (receipt, sig []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "forged root"},
		NotBefore:             time.Unix(1_600_000_000, 0),
		NotAfter:              time.Unix(2_000_000_000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "forged leaf"},
		NotBefore:    time.Unix(1_600_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	report := make([]byte, 48)
	report[0] = 0xAB
	binary.BigEndian.PutUint64(report[32:40], 1_700_000_000)
	receipt = append(append([]byte{}, report...), leaf.Raw...)

	digest := sha256.Sum256(report)
	r, s, _ := ecdsa.Sign(rand.Reader, leafKey, digest[:])
	sig = append(leftPad32(r.Bytes()), leftPad32(s.Bytes())...)
	return receipt, sig
}

// minimal AccessibleState exposing only a block timestamp (the only consensus
// input the attestation precompile reads).
type attBC struct{ ts uint64 }

func (b attBC) Number() *big.Int                                       { return big.NewInt(1) }
func (b attBC) Timestamp() uint64                                      { return b.ts }
func (b attBC) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

type attAS struct{ ts uint64 }

func (a attAS) GetStateDB() contract.StateDB                     { return nil }
func (a attAS) GetBlockContext() contract.BlockContext           { return attBC{a.ts} }
func (a attAS) GetConsensusContext() context.Context             { return context.Background() }
func (a attAS) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (a attAS) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

// --- forge rejection: zero / garbage / self-rooted evidence -----------------

// TestVerifyNVTrust_ForgedRejected is the proof the GPU-attestation forge is
// closed. The prior fake returned Verified:true (score 93) for zero-filled
// evidence; the real verifier rejects zero-byte, garbage, and self-rooted
// quotes alike.
func TestVerifyNVTrust_ForgedRejected(t *testing.T) {
	cases := map[string]QuoteInput{
		"zero":      {Receipt: make([]byte, 512), Signature: make([]byte, 64)},
		"empty":     {Receipt: nil, Signature: nil},
		"garbage":   {Receipt: []byte("not-a-tee-quote-at-all"), Signature: []byte("nope")},
		"shortrcpt": {Receipt: make([]byte, 10), Signature: make([]byte, 64)},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := VerifyNVTrust(mustJSON(t, in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var o VerifyNVTrustOutput
			if err := json.Unmarshal(out, &o); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if o.Verified {
				t.Fatal("forged GPU evidence must NOT verify")
			}
			if o.TrustScore != 0 {
				t.Fatalf("unverified quote must score 0, got %d", o.TrustScore)
			}
		})
	}
}

// TestVerifyNVTrust_SelfRootedRejected: a well-formed quote that chains to the
// attacker's own root (not the embedded vendor root) is rejected.
func TestVerifyNVTrust_SelfRootedRejected(t *testing.T) {
	rcpt, sig := selfRootedQuote(t)
	out, err := VerifyNVTrust(mustJSON(t, QuoteInput{Receipt: rcpt, Signature: sig}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var o VerifyNVTrustOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if o.Verified {
		t.Fatal("a quote not anchored at an embedded vendor root must be REJECTED")
	}
}

func TestVerifyTPM_ForgedRejected(t *testing.T) {
	out, err := VerifyTPM(mustJSON(t, QuoteInput{Receipt: make([]byte, 1200), Signature: make([]byte, 64)}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var o VerifyTPMOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if o.Verified || o.TrustScore != 0 {
		t.Fatalf("forged CPU TEE quote must be rejected, got verified=%v score=%d", o.Verified, o.TrustScore)
	}
}

func TestVerifyCompute_ForgedRejected(t *testing.T) {
	rcpt, sig := selfRootedQuote(t)
	out, err := VerifyCompute(mustJSON(t, QuoteInput{Receipt: rcpt, Signature: sig}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var o VerifyComputeOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if o.Verified || o.ResultValid {
		t.Fatal("compute result without a genuine TEE quote must be rejected")
	}
}

func TestVerifyNVTrust_MalformedJSON(t *testing.T) {
	if _, err := VerifyNVTrust([]byte("{not json")); err != ErrInvalidInput {
		t.Fatalf("malformed JSON: want ErrInvalidInput, got %v", err)
	}
}

// --- CreateAttestation: fail-closed + deterministic block-time expiry --------

func TestCreateAttestation_FailsClosed(t *testing.T) {
	const blockTS = uint64(1_700_000_000)
	out, err := CreateAttestation(mustJSON(t, QuoteInput{Receipt: make([]byte, 512), Signature: make([]byte, 64)}), blockTS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var o CreateAttestationOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if o.Success {
		t.Fatal("forged evidence must NOT create a successful attestation")
	}
	if o.TrustScore != 0 {
		t.Fatalf("failed attestation must score 0, got %d", o.TrustScore)
	}
	// ExpiresAt is derived from the block timestamp, never the wall clock.
	if o.ExpiresAt != blockTS+attestationTTL {
		t.Fatalf("expiry must be block-time+TTL=%d, got %d", blockTS+attestationTTL, o.ExpiresAt)
	}
	// A deterministic id is still issued, bound to the presented receipt.
	if o.AttestationID == [32]byte{} {
		t.Fatal("attestation id must be derived from the receipt")
	}
}

// TestCreateAttestation_Deterministic proves the consensus-split non-determinism
// (time.Now + process-global map) is gone: identical (input, blockTS) yields
// byte-identical output, and the expiry tracks the block timestamp exactly.
func TestCreateAttestation_Deterministic(t *testing.T) {
	in := mustJSON(t, QuoteInput{Receipt: make([]byte, 64), Signature: make([]byte, 64)})

	a, err := CreateAttestation(in, 1000)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CreateAttestation(in, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("CreateAttestation must be deterministic for identical (input, blockTS)")
	}

	var o1, o2 CreateAttestationOutput
	_ = json.Unmarshal(a, &o1)
	c, _ := CreateAttestation(in, 2000)
	_ = json.Unmarshal(c, &o2)
	if o2.ExpiresAt-o1.ExpiresAt != 1000 {
		t.Fatalf("expiry must move with block time: delta=%d, want 1000", o2.ExpiresAt-o1.ExpiresAt)
	}
}

// --- GetDeviceStatus: stateless, always not-found ---------------------------

func TestGetDeviceStatus_NotFound(t *testing.T) {
	out, err := GetDeviceStatus(mustJSON(t, GetDeviceStatusInput{DeviceID: [32]byte{0xFF}}))
	if err != nil {
		t.Fatal(err)
	}
	var o GetDeviceStatusOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatal(err)
	}
	if o.Found {
		t.Error("stateless precompile keeps no registry: status must be not-found")
	}
}

// --- Run dispatch + stateful wrapper threading ------------------------------

func TestRun_DispatchAndDeterminism(t *testing.T) {
	// Every known selector routes and verification fails closed on a dummy quote.
	payload := mustJSON(t, QuoteInput{Receipt: make([]byte, 64), Signature: make([]byte, 64)})
	for _, sel := range [][4]byte{{1, 0, 0, 0}, {2, 0, 0, 0}, {3, 0, 0, 0}, {4, 0, 0, 0}} {
		input := append(sel[:], payload...)
		out1, err1 := Run(input, 1700000000)
		out2, err2 := Run(input, 1700000000)
		if err1 != nil || err2 != nil {
			t.Fatalf("selector %v: unexpected error %v / %v", sel, err1, err2)
		}
		if string(out1) != string(out2) {
			t.Fatalf("selector %v: non-deterministic output", sel)
		}
	}
	if _, err := Run([]byte{0xff, 0xff, 0xff, 0xff}, 0); err != ErrInvalidInput {
		t.Errorf("unknown selector: want ErrInvalidInput, got %v", err)
	}
	if _, err := Run([]byte{0x01}, 0); err != ErrInvalidInput {
		t.Errorf("short input: want ErrInvalidInput, got %v", err)
	}
}

// TestStatefulRun_BlockTimestampThreaded proves the stateful wrapper passes the
// block timestamp from AccessibleState (not time.Now) into CreateAttestation.
func TestStatefulRun_BlockTimestampThreaded(t *testing.T) {
	payload := mustJSON(t, QuoteInput{Receipt: make([]byte, 64), Signature: make([]byte, 64)})
	input := append([]byte{0x04, 0x00, 0x00, 0x00}, payload...)

	out, _, err := Precompile.Run(attAS{ts: 4242}, common.Address{}, ContractAddress, input, RequiredGas(input), false)
	if err != nil {
		t.Fatalf("stateful run: %v", err)
	}
	var o CreateAttestationOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatal(err)
	}
	if o.ExpiresAt != 4242+attestationTTL {
		t.Fatalf("expiry must come from block ts: got %d, want %d", o.ExpiresAt, 4242+attestationTTL)
	}
}

// --- pure helpers + gas (unchanged surface) ---------------------------------

func TestIsHardwareCCCapable(t *testing.T) {
	for _, tt := range []struct {
		model string
		want  bool
	}{
		{"H100", true}, {"H200", true}, {"B100", true}, {"B200", true},
		{"GB200", true}, {"RTX PRO 6000", true},
		{"RTX 5090", false}, {"RTX 4090", false}, {"A100", false},
		{"M4 Max", false}, {"DGX Spark", false},
	} {
		if got := IsHardwareCCCapable(tt.model); got != tt.want {
			t.Errorf("IsHardwareCCCapable(%s) = %v, want %v", tt.model, got, tt.want)
		}
	}
}

func TestSupportedGPUModels(t *testing.T) {
	models := SupportedGPUModels()
	if len(models) == 0 {
		t.Fatal("expected supported GPU models")
	}
	for _, m := range models {
		if !IsHardwareCCCapable(m) {
			t.Errorf("supported model %s must be CC capable", m)
		}
	}
}

func TestRequiredGas(t *testing.T) {
	// A bare selector costs its base fee plus the four selector bytes.
	for _, tt := range []struct {
		selector [4]byte
		base     uint64
	}{
		{[4]byte{0x01, 0x00, 0x00, 0x00}, GasVerifyNVTrust},
		{[4]byte{0x02, 0x00, 0x00, 0x00}, GasVerifyTPM},
		{[4]byte{0x03, 0x00, 0x00, 0x00}, GasVerifyCompute},
		{[4]byte{0x04, 0x00, 0x00, 0x00}, GasCreateAttest},
		{[4]byte{0x05, 0x00, 0x00, 0x00}, GasGetDeviceStatus},
	} {
		want := tt.base + 4*GasPerByte
		if gas := RequiredGas(tt.selector[:]); gas != want {
			t.Errorf("RequiredGas(%v) = %d, want %d", tt.selector, gas, want)
		}
	}
}

func TestABIEncode(t *testing.T) {
	result := ABIEncode(true, uint8(42), uint64(1000))
	if len(result) != 96 {
		t.Errorf("expected 96 bytes, got %d", len(result))
	}
	if result[31] != 1 {
		t.Error("bool true should encode to ...01")
	}
	if result[63] != 42 {
		t.Errorf("uint8(42) should encode to ...42, got %d", result[63])
	}
}
