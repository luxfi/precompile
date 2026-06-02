package attestation

import (
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// VerifyCompute: input below the 128-byte floor is rejected.
func TestVerifyCompute_TooShort(t *testing.T) {
	if _, err := VerifyCompute([]byte(`{}`)); err != ErrInvalidInput {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
}

// VerifyCompute: an unattested provider verifies to false (covers the main
// body + GetDeviceStatus miss + encodeOutput — previously 0% covered).
func TestVerifyCompute_UnattestedProvider(t *testing.T) {
	var pid [32]byte
	copy(pid[:], []byte("unattested-provider-aaaaaaaaaaaa"))
	in := VerifyComputeInput{
		ProviderID: pid,
		TEEQuote:   make([]byte, 48),
		Signature:  make([]byte, 64),
	}
	b := mustJSON(t, in)
	if len(b) < 128 {
		t.Fatalf("test input must be >=128 bytes, got %d", len(b))
	}
	out, err := VerifyCompute(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var o VerifyComputeOutput
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if o.ProviderOK {
		t.Error("unattested provider must not be ProviderOK")
	}
	if o.Verified {
		t.Error("unattested provider must not verify")
	}
}

// Run dispatch: every known selector routes; unknown/short are rejected.
func TestRun_DispatchAllSelectors(t *testing.T) {
	for _, sel := range [][4]byte{{1, 0, 0, 0}, {2, 0, 0, 0}, {3, 0, 0, 0}, {4, 0, 0, 0}, {5, 0, 0, 0}} {
		input := append(sel[:], make([]byte, 256)...)
		_, _ = Run(input) // inner may error on the dummy payload; we only need the dispatch arm
	}
	if _, err := Run([]byte{0xff, 0xff, 0xff, 0xff}); err != ErrInvalidInput {
		t.Errorf("unknown selector: want ErrInvalidInput, got %v", err)
	}
	if _, err := Run([]byte{0x01}); err != ErrInvalidInput {
		t.Errorf("short input: want ErrInvalidInput, got %v", err)
	}
}

func TestSupportedGPUModels_Coverage(t *testing.T) {
	models := SupportedGPUModels()
	if len(models) == 0 {
		t.Fatal("expected supported GPU models")
	}
	var hasH100 bool
	for _, m := range models {
		if m == "H100" {
			hasH100 = true
		}
	}
	if !hasH100 {
		t.Error("expected H100 in supported models")
	}
}

func TestRegisterTrustedMeasurement_Coverage(t *testing.T) {
	// Smoke: previously 0% covered. Must not panic.
	RegisterTrustedMeasurement("test-firmware-v1", []byte{0x01, 0x02, 0x03, 0x04})
}

func TestIsHardwareCCCapable_TwoAxis(t *testing.T) {
	if !IsHardwareCCCapable("H100") {
		t.Error("H100 must be confidential-compute capable")
	}
	if IsHardwareCCCapable("M4 Max") {
		t.Error("Apple M4 Max is not NVTrust GPU-TEE capable")
	}
	if IsHardwareCCCapable("DGX Spark") {
		t.Error("DGX Spark must NOT be GPU-TEE capable (neutered)")
	}
}
