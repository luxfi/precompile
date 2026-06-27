// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"crypto/x509"
	"encoding/pem"
	"sync"
)

// intelSGXRootCAPEM is the Intel SGX Provisioning Certification Root CA,
// fetched verbatim from Intel's trusted-services distribution point:
//
//	https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
//
// It is the self-signed ECDSA P-256 root that anchors all Intel SGX / TDX
// DCAP attestation (the PCK certificate chain ultimately terminates here).
// Provenance — reproduce with `openssl x509 -in root.pem -noout -serial -fingerprint -sha256`:
//
//	Subject/Issuer: CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US
//	Serial:         22650CD65A9D3489F383B49552BF501B392706AC
//	Validity:       2018-05-21 .. 2049-12-31
//	Public key:     id-ecPublicKey, NIST P-256
//	SHA-256 FP:     44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:
//	                0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3
//
// This is a public, long-lived trust anchor; embedding it (rather than
// fetching it at runtime) keeps verification deterministic across every
// validator. To add another vendor (e.g. an NVIDIA device-identity root or
// an operator-run attestation CA), append its PEM to embeddedTEERoots — the
// verification core is vendor-agnostic. Until a vendor's root is embedded,
// chains presenting that vendor's leaf fail closed.
const intelSGXRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

// embeddedTEERoots is the set of compiled-in vendor root CAs. Add a vendor by
// appending its PEM here.
var embeddedTEERoots = []string{intelSGXRootCAPEM}

var (
	teeRootsOnce sync.Once
	teeRoots     *x509.CertPool
)

// teeRootPool returns the trusted vendor-root pool that anchors TEE
// attestation certificate chains, built once from embeddedTEERoots. If no
// embedded root parses, the pool is EMPTY and every chain fails closed
// (verifyAttestation can never reach a trust anchor and returns false). The
// pool is never nil and is never the system root store.
func teeRootPool() *x509.CertPool {
	teeRootsOnce.Do(func() {
		pool := x509.NewCertPool()
		for _, p := range embeddedTEERoots {
			block, _ := pem.Decode([]byte(p))
			if block == nil {
				continue
			}
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				pool.AddCert(cert)
			}
		}
		teeRoots = pool
	})
	return teeRoots
}
