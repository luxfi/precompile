// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"time"
)

// teeReportLen is the length of the signed report header at the front of a
// TEE attestation receipt:
//
//	[0:32]  deviceID  — TEE / GPU identity (enclave or device measurement id)
//	[32:40] timestamp — unix seconds, big-endian (the attestation time)
//	[40:48] nonce     — anti-replay challenge
//
// Everything after the header is an X.509 certificate chain (concatenated
// DER): chain[0] is the attestation leaf whose key signed the report and
// chain[1:] are intermediates leading up toward an embedded vendor root.
const teeReportLen = 48

// verifyAttestation is the real attestation-verification core. It establishes
// that:
//
//  1. the receipt carries a parseable certificate chain whose leaf chains to
//     one of the trusted vendor roots, valid at the report's timestamp; and
//  2. `signature` is a valid signature over the 48-byte report header by that
//     leaf certificate's public key.
//
// It is deterministic — validity is checked at the report's embedded
// timestamp, never the wall clock, and the roots pool is explicit (never the
// host's system store) — so every validator reaches the same verdict.
//
// Failure taxonomy:
//   - malformed INPUT that cannot even be evaluated (short receipt, absent
//     signature, unparseable chain) returns (false, error);
//   - a well-formed chain that does not terminate at a trusted root, is
//     expired, or carries a signature that does not bind the report returns
//     (false, nil) — verification ran and the attestation is rejected;
//   - a fully valid attestation returns (true, nil).
//
// It never returns true by default: with an empty roots pool, or any chain
// that does not reach an embedded vendor root, the leaf cannot be verified
// and the result is false.
func verifyAttestation(receipt, signature []byte, roots *x509.CertPool) (bool, error) {
	if len(receipt) < teeReportLen {
		return false, ErrInvalidTEEReceipt
	}
	if len(signature) == 0 {
		return false, ErrTEESignatureInvalid
	}
	report := receipt[:teeReportLen]
	chainDER := receipt[teeReportLen:]
	if len(chainDER) == 0 {
		return false, ErrInvalidTEEReceipt
	}

	certs, err := x509.ParseCertificates(chainDER)
	if err != nil || len(certs) == 0 {
		return false, ErrInvalidTEEReceipt
	}
	leaf := certs[0]

	// Attestation time taken from the report itself keeps verification
	// deterministic and checks the chain was valid when the quote was made.
	attTime := time.Unix(int64(binary.BigEndian.Uint64(report[32:40])), 0).UTC()

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   attTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		// Untrusted, incomplete, or expired chain: fail closed.
		return false, nil
	}

	if !verifyReportSignature(leaf.PublicKey, report, signature) {
		// The certified key did not sign this report: fail closed.
		return false, nil
	}
	return true, nil
}

// verifyReportSignature verifies sig over report under the leaf certificate's
// public key. It accepts the signature encodings TEE quotes use in practice:
// raw r‖s and ASN.1 DER for ECDSA, raw 64-byte Ed25519, and PKCS#1 v1.5 for
// RSA. The pre-hash is selected from the key/curve (SHA-256 for P-256 and
// RSA, SHA-384 for P-384, none for Ed25519).
func verifyReportSignature(pub crypto.PublicKey, report, sig []byte) bool {
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSAReport(pk, report, sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pk, report, sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(report)
		return rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig) == nil
	default:
		return false
	}
}

func verifyECDSAReport(pk *ecdsa.PublicKey, report, sig []byte) bool {
	if pk.Curve == nil {
		return false
	}
	bitSize := pk.Curve.Params().BitSize
	var digest []byte
	if bitSize > 256 {
		d := sha512.Sum384(report)
		digest = d[:]
	} else {
		d := sha256.Sum256(report)
		digest = d[:]
	}
	// ASN.1 DER encoding (SEQUENCE{ r, s }).
	if ecdsa.VerifyASN1(pk, digest, sig) {
		return true
	}
	// Fixed-width raw r‖s, big-endian — the SGX/TDX ECDSA quote encoding.
	byteLen := (bitSize + 7) / 8
	if len(sig) == 2*byteLen {
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		return ecdsa.Verify(pk, digest, r, s)
	}
	return false
}
