//go:build pqc

// Package hsm — post-quantum provider wiring.
//
// This file is compiled ONLY with the `pqc` build tag:
//
//	go build -tags pqc ./...
//
// It registers a FIPS-204 ML-DSA (Dilithium) key provider at the same seam the
// classical providers use, so turning on PQC is a build-flag + config change —
// nothing in the CA hierarchy, issuance, OCSP, or CRL code changes.
//
// Because Go's standard library does not yet ship an ML-DSA *signature*
// implementation (only ML-KEM, in crypto/mlkem) and crypto/x509 only serialises
// RSA/ECDSA/Ed25519 keys natively, a runnable ML-DSA hierarchy requires one of:
//
//   - An X.509 toolchain built against OpenSSL 3 + oqs-provider (ML-DSA OIDs),
//     with a cgo binding that returns a crypto.Signer, OR
//   - A pure-Go ML-DSA signer plus the custom X.509 marshalling for the ML-DSA
//     SubjectPublicKeyInfo / signature OIDs (FIPS 204).
//
// The binding below is the single integration point. Replace the body of
// newMLDSASigner with the concrete provider; the registration wiring is final.

package hsm

import (
	"crypto"
	"fmt"
)

func init() {
	// ML-DSA parameter sets (FIPS 204). Register each as its own key type so
	// config/hierarchy.yaml can select e.g. key: { type: mldsa65 }.
	RegisterProvider("mldsa44", func(_ int, _ string) (crypto.Signer, error) {
		return newMLDSASigner("ML-DSA-44")
	})
	RegisterProvider("mldsa65", func(_ int, _ string) (crypto.Signer, error) {
		return newMLDSASigner("ML-DSA-65")
	})
	RegisterProvider("mldsa87", func(_ int, _ string) (crypto.Signer, error) {
		return newMLDSASigner("ML-DSA-87")
	})
}

// newMLDSASigner returns a crypto.Signer backed by the named ML-DSA parameter
// set. Wire this to oqs-provider (cgo) or a pure-Go FIPS-204 implementation.
func newMLDSASigner(paramSet string) (crypto.Signer, error) {
	// INTEGRATION POINT — replace with the concrete ML-DSA key generation.
	// Example (oqs cgo binding, pseudocode):
	//
	//   sig := oqs.NewSignature(paramSet)
	//   pub, sk := sig.GenerateKeyPair()
	//   return &oqsSigner{paramSet: paramSet, pub: pub, sk: sk}, nil
	//
	return nil, fmt.Errorf("hsm: ML-DSA provider %q not linked; build with an oqs-provider binding (see docs/PQC.md)", paramSet)
}
