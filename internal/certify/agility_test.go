package certify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/chrisaike/hybrid-pki-test-env/internal/ca"
	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
	"github.com/chrisaike/hybrid-pki-test-env/internal/hsm"
	"github.com/chrisaike/hybrid-pki-test-env/internal/revocation"
	"github.com/chrisaike/hybrid-pki-test-env/internal/service"
	"github.com/chrisaike/hybrid-pki-test-env/internal/store"
)

// TestCryptoAgilityEd25519 proves the crypto-agility seam: an entirely Ed25519
// hierarchy (a third algorithm family, registered through the same provider
// seam a PQC algorithm uses) builds, issues, validates to root, and produces
// working OCSP + CRL — with NO change to the CA/issuance/revocation code.
//
// This is the certification path a future ML-DSA (PQC) change follows: swap the
// provider + config key type, then re-run the harness.
func TestCryptoAgilityEd25519(t *testing.T) {
	dir := t.TempDir()

	// Build an Ed25519-only hierarchy programmatically (mirrors setting
	// key.type: ed25519 across all tiers in hierarchy.yaml).
	cfg := &config.Config{
		Organization: "Hybrid PKI Test Environment",
		Root: config.CA{
			Name: "TEST Ed25519 Root - DO NOT TRUST", Slot: "root",
			Key: config.KeySpec{Type: "ed25519"}, ValidityDays: 3650,
		},
		Intermediates: []config.CA{{
			Name: "TEST Ed25519 Intermediate - DO NOT TRUST", Slot: "intermediate",
			Key: config.KeySpec{Type: "ed25519"}, ValidityDays: 1825, PathLen: 1, HasPathLen: true,
		}},
		Issuing: []config.CA{{
			Name: "TEST Ed25519 Issuing - DO NOT TRUST", Slot: "issuing",
			Parent: "TEST Ed25519 Intermediate - DO NOT TRUST",
			Key:    config.KeySpec{Type: "ed25519"}, ValidityDays: 365,
			AIA: "http://pki.test.local:8080/ocsp",
			CDP: "http://pki.test.local:8080/crl/issuing.crl",
		}},
		Profiles: map[string]config.Profile{
			"tls-server": {Name: "tls-server", EKU: []string{"serverAuth"},
				KeyUsage: []string{"digitalSignature"}, ValidityDays: 90},
		},
	}

	pins := map[string]string{
		"root":         "test-pin-root",
		"intermediate": "test-pin-intermediate",
		"issuing":      "test-pin-issuing",
	}
	token, err := hsm.NewSoftHSM(filepath.Join(dir, "hsm"), pins)
	if err != nil {
		t.Fatalf("hsm: %v", err)
	}
	h := ca.New(cfg, token, dir)
	if err := h.Build(false); err != nil {
		t.Fatalf("build ed25519 hierarchy: %v", err)
	}

	// All tiers must be Ed25519.
	if h.Root.Cert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("root not Ed25519: %v", h.Root.Cert.PublicKeyAlgorithm)
	}

	st, _ := store.Open(filepath.Join(dir, "status.json"))
	issuing := h.FirstIssuing()
	key, _ := token.Signer(issuing.Slot)
	crl := revocation.NewCRLPublisher(issuing.Cert, key, st, filepath.Join(dir, "issuing.crl"))
	ocsp := revocation.NewOCSPResponder(issuing.Cert, key, st)
	svc := service.New(h, cfg, st, crl)

	// Issue a leaf and validate the chain to root.
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "agility.pki.test.local"}}, leafKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	res, err := svc.Enroll(csrPEM, "tls-server")
	if err != nil {
		t.Fatalf("enroll ed25519 leaf: %v", err)
	}
	leaf := parsePEM(res.CertPEM)
	if err := h.Verify(leaf); err != nil {
		t.Fatalf("ed25519 chain verify: %v", err)
	}

	// OCSP + CRL must work with the Ed25519 issuer key.
	serial, _ := new(big.Int).SetString(res.Serial, 10)
	if code, _, _ := ocsp.Status(serial); revocation.StatusString(code) != "good" {
		t.Fatalf("ed25519 OCSP pre-revoke != good")
	}
	if err := svc.Revoke(res.ID, 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if code, _, _ := ocsp.Status(serial); revocation.StatusString(code) != "revoked" {
		t.Fatalf("ed25519 OCSP post-revoke != revoked")
	}
	crlObj, err := crl.Publish()
	if err != nil {
		t.Fatalf("ed25519 CRL publish: %v", err)
	}
	if len(crlObj.RevokedCertificateEntries) == 0 {
		t.Fatalf("ed25519 CRL empty after revoke")
	}
}

// TestRegisteredKeyTypes confirms the agility registry exposes the algorithms,
// so tooling/reports can show crypto-agility status.
func TestRegisteredKeyTypes(t *testing.T) {
	got := hsm.RegisteredKeyTypes()
	want := map[string]bool{"rsa": true, "ecdsa": true, "ed25519": true}
	for _, k := range got {
		delete(want, k)
	}
	if len(want) != 0 {
		t.Fatalf("missing registered key types: %v (got %v)", want, got)
	}
}
