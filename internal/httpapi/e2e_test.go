package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/chrisaike/hybrid-pki-test-env/internal/ca"
	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
	"github.com/chrisaike/hybrid-pki-test-env/internal/hsm"
	"github.com/chrisaike/hybrid-pki-test-env/internal/revocation"
	"github.com/chrisaike/hybrid-pki-test-env/internal/service"
)

// buildEnv spins up an in-process environment (hierarchy + store + services)
// backed by a temp dir, and returns an httptest server wrapping the real mux.
func buildEnv(t *testing.T) (*httptest.Server, *service.Service, *revocation.OCSPResponder) {
	t.Helper()
	dir := t.TempDir()

	cfg, err := config.Load("../../config/hierarchy.yaml")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pins := map[string]string{}
	for _, c := range cfg.AllCAs() {
		pins[c.Slot] = "test-pin-" + c.Slot
	}
	token, err := hsm.NewSoftHSM(filepath.Join(dir, "hsm"), pins)
	if err != nil {
		t.Fatalf("hsm: %v", err)
	}
	h := ca.New(cfg, token, dir)
	if err := h.Build(false); err != nil {
		t.Fatalf("build: %v", err)
	}
	st := mustStore(t, filepath.Join(dir, "status.json"))
	issuing := h.FirstIssuing()
	key, err := token.Signer(issuing.Slot)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	crl := revocation.NewCRLPublisher(issuing.Cert, key, st, filepath.Join(dir, "issuing.crl"))
	if _, err := crl.Publish(); err != nil {
		t.Fatalf("crl publish: %v", err)
	}
	ocsp := revocation.NewOCSPResponder(issuing.Cert, key, st)
	svc := service.New(h, cfg, st, crl)
	srv := New(svc, ocsp, func() []byte { b, _ := readFile(filepath.Join(dir, "issuing.crl")); return b }, "test")
	return httptest.NewServer(srv.Handler()), svc, ocsp
}

// TestFullLifecycle drives enroll -> OCSP good -> revoke -> OCSP revoked via the
// real HTTP handlers (Requirements 3, 4).
func TestFullLifecycle(t *testing.T) {
	ts, _, ocsp := buildEnv(t)
	defer ts.Close()

	// health check
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v status=%v", err, resp.StatusCode)
	}

	// enroll a TLS server cert via the mock Venafi API
	csrPEM, _ := makeCSR(t, "test-leaf.pki.test.local")
	body, _ := json.Marshal(enrollReq{CSR: string(csrPEM), Profile: "tls-server"})
	resp, err = http.Post(ts.URL+"/v1/certificates/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("enroll status=%d", resp.StatusCode)
	}
	var er enrollResp
	json.NewDecoder(resp.Body).Decode(&er)
	if er.ID == "" || er.Serial == "" {
		t.Fatalf("enroll missing id/serial: %+v", er)
	}
	leaf := parseCert(t, er.Cert)

	// AIA/CDP present (Requirement 4.4)
	if len(leaf.OCSPServer) == 0 || len(leaf.CRLDistributionPoints) == 0 {
		t.Fatalf("leaf missing AIA/CDP: ocsp=%v cdp=%v", leaf.OCSPServer, leaf.CRLDistributionPoints)
	}

	serial, _ := new(big.Int).SetString(er.Serial, 10)

	// OCSP should say good
	if got := ocspStatus(t, ocsp, serial); got != "good" {
		t.Fatalf("pre-revoke OCSP = %q, want good", got)
	}

	// revoke via API
	rb, _ := json.Marshal(map[string]int{"reason": 1})
	resp, err = http.Post(ts.URL+"/v1/certificates/"+er.ID+"/revoke", "application/json", bytes.NewReader(rb))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("revoke: %v status=%v", err, resp.StatusCode)
	}

	// OCSP should now say revoked
	if got := ocspStatus(t, ocsp, serial); got != "revoked" {
		t.Fatalf("post-revoke OCSP = %q, want revoked", got)
	}

	// status endpoint reflects revoked
	resp, _ = http.Get(ts.URL + "/v1/certificates/" + er.ID)
	var sresp map[string]any
	json.NewDecoder(resp.Body).Decode(&sresp)
	if sresp["status"] != "revoked" {
		t.Fatalf("status endpoint = %v, want revoked", sresp["status"])
	}
}

// TestProfileDenial verifies non-allowlisted profiles are denied (Req 5.4).
func TestProfileDenial(t *testing.T) {
	ts, _, _ := buildEnv(t)
	defer ts.Close()
	csrPEM, _ := makeCSR(t, "x.pki.test.local")
	body, _ := json.Marshal(enrollReq{CSR: string(csrPEM), Profile: "not-a-real-profile"})
	resp, _ := http.Post(ts.URL+"/v1/certificates/request", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 403 {
		t.Fatalf("bad profile status=%d, want 403", resp.StatusCode)
	}
}

// TestESTEnroll verifies the AD auto-enroll surface issues a client cert (Req 5).
func TestESTEnroll(t *testing.T) {
	ts, _, _ := buildEnv(t)
	defer ts.Close()
	csrPEM, _ := makeCSR(t, "device01.pki.test.local")
	resp, err := http.Post(ts.URL+"/.well-known/est/simpleenroll?profile=device-autoenroll",
		"application/pkcs10", bytes.NewReader(csrPEM))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("EST enroll: %v status=%v", err, resp.StatusCode)
	}
}

// --- helpers ---

func ocspStatus(t *testing.T, o *revocation.OCSPResponder, serial *big.Int) string {
	t.Helper()
	code, _, _ := o.Status(serial)
	return revocation.StatusString(code)
}

func makeCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func parseCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

var _ = asn1.Marshal // keep asn1 import for potential OCSP wire tests
