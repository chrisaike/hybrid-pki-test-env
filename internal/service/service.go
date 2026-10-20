// Package service is the issuance + lifecycle layer shared by the mock Venafi
// API, the enrollment surface, and the certification harness. It wires the CA
// hierarchy to the status store and triggers CRL republication on revocation.
package service

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/chrisaike/hybrid-pki-test-env/internal/ca"
	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
	"github.com/chrisaike/hybrid-pki-test-env/internal/revocation"
	"github.com/chrisaike/hybrid-pki-test-env/internal/store"
)

// Service coordinates issuance and lifecycle operations.
type Service struct {
	mu     sync.Mutex
	h      *ca.Hierarchy
	cfg    *config.Config
	st     *store.Store
	crl    *revocation.CRLPublisher
	nextID func() string
}

// New constructs the service. crl may be nil (CRL republication skipped).
func New(h *ca.Hierarchy, cfg *config.Config, st *store.Store, crl *revocation.CRLPublisher) *Service {
	return &Service{h: h, cfg: cfg, st: st, crl: crl, nextID: newID}
}

// newID generates a random hex identifier (UUID-shaped) using stdlib crypto/rand.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// EnrollResult is returned from Enroll/Renew.
type EnrollResult struct {
	ID       string
	Serial   string
	CertPEM  string
	ChainPEM string
	NotAfter time.Time
	Subject  string
}

// Enroll signs a CSR (PEM) under a profile and records it in the status store.
func (s *Service) Enroll(csrPEM []byte, profile string) (*EnrollResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	res, err := s.h.Issue(ca.IssueRequest{CSR: csr, Profile: profile}, s.cfg.Profiles)
	if err != nil {
		return nil, err // includes profile allow-list denial
	}

	id := s.nextID()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.DER})
	rec := &store.Record{
		ID:        id,
		Serial:    res.Serial.String(),
		Subject:   res.Cert.Subject.String(),
		Profile:   profile,
		IssuingCA: issuerName(s.h),
		Status:    store.StatusValid,
		IssuedAt:  time.Now().UTC(),
		PEM:       string(certPEM),
	}
	if err := s.st.Put(rec); err != nil {
		return nil, err
	}
	return &EnrollResult{
		ID:       id,
		Serial:   res.Serial.String(),
		CertPEM:  string(certPEM),
		ChainPEM: s.chainPEM(),
		NotAfter: res.Cert.NotAfter,
		Subject:  res.Cert.Subject.String(),
	}, nil
}

// Renew issues a fresh certificate for the same subject key as an existing one,
// marking the prior record renewed (Requirement 3.2).
func (s *Service) Renew(id string, csrPEM []byte) (*EnrollResult, error) {
	s.mu.Lock()
	old, ok := s.st.Get(id)
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("renew: unknown certificate id %q", id)
	}
	if old.Status == store.StatusRevoked {
		return nil, fmt.Errorf("renew: certificate is revoked")
	}
	res, err := s.Enroll(csrPEM, old.Profile)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	old.Status = store.StatusRenewed
	old.RenewedTo = res.ID
	_ = s.st.Put(old)
	s.mu.Unlock()
	return res, nil
}

// Revoke marks a certificate revoked and republishes the CRL (Requirement 3.3/4.1).
func (s *Service) Revoke(id string, reason int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.Revoke(id, reason); err != nil {
		return err
	}
	if s.crl != nil {
		if _, err := s.crl.Publish(); err != nil {
			return fmt.Errorf("revoke: republish CRL: %w", err)
		}
	}
	return nil
}

// Status returns the lifecycle record for an id.
func (s *Service) Status(id string) (*store.Record, bool) {
	return s.st.Get(id)
}

func (s *Service) chainPEM() string {
	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.h.FirstIssuing().Cert.Raw})...)
	for _, a := range s.h.Intermediates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Cert.Raw})...)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.h.Root.Cert.Raw})...)
	return string(out)
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}

func issuerName(h *ca.Hierarchy) string {
	if a := h.FirstIssuing(); a != nil {
		return a.Name
	}
	return ""
}
