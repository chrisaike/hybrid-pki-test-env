package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
)

// IssueRequest is a leaf-certificate issuance request.
type IssueRequest struct {
	CSR     *x509.CertificateRequest
	Profile string // must match a configured profile name
	Issuer  string // issuing CA name ("" => first issuing CA)
}

// IssueResult is the issued leaf plus its serial (for lifecycle tracking).
type IssueResult struct {
	Cert   *x509.Certificate
	DER    []byte
	Serial *big.Int
}

// Issue signs a CSR against a profile, enforcing the profile allow-list and
// stamping AIA/CDP from the issuing CA so revocation endpoints are discoverable.
func (h *Hierarchy) Issue(req IssueRequest, profiles map[string]config.Profile) (*IssueResult, error) {
	prof, ok := profiles[req.Profile]
	if !ok {
		// Requirement 5.4 / 4.4: deny requests that do not match an allowed profile.
		return nil, fmt.Errorf("issue denied: unknown profile %q", req.Profile)
	}
	if req.CSR == nil {
		return nil, fmt.Errorf("issue: nil CSR")
	}
	if err := req.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("issue: CSR signature invalid: %w", err)
	}

	var issuer *Authority
	if req.Issuer == "" {
		issuer = h.FirstIssuing()
	} else {
		issuer = h.Issuing[req.Issuer]
	}
	if issuer == nil {
		return nil, fmt.Errorf("issue: issuing CA not found")
	}

	issuerKey, err := h.token.Signer(issuer.Slot)
	if err != nil {
		return nil, fmt.Errorf("issue: open issuer slot: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.CSR.Subject,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Duration(prof.ValidityDays) * 24 * time.Hour),
		KeyUsage:              keyUsage(prof.KeyUsage),
		ExtKeyUsage:           extKeyUsage(prof.EKU),
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              req.CSR.DNSNames,
		IPAddresses:           req.CSR.IPAddresses,
		EmailAddresses:        req.CSR.EmailAddresses,
	}
	// Inherit AIA/CDP from the issuing CA (Requirement 4.4).
	if issuer.spec.AIA != "" {
		tmpl.OCSPServer = []string{issuer.spec.AIA}
	}
	if issuer.spec.CDP != "" {
		tmpl.CRLDistributionPoints = []string{issuer.spec.CDP}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.Cert, req.CSR.PublicKey, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("issue: create cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &IssueResult{Cert: cert, DER: der, Serial: serial}, nil
}

// Verify builds and validates a leaf to the Root using the hierarchy as roots
// and intermediates (Requirement 1.2 / 9.1).
func (h *Hierarchy) Verify(leaf *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(h.Root.Cert)
	inter := x509.NewCertPool()
	for _, a := range h.Intermediates {
		inter.AddCert(a.Cert)
	}
	for _, a := range h.Issuing {
		inter.AddCert(a.Cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   time.Now(),
	})
	return err
}

func keyUsage(names []string) x509.KeyUsage {
	var ku x509.KeyUsage
	for _, n := range names {
		switch n {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "keyAgreement":
			ku |= x509.KeyUsageKeyAgreement
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "nonRepudiation", "contentCommitment":
			ku |= x509.KeyUsageContentCommitment
		}
	}
	return ku
}

func extKeyUsage(names []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	for _, n := range names {
		switch n {
		case "serverAuth":
			out = append(out, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			out = append(out, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			out = append(out, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			out = append(out, x509.ExtKeyUsageEmailProtection)
		case "OCSPSigning":
			out = append(out, x509.ExtKeyUsageOCSPSigning)
		}
	}
	return out
}

var _ = pkix.Name{} // keep pkix import for template authoring clarity
