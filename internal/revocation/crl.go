// Package revocation implements CRL publishing and OCSP responding backed by
// the status store.
package revocation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/chrisaike/hybrid-pki-test-env/internal/store"
)

// CRLPublisher builds and publishes CRLs signed by an issuing CA key.
type CRLPublisher struct {
	issuerCert *x509.Certificate
	issuerKey  crypto.Signer
	st         *store.Store
	crlNumber  int64
	outPath    string
}

// NewCRLPublisher wires a publisher to an issuing CA and the status store.
func NewCRLPublisher(issuerCert *x509.Certificate, issuerKey crypto.Signer, st *store.Store, outPath string) *CRLPublisher {
	return &CRLPublisher{issuerCert: issuerCert, issuerKey: issuerKey, st: st, outPath: outPath}
}

// Publish regenerates the CRL from current revoked records and writes it to disk.
// Called on-revocation and on a schedule (Requirement 4.1, 4.5).
func (p *CRLPublisher) Publish() (*x509.RevocationList, error) {
	var revoked []x509.RevocationListEntry
	for _, r := range p.st.Revoked() {
		serial, ok := new(big.Int).SetString(r.Serial, 10)
		if !ok {
			continue
		}
		revoked = append(revoked, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: r.RevokedAt.UTC(),
			ReasonCode:     r.ReasonCode,
		})
	}

	p.crlNumber++
	now := time.Now()
	tmpl := &x509.RevocationList{
		// Signature algorithm must match the SIGNING KEY, not the issuer cert
		// (the issuing CA cert may be signed by a different-algorithm parent).
		SignatureAlgorithm:        crlSigAlg(p.issuerKey),
		RevokedCertificateEntries: revoked,
		Number:                    big.NewInt(p.crlNumber),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, p.issuerCert, p.issuerKey)
	if err != nil {
		return nil, fmt.Errorf("crl: create: %w", err)
	}
	if p.outPath != "" {
		f, err := os.Create(p.outPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := pem.Encode(f, &pem.Block{Type: "X509 CRL", Bytes: der}); err != nil {
			return nil, err
		}
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	return crl, nil
}

// crlSigAlg selects a signature algorithm matching the signing key type.
func crlSigAlg(key crypto.Signer) x509.SignatureAlgorithm {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA384
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	default:
		return x509.UnknownSignatureAlgorithm // let x509 pick a default
	}
}

var _ = pkix.Name{}
