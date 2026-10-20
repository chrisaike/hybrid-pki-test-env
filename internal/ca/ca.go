// Package ca implements the CA hierarchy and the issuing signer.
//
// All key operations go through the hsm.Token interface, mirroring the
// production HSM call path. The Root CA key lives in its own slot and is only
// used to sign intermediates and the Root CRL (offline-by-default posture).
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
	"github.com/chrisaike/hybrid-pki-test-env/internal/hsm"
)

// Authority is a materialised CA: its certificate plus the slot holding its key.
type Authority struct {
	Name string
	Slot string
	Cert *x509.Certificate
	spec config.CA
}

// Hierarchy holds the built chain and the backing token.
type Hierarchy struct {
	cfg    *config.Config
	token  hsm.Token
	outDir string

	Root          *Authority
	Intermediates map[string]*Authority
	Issuing       map[string]*Authority
}

// New prepares a hierarchy manager.
func New(cfg *config.Config, token hsm.Token, outDir string) *Hierarchy {
	return &Hierarchy{
		cfg:           cfg,
		token:         token,
		outDir:        outDir,
		Intermediates: map[string]*Authority{},
		Issuing:       map[string]*Authority{},
	}
}

// Build creates (or re-creates) the full hierarchy idempotently. Existing slots
// with keys are reused unless force is set; certificates are always (re)written
// so a trust-path change can be applied without manual key handling.
func (h *Hierarchy) Build(force bool) error {
	if err := os.MkdirAll(h.outDir, 0o755); err != nil {
		return err
	}

	// Root (self-signed, offline slot).
	root, err := h.buildCA(h.cfg.Root, nil, force)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	h.Root = root

	// Intermediates signed by root.
	for _, ic := range h.cfg.Intermediates {
		a, err := h.buildCA(ic, root, force)
		if err != nil {
			return fmt.Errorf("intermediate %s: %w", ic.Name, err)
		}
		h.Intermediates[ic.Name] = a
	}

	// Issuing CAs signed by their named parent intermediate.
	for _, sc := range h.cfg.Issuing {
		parent := h.Intermediates[sc.Parent]
		if parent == nil {
			// default to the first intermediate if parent unspecified
			for _, v := range h.Intermediates {
				parent = v
				break
			}
		}
		a, err := h.buildCA(sc, parent, force)
		if err != nil {
			return fmt.Errorf("issuing %s: %w", sc.Name, err)
		}
		h.Issuing[sc.Name] = a
	}

	return h.writeBundle()
}

func (h *Hierarchy) buildCA(spec config.CA, parent *Authority, force bool) (*Authority, error) {
	pin := slotPIN(spec.Slot)
	if err := h.token.OpenSlot(spec.Slot, pin); err != nil {
		return nil, err
	}

	if !h.token.HasKey(spec.Slot) || force {
		if _, err := h.token.GenerateKey(spec.Slot, spec.Key.Type, spec.Key.Bits, spec.Key.Curve); err != nil {
			return nil, err
		}
	}
	signer, err := h.token.Signer(spec.Slot)
	if err != nil {
		return nil, err
	}

	tmpl := h.caTemplate(spec, parent == nil)

	var (
		der       []byte
		issuerCrt *x509.Certificate
		issuerKey crypto.Signer
	)
	if parent == nil {
		issuerCrt = tmpl // self-signed
		issuerKey = signer
	} else {
		issuerCrt = parent.Cert
		pk, err := h.token.Signer(parent.Slot)
		if err != nil {
			return nil, fmt.Errorf("open parent slot: %w", err)
		}
		issuerKey = pk
	}

	der, err = x509.CreateCertificate(rand.Reader, tmpl, issuerCrt, signer.Public(), issuerKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := h.writeCertPEM(fileSafe(spec.Name)+".crt", der); err != nil {
		return nil, err
	}
	return &Authority{Name: spec.Name, Slot: spec.Slot, Cert: cert, spec: spec}, nil
}

func (h *Hierarchy) caTemplate(spec config.CA, isRoot bool) *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   spec.Name,
			Organization: []string{h.cfg.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Duration(spec.ValidityDays) * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	if spec.HasPathLen {
		tmpl.MaxPathLen = spec.PathLen
		tmpl.MaxPathLenZero = spec.PathLen == 0
	}
	// Issuing CAs advertise AIA/CDP so leaf certs can inherit them.
	if spec.AIA != "" {
		tmpl.OCSPServer = []string{spec.AIA}
	}
	if spec.CDP != "" {
		tmpl.CRLDistributionPoints = []string{spec.CDP}
	}
	return tmpl
}

// --- output helpers ---

func (h *Hierarchy) writeCertPEM(name string, der []byte) error {
	path := filepath.Join(h.outDir, name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeBundle writes the full chain (root first) as ca-bundle.pem — the trust
// anchor set clients import.
func (h *Hierarchy) writeBundle() error {
	var b strings.Builder
	write := func(a *Authority) {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Cert.Raw}))
	}
	write(h.Root)
	for _, ic := range h.cfg.Intermediates {
		if a := h.Intermediates[ic.Name]; a != nil {
			write(a)
		}
	}
	for _, sc := range h.cfg.Issuing {
		if a := h.Issuing[sc.Name]; a != nil {
			write(a)
		}
	}
	return os.WriteFile(filepath.Join(h.outDir, "ca-bundle.pem"), []byte(b.String()), 0o644)
}

// FirstIssuing returns the first issuing CA (helper for single-issuer setups).
func (h *Hierarchy) FirstIssuing() *Authority {
	for _, sc := range h.cfg.Issuing {
		if a := h.Issuing[sc.Name]; a != nil {
			return a
		}
	}
	return nil
}

func fileSafe(s string) string {
	r := strings.NewReplacer(" ", "_", "/", "_", "-", "-")
	return strings.ToLower(r.Replace(s))
}

// slotPIN returns the per-slot PIN. In the test tier PINs are derived
// deterministically; production injects them from the secret store.
func slotPIN(slot string) string {
	if v := os.Getenv("HSM_PIN_" + strings.ToUpper(slot)); v != "" {
		return v
	}
	return "test-pin-" + slot
}
