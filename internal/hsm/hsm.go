// Package hsm provides a PKCS#11-shaped key/signing abstraction.
//
// The production environment backs CA keys with a real HSM accessed over
// PKCS#11 (CloudHSM / Key Vault Managed HSM / Cloud HSM). In this TEST tier the
// same interface is implemented by a *simulated* HSM:
//
//   - SoftHSMBackend  : software keys organised by slot label + PIN, modelling a
//     SoftHSM token. This mirrors the production call path
//     (open slot -> login -> find key -> sign) so integration
//     seams are exercised without licensed hardware.
//
// Production swap point: replace SoftHSMBackend with a cgo PKCS#11 backend
// (e.g. github.com/miekg/pkcs11) pointing SOFTHSM2_MODULE at the HSM provider.
// Issuing logic above this interface is unchanged.
package hsm

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Token is the PKCS#11-shaped interface the CA core depends on. A real HSM and
// the simulated SoftHSM backend both satisfy it.
type Token interface {
	// GenerateKey creates a key in the given slot, failing closed if the slot
	// is not open/logged-in. keyType is "rsa" or "ecdsa".
	GenerateKey(slot, keyType string, rsaBits int, ecCurve string) (crypto.Signer, error)
	// Signer returns the signer for an existing key in a slot (fail-closed if absent).
	Signer(slot string) (crypto.Signer, error)
	// OpenSlot models PKCS#11 C_OpenSession + C_Login.
	OpenSlot(slot, pin string) error
	// HasKey reports whether a slot already holds a key.
	HasKey(slot string) bool
}

// errFailClosed is returned whenever a slot is used without a successful login,
// implementing the "fail closed, no silent file-key fallback" requirement.
var errFailClosed = fmt.Errorf("hsm: slot not open/logged-in (fail-closed)")

// SoftHSMBackend simulates a SoftHSM PKCS#11 token using software keys persisted
// per slot. PINs are required per slot to mirror the login step.
type SoftHSMBackend struct {
	mu      sync.Mutex
	dir     string            // where slot key material is persisted
	pins    map[string]string // slot -> expected PIN
	opened  map[string]bool   // slot -> logged in
	signers map[string]crypto.Signer
}

// NewSoftHSM creates a simulated token persisting keys under dir. slotPINs maps
// slot label -> PIN (mirroring production slot/PIN provisioning).
func NewSoftHSM(dir string, slotPINs map[string]string) (*SoftHSMBackend, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("hsm: init token dir: %w", err)
	}
	return &SoftHSMBackend{
		dir:     dir,
		pins:    slotPINs,
		opened:  map[string]bool{},
		signers: map[string]crypto.Signer{},
	}, nil
}

// OpenSlot models C_OpenSession + C_Login. Wrong/absent PIN fails closed.
func (b *SoftHSMBackend) OpenSlot(slot, pin string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	want, ok := b.pins[slot]
	if !ok {
		return fmt.Errorf("hsm: unknown slot %q", slot)
	}
	if pin != want {
		return fmt.Errorf("hsm: login failed for slot %q (bad PIN)", slot)
	}
	b.opened[slot] = true
	// lazily load persisted key if present
	if _, loaded := b.signers[slot]; !loaded {
		if s, err := b.load(slot); err == nil {
			b.signers[slot] = s
		}
	}
	return nil
}

func (b *SoftHSMBackend) HasKey(slot string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.signers[slot]; ok {
		return true
	}
	_, err := os.Stat(b.keyPath(slot))
	return err == nil
}

// GenerateKey creates and persists a key in slot. Fails closed if slot not open.
func (b *SoftHSMBackend) GenerateKey(slot, keyType string, rsaBits int, ecCurve string) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.opened[slot] {
		return nil, errFailClosed
	}
	// Mint via the provider registry — the crypto-agility seam. Classical
	// (rsa/ecdsa) are built in; PQC providers register themselves under their
	// own key types (e.g. mldsa65) and flow through here unchanged.
	provider, err := lookupProvider(keyType)
	if err != nil {
		return nil, err
	}
	signer, err := provider(rsaBits, ecCurve)
	if err != nil {
		return nil, fmt.Errorf("hsm: keygen in slot %q: %w", slot, err)
	}
	if err := b.persist(slot, signer); err != nil {
		return nil, err
	}
	b.signers[slot] = signer
	return signer, nil
}

// Signer returns the key in slot, failing closed if the slot is not open or empty.
func (b *SoftHSMBackend) Signer(slot string) (crypto.Signer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.opened[slot] {
		return nil, errFailClosed
	}
	s, ok := b.signers[slot]
	if !ok {
		return nil, fmt.Errorf("hsm: no key in slot %q", slot)
	}
	return s, nil
}

// --- persistence (models the HSM holding key material across restarts) ---

type storedKey struct {
	Type string `json:"type"`
	PEM  string `json:"pem"`
}

func (b *SoftHSMBackend) keyPath(slot string) string {
	return filepath.Join(b.dir, "slot-"+slot+".key.json")
}

func (b *SoftHSMBackend) persist(slot string, s crypto.Signer) error {
	pemBytes, typ, err := marshalKey(s)
	if err != nil {
		return err
	}
	sk := storedKey{Type: typ, PEM: string(pemBytes)}
	data, _ := json.MarshalIndent(sk, "", "  ")
	if err := os.WriteFile(b.keyPath(slot), data, 0o600); err != nil {
		return fmt.Errorf("hsm: persist slot %q: %w", slot, err)
	}
	return nil
}

func (b *SoftHSMBackend) load(slot string) (crypto.Signer, error) {
	data, err := os.ReadFile(b.keyPath(slot))
	if err != nil {
		return nil, err
	}
	var sk storedKey
	if err := json.Unmarshal(data, &sk); err != nil {
		return nil, err
	}
	return unmarshalKey([]byte(sk.PEM), sk.Type)
}
