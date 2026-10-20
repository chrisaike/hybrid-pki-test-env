// Provider registry — the crypto-agility seam.
//
// Every key algorithm the HSM can mint is registered here as a KeyProvider that
// returns a crypto.Signer. Classical providers (rsa, ecdsa) are built in. A
// post-quantum provider plugs in at this exact point WITHOUT touching the CA
// hierarchy or issuing code, because everything above depends only on
// crypto.Signer.
//
// To certify a PQC change (see docs/PQC.md):
//  1. Register a FIPS-204 ML-DSA provider here (e.g. a cgo oqs-provider binding
//     or a pure-Go implementation) under a key type such as "mldsa65".
//  2. Set key.type: mldsa65 in config/hierarchy.yaml.
//  3. make issue && make certify.
package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sort"
	"sync"
)

// KeyProvider mints a crypto.Signer for a given key specification. rsaBits is
// used for RSA; ecCurve for ECDSA; both are ignored by PQC providers (which may
// read their own parameter set from the key type name, e.g. mldsa65).
type KeyProvider func(rsaBits int, ecCurve string) (crypto.Signer, error)

var (
	providerMu sync.RWMutex
	providers  = map[string]KeyProvider{
		"rsa": func(bits int, _ string) (crypto.Signer, error) {
			if bits == 0 {
				bits = 3072
			}
			return rsa.GenerateKey(rand.Reader, bits)
		},
		"ecdsa": func(_ int, curveName string) (crypto.Signer, error) {
			return ecdsa.GenerateKey(curveFor(curveName), rand.Reader)
		},
		// Ed25519 (EdDSA) — a third algorithm family, registered through the
		// exact same seam a PQC provider uses. Its presence proves that adding a
		// new signature algorithm is purely a provider registration: the CA
		// hierarchy, issuance, OCSP, and CRL code are all unchanged.
		"ed25519": func(_ int, _ string) (crypto.Signer, error) {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			return priv, err
		},
	}
)

// RegisterProvider adds or replaces a key provider for a key type. PQC providers
// call this (e.g. from an init() in a build-tagged file) to join the registry.
func RegisterProvider(keyType string, p KeyProvider) {
	providerMu.Lock()
	defer providerMu.Unlock()
	providers[keyType] = p
}

// lookupProvider returns the provider for a key type.
func lookupProvider(keyType string) (KeyProvider, error) {
	providerMu.RLock()
	defer providerMu.RUnlock()
	p, ok := providers[keyType]
	if !ok {
		return nil, fmt.Errorf("hsm: no key provider registered for type %q (have: %v)", keyType, registeredTypes())
	}
	return p, nil
}

// RegisteredKeyTypes lists the key types the HSM can currently mint. Useful for
// surfacing crypto-agility status in tooling/reports.
func RegisteredKeyTypes() []string {
	providerMu.RLock()
	defer providerMu.RUnlock()
	return registeredTypes()
}

func registeredTypes() []string {
	out := make([]string, 0, len(providers))
	for k := range providers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func curveFor(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-521":
		return elliptic.P521()
	default:
		return elliptic.P384()
	}
}
