package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// marshalKey serialises a private key to PKCS#8 PEM, returning the PEM bytes and
// a type tag ("rsa"/"ecdsa"/"ed25519"). PKCS#8 handles all x509-native key
// types; PQC keys provide their own marshalling via their signer type.
func marshalKey(s crypto.Signer) ([]byte, string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s)
	if err != nil {
		return nil, "", fmt.Errorf("hsm: marshal key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	var typ string
	switch s.(type) {
	case *rsa.PrivateKey:
		typ = "rsa"
	case *ecdsa.PrivateKey:
		typ = "ecdsa"
	case ed25519.PrivateKey:
		typ = "ed25519"
	default:
		return nil, "", fmt.Errorf("hsm: unsupported signer type %T", s)
	}
	return pem.EncodeToMemory(block), typ, nil
}

// unmarshalKey parses a PKCS#8 PEM private key.
func unmarshalKey(pemBytes []byte, _ string) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("hsm: invalid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hsm: parse key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("hsm: key is not a signer")
	}
	return signer, nil
}
