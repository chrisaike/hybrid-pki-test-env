package revocation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/chrisaike/hybrid-pki-test-env/internal/store"
)

// OCSP certificate status values (RFC 6960).
const (
	ocspGood    = 0
	ocspRevoked = 1
	ocspUnknown = 2
)

var (
	oidSHA1           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidOCSPBasic      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSigSHA256RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSigSHA256ECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSigEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// OCSPResponder answers OCSP requests from the status store, signing responses
// with the issuing CA key (delegated-responder pattern supported in prod).
type OCSPResponder struct {
	issuerCert *x509.Certificate
	issuerKey  crypto.Signer
	st         *store.Store
}

// NewOCSPResponder wires a responder.
func NewOCSPResponder(issuerCert *x509.Certificate, issuerKey crypto.Signer, st *store.Store) *OCSPResponder {
	return &OCSPResponder{issuerCert: issuerCert, issuerKey: issuerKey, st: st}
}

// --- request parsing (RFC 6960 OCSPRequest, minimal) ---

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  *big.Int
}

type requestEntry struct {
	Cert certID
}

type tbsRequest struct {
	Version     int `asn1:"explicit,tag:0,optional"`
	RequestList []requestEntry
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

// Status returns the OCSP status for a serial by consulting the store.
// Returns one of ocspGood/ocspRevoked/ocspUnknown and the revocation time.
func (r *OCSPResponder) Status(serial *big.Int) (int, time.Time, int) {
	rec, ok := r.st.BySerial(serial.String())
	if !ok {
		return ocspUnknown, time.Time{}, 0
	}
	if rec.Status == store.StatusRevoked {
		return ocspRevoked, rec.RevokedAt, rec.ReasonCode
	}
	return ocspGood, time.Time{}, 0
}

// ParseRequestSerials extracts the requested serial numbers from a DER OCSP request.
func ParseRequestSerials(der []byte) ([]*big.Int, error) {
	var req ocspRequest
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		return nil, fmt.Errorf("ocsp: parse request: %w", err)
	}
	var serials []*big.Int
	for _, e := range req.TBSRequest.RequestList {
		serials = append(serials, e.Cert.SerialNumber)
	}
	if len(serials) == 0 {
		return nil, fmt.Errorf("ocsp: no requests in list")
	}
	return serials, nil
}

// --- response construction (RFC 6960 BasicOCSPResponse) ---

type singleResponse struct {
	CertID     certID
	Good       asn1.RawValue `asn1:"optional"`
	Revoked    asn1.RawValue `asn1:"optional"`
	ThisUpdate time.Time     `asn1:"generalized"`
	NextUpdate time.Time     `asn1:"explicit,tag:0,optional,generalized"`
}

type responderID struct {
	ByName asn1.RawValue `asn1:"explicit,tag:1"`
}

type responseData struct {
	ResponderID responderID
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
}

type basicOCSPResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspResponse struct {
	Status        asn1.Enumerated
	ResponseBytes responseBytes `asn1:"explicit,tag:0,optional"`
}

// BuildResponse builds a signed DER OCSP response for a single serial.
func (r *OCSPResponder) BuildResponse(serial *big.Int) ([]byte, error) {
	status, revTime, _ := r.Status(serial)

	cid, err := r.makeCertID(serial)
	if err != nil {
		return nil, err
	}

	sr := singleResponse{
		CertID:     cid,
		ThisUpdate: time.Now().UTC(),
		NextUpdate: time.Now().Add(24 * time.Hour).UTC(),
	}
	switch status {
	case ocspGood:
		sr.Good = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: false, Bytes: []byte{}}
	case ocspRevoked:
		revokedInfo, _ := asn1.MarshalWithParams(revTime.UTC(), "generalized")
		sr.Revoked = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: revokedInfo}
	default:
		sr.Good = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: false, Bytes: []byte{}}
	}

	nameDER, err := asn1.Marshal(r.issuerCert.Subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	rd := responseData{
		ResponderID: responderID{ByName: asn1.RawValue{FullBytes: nameDER}},
		ProducedAt:  time.Now().UTC(),
		Responses:   []singleResponse{sr},
	}
	tbs, err := asn1.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("ocsp: marshal tbs: %w", err)
	}

	sigAlg, hashFn := r.sigAlg()
	var (
		digest []byte
		opts   crypto.SignerOpts = hashFn
	)
	if hashFn == crypto.Hash(0) {
		// Ed25519 signs the full message (no pre-hash).
		digest = tbs
	} else {
		h := hashFn.New()
		h.Write(tbs)
		digest = h.Sum(nil)
	}
	sig, err := r.issuerKey.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("ocsp: sign: %w", err)
	}

	basic := basicOCSPResponse{
		TBSResponseData:    asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigAlg},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
		Certs:              []asn1.RawValue{{FullBytes: r.issuerCert.Raw}},
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		return nil, err
	}

	resp := ocspResponse{
		Status: 0, // successful
		ResponseBytes: responseBytes{
			ResponseType: oidOCSPBasic,
			Response:     basicDER,
		},
	}
	return asn1.Marshal(resp)
}

func (r *OCSPResponder) makeCertID(serial *big.Int) (certID, error) {
	nameHash := sha1.Sum(r.issuerCert.RawSubject)
	// KeyHash is SHA1 of the issuer public key BIT STRING contents.
	keyHash := sha1.Sum(r.issuerCert.RawSubjectPublicKeyInfo)
	return certID{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1},
		NameHash:      nameHash[:],
		KeyHash:       keyHash[:],
		SerialNumber:  serial,
	}, nil
}

func (r *OCSPResponder) sigAlg() (asn1.ObjectIdentifier, crypto.Hash) {
	switch r.issuerKey.Public().(type) {
	case *ecdsa.PublicKey:
		return oidSigSHA256ECDSA, crypto.SHA256
	case ed25519.PublicKey:
		return oidSigEd25519, crypto.Hash(0)
	default:
		return oidSigSHA256RSA, crypto.SHA256
	}
}

// StatusString is a convenience for tests/logging.
func StatusString(code int) string {
	switch code {
	case ocspGood:
		return "good"
	case ocspRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}
