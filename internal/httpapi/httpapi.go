// Package httpapi exposes the PKI test environment over HTTP:
//
//   - Mock Venafi REST API:   /v1/certificates/...        (enroll/renew/revoke/status)
//   - Enrollment surface:     /.well-known/est/simpleenroll (AD auto-enroll representation)
//   - Revocation:             /ocsp, /crl/{name}.crl
//   - Health:                 /healthz                     (for LB health checks / HA)
//
// All issuance flows share internal/service, so lifecycle state is consistent
// across every surface.
package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/chrisaike/hybrid-pki-test-env/internal/revocation"
	"github.com/chrisaike/hybrid-pki-test-env/internal/service"
)

// Server bundles the HTTP surfaces.
type Server struct {
	svc     *service.Service
	ocsp    *revocation.OCSPResponder
	crlPEM  func() []byte
	replica string // replica id (for HA visibility)
}

// New builds the HTTP server.
func New(svc *service.Service, ocsp *revocation.OCSPResponder, crlPEM func() []byte, replica string) *Server {
	return &Server{svc: svc, ocsp: ocsp, crlPEM: crlPEM, replica: replica}
}

// Handler returns the configured mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health check (Requirement 6.3) — reports replica id for HA visibility.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "replica": s.replica})
	})

	// --- Mock Venafi API (Requirement 3) ---
	mux.HandleFunc("/v1/certificates/request", s.handleEnroll)
	mux.HandleFunc("/v1/certificates/", s.handleCertByID) // renew/revoke/status

	// --- Enrollment surface / EST (Requirement 5) ---
	mux.HandleFunc("/.well-known/est/simpleenroll", s.handleEST)

	// --- Revocation (Requirement 4) ---
	mux.HandleFunc("/ocsp", s.handleOCSP)
	mux.HandleFunc("/crl/", s.handleCRL)

	return logMiddleware(s.replica, mux)
}

// --- Venafi mock handlers ---

type enrollReq struct {
	CSR     string `json:"csr"`     // PEM
	Profile string `json:"profile"` // profile/template name
}

type enrollResp struct {
	ID       string `json:"id"`
	Serial   string `json:"serial"`
	Cert     string `json:"certificate"`
	Chain    string `json:"chain"`
	NotAfter string `json:"not_after"`
	Subject  string `json:"subject"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	var req enrollReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	res, err := s.svc.Enroll([]byte(req.CSR), req.Profile)
	if err != nil {
		// profile allow-list denial surfaces as 403 (Requirement 5.4)
		code := 400
		if strings.Contains(err.Error(), "denied") {
			code = 403
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, 201, toEnrollResp(res))
}

func (s *Server) handleCertByID(w http.ResponseWriter, r *http.Request) {
	// paths: /v1/certificates/{id}  | /v1/certificates/{id}/renew | /v1/certificates/{id}/revoke
	rest := strings.TrimPrefix(r.URL.Path, "/v1/certificates/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeErr(w, 404, "certificate id required")
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "" && r.Method == http.MethodGet:
		rec, ok := s.svc.Status(id)
		if !ok {
			writeErr(w, 404, "unknown certificate")
			return
		}
		writeJSON(w, 200, map[string]any{
			"id": rec.ID, "serial": rec.Serial, "status": rec.Status,
			"subject": rec.Subject, "profile": rec.Profile,
			"issued_at": rec.IssuedAt, "revoked_at": rec.RevokedAt,
		})
	case action == "renew" && r.Method == http.MethodPost:
		var req enrollReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, err := s.svc.Renew(id, []byte(req.CSR))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, toEnrollResp(res))
	case action == "revoke" && r.Method == http.MethodPost:
		var body struct {
			Reason int `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := s.svc.Revoke(id, body.Reason); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"id": id, "status": "revoked"})
	default:
		writeErr(w, 405, "method/action not allowed")
	}
}

// --- EST enrollment surface (AD auto-enroll representation) ---

// handleEST accepts a base64 PKCS#10 (EST simpleenroll) and a ?profile= selector.
func (s *Server) handleEST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	profile := r.URL.Query().Get("profile")
	if profile == "" {
		profile = "device-autoenroll" // default AD machine template
	}
	body, _ := io.ReadAll(r.Body)
	// EST sends base64 DER; accept PEM too for convenience.
	csrPEM := body
	if !strings.Contains(string(body), "-----BEGIN") {
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			writeErr(w, 400, "bad EST body")
			return
		}
		csrPEM = pemWrap("CERTIFICATE REQUEST", der)
	}
	res, err := s.svc.Enroll(csrPEM, profile)
	if err != nil {
		code := 400
		if strings.Contains(err.Error(), "denied") {
			code = 403
		}
		writeErr(w, code, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	_, _ = w.Write([]byte(res.CertPEM))
}

// --- Revocation handlers ---

func (s *Server) handleOCSP(w http.ResponseWriter, r *http.Request) {
	var der []byte
	switch r.Method {
	case http.MethodPost:
		der, _ = io.ReadAll(r.Body)
	case http.MethodGet:
		enc := strings.TrimPrefix(r.URL.Path, "/ocsp/")
		b, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			writeErr(w, 400, "bad OCSP GET")
			return
		}
		der = b
	default:
		writeErr(w, 405, "method not allowed")
		return
	}
	serials, err := revocation.ParseRequestSerials(der)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	resp, err := s.ocsp.BuildResponse(serials[0])
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(resp)
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.crlPEM())
}

// --- helpers ---

func toEnrollResp(res *service.EnrollResult) enrollResp {
	return enrollResp{
		ID: res.ID, Serial: res.Serial, Cert: res.CertPEM, Chain: res.ChainPEM,
		NotAfter: res.NotAfter.Format("2006-01-02T15:04:05Z07:00"), Subject: res.Subject,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func pemWrap(typ string, der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + typ + "-----\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end] + "\n")
	}
	sb.WriteString("-----END " + typ + "-----\n")
	return []byte(sb.String())
}

func logMiddleware(replica string, next http.Handler) http.Handler { //nolint
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[replica=%s] %s %s", replica, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
