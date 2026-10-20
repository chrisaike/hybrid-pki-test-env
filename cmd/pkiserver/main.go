// Command pkiserver runs the online PKI test services (mock Venafi API,
// EST enrollment surface, OCSP responder, CRL endpoint, health checks).
//
// Multiple instances can run behind a load balancer for HA; each advertises its
// replica id on /healthz. The Root CA key is NOT used here — only the issuing
// CA signs leaf certs, OCSP responses, and CRLs.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/chrisaike/hybrid-pki-test-env/internal/ca"
	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
	"github.com/chrisaike/hybrid-pki-test-env/internal/hsm"
	"github.com/chrisaike/hybrid-pki-test-env/internal/httpapi"
	"github.com/chrisaike/hybrid-pki-test-env/internal/revocation"
	"github.com/chrisaike/hybrid-pki-test-env/internal/service"
	"github.com/chrisaike/hybrid-pki-test-env/internal/store"
)

func openStore(path string) (*store.Store, error) { return store.Open(path) }

func main() {
	cfgPath := flag.String("config", "config/hierarchy.yaml", "path to hierarchy.yaml")
	outDir := flag.String("out", "out", "hierarchy output dir")
	hsmDir := flag.String("hsm", "out/hsm", "simulated HSM token dir")
	storePath := flag.String("store", "out/status.json", "status store path")
	crlPath := flag.String("crl", "out/issuing-ca-1.crl", "CRL output path")
	addr := flag.String("addr", ":8080", "listen address")
	replica := flag.String("replica", envOr("REPLICA_ID", "r1"), "replica id (HA visibility)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	must(err)

	token, err := hsm.NewSoftHSM(*hsmDir, slotPINs(cfg))
	must(err)

	h := ca.New(cfg, token, *outDir)
	must(h.Build(false)) // reuse existing keys/certs; build if absent

	st, err := openStore(*storePath)
	must(err)

	issuing := h.FirstIssuing()
	issuerKey, err := token.Signer(issuing.Slot)
	must(err)

	crl := revocation.NewCRLPublisher(issuing.Cert, issuerKey, st, *crlPath)
	if _, err := crl.Publish(); err != nil {
		log.Printf("warning: initial CRL publish: %v", err)
	}

	ocsp := revocation.NewOCSPResponder(issuing.Cert, issuerKey, st)
	svc := service.New(h, cfg, st, crl)

	crlPEM := func() []byte {
		b, _ := os.ReadFile(*crlPath)
		return b
	}

	srv := httpapi.New(svc, ocsp, crlPEM, *replica)
	log.Printf("pkiserver replica=%s listening on %s", *replica, *addr)
	log.Printf("issuing CA: %s", issuing.Name)
	must(http.ListenAndServe(*addr, srv.Handler()))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func slotPINs(cfg *config.Config) map[string]string {
	m := map[string]string{}
	for _, c := range cfg.AllCAs() {
		if v := os.Getenv("HSM_PIN_" + upper(c.Slot)); v != "" {
			m[c.Slot] = v
		} else {
			m[c.Slot] = "test-pin-" + c.Slot
		}
	}
	return m
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
