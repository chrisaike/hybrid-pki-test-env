// Command pkitool drives the PKI test environment hierarchy from the CLI:
//
//	pkitool build            # build/re-issue the CA hierarchy into ./out
//	pkitool build --force    # regenerate keys too
//	pkitool info             # print the built hierarchy
//
// It is the offline control path (the Root CA is only touched here).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chrisaike/hybrid-pki-test-env/internal/ca"
	"github.com/chrisaike/hybrid-pki-test-env/internal/config"
	"github.com/chrisaike/hybrid-pki-test-env/internal/hsm"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "config/hierarchy.yaml", "path to hierarchy.yaml")
	outDir := fs.String("out", "out", "output directory for certs/bundle")
	hsmDir := fs.String("hsm", "out/hsm", "simulated HSM token directory")
	force := fs.Bool("force", false, "force key regeneration")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*cfgPath)
	check(err)

	token, err := hsm.NewSoftHSM(*hsmDir, slotPINs(cfg))
	check(err)

	h := ca.New(cfg, token, *outDir)

	switch cmd {
	case "build":
		check(h.Build(*force))
		printBuilt(h, *outDir)
	case "info":
		check(h.Build(false))
		printBuilt(h, *outDir)
	default:
		usage()
	}
}

func printBuilt(h *ca.Hierarchy, outDir string) {
	fmt.Println("CA hierarchy built:")
	fmt.Printf("  Root:         %s\n", h.Root.Name)
	for _, a := range h.Intermediates {
		fmt.Printf("  Intermediate: %s\n", a.Name)
	}
	for _, a := range h.Issuing {
		fmt.Printf("  Issuing:      %s (AIA/CDP embedded)\n", a.Name)
	}
	fmt.Printf("\nTrust anchor + chain written to: %s\n", filepath.Join(outDir, "ca-bundle.pem"))
	fmt.Println("Import ca-bundle.pem into clients as the TEST trust anchor set.")
}

func slotPINs(cfg *config.Config) map[string]string {
	m := map[string]string{}
	for _, c := range cfg.AllCAs() {
		m[c.Slot] = pinFor(c.Slot)
	}
	return m
}

func pinFor(slot string) string {
	if v := os.Getenv("HSM_PIN_" + upper(slot)); v != "" {
		return v
	}
	return "test-pin-" + slot
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pkitool <build|info> [--config f] [--out d] [--hsm d] [--force]")
	os.Exit(2)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
