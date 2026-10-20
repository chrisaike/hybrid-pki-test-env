// Command certify runs the PKI certification harness and emits a machine-readable
// report (JSON) plus a human summary. It certifies a PKI change / migration /
// OEM product / rollback plan by exercising the full environment in-process.
//
//	certify --report out/certification-report.json
//
// Exit code is non-zero if any check fails, so it gates CI/CD.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chrisaike/hybrid-pki-test-env/internal/certify"
)

func main() {
	cfgPath := flag.String("config", "config/hierarchy.yaml", "hierarchy.yaml")
	reportPath := flag.String("report", "out/certification-report.json", "JSON report output path")
	junitPath := flag.String("junit", "", "JUnit XML report output path (optional, for CI)")
	flag.Parse()

	start := time.Now()
	report := certify.Run(*cfgPath)
	report.DurationMS = time.Since(start).Milliseconds()

	// write machine-readable JSON report
	if err := os.MkdirAll(dir(*reportPath), 0o755); err == nil {
		b, _ := json.MarshalIndent(report, "", "  ")
		_ = os.WriteFile(*reportPath, b, 0o644)
	}

	// write JUnit XML report for CI systems (Requirement 9.6)
	if *junitPath != "" {
		if err := os.MkdirAll(dir(*junitPath), 0o755); err == nil {
			if xmlBytes, err := report.JUnitXML(); err == nil {
				_ = os.WriteFile(*junitPath, xmlBytes, 0o644)
			}
		}
	}

	// human summary
	fmt.Println("==================================================")
	fmt.Println(" PKI CERTIFICATION REPORT")
	fmt.Println("==================================================")
	for _, c := range report.Checks {
		status := "PASS"
		mark := "PASS"
		if !c.Pass {
			status, mark = "FAIL", "FAIL"
		}
		fmt.Printf(" [%-4s] %-42s %s\n", mark, c.Name, status)
		if c.Detail != "" {
			fmt.Printf("        %s\n", c.Detail)
		}
	}
	fmt.Println("--------------------------------------------------")
	fmt.Printf(" Requirement coverage: %d checks | %d passed | %d failed\n",
		len(report.Checks), report.Passed, report.Failed)
	fmt.Printf(" Overall: %s  (%.0f%% pass, %dms)\n",
		verdict(report), report.PassRate*100, report.DurationMS)
	fmt.Printf(" Report: %s\n", *reportPath)
	if *junitPath != "" {
		fmt.Printf(" JUnit:  %s\n", *junitPath)
	}
	fmt.Println("==================================================")

	if report.Failed > 0 {
		os.Exit(1)
	}
}

func verdict(r *certify.Report) string {
	if r.Failed == 0 {
		return "CERTIFIED"
	}
	return "NOT CERTIFIED"
}

func dir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
