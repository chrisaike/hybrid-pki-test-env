# Dashboard

A single self-contained HTML dashboard that visualizes the Hybrid PKI Test &
Certification Environment and its step-by-step build process. No dependencies,
no build step.

## View it

- **Locally:** open `index.html` in any browser.
- **GitHub Pages:** enable Pages for the repo (Settings → Pages → source:
  GitHub Actions). The `pages.yml` workflow publishes `docs/dashboard/` and the
  dashboard is served at `https://<owner>.github.io/<repo>/`.

## What it shows

| Tab | Content |
|-----|---------|
| Overview | Live KPIs, the "hybrid" definition, Priority-1 rationale, trust paths |
| Build Process | 12-step timeline mapping to real tasks/files and requirements |
| CA Hierarchy | Root → Intermediate → Issuing → leaf, with real cert fields |
| Components | The 9 services/packages and their roles |
| Lifecycle & Revocation | Enroll → validate and revoke → OCSP/CRL flows |
| Certification | The live certification report (per-check pass/fail) |
| Multi-Cloud | AWS→Azure→GCP resource-equivalence table |
| Crypto Agility | RSA/ECDSA/Ed25519 live + ML-DSA (PQC) seam |

## Data source

The figures (certification checks, hierarchy cert fields) are captured from an
actual `make certify` + `pkitool build` run and embedded in the page's
`<script id="data">` block. To refresh after changes:

```bash
make issue
./bin/certify --report out/certification-report.json
# then update the embedded JSON in index.html (report + hierarchy blocks)
```
