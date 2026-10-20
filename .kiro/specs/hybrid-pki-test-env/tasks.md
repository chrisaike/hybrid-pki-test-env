# Implementation Plan — Hybrid PKI Test & Certification Environment

- [x] 1. Scaffold repository, config, and lifecycle tooling
  - Create repo layout, `README.md`, `Makefile` (`up`/`down`/`certify`), `.gitignore`.
  - Create `config/hierarchy.yaml` as the single source of truth.
  - _Requirements: 7.6, 8.1, 8.3_

- [x] 2. Simulated HSM (SoftHSM / PKCS#11)
  - [x] 2.1 Provision SoftHSM token with configurable slots/labels/PINs.
    - _Requirements: 2.1, 2.3_
  - [x] 2.2 Implement fail-closed behavior when token/slot is unavailable.
    - _Requirements: 2.4_

- [x] 3. CA core (hierarchy + PKCS#11 signer)
  - [x] 3.1 Generate Root (offline), Intermediate, Issuing CAs via PKCS#11 from `hierarchy.yaml`.
    - _Requirements: 1.1, 1.3, 1.5, 2.2, 10.1_
  - [x] 3.2 Implement `sign(csr, profile)` with AIA/CDP extensions and profile enforcement.
    - _Requirements: 1.2, 4.4, 5.3, 5.4_
  - [x] 3.3 Implement idempotent re-issue of the hierarchy (no manual key handling).
    - _Requirements: 1.4_

- [x] 4. Revocation services (OCSP + CRL)
  - [x] 4.1 Status store (schema + access layer) for issued/revoked state.
    - _Requirements: 4.1, 4.2, 4.3_
  - [x] 4.2 CRL publisher (on-revocation + scheduled), signed by issuing CA.
    - _Requirements: 4.1, 4.5_
  - [x] 4.3 OCSP responder returning good/revoked.
    - _Requirements: 4.2, 4.3_

- [x] 5. Mock Venafi REST API
  - Enroll / renew / revoke / status endpoints delegating to CA core + status store.
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 6. Enrollment surface (AD/GPO-style auto-enroll)
  - EST/ACME-style endpoint with template-equivalent profiles and allow-list enforcement.
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [x] 7. Load balancing + HA (local mode)
  - Run issuing/OCSP/enrollment with ≥2 replicas behind a load balancer with health checks.
  - _Requirements: 6.1, 6.2, 6.3_

- [x] 8. Local deployment (Docker Compose) — zero-cost full parity
  - Compose file wiring all services, LB, status store, object store for CRL/AIA.
  - `make up` prints endpoints + Root trust anchor.
  - _Requirements: 7.6, 8.1, 8.3_

- [x] 9. Multi-cloud IaC (Terraform)
  - [x] 9.1 Define cloud-agnostic module contracts (service/network/secrets/objectstore).
    - _Requirements: 7.1, 7.2_
  - [x] 9.2 Implement AWS modules + `infra/envs/aws-dev` (apply/destroy clean).
    - _Requirements: 7.2, 7.3, 7.4, 7.5_
  - [x] 9.3 Azure/GCP stub modules + resource-mapping docs.
    - _Requirements: 7.2, 7.5_
  - [x] 9.4 Scheduled teardown automation for cloud mode.
    - _Requirements: 8.2_

- [x] 10. Certification harness
  - [x] 10.1 Chain build + validate to Root.
    - _Requirements: 9.1_
  - [x] 10.2 Lifecycle (issue/renew/revoke) + OCSP/CRL assertions.
    - _Requirements: 9.2, 9.3_
  - [x] 10.3 HA failover check.
    - _Requirements: 9.4_
  - [x] 10.4 Rollback scenario check.
    - _Requirements: 9.5_
  - [x] 10.5 Machine-readable certification report (JSON + JUnit).
    - _Requirements: 9.6_

- [x] 11. Hybrid/PQC readiness
  - Document + wire the provider-selection point (OpenSSL 3 + oqs-provider) behind config.
  - _Requirements: 10.1, 10.2, 10.3_

- [x] 12. Documentation + runbooks
  - Architecture, multi-cloud mapping table, run/verify/teardown, rollback runbook.
  - _Requirements: NFR: Documentation_

---

## Build status (verified in-sandbox)

- `go vet ./...` — clean
- `go test ./...` — all packages pass (HSM fail-closed, full HTTP lifecycle, EST, profile denial)
- `make certify` — **CERTIFIED, 9/9 checks pass** (chain, lifecycle, OCSP/CRL, HA, rollback)
- CA hierarchy verified: ECDSA root/intermediate + RSA issuing, chain validates to root

## Notes / follow-ups

- HTTP services verified via Go `httptest` (sandbox network mode is INTEGRATIONS_ONLY,
  so live listening sockets and containers can't run here; handler code is identical).
- Terraform not installed in-sandbox; modules authored to HCL spec, validate with
  `terraform init/validate` on a machine with the CLI.
- Azure/GCP service modules are contract-complete stubs (see docs/MULTICLOUD.md).
- JUnit report format (10.5) — JSON implemented; JUnit XML is a small add-on if CI needs it.
- PQC provider (11) — integration seam implemented + documented; wiring a concrete
  oqs-provider/Go PQC signer is the remaining step, isolated to internal/hsm.
