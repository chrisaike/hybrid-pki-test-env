# Project Plan — Cloud-First (AWS) Hybrid PKI Test & Certification Environment

> **Scope change (this plan):** the **first test is 100% in the cloud on AWS**.
> We stand up the full production-representative PKI test environment in AWS
> first, then layer the *hybrid* (on-prem / cross-cloud) interfaces afterward.
> This document is a **plan only** — no implementation is included.

## 1. Objectives

| # | Objective | Source |
|---|-----------|--------|
| P1 | Build an enterprise-class, scalable PKI test environment that is a representative end-to-end path of PKI Production — CA chains, HSM, Venafi, OCSP/CRL, AD/GPO interfaces, load balancing, cloud interfaces, HA — delivered as IaC with on-demand spin-up/tear-down. | Priority 1 |
| P2 | Assess current on-prem + hybrid PKI architecture against expected 6–12 month demand: validate issuance/renewal/validation capacity, test end-to-end dependencies, availability, and peak-load behavior; recommend targeted changes. | Priority 2 |

**Definition of done (program):** AWS environment can be `apply`/`destroy` on
demand; a certification run exercises every critical trust path and emits a
machine-readable report; a capacity assessment produces an evidence-based
near-term recommendation for VA leadership.

## 2. Guiding principles

- **Cloud-first, AWS-first.** Build the complete test environment in AWS before
  wiring hybrid/on-prem paths. Keep the design portable so Azure/GCP remain
  reachable later, but do not block on them.
- **IaC everything.** No click-ops. Spin up on demand, tear down automatically to
  control cost (Priority-1 cost rationale).
- **Representative, not production.** Mirror production trust paths and call
  shapes; never share production key material or trust anchors. All test anchors
  are clearly labeled.
- **Certify, don't assume.** Every trust path is validated by an automated
  harness that gates promotion.
- **Security by default.** HSM-backed keys, offline root posture, least-privilege
  IAM, secrets in a managed store, full audit logging.

## 3. Workstreams

1. **Foundation & Landing Zone** — AWS accounts, networking, identity, guardrails.
2. **PKI Core** — CA hierarchy (Root/Intermediate/Issuing), HSM (CloudHSM) key ops.
3. **Revocation & Validation** — OCSP responder, CRL publication/distribution.
4. **Lifecycle & Integrations** — Venafi interface, EST/SCEP, AD/GPO enrollment path.
5. **Platform & HA** — compute, load balancing, multi-AZ, autoscaling, DNS.
6. **Automation & Lifecycle** — IaC pipelines, on-demand spin-up/tear-down, scheduled teardown.
7. **Certification Service** — automated trust-path certification + reporting.
8. **Capacity Assessment (Priority 2)** — load modeling, peak-load tests, recommendation.
9. **Observability, Security & Governance** — logging, monitoring, audit, cost controls.

## 4. Roadmap — two-week sprints

Each sprint is a **2-week deliverable increment**. Dates are relative (Sprint N),
so the plan is start-date-agnostic. Every sprint ends with a demo + a tangible,
reviewable artifact.

### Phase A — Foundation (Sprints 1–2)

**Sprint 1 — AWS Landing Zone & Network Foundation**
- Deliverables: AWS account/OU structure (or dedicated test account), region
  selection, VPC with public/private/isolated subnets across ≥2 AZs, VPC
  endpoints, baseline IAM roles/SCPs, Terraform remote state (S3 + DynamoDB lock),
  tagging & cost-allocation standard, budget + alerts.
- Exit criteria: `terraform apply`/`destroy` of the network baseline succeeds
  cleanly; state is remote and locked; budget alarms live.

**Sprint 2 — Identity, Secrets, Security Baseline**
- Deliverables: least-privilege IAM for each workstream, Secrets Manager + KMS
  key hierarchy, CloudTrail (org/account), AWS Config rules, GuardDuty, Security
  Hub baseline, DNS (Route 53 private zone `pki.test.`).
- Exit criteria: audit trail capturing all API calls; secrets never in code;
  Config/GuardDuty reporting clean baseline.

### Phase B — PKI Core (Sprints 3–5)

**Sprint 3 — CloudHSM & Key Management**
- Deliverables: CloudHSM cluster (multi-AZ), HSM user/role model, slot/label
  convention mirroring production, PKCS#11 access pattern validated, break-glass
  and backup/restore runbook. (Simulated-HSM parity option documented for
  low-cost iterations.)
- Exit criteria: a test key can be generated and used to sign through PKCS#11;
  HSM failover across AZ verified.

**Sprint 4 — CA Hierarchy (Root → Intermediate → Issuing)**
- Deliverables: offline-posture Root CA, Intermediate CA(s), online Issuing CA(s)
  with keys in CloudHSM; `hierarchy` config as single source of truth; chain
  bundle; AIA/CDP wiring. Decision recorded: AWS Private CA vs. self-managed CA
  software (trade-offs documented).
- Exit criteria: issued leaf validates to Root via full chain; re-issue is
  repeatable with no manual key handling.

**Sprint 5 — Revocation: OCSP & CRL**
- Deliverables: OCSP responder service, CRL generation + publication to S3 +
  CloudFront, correct AIA/CDP in issued certs, revocation status store.
- Exit criteria: revoke → OCSP returns `revoked` and CRL contains the serial;
  valid cert returns `good`.

### Phase C — Integrations & Platform (Sprints 6–8)

**Sprint 6 — Platform, Load Balancing & HA**
- Deliverables: containerized PKI services on ECS Fargate (or EKS — decision
  recorded) behind an ALB/NLB, ≥2 replicas across AZs, health checks,
  autoscaling policies, multi-AZ data stores.
- Exit criteria: service survives loss of one replica/AZ; autoscaling triggers
  under synthetic load.

**Sprint 7 — Certificate Lifecycle & Venafi Interface**
- Deliverables: enroll/renew/revoke/status API surface representing the Venafi
  control-plane operations used in production; status lifecycle tracking; profile
  catalog (certificate templates).
- Exit criteria: full issue→renew→revoke lifecycle works end-to-end through the
  Venafi-shaped interface and reflects in OCSP/CRL.

**Sprint 8 — Enrollment Surfaces & AD/GPO Interface**
- Deliverables: EST/SCEP enrollment endpoints representing AD auto-enrollment;
  template-to-GPO-equivalent profile mapping; allow-list enforcement; AD
  connectivity interface (hybrid hook, stubbed in the AWS-only phase).
- Exit criteria: device/user auto-enrollment path issues a cert via the Issuing
  CA; non-matching profiles are denied.

### Phase D — Automation & Certification (Sprints 9–10)

**Sprint 9 — IaC Lifecycle & On-Demand Environments**
- Deliverables: one-command spin-up/tear-down pipeline (CI/CD), ephemeral
  environment per test run, scheduled teardown for cost control, environment
  outputs (endpoints + trust anchor) published to testers.
- Exit criteria: a reviewer can spin up a full environment and tear it down with
  zero manual steps; idle cost ≈ $0.

**Sprint 10 — Certification Service & Reporting**
- Deliverables: automated certification harness covering chain-to-root,
  lifecycle, OCSP/CRL, HA failover, and rollback; machine-readable report
  (JSON + JUnit); CI gate; certification runbook for PKI updates/migrations/OEM
  products/rollback plans.
- Exit criteria: a green certification run is required to promote a change;
  report archived as evidence.

### Phase E — Capacity Assessment / Priority 2 (Sprints 11–12)

**Sprint 11 — Capacity Model & Load Harness**
- Deliverables: demand model for the next 6–12 months (issuance, renewal,
  validation rates), load-generation harness, SLO/SLA targets, instrumentation of
  issuance/OCSP/CRL latency and throughput.
- Exit criteria: repeatable load tests produce latency/throughput curves per
  trust path.

**Sprint 12 — Peak-Load Tests & Leadership Recommendation**
- Deliverables: peak-load and soak tests against the AWS environment, dependency
  and availability analysis, bottleneck identification, evidence-based near-term
  capacity recommendation + prioritized operational changes for VA leadership.
- Exit criteria: a decision memo answering "can today's PKI config meet
  near-term demand?" backed by test data.

### Phase F — Hybrid Enablement (Sprints 13–14, follow-on)

> After the AWS-only test is validated, extend to the *hybrid* reality.

**Sprint 13 — Hybrid Connectivity**
- Deliverables: Direct Connect / Site-to-Site VPN to the on-prem/VA network,
  DNS resolution across boundaries, routing, firewall/security-group policy for
  cross-boundary PKI traffic.
- Exit criteria: AWS PKI services reach on-prem AD and vice-versa over a private,
  authenticated path.

**Sprint 14 — On-Prem Trust-Path Integration & Cross-Env Certification**
- Deliverables: live AD/GPO auto-enrollment against on-prem AD, on-prem HSM or
  trust-anchor bridging where required, cross-environment certification run.
- Exit criteria: the hybrid end-to-end path is certified by the harness, matching
  the AWS-only baseline.

## 5. Milestones

| Milestone | Sprint | Evidence |
|-----------|--------|----------|
| M1 — Landing zone live | 2 | apply/destroy network + security baseline |
| M2 — PKI core issuing | 5 | leaf chains to root; OCSP/CRL working |
| M3 — Platform HA + lifecycle | 8 | HA failover + full lifecycle via Venafi/EST |
| M4 — On-demand + certified | 10 | one-command env + green certification report |
| M5 — Capacity recommendation | 12 | leadership decision memo with test evidence |
| M6 — Hybrid certified | 14 | cross-environment certification run passes |

## 6. RACI (summary)

| Activity | PKI Eng | Cloud/Platform | Security | QA/Perf | Leadership |
|----------|:-------:|:--------------:|:--------:|:-------:|:----------:|
| Landing zone / IaC | C | **R/A** | C | I | I |
| CA hierarchy / HSM | **R/A** | C | C | I | I |
| Revocation (OCSP/CRL) | **R/A** | C | C | C | I |
| HA / platform | C | **R/A** | C | C | I |
| Certification service | **R/A** | C | C | **R** | I |
| Capacity assessment | C | C | I | **R/A** | **A** |
| Hybrid connectivity | C | **R/A** | **R** | I | I |

## 7. Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|:----------:|:------:|-----------|
| CloudHSM cost/complexity | Med | Med | Simulated-HSM parity path for iteration; reserve CloudHSM for certification runs |
| Scope creep from hybrid before AWS baseline is stable | Med | High | Gate hybrid work behind M4 (certified AWS baseline) |
| Production trust-anchor leakage | Low | High | Hard isolation; labeled test anchors; separate account |
| Capacity model lacks real demand data | Med | Med | Instrument early (Sprint 11); validate model against observed rates |
| Cross-boundary networking delays (Priority 2 realism) | Med | Med | Start Direct Connect/VPN procurement during Phase B |

## 8. Cost control

- Ephemeral environments + scheduled teardown → near-zero idle cost.
- Budgets + alarms from Sprint 1; cost-allocation tags on every resource.
- Reserve the most expensive components (CloudHSM, always-on NAT) for active test
  windows; tear down between runs.

## 9. Out of scope (this phase)

- Production cutover or any change to the live PKI.
- Permanent always-on environment (environments are on-demand).
- Azure/GCP implementation (kept portable, built later if prioritized).
