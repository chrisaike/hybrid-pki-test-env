# Hybrid PKI Test & Certification Environment

An **enterprise-class, scalable, representative end-to-end** replica of a PKI
Production environment, built to **de-risk high-impact changes** (root, crypto,
cloud, workload, and trust changes) *before* they reach production.

It is delivered as **Infrastructure as Code** so large portions can be spun up on
demand and torn down automatically, keeping cost near zero when idle. It doubles
as a reusable **certification service** for PKI service updates, new services,
migrations, integrations, OEM product testing, and rollback-plan validation.

> **Why Priority 1:** A hybrid PKI test environment decreases the risk of future
> failed deployments and cuts the cost of an on-prem test environment. It prevents
> Production from becoming the first realistic integration test for high-risk
> changes. It closes a major engineering-control gap and creates a reusable
> certification service.

---

## What "hybrid" means here

| Axis | Coverage |
|------|----------|
| **Deployment** | On-prem-style services (CA, AD/GPO enrollment, SoftHSM) **+** cloud services |
| **Cloud** | **Multi-cloud**: AWS implemented; Azure/GCP via the same module contracts |
| **Cryptography** | Classical (RSA / ECDSA) now, with a documented **post-quantum** integration point |

## Critical trust paths covered

- **CA chains** — Root (offline) → Intermediate → Issuing
- **HSM operations** — *simulated* via SoftHSM / PKCS#11-shaped interface
- **Venafi control plane** — *simulated* mock REST API (enroll / renew / revoke / status)
- **OCSP / CRL** revocation
- **AD / GPO** interface — EST auto-enrollment surface with template-equivalent profiles
- **Load balancing + High Availability** — ≥2 replicas behind an LB
- **Cloud interfaces** — multi-cloud Terraform

---

## Quick start (local, zero cost)

Requires **Go 1.25+** (no other dependencies — everything is Go stdlib).

```bash
make issue      # build the CA hierarchy from config/hierarchy.yaml into ./out
make certify    # run the certification harness -> out/certification-report.json
make test       # run all unit + integration tests
```

Run the online services (two replicas + an LB is the HA topology):

```bash
make build
./bin/pkiserver --addr :8080 --replica r1   # terminal 1
./bin/pkiserver --addr :8081 --replica r2   # terminal 2
```

Then exercise it:

```bash
# health
curl localhost:8080/healthz

# enroll a TLS server cert via the mock Venafi API (CSR is PEM in JSON)
curl -s localhost:8080/v1/certificates/request \
  -H 'content-type: application/json' \
  -d '{"csr":"<PEM CSR>","profile":"tls-server"}'

# AD-style auto-enrollment (EST)
curl -s --data-binary @device.csr \
  'localhost:8080/.well-known/est/simpleenroll?profile=device-autoenroll'

# revoke, then check OCSP/CRL reflect it
curl -s -XPOST localhost:8080/v1/certificates/<id>/revoke -d '{"reason":1}'
curl -s localhost:8080/crl/issuing-ca-1.crl
```

The **trust anchor** clients import is `out/ca-bundle.pem` (labelled
`TEST - DO NOT TRUST`).

## Local HA topology (Docker Compose)

```bash
make compose-up     # nginx LB on :8080 -> pki-r1, pki-r2 (shared CA + store)
make compose-down
```

## Multi-cloud (Terraform)

```bash
make tf-init CLOUD=aws
make tf-apply CLOUD=aws     # spin up on AWS (ECS Fargate + ALB, >=2 replicas)
make tf-destroy CLOUD=aws   # tear down, no orphaned billable resources
```

Switching cloud = pointing the environment at the Azure/GCP module (same
contract). See [docs/MULTICLOUD.md](docs/MULTICLOUD.md).

---

## Configuration

Everything about the hierarchy lives in **`config/hierarchy.yaml`** — key types
(RSA/ECDSA), validities, path-length constraints, slot labels, AIA/CDP URLs, and
the certificate **profiles** that model AD templates. Edit it and
`make issue` to re-issue the hierarchy with no manual key handling.

## Architecture

See the Kiro spec under `.kiro/specs/hybrid-pki-test-env/` (`requirements.md`,
`design.md`, `tasks.md`) and `docs/` for the architecture, multi-cloud mapping,
PQC readiness, and runbooks.

```
services (Go):  ca-core · hsm-sim · venafi-sim · revocation (OCSP/CRL) · enrollment
commands:       pkitool (offline control) · pkiserver (online) · certify (harness)
infra:          Terraform modules (aws|azure|gcp) + envs + Docker Compose
```

## Simulated components

| Component | Simulation | Production swap point |
|-----------|------------|-----------------------|
| **HSM** | SoftHSM-style PKCS#11 interface with software keys per slot | Repoint PKCS#11 module to CloudHSM / Key Vault Managed HSM / Cloud HSM |
| **Venafi** | Mock REST API mirroring enroll/renew/revoke/status | Point clients at the real Venafi tenant; same request shapes |
| **AD / GPO** | EST enrollment surface + profiles = templates | Wire to NDES/SCEP or EST against the real forest |

## Security posture

- Root CA key kept **offline** (its own slot, never bound to an online service).
- Test trust anchors clearly labelled `TEST - DO NOT TRUST`.
- No secrets committed; generated keys/CRLs/state are `.gitignore`d.
- Cloud IAM scoped least-privilege.

## Certification report

`make certify` produces `out/certification-report.json` (machine-readable, gates
CI) plus a human summary. Checks: chain-to-root, lifecycle, OCSP/CRL, HA failover,
rollback.
