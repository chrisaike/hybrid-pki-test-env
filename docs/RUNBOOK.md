# Runbook — Hybrid PKI Test & Certification Environment

Operational procedures for spinning up, certifying, and tearing down the
environment, plus the rollback drill.

## 1. Spin up (local, zero cost)

```bash
make issue          # build CA hierarchy from config/hierarchy.yaml -> ./out
make build          # build pkitool / pkiserver / certify
./bin/pkiserver --addr :8080 --replica r1 &
./bin/pkiserver --addr :8081 --replica r2 &
```

Trust anchor for clients: `out/ca-bundle.pem`.

## 2. Spin up (local HA via Docker Compose)

```bash
make compose-up     # nginx LB :8080 -> r1, r2 (shared CA + status store)
curl localhost:8080/healthz
make compose-down
```

## 3. Spin up (cloud, AWS)

```bash
# 1. build + push the image to ECR, set var.image
# 2. provision
make tf-init  CLOUD=aws
make tf-apply CLOUD=aws
terraform -chdir=infra/envs/aws-dev output service_url
```

Tear down (no orphaned billable resources):

```bash
make tf-destroy CLOUD=aws
```

### Scheduled teardown (cost control)

`infra/envs/aws-dev/scheduled_teardown.tf` defines EventBridge rules to scale the
service to zero at 20:00 UTC and back to `var.replicas` at 07:00 UTC on weekdays.
Attach the documented "set-desired-count" Lambda (or AWS Scheduler → ECS
`UpdateService`) to complete the automation. A full `make tf-destroy` remains the
hard teardown.

## 4. Certify a change (the core use case)

```bash
make certify
# -> human summary + out/certification-report.json (machine-readable)
# exit code != 0 if any check fails, so it gates CI/CD
```

Checks performed: chain builds & validates to Root; issue/renew/revoke lifecycle;
OCSP good/revoked; CRL contains revoked serials; HA survives one replica loss;
rollback restores prior state.

Use it to certify: PKI service updates, new PKI services, migrations,
integrations, OEM products, and **rollback plans**.

## 5. Rollback drill

The status store supports snapshot/restore, which the harness exercises
automatically. Manual drill:

1. Snapshot current trust/lifecycle state (store `Snapshot`).
2. Apply the change under test (new issuing CA, re-issue, etc.).
3. If the change fails certification, `Restore` the snapshot.
4. Re-run `make certify` to confirm the prior state is reinstated.

## 6. Re-issue the hierarchy after a config change

Edit `config/hierarchy.yaml` (key types, validities, path lengths, AIA/CDP,
profiles), then:

```bash
make issue          # re-issues without manual key handling
make certify        # re-certify the new hierarchy
```

Use `./bin/pkitool build --force` to also regenerate keys.

## 7. Simulated HSM notes

- Keys live per slot under `out/hsm/` and require a per-slot PIN (login step).
- Using a slot without a successful login **fails closed** (no file-key
  fallback) — this is intentional and mirrors production HSM behaviour.
- Override PINs with `HSM_PIN_ROOT`, `HSM_PIN_INTERMEDIATE`, `HSM_PIN_ISSUING`.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `slot not open/logged-in (fail-closed)` | Expected without login; ensure the PIN env/config is set. |
| `issue denied: unknown profile` | Profile not in `config/hierarchy.yaml`; add it or use an allowed one. |
| OCSP `unknown` | Serial not in the status store (cert not issued by this environment). |
| CRL empty after revoke | Confirm `--crl` path matches between `pkiserver` and the reader. |
