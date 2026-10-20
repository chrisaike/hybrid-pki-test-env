# Architecture & Component Walk-Through

A guided tour of how the environment is built and why. Read this with
`.kiro/specs/hybrid-pki-test-env/design.md` for the full design.

## Layering (the big idea)

Everything depends on **one narrow interface** — a `crypto.Signer` produced by an
`hsm.Token`. That single seam is what makes the system both *simulatable* (swap
the HSM backend) and *crypto-agile* (swap the key provider):

```
cmd/pkitool  cmd/pkiserver  cmd/certify        <- entry points
        \          |            /
          internal/service                     <- issue / renew / revoke lifecycle
         /         |          \
internal/ca   internal/revocation  internal/store
     |            (OCSP + CRL)                  <- x509, status
internal/hsm.Token  <- crypto.Signer           <- the ONE seam
     |
 provider registry: rsa | ecdsa | ed25519 | (mldsa* via -tags pqc)
```

Nothing above `hsm.Token` knows whether keys live in SoftHSM, a real HSM, or
which algorithm they use. That is the entire point: production swaps the backend,
not the business logic.

## Request flow: enrolling a certificate

```
client ──POST /v1/certificates/request {csr, profile}──▶ httpapi.handleEnroll
                                                             │
                                               service.Enroll(csrPEM, profile)
                                                             │
                                   ca.Issue(csr, profile, profiles)   ── enforces profile allow-list
                                                             │          ── stamps AIA/CDP from issuing CA
                                   token.Signer(issuingSlot) ─ crypto.Signer (RSA/ECDSA/Ed25519)
                                                             │
                                   x509.CreateCertificate(...)
                                                             │
                                   store.Put(record: valid) ─ lifecycle state
                                                             ▼
client ◀──201 {id, serial, certificate, chain}──────────────┘
```

Revocation walks the same spine: `service.Revoke` → `store.Revoke` →
`crl.Publish()` regenerates the signed CRL, and the OCSP responder reads the same
store.

## Walk-through 1: the OCSP responder (wire format)

File: `internal/revocation/ocsp.go`. Go's stdlib has **no** OCSP package
(`golang.org/x/crypto/ocsp` is external and unavailable offline), so the
responder implements RFC 6960 directly with `encoding/asn1`. This is also a more
faithful exercise of the production wire path.

**Parsing the request** — an `OCSPRequest` is a nested ASN.1 SEQUENCE. We unmarshal
just enough to pull the requested serial(s):

```
OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
TBSRequest  ::= SEQUENCE { requestList SEQUENCE OF Request }
Request     ::= SEQUENCE { reqCert CertID }
CertID      ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
```

`ParseRequestSerials` returns the serials; we look each up in the status store.

**Building the response** — a `BasicOCSPResponse` whose `tbsResponseData` we sign
with the issuing CA key:

```
tbsResponseData  = { responderID (byName), producedAt, responses[singleResponse] }
singleResponse   = { certID, certStatus (good|revoked|unknown), thisUpdate, nextUpdate }
BasicOCSPResponse= { tbsResponseData, signatureAlgorithm, signature, certs[issuer] }
OCSPResponse     = { responseStatus=successful, responseBytes{ id-pkix-ocsp-basic, BasicOCSPResponse } }
```

Three subtleties worth noting:
1. **CertID hashes** — `issuerNameHash` is SHA-1 over the issuer's RawSubject and
   `issuerKeyHash` is SHA-1 over the issuer SPKI (RFC 6960 default).
2. **certStatus is a CHOICE** — `good` is context tag [0] (empty), `revoked` is
   [1] carrying the revocation time. We emit these as `asn1.RawValue`s.
3. **Signature algorithm follows the KEY, not the issuer cert** — the issuing CA
   cert is signed by the intermediate (possibly a different algorithm), so we
   pick the OCSP signature OID from the issuing key type (`sigAlg()`), including
   the Ed25519 case (hash = `crypto.Hash(0)`, sign the message directly).

That third point is the same class of bug the test suite caught for CRLs — a good
reminder that "signed by X" and "has X's algorithm" are different things in a
multi-tier hierarchy.

## Walk-through 2: the multi-cloud contract pattern

Directory: `infra/`. The goal is "switch cloud = change one line," achieved with
**contract-identical modules**:

```
infra/modules/service/
├── aws/     variables.tf  outputs.tf  main.tf   (ECS Fargate + ALB — implemented)
├── azure/   variables.tf  outputs.tf  main.tf   (Container Apps + LB — stub)
└── gcp/     variables.tf  outputs.tf  main.tf   (Cloud Run + CLB — stub)
```

`variables.tf` and `outputs.tf` are **the same shape in all three** — that is the
contract:

```
inputs : name, image, replicas(>=2), port, health_path, env, <networking>
outputs: service_url, lb_dns_name
```

The environment composition (`infra/envs/aws-dev/main.tf`) wires the contract:

```hcl
module "pki" {
  source   = "../../modules/service/aws"   # change to .../azure or .../gcp
  name     = "pki-test"
  image    = var.image
  replicas = var.replicas                  # validated >= 2 for HA
  # ...
}
```

Because the contract never changes, the rest of the composition, the `make
tf-apply/destroy` targets, and the certification harness (which just hits
`service_url`) are cloud-agnostic. `docs/MULTICLOUD.md` carries the full AWS →
Azure → GCP resource-equivalence table. The `replicas >= 2` validation is encoded
in every module so HA (Requirement 6) can't be accidentally violated on any
cloud.

## Walk-through 3: the simulated HSM (fail-closed)

File: `internal/hsm/hsm.go`. `SoftHSMBackend` models a PKCS#11 token:

- `OpenSlot(slot, pin)` = `C_OpenSession` + `C_Login`. Wrong/absent PIN → error.
- `GenerateKey` / `Signer` on a slot that was never opened → `errFailClosed`
  (Requirement 2.4: *no silent fallback to file keys*). The unit test
  `TestFailClosedWithoutLogin` asserts exactly this.
- Keys persist per slot (`slot-<label>.key.json`) to model an HSM retaining key
  material across restarts.

Production swap: replace `SoftHSMBackend` with a cgo PKCS#11 backend pointed at
CloudHSM / Key Vault Managed HSM / Cloud HSM. The `Token` interface and every
caller stay the same.

## Walk-through 4: the certification harness

Files: `internal/certify/`, `cmd/certify/`. `certify.Run` spins up an ephemeral
environment in a temp dir and runs five check groups mapped to Requirement 9,
then emits:

- **JSON** (`certification-report.json`) — each check with its requirement id.
- **JUnit XML** (`certification-report.xml`) — checks grouped by requirement as
  the `classname`, consumable by Jenkins/GitLab/GitHub Actions test reporters.

The command exits non-zero if any check fails, so it gates CI/CD — this is what
turns the environment into a reusable *certification service* for PKI changes,
migrations, OEM products, and rollback plans.

## Where to look next

| I want to… | Start here |
|------------|-----------|
| Change the hierarchy | `config/hierarchy.yaml` + `make issue` |
| Understand issuance/profiles | `internal/ca/issue.go` |
| Understand OCSP/CRL | `internal/revocation/` |
| Add a cloud | `infra/modules/service/<cloud>` (match the contract) |
| Add an algorithm (incl. PQC) | `internal/hsm/provider.go` + `docs/PQC.md` |
| Run a certification | `make certify` |
