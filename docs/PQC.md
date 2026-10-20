# Post-Quantum / Hybrid Cryptography Readiness

The environment supports **classical** crypto today (RSA 2048/3072/4096, ECDSA
P-256/P-384/P-521) and is structured so a future **post-quantum (PQC)** or
**hybrid** crypto change can be *certified here first* — which is one of the main
reasons this test environment exists (de-risking high-impact crypto changes).

## Integration point

All key generation and signing flow through **one interface** — `hsm.Token` in
`internal/hsm`. The CA hierarchy (`internal/ca`) never calls a crypto primitive
directly; it asks the token for a `crypto.Signer`. This single seam is where PQC
plugs in:

```
config/hierarchy.yaml   ->  key.type: "mldsa65" (future)
        |
internal/hsm.Token      ->  GenerateKey(slot, keyType, ...) returns crypto.Signer
        |
internal/ca             ->  x509.CreateCertificate(..., signer)   # unchanged
```

Because issuance and the hierarchy are expressed in terms of `crypto.Signer` and
`x509`, adding a PQC algorithm is a **backend/provider swap**, not a redesign.

## How to certify a PQC change

1. **Provider**: build the services against an OpenSSL 3 + `oqs-provider`
   toolchain (ML-DSA / Dilithium, ML-KEM / Kyber) or a Go PQC signer that
   satisfies `crypto.Signer`.
2. **Config**: set `crypto.pqc_ready: true` and the CA `key.type` to the PQC (or
   hybrid classical+PQC) algorithm in `config/hierarchy.yaml`.
3. **Issue**: `make issue` rebuilds the hierarchy using the PQC provider through
   the same `hsm.Token` seam.
4. **Certify**: `make certify` re-runs the full battery (chain-to-root,
   lifecycle, OCSP/CRL, HA, rollback) against the PQC hierarchy and produces a
   pass/fail certification report — exactly the rollback-safe, production-
   representative validation this environment is for.

## Hybrid certificates

For a classical+PQC **hybrid** certificate strategy (dual signatures / composite
keys), the same seam applies: the token returns a composite signer and the
issuing templates carry both algorithms. Model it in `hierarchy.yaml`, issue, and
certify — no change to the control flow.

## The provider registry (implemented)

`internal/hsm/provider.go` holds a `KeyProvider` registry — the single
crypto-agility seam. Built-in providers:

| Key type | Algorithm family | Status |
|----------|------------------|--------|
| `rsa` | RSA (2048/3072/4096) | built in |
| `ecdsa` | ECDSA (P-256/384/521) | built in |
| `ed25519` | EdDSA (Ed25519) | built in |
| `mldsa44` / `mldsa65` / `mldsa87` | ML-DSA / Dilithium (FIPS 204) | registered under `-tags pqc`, binding pending |

Adding an algorithm is one `RegisterProvider(keyType, fn)` call; the CA
hierarchy, issuance, OCSP, and CRL code are untouched because they depend only on
`crypto.Signer`.

## Proof the seam works (automated)

`internal/certify/agility_test.go` builds an **entirely Ed25519 hierarchy** — a
third algorithm family added purely by provider registration — and certifies it
end-to-end (chain-to-root, issue, OCSP good→revoked, CRL contents). This
demonstrates the exact path an ML-DSA change will take: register the provider,
set `key.type`, re-run `make certify`.

## ML-DSA (PQC) wiring

`internal/hsm/provider_pqc.go` (build tag `pqc`) already registers the three
ML-DSA parameter sets at the seam. The one remaining step is to link a concrete
signer in `newMLDSASigner` — either:

- an **oqs-provider** cgo binding returning a `crypto.Signer`, plus the FIPS-204
  X.509 marshalling (SPKI + signature OIDs), or
- a **pure-Go** FIPS-204 implementation.

Build and certify a PQC hierarchy with:

```bash
go build -tags pqc ./...
# set key.type: mldsa65 in config/hierarchy.yaml
make certify
```

## Status summary

- **Implemented + verified**: RSA, ECDSA, and Ed25519 across all CA tiers. The
  default hierarchy mixes ECDSA root/intermediate with an RSA issuing CA, and the
  agility test runs a full Ed25519 hierarchy — both certified by the harness.
- **Wired, binding pending**: ML-DSA (`-tags pqc`) registration is complete; only
  the concrete signer in `newMLDSASigner` remains, isolated to the `hsm` backend.
