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

## Status

- Implemented: RSA + ECDSA across all CA tiers, verified by the certification
  harness (the current hierarchy mixes ECDSA root/intermediate with an RSA
  issuing CA, proving the mixed-algorithm path).
- Documented + ready: the provider-selection seam above. Wiring a concrete PQC
  provider is the remaining step and is intentionally isolated to the `hsm`
  backend.
