# Architecture — Cloud-First (AWS) Hybrid PKI Test & Certification Environment

> For leadership. Two views: **(1) target AWS all-in architecture** (what we build
> first) and **(2) hybrid extension** (how on-prem/VA connects afterward).
> Diagrams render on GitHub (Mermaid). A standalone, zoomable HTML/SVG version is
> in `diagram.html` for presentations.

---

## View 1 — AWS all-in test environment (Phase A–D)

```mermaid
flowchart TB
    subgraph Testers["Testers / CI-CD"]
      T1["PKI engineers<br/>& certification harness"]
    end

    subgraph AWS["AWS — dedicated PKI TEST account (multi-AZ)"]
      direction TB

      subgraph Edge["Edge / DNS"]
        R53["Route 53<br/>private zone pki.test."]
        CF["CloudFront<br/>(CRL/AIA distribution)"]
      end

      subgraph Net["VPC (≥2 AZs): public / private / isolated subnets"]
        ALB["Application Load Balancer<br/>(health-checked, multi-AZ)"]

        subgraph App["ECS Fargate services (≥2 replicas / AZ, autoscaled)"]
          VEN["Venafi-shaped<br/>lifecycle API"]
          EST["EST / SCEP<br/>enrollment surface"]
          CA["CA core<br/>(issuing signer)"]
          OCSP["OCSP responder"]
        end

        subgraph Data["Data & state (multi-AZ)"]
          DB["Status store<br/>(RDS / DynamoDB)"]
          S3["S3<br/>(CRL, AIA, artifacts)"]
        end
      end

      subgraph KeyMgmt["Key management"]
        HSM["CloudHSM cluster<br/>(multi-AZ, PKCS#11)"]
        KMS["KMS<br/>(envelope keys)"]
        SM["Secrets Manager<br/>(PINs, config)"]
      end

      subgraph Gov["Security & observability"]
        CT["CloudTrail"]
        CW["CloudWatch<br/>(logs/metrics/alarms)"]
        CFG["AWS Config"]
        GD["GuardDuty / Security Hub"]
      end
    end

    T1 -->|HTTPS| R53 --> ALB
    ALB --> VEN & EST & OCSP
    VEN --> CA
    EST --> CA
    CA -->|PKCS#11 sign| HSM
    OCSP --> DB
    CA --> DB
    CA -->|publish CRL/AIA| S3 --> CF
    KMS -. envelope .- SM
    App -. secrets .- SM
    App -. logs .- CW
    AWS -. audit .- CT
```

**Root CA posture:** the Root CA key is held offline (dedicated CloudHSM
partition / exported-and-stored), used only to sign Intermediates and the Root
CRL — never attached to an online issuing service.

### Trust-chain logical view

```mermaid
flowchart LR
    Root["Root CA<br/>(offline, CloudHSM)"] --> Int["Intermediate CA<br/>(CloudHSM)"]
    Int --> Iss["Issuing CA<br/>(online, CloudHSM)"]
    Iss --> Leaf["End-entity leaf<br/>(TLS / client / device)"]
    Leaf -. AIA/CDP .-> OCSP["OCSP responder"]
    Leaf -. AIA/CDP .-> CRL["CRL (S3 + CloudFront)"]
```

### Certificate request flow

```mermaid
sequenceDiagram
    participant C as Client / Venafi API
    participant LB as ALB
    participant S as Lifecycle API
    participant CA as CA core
    participant H as CloudHSM
    participant DB as Status store
    C->>LB: enroll (CSR, profile)
    LB->>S: route (health-checked)
    S->>S: validate profile (allow-list)
    S->>CA: issue
    CA->>H: sign via PKCS#11
    H-->>CA: signature
    CA->>DB: record (valid) + stamp AIA/CDP
    CA-->>C: certificate + chain
```

---

## View 2 — Hybrid extension (Phase F, follow-on)

```mermaid
flowchart LR
    subgraph OnPrem["VA / On-prem data center"]
      AD["Active Directory<br/>+ GPO auto-enroll"]
      ONHSM["On-prem HSM<br/>(optional trust bridge)"]
      LEGACY["Existing PKI<br/>consumers"]
    end

    subgraph Link["Private connectivity"]
      DX["Direct Connect<br/>/ Site-to-Site VPN"]
    end

    subgraph AWS["AWS PKI TEST environment (View 1)"]
      PKI["PKI services<br/>(CA / OCSP / CRL / enroll)"]
      HSM["CloudHSM"]
    end

    AD <-->|LDAP/enroll over private link| DX
    LEGACY <-->|validation/issuance| DX
    ONHSM -. trust-anchor bridge .- DX
    DX <--> PKI
    PKI --- HSM
```

**Hybrid note:** in Phase A–D everything runs in AWS and the AD/GPO interface is a
stubbed enrollment surface. In Phase F we connect the real VA AD over Direct
Connect/VPN and certify the cross-environment path against the same harness.

---

## Deployment topology (resilience)

- **Multi-AZ** for ALB, ECS services, CloudHSM, and data stores.
- **Autoscaling** on the issuing/OCSP/enrollment services.
- **Ephemeral by IaC:** the whole stack is `terraform apply`/`destroy`; scheduled
  teardown returns idle cost to ≈ $0.

## How to present this to leadership

1. Open `diagram.html` (standalone, no dependencies) for a clean, zoomable visual.
2. Lead with **View 1** (what we build first — all AWS).
3. Use **View 2** to show the hybrid future without implying it blocks the first
   test.
4. Pair with `01-project-plan.md` (the 2-week sprint roadmap) and
   `03-aws-services.md` (the services inventory + cost drivers).
