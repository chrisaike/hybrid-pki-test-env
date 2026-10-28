# AWS Services Inventory — All-in-Cloud vs. Hybrid

> Two tiers:
> **(A) All-in-cloud (AWS-only)** — everything needed to stand up the full
> production-representative PKI test environment in AWS for the first test.
> **(B) Hybrid add-ons** — the *additional* services required to connect the AWS
> environment to on-prem/VA (and keep the door open to other clouds) in the
> follow-on phase.
>
> Planning artifact only — no resources are provisioned here.

---

## A. All-in-cloud architecture (AWS-only, Phase A–D)

### A1. Foundation & networking
| Service | Purpose in this environment | Notes |
|---------|-----------------------------|-------|
| AWS Organizations / dedicated **Account** | Hard isolation of the PKI TEST environment from production | Separate account preferred |
| **IAM** (roles, policies) + **IAM Identity Center** | Least-privilege access per workstream; human SSO | No long-lived keys |
| **VPC** | Network boundary: public / private / isolated subnets across ≥2 AZs | Multi-AZ for HA |
| **Subnets, Route Tables, Internet/NAT Gateways** | Connectivity + egress control | NAT only during active test windows (cost) |
| **VPC Endpoints** (S3, Secrets Manager, ECR, CloudWatch, KMS) | Keep traffic on the AWS backbone; reduce NAT cost/exposure | Interface + gateway endpoints |
| **Security Groups / NACLs** | Micro-segmentation of PKI service traffic | |
| **Route 53** (private hosted zone) | Internal DNS (`pki.test.`) for services, AIA/CDP hostnames | |

### A2. Key management & cryptography
| Service | Purpose | Notes |
|---------|---------|-------|
| **AWS CloudHSM** | FIPS 140-2/3 HSM for CA key generation + PKCS#11 signing; mirrors production HSM call path | Multi-AZ cluster; Root key offline posture |
| **AWS KMS** | Envelope encryption for secrets, state, S3/EBS; CMKs per workstream | |
| **AWS Secrets Manager** | HSM PINs, service config, DB creds | Never in code |
| **AWS Private CA (ACM PCA)** *(decision point)* | Managed CA alternative/complement to self-managed CA software | Evaluate vs. self-managed in Sprint 4 |
| **AWS Certificate Manager (ACM)** | TLS certs for the ALB/edge of the test services | Separate from the test CA hierarchy |

### A3. Compute & platform
| Service | Purpose | Notes |
|---------|---------|-------|
| **Amazon ECS on Fargate** *(primary)* or **Amazon EKS** | Run PKI services (CA core, OCSP, enrollment, Venafi-shaped API) as ≥2 replicas/AZ | Fargate = less ops; EKS if k8s standard required |
| **Amazon ECR** | Container image registry for the PKI service images | Image scanning on push |
| **Application Load Balancer (ALB)** / **NLB** | Health-checked, multi-AZ load balancing + HA | ALB for HTTP(S); NLB if raw TCP needed |
| **Auto Scaling** (ECS service autoscaling) | Scale issuing/OCSP under load (feeds Priority-2 capacity tests) | Target-tracking policies |

### A4. Data, state & distribution
| Service | Purpose | Notes |
|---------|---------|-------|
| **Amazon RDS** or **DynamoDB** | Certificate lifecycle status store (issued/renewed/revoked) | Multi-AZ; choice recorded in Sprint 5/6 |
| **Amazon S3** | CRL + AIA artifacts, certification reports, Terraform state | Versioned, encrypted |
| **Amazon CloudFront** | Public, cached distribution of CRL/AIA endpoints | Low-latency revocation lookups |
| **Amazon DynamoDB** (lock table) | Terraform state locking | Pairs with S3 backend |

### A5. Automation & delivery (IaC + CI/CD)
| Service | Purpose | Notes |
|---------|---------|-------|
| **Terraform** (on S3/DynamoDB backend) | All infrastructure as code; on-demand spin-up/tear-down | Core to the cost story |
| **GitHub Actions** *(current)* or **CodePipeline/CodeBuild** | Build, test, certify, and apply/destroy pipelines | CI already in repo |
| **Amazon EventBridge** + **AWS Lambda** | Scheduled teardown / scale-to-zero of idle environments | Cost control |
| **AWS Step Functions** *(optional)* | Orchestrate multi-stage spin-up/certify/tear-down | If flow grows |

### A6. Security, governance & observability
| Service | Purpose | Notes |
|---------|---------|-------|
| **AWS CloudTrail** | Full API audit trail (control-plane evidence) | Org/account level |
| **Amazon CloudWatch** (Logs, Metrics, Alarms, Dashboards) | Service logs, issuance/OCSP latency + throughput metrics, alarms | Feeds capacity assessment |
| **AWS Config** | Resource compliance + drift detection | Guardrails |
| **Amazon GuardDuty** + **AWS Security Hub** | Threat detection + security posture aggregation | Baseline from Sprint 2 |
| **AWS Budgets** + **Cost Explorer** + **cost-allocation tags** | Enforce the near-zero-idle-cost goal; per-workstream cost visibility | Alarms from Sprint 1 |
| **AWS WAF** *(optional)* | Protect public edge (CRL/AIA, enrollment) | If exposed publicly |

### A7. Capacity assessment support (Priority 2)
| Service | Purpose | Notes |
|---------|---------|-------|
| **CloudWatch** + **Synthetics** | Latency/throughput measurement + canaries for issuance/validation | SLO tracking |
| **Load generation** (Fargate tasks / **AWS Distributed Load Testing** solution) | Drive peak-load and soak tests | Repeatable harness |
| **Amazon Athena** *(optional)* | Query S3-stored test/metric data for the recommendation memo | Evidence reporting |

---

## B. Hybrid add-ons (Phase F — connect AWS ↔ on-prem/VA)

> These are **in addition to** everything in Section A. They provide private
> connectivity, cross-boundary identity/DNS, and trust bridging.

### B1. Connectivity (AWS ↔ VA / on-prem)
| Service | Purpose | Notes |
|---------|---------|-------|
| **AWS Direct Connect** | Dedicated private, high-throughput link to the VA data center | Preferred for production-like realism; lead time — start procurement early |
| **AWS Site-to-Site VPN** | Encrypted IPsec tunnel (standalone or Direct Connect backup) | Faster to stand up than DX |
| **AWS Transit Gateway** | Hub for routing between VPC(s), VPN, and Direct Connect | Scales multi-VPC / multi-account |
| **Direct Connect Gateway** | Associate DX with VPCs across regions/accounts | With Transit Gateway |
| **Customer Gateway** | Represents the on-prem VPN endpoint | For VPN |

### B2. Cross-boundary DNS & identity
| Service | Purpose | Notes |
|---------|---------|-------|
| **Route 53 Resolver (inbound/outbound endpoints)** + **Resolver Rules** | Resolve on-prem AD domains from AWS and vice-versa | Required for AD/GPO enrollment |
| **AD Connector** or **AWS Managed Microsoft AD** | Interface to the real VA Active Directory for auto-enrollment | AD Connector proxies to on-prem AD; Managed AD if a bridged forest is used |
| **IAM Identity Center** (external IdP federation) | Federated human access across the hybrid boundary | Optional |

### B3. Trust bridging & key custody (hybrid)
| Service / mechanism | Purpose | Notes |
|---------------------|---------|-------|
| **On-prem HSM ↔ CloudHSM trust bridge** | Cross-sign or anchor bridging between on-prem and cloud trust | Design decision in Phase F |
| **AWS Private CA cross-account/cross-env sharing** (**RAM**) | Share CA across accounts/boundaries if ACM PCA is chosen | Via AWS Resource Access Manager |
| **AWS RAM** | Share subnets/CA/TGW across accounts for the hybrid topology | |

### B4. Monitoring across the boundary
| Service | Purpose | Notes |
|---------|---------|-------|
| **CloudWatch cross-account/region** + on-prem agent | Unified view of hybrid trust-path latency/health | |
| **VPC Reachability Analyzer / Network Manager** | Validate and troubleshoot the hybrid routing/firewall paths | |

### B5. Multi-cloud portability (optional, later)
> Kept portable via the contract-based IaC modules already in the repo. If
> prioritized, the Azure/GCP equivalents map as follows (no AWS change required
> to the callers):

| Logical | AWS | Azure | GCP |
|---------|-----|-------|-----|
| Compute | ECS Fargate | Container Apps | Cloud Run |
| Load balancer | ALB | Azure LB / App Gateway | Cloud Load Balancing |
| HSM | CloudHSM | Key Vault Managed HSM | Cloud HSM |
| Secrets | Secrets Manager | Key Vault | Secret Manager |
| Object store | S3 + CloudFront | Blob + CDN | GCS + Cloud CDN |
| Status store | RDS / DynamoDB | Azure SQL / Cosmos | Cloud SQL / Firestore |
| Private link | Direct Connect / VPN | ExpressRoute / VPN | Cloud Interconnect / VPN |

---

## C. Minimum vs. full footprint

**Minimum viable test (fastest path to a certified AWS baseline):**
VPC + IAM + CloudHSM (or simulated-HSM parity) + ECS Fargate + ALB + S3 +
DynamoDB/RDS + Secrets Manager + KMS + CloudWatch + CloudTrail + Terraform
state (S3/DynamoDB).

**Full footprint (production-representative):** add CloudFront, Route 53, AWS
Config, GuardDuty/Security Hub, EventBridge+Lambda teardown, ACM, autoscaling,
WAF, and the capacity-test tooling.

**Hybrid:** add Direct Connect/VPN, Transit Gateway, Route 53 Resolver, AD
Connector/Managed AD, and the trust-bridge mechanism.

## D. Cost drivers to watch (for the IaC teardown story)
- **CloudHSM** (per-HSM-hour) — the largest driver; run during certification
  windows, tear down between runs; use simulated-HSM parity for routine iteration.
- **NAT Gateway** and **Direct Connect** (hourly + data) — minimize/standby when idle.
- **ALB / RDS always-on** — prefer ephemeral; scale-to-zero via EventBridge+Lambda.
- Everything carries cost-allocation tags; Budgets alarms guard the near-zero-idle goal.
