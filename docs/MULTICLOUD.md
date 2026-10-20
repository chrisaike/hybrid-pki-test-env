# Multi-Cloud Design

The environment is cloud-portable by construction: each Terraform module exposes
a **cloud-agnostic contract** (identical `variables.tf` + `outputs.tf`), and the
module *body* is cloud-specific. The environment composition
(`infra/envs/<cloud>-dev`) selects which implementation to use. Switching clouds
means changing **one `source =` line**, because the contract never changes.

```
infra/modules/service/
├── aws/     # IMPLEMENTED — ECS Fargate + ALB
├── azure/   # STUB       — Container Apps/VMSS + Load Balancer/App Gateway
└── gcp/     # STUB       — Cloud Run/MIG + Cloud Load Balancing
```

## The "service" contract

| Input | Meaning |
|-------|---------|
| `name` | logical service name |
| `image` | container image for the PKI replicas |
| `replicas` | replica count (validated `>= 2` for HA) |
| `port` / `health_path` | listener + health check |
| `env` | environment variables |
| networking | `vpc_id`/`subnets` (AWS), `subnet_id` (Azure), `project`/`region` (GCP) |

| Output | Meaning |
|--------|---------|
| `service_url` | base URL of the load-balanced PKI service |
| `lb_dns_name` | load balancer DNS name |

## Resource equivalence (AWS → Azure → GCP)

| Logical | AWS (implemented) | Azure | GCP |
|---------|-------------------|-------|-----|
| Compute (replicas) | ECS Fargate service | Container Apps / VMSS | Cloud Run / MIG |
| Load balancer | Application Load Balancer | Azure LB / App Gateway | Cloud Load Balancing |
| Health check | ALB target-group health check | LB health probe | Backend-service health check |
| Network isolation | Security Group | Network Security Group | VPC firewall rule |
| Image registry | ECR | ACR | Artifact Registry |
| Secrets | Secrets Manager | Key Vault | Secret Manager |
| Object store (CRL/AIA) | S3 + CloudFront | Blob + CDN | GCS + Cloud CDN |
| Status store | RDS / DynamoDB | Azure SQL / Cosmos DB | Cloud SQL / Firestore |
| HSM (prod) | CloudHSM | Key Vault Managed HSM | Cloud HSM |
| DNS | Route 53 | Azure DNS | Cloud DNS |
| Scheduler (teardown) | EventBridge + Lambda | Logic Apps / Automation | Cloud Scheduler + Functions |

## How to target another cloud

In `infra/envs/aws-dev/main.tf`:

```hcl
module "pki" {
  source = "../../modules/service/aws"   # <- change to .../azure or .../gcp
  name        = "pki-test"
  image       = var.image
  replicas    = var.replicas
  port        = 8080
  health_path = "/healthz"
  # ...cloud-specific networking inputs...
}
```

Because the AWS, Azure, and GCP modules share the contract, the rest of the
composition and the consuming tooling (`make tf-apply`, the certification harness
pointed at `service_url`) are unchanged.

## Current status

- **AWS** — runnable (ECS Fargate + ALB, ≥2 replicas, least-privilege exec role,
  scheduled-teardown rules).
- **Azure / GCP** — contract-complete **stubs** with the resource map above; drop
  in the documented resources to make them runnable without touching callers.
