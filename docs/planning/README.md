# Planning — Cloud-First (AWS) Hybrid PKI Test & Certification Environment

Planning artifacts for the scope change: **the first test runs entirely in the
cloud on AWS**, then extends to hybrid (on-prem/VA) afterward. No implementation
here — these are the plan, the picture, and the parts list.

| # | Deliverable | File |
|---|-------------|------|
| Task 1 | Project plan in **2-week sprints** (Phases A–F, 14 sprints) with milestones, RACI, risks, cost control | [`01-project-plan.md`](01-project-plan.md) |
| Task 2 | **Architecture diagram** for leadership — AWS all-in + hybrid extension + trust chain | [`02-architecture.md`](02-architecture.md) (Mermaid) · [`diagram.html`](diagram.html) (standalone, zoomable) |
| Task 3 | **AWS services inventory** — all-in-cloud vs. hybrid add-ons, with cost drivers | [`03-aws-services.md`](03-aws-services.md) |

## How these fit together

- **Priority 1** (build the representative test environment) is delivered across
  Phases A–D (Sprints 1–10), ending in a certified, on-demand AWS environment.
- **Priority 2** (near-term capacity assessment) is Phase E (Sprints 11–12),
  producing an evidence-based recommendation for VA leadership.
- **Hybrid** connectivity to VA/on-prem is Phase F (Sprints 13–14), gated behind
  a certified AWS baseline so it never blocks the first test.

## For the leadership review

1. Open **`diagram.html`** (no setup — self-contained) to walk the architecture.
2. Use **`01-project-plan.md`** for the sprint roadmap and milestones.
3. Use **`03-aws-services.md`** for scope/cost of the AWS build vs. the hybrid step.
