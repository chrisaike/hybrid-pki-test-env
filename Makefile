# Hybrid PKI Test & Certification Environment — lifecycle automation.
#
# Local (zero-cost) targets drive the Go services directly. Cloud targets wrap
# Terraform for on-demand spin-up / tear-down.

SHELL := /bin/bash
OUT   := out
CONFIG := config/hierarchy.yaml
GO    := go

.PHONY: help build issue up down certify test clean fmt vet \
        tf-init tf-plan tf-apply tf-destroy compose-up compose-down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## ---------- Build ----------

build: ## Build all Go binaries into ./bin
	@mkdir -p bin
	$(GO) build -o bin/pkitool   ./cmd/pkitool
	$(GO) build -o bin/pkiserver ./cmd/pkiserver
	$(GO) build -o bin/certify   ./cmd/certify
	@echo "built: bin/pkitool bin/pkiserver bin/certify"

issue: build ## Build (or re-issue) the CA hierarchy from config/hierarchy.yaml
	./bin/pkitool build --config $(CONFIG) --out $(OUT)

## ---------- Local lifecycle (zero cost) ----------

up: build issue ## Spin up the local environment and print endpoints + trust anchor
	@echo ""
	@echo "Starting PKI test environment (local mode)."
	@echo "Run a replica:  ./bin/pkiserver --addr :8080 --replica r1"
	@echo "Run a 2nd one:  ./bin/pkiserver --addr :8081 --replica r2"
	@echo "Trust anchor:   $(OUT)/ca-bundle.pem"
	@echo "Endpoints:      /v1/certificates/*  /.well-known/est/simpleenroll  /ocsp  /crl/  /healthz"

down: ## Tear down local artifacts (stops nothing persistent; HSM keys kept unless clean)
	-pkill -f pkiserver 2>/dev/null || true
	@echo "local services stopped"

## ---------- Certification ----------

certify: build ## Run the certification harness and emit a machine-readable report
	./bin/certify --config $(CONFIG) --report $(OUT)/certification-report.json

## ---------- Quality ----------

test: ## Run all unit + integration tests
	$(GO) test ./...

fmt: ## Format code
	$(GO) fmt ./...

vet: ## Vet code
	$(GO) vet ./...

## ---------- Docker Compose (local HA topology) ----------

compose-up: ## Bring up the HA topology (LB + 2 replicas) via Docker Compose
	cd compose && docker compose up --build -d
	@echo "LB on http://localhost:8080  (health: /healthz)"

compose-down: ## Tear down the Compose topology
	cd compose && docker compose down -v

## ---------- Cloud (multi-cloud IaC) ----------

CLOUD ?= aws
TFDIR := infra/envs/$(CLOUD)-dev

tf-init: ## terraform init for the selected CLOUD env (default aws)
	cd $(TFDIR) && terraform init

tf-plan: ## terraform plan
	cd $(TFDIR) && terraform plan

tf-apply: ## Spin up cloud environment (terraform apply)
	cd $(TFDIR) && terraform apply -auto-approve

tf-destroy: ## Tear down cloud environment (terraform destroy)
	cd $(TFDIR) && terraform destroy -auto-approve

## ---------- Cleanup ----------

clean: ## Remove build + runtime artifacts (including simulated HSM keys)
	rm -rf bin $(OUT)
	@echo "cleaned"
