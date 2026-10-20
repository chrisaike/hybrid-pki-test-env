# GCP implementation STUB of the cloud-agnostic "service" contract.
#
# Same inputs/outputs as infra/modules/service/aws. Fill in with Cloud Run (or a
# Managed Instance Group) + Cloud Load Balancing. Resource map:
#
#   AWS                         GCP
#   ---                         ---
#   ECS Fargate service    ->   Cloud Run service / MIG
#   Application Load Bal.  ->   Cloud Load Balancing (HTTPS LB)
#   Target group + health  ->   Serverless NEG + health check
#   Security group         ->   VPC firewall rules
#   ECS task def (image)   ->   Cloud Run container (image)
#
# Contract (variables.tf + outputs.tf) is identical to the AWS module, so the
# environment composition switches clouds by referencing this module.

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

# resource "google_cloud_run_v2_service" "this" { ... scaling { min_instance_count = var.replicas } }
# resource "google_compute_region_network_endpoint_group" "neg" { ... }
# resource "google_compute_backend_service" "this" { health_checks = [...] }

# TODO: implement. Contract outputs provided below as placeholders.
