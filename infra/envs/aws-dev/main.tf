# AWS-dev environment composition.
#
# Wires the cloud-agnostic "service" module (AWS implementation) to run the PKI
# replicas behind an ALB with >= 2 replicas (HA). To target another cloud, point
# the module source at infra/modules/service/azure or .../gcp — the contract is
# identical, so nothing else changes here.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# --- networking (uses the default VPC for a low-friction dev env) ---
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Least-privilege ECS task execution role.
resource "aws_iam_role" "exec" {
  name = "pki-test-ecs-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "exec" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- the PKI service (HA: >= 2 replicas behind an ALB) ---
module "pki" {
  source = "../../modules/service/aws" # swap to .../azure or .../gcp to change cloud

  name               = "pki-test"
  image              = var.image
  replicas           = var.replicas
  port               = 8080
  health_path        = "/healthz"
  vpc_id             = data.aws_vpc.default.id
  subnets            = data.aws_subnets.default.ids
  execution_role_arn = aws_iam_role.exec.arn

  env = {
    REPLICA_ID = "cloud"
  }
}
