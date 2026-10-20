# Cloud-agnostic "service" module CONTRACT (AWS implementation).
# Azure and GCP implementations expose the SAME variables + outputs so the
# environment composition is cloud-portable.

variable "name" {
  type        = string
  description = "Logical service name (e.g. pki-issuing)."
}

variable "image" {
  type        = string
  description = "Container image for the PKI replicas."
}

variable "replicas" {
  type        = number
  default     = 2
  description = "Replica count (>= 2 for HA)."
  validation {
    condition     = var.replicas >= 2
    error_message = "HA requires at least 2 replicas (Requirement 6.1)."
  }
}

variable "port" {
  type    = number
  default = 8080
}

variable "health_path" {
  type    = string
  default = "/healthz"
}

variable "env" {
  type    = map(string)
  default = {}
}

variable "vpc_id" {
  type = string
}

variable "subnets" {
  type = list(string)
}

variable "cpu" {
  type    = string
  default = "256"
}

variable "memory" {
  type    = string
  default = "512"
}

variable "execution_role_arn" {
  type        = string
  description = "ECS task execution role ARN (least-privilege)."
}
