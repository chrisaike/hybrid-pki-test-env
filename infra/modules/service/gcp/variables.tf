# GCP "service" module CONTRACT — identical to the AWS module's contract.
variable "name" {
  type = string
}

variable "image" {
  type = string
}

variable "replicas" {
  type    = number
  default = 2
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

variable "project" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}
