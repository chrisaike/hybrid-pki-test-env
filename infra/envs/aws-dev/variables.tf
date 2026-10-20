variable "region" {
  type    = string
  default = "us-east-1"
}

variable "image" {
  type        = string
  description = "Container image for the PKI replicas (push the repo Dockerfile to ECR)."
  default     = "PUSH_YOUR_IMAGE_TO_ECR"
}

variable "replicas" {
  type    = number
  default = 2 # HA
}
