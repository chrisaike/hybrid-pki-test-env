# Azure implementation STUB of the cloud-agnostic "service" contract.
#
# Same inputs/outputs as infra/modules/service/aws. Fill in with Azure Container
# Apps (or VMSS) + Azure Load Balancer / Application Gateway. The resource map
# below documents the 1:1 equivalence used when porting from AWS.
#
#   AWS                         Azure
#   ---                         -----
#   ECS Fargate service    ->   Azure Container App / VMSS
#   Application Load Bal.  ->   Azure Load Balancer / Application Gateway
#   Target group + health  ->   Backend pool + health probe
#   Security group         ->   Network Security Group
#   ECS task def (image)   ->   Container App template (image)
#
# Because the CONTRACT (variables.tf + outputs.tf) is identical to the AWS
# module, the environment composition references this module without any other
# change to switch clouds.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

# resource "azurerm_container_app" "this" { ... desired_count = var.replicas ... }
# resource "azurerm_lb" "this"            { ... }
# resource "azurerm_lb_probe" "health"    { request_path = var.health_path }

# TODO: implement. Contract outputs are provided below as placeholders so the
# module type-checks and the composition stays cloud-portable.
