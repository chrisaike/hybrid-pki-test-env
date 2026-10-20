# Contract outputs — same names as AWS so composition is portable.
# Placeholder values until the Azure resources are implemented.
output "service_url" {
  value       = "http://TODO-azure-lb"
  description = "Base URL of the load-balanced PKI service (STUB)."
}
output "lb_dns_name" {
  value       = "TODO-azure-lb"
  description = "Load balancer DNS name (STUB)."
}
