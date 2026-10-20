# Contract outputs — same names as AWS so composition is portable.
output "service_url" {
  value       = "http://TODO-gcp-lb"
  description = "Base URL of the load-balanced PKI service (STUB)."
}
output "lb_dns_name" {
  value       = "TODO-gcp-lb"
  description = "Load balancer DNS name (STUB)."
}
