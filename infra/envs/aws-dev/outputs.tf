output "service_url" {
  value       = module.pki.service_url
  description = "Load-balanced PKI endpoint. Append /healthz, /v1/certificates/*, /ocsp, /crl/."
}

output "lb_dns_name" {
  value = module.pki.lb_dns_name
}
