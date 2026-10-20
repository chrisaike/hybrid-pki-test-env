# Contract outputs (identical across clouds).

output "service_url" {
  value       = "http://${aws_lb.this.dns_name}"
  description = "Base URL of the load-balanced PKI service."
}

output "lb_dns_name" {
  value       = aws_lb.this.dns_name
  description = "Load balancer DNS name."
}
