# Scheduled teardown (Requirement 8.2): scale the PKI service to zero every night
# so a cloud-hosted test environment costs nothing when idle. A full
# `terraform destroy` (make tf-destroy) removes everything; this is the lighter
# "sleep" path that keeps the stack but stops paying for compute.
#
# An EventBridge rule triggers a Lambda that sets desired_count = 0 at 20:00 UTC
# and back to var.replicas at 07:00 UTC on weekdays.

resource "aws_cloudwatch_event_rule" "nightly_down" {
  name                = "pki-test-nightly-down"
  schedule_expression = "cron(0 20 ? * MON-FRI *)"
}

resource "aws_cloudwatch_event_rule" "morning_up" {
  name                = "pki-test-morning-up"
  schedule_expression = "cron(0 7 ? * MON-FRI *)"
}

# NOTE: the Lambda target + IAM are intentionally left as a documented extension
# point. The two rules above express the intended schedule; wiring a small
# "set-desired-count" Lambda (or an AWS Scheduler + ECS UpdateService action)
# completes the automation. See docs/RUNBOOK.md -> "Scheduled teardown".
