# ============================================================================
#  outputs.tf — Values surfaced after `terraform apply`.
#
#  Outputs are useful for:
#   - showing key resource identifiers (ARNs, names) in your terminal
#   - feeding into post-apply commands (e.g. setting the real PAT)
#   - other Terraform stacks consuming this one (later)
#
#  After `terraform apply`, retrieve any value with:  terraform output <name>
# ============================================================================

output "report_bucket_name" {
  description = "S3 bucket where scan reports are written."
  value       = aws_s3_bucket.reports.id
}

output "report_bucket_arn" {
  description = "ARN of the report bucket. Matches the IAM policy resource."
  value       = aws_s3_bucket.reports.arn
}

output "sns_topic_arn" {
  description = "Topic ARN the buildspec publishes to. Set this as SNS_TOPIC_ARN in CodeBuild env if you ever rewire by hand."
  value       = aws_sns_topic.notifications.arn
}

output "github_token_secret_arn" {
  description = "ARN of the GitHub PAT secret. Set the real value with: aws secretsmanager put-secret-value --secret-id <name> --secret-string <PAT>"
  value       = aws_secretsmanager_secret.github_token.arn
}

output "target_auth_header_secret_arn" {
  description = "ARN of the optional ZAP auth header secret. Leave value as 'none' unless doing web/api scans with auth."
  value       = aws_secretsmanager_secret.target_auth_header.arn
}

output "codebuild_role_arn" {
  description = "ARN of the CodeBuild service role."
  value       = aws_iam_role.codebuild.arn
}

output "codebuild_project_name" {
  description = "Name of the CodeBuild project. Use this to start a build: aws codebuild start-build --project-name <name>"
  value       = aws_codebuild_project.scan.name
}

output "codebuild_project_url" {
  description = "Direct console link to the CodeBuild project."
  value       = "https://console.aws.amazon.com/codesuite/codebuild/projects/${aws_codebuild_project.scan.name}?region=${var.aws_region}"
}

output "kms_key_arn" {
  description = "ARN of the CMK encrypting the S3 reports, SNS topic, and secrets."
  value       = aws_kms_key.scan.arn
}
