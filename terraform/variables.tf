# ============================================================================
#  variables.tf — Inputs to the Managed Security Scan Platform stack.
#
#  Every input the stack needs is declared here as a `variable` block.
#  Each variable has: a description (shown in `terraform plan`), a type,
#  and a default. Defaults are the values used on Will's account today.
#  Override any of them via terraform.tfvars or `-var name=value` on the CLI.
# ============================================================================

# ---------------------------------------------------------------------------
# Account-level
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for all resources. Bucket, topic, secrets, role, and project must all live here."
  type        = string
  default     = "us-east-1"
}

# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

variable "project_name" {
  description = "Short identifier used in the CodeBuild project name, the service role name, and the log group path."
  type        = string
  default     = "managed-security-scan-platform"
}

variable "report_bucket_name" {
  description = "Globally-unique S3 bucket name for scan reports. Lowercase, no underscores, 3-63 chars."
  type        = string
  default     = "managed-security-scan-reports-will-001"
}

variable "sns_topic_name" {
  description = "Name of the SNS topic the buildspec publishes to. Must equal what's in env.variables in buildspec.yml."
  type        = string
  default     = "scan-notifications"
}

variable "secrets_prefix" {
  description = "Path prefix for Secrets Manager secrets. Hardcoded in the buildspec — change here AND there."
  type        = string
  default     = "security-scan"
}

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

variable "notification_email" {
  description = "Email address subscribed to the SNS topic. You'll need to re-confirm via email after every apply."
  type        = string
  default     = "wmlacy3000@gmail.com"
}

# ---------------------------------------------------------------------------
# CodeBuild source
# ---------------------------------------------------------------------------

variable "github_repo_url" {
  description = "HTTPS URL of the pipeline repo (the one containing buildspec.yml and scan.sh)."
  type        = string
  default     = "https://github.com/wmlacy/aws-managed-security-scan-platform.git"
}

# ---------------------------------------------------------------------------
# CodeBuild compute
# ---------------------------------------------------------------------------

variable "compute_type" {
  description = "CodeBuild instance size. SMALL is fine for repo scans; bump up for heavier ZAP runs."
  type        = string
  default     = "BUILD_GENERAL1_SMALL"
}

variable "image" {
  description = "CodeBuild container image. Standard 7.0 is Ubuntu-based and ships with bash + Python."
  type        = string
  default     = "aws/codebuild/standard:7.0"
}

variable "privileged_mode" {
  description = "Privileged mode is required for Docker-in-Docker, which the ZAP image needs for web/api scans."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

variable "tags" {
  description = "Tags applied to every taggable resource. Closes the gap we hit before (no inventory by tag)."
  type        = map(string)
  default = {
    Project   = "managed-security-scan-platform"
    ManagedBy = "Terraform"
  }
}
