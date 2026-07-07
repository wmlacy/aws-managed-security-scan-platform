# ============================================================================
#  main.tf — Resource definitions for the Managed Security Scan Platform.
#
#  Reads inputs from variables.tf. Surfaces values via outputs.tf.
#  Apply with: terraform init && terraform plan && terraform apply
# ============================================================================

# ---------------------------------------------------------------------------
# Terraform + AWS provider
# ---------------------------------------------------------------------------
#
# `terraform { ... }` pins which versions of Terraform and the AWS provider
# are allowed to use this code. Pinning prevents "works on my laptop" drift.
#
# `default_tags` on the provider applies var.tags to every taggable resource
# automatically — no need to repeat `tags = var.tags` on each block.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

# `data "aws_caller_identity"` looks up the account ID at apply time, so we
# can build ARNs (logs, secrets) without hardcoding the account number.
data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# KMS customer-managed key (CMK)
# ---------------------------------------------------------------------------
#
# One CMK encrypts all three data-at-rest stores: the S3 report bucket, the
# SNS topic, and the Secrets Manager secrets. AWS-managed keys (the default)
# work, but the platform's own self-scan flags them HIGH/MEDIUM — so a
# security product should hold itself to the CMK standard it enforces.
#
# Key policy design (KMS is deny-by-default; access must be granted HERE or
# delegated to IAM via the root statement):
#   1. Root/account keeps full admin — standard, and prevents lockout.
#   2. The CodeBuild role gets exactly the operations it needs: Decrypt (read
#      secrets, read SSE-KMS objects), GenerateDataKey (write SSE-KMS objects,
#      publish to the encrypted topic), DescribeKey.
#   3. The SNS service principal can use the key so encrypted publishes and
#      email delivery succeed.
# Access is granted to the role HERE (not in its IAM policy) on purpose: a
# mutual key<->role reference would be a Terraform dependency cycle.

data "aws_iam_policy_document" "scan_kms" {
  statement {
    sid       = "EnableRootAccountAdmin"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCodeBuildRoleUse"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.codebuild.arn]
    }
  }

  statement {
    sid       = "AllowSNSServiceUse"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "scan" {
  description             = "CMK for the Managed Security Scan Platform: S3 reports, SNS topic, and Secrets Manager secrets."
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.scan_kms.json
}

resource "aws_kms_alias" "scan" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.scan.key_id
}

# ---------------------------------------------------------------------------
# S3 report bucket
# ---------------------------------------------------------------------------
#
# The bucket holds scan reports. New S3 buckets block public access by
# default; we re-assert the public access block explicitly so the intent is
# in code, and set SSE-KMS with the CMK above. `bucket_key_enabled` cuts KMS
# API calls (and cost) by using an S3 bucket key.

resource "aws_s3_bucket" "reports" {
  bucket = var.report_bucket_name
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.scan.arn
    }
    bucket_key_enabled = true
  }
}

# ---------------------------------------------------------------------------
# SNS topic + email subscription
# ---------------------------------------------------------------------------
#
# `aws_sns_topic_subscription` creates the subscription as "pending
# confirmation". AWS emails the address; the link in that email must be
# clicked before notifications start arriving.

resource "aws_sns_topic" "notifications" {
  name              = var.sns_topic_name
  kms_master_key_id = aws_kms_key.scan.id
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------------------------------------------------------------------------
# Secrets Manager (two secrets, placeholder values on create)
# ---------------------------------------------------------------------------
#
# Real secret values never enter Terraform. We create the secret containers
# with placeholder strings, then update the real values via CLI post-apply:
#
#   aws secretsmanager put-secret-value --secret-id security-scan/github-token \
#     --secret-string YOUR_REAL_PAT
#
# `lifecycle.ignore_changes = [secret_string]` tells Terraform not to revert
# those post-apply edits on the next plan/apply.

resource "aws_secretsmanager_secret" "github_token" {
  name        = "${var.secrets_prefix}/github-token"
  description = "GitHub PAT (repo scope) for cloning target repos. Real value set via CLI."
  kms_key_id  = aws_kms_key.scan.arn
}

resource "aws_secretsmanager_secret_version" "github_token_placeholder" {
  secret_id     = aws_secretsmanager_secret.github_token.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "target_auth_header" {
  name        = "${var.secrets_prefix}/target-auth-header"
  description = "Optional ZAP auth header for web/api scans. 'none' or empty = no header."
  kms_key_id  = aws_kms_key.scan.arn
}

resource "aws_secretsmanager_secret_version" "target_auth_header_placeholder" {
  secret_id     = aws_secretsmanager_secret.target_auth_header.id
  secret_string = "none"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ---------------------------------------------------------------------------
# IAM role for CodeBuild
# ---------------------------------------------------------------------------
#
# Two policies are involved:
#   1. assume_role_policy (the "trust" policy) — who is allowed to BECOME this role
#   2. an attached inline policy (further down) — what the role CAN DO
#
# `aws_iam_policy_document` is a data source that builds JSON policy text
# from HCL blocks. Cleaner than writing raw JSON, and Terraform validates it.

data "aws_iam_policy_document" "codebuild_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "codebuild-${var.project_name}-service-role"
  description        = "CodeBuild service role for the managed security scan project."
  assume_role_policy = data.aws_iam_policy_document.codebuild_trust.json
}

# Permissions policy — same four statements as codebuild-scan-policy.json,
# but the resource ARNs are computed from real resource attributes instead
# of placeholder strings.

data "aws_iam_policy_document" "codebuild_permissions" {
  statement {
    sid       = "WriteScanReportsToS3"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }

  statement {
    sid       = "PublishScanNotifications"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
  }

  statement {
    sid       = "ReadScanSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.secrets_prefix}/*"]
  }

  statement {
    sid     = "WriteBuildLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/${var.project_name}",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/${var.project_name}:*",
    ]
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "codebuild-scan-policy"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild_permissions.json
}

# ---------------------------------------------------------------------------
# CodeBuild project
# ---------------------------------------------------------------------------
#
# - `source.type = GITHUB` + `source.location = <repo URL>` pulls the
#   buildspec.yml from the source repo on every build.
# - REPORT_BUCKET and SNS_TOPIC_ARN env vars wire the buildspec to the
#   resources created above. TARGET_TYPE and CLIENT_NAME are sensible
#   defaults; you override TARGET_REPO/TARGET_URL/OPENAPI_SPEC per run.
# - Source credentials (GitHub OAuth/PAT) are an ACCOUNT-LEVEL resource
#   set up separately; this project automatically picks them up.

resource "aws_codebuild_project" "scan" {
  name         = var.project_name
  description  = "Runs managed security scans (semgrep/trivy/gitleaks for repos, ZAP for web/api) against client targets."
  service_role = aws_iam_role.codebuild.arn

  # Encrypt build output artifacts/logs with the platform CMK instead of the
  # default AWS-managed S3 key. The service role can use this key via the key
  # policy (GenerateDataKey/Decrypt).
  encryption_key = aws_kms_key.scan.arn

  source {
    type      = "GITHUB"
    location  = var.github_repo_url
    buildspec = "buildspec.yml"
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type    = var.compute_type
    image           = var.image
    type            = "LINUX_CONTAINER"
    privileged_mode = var.privileged_mode

    environment_variable {
      name  = "REPORT_BUCKET"
      value = aws_s3_bucket.reports.id
    }

    environment_variable {
      name  = "SNS_TOPIC_ARN"
      value = aws_sns_topic.notifications.arn
    }

    environment_variable {
      name  = "TARGET_TYPE"
      value = "repo"
    }

    environment_variable {
      name  = "CLIENT_NAME"
      value = "unknown-client"
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name = "/aws/codebuild/${var.project_name}"
    }
  }
}
