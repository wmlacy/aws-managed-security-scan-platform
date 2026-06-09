# Managed Security Scan Platform

A managed, infrastructure-as-code security scanning pipeline. One AWS CodeBuild project runs the right scanners against a **GitHub repo**, a **web URL**, or an **API spec** — uploads structured findings to S3 and emails a human-readable summary.

Built end-to-end as a portfolio piece: AWS architecture, Terraform IaC, Bash, Python, and four open-source security scanners stitched into a single deliverable.

---

## Architecture

```
            ┌─────────────────────────┐
            │  Trigger: aws codebuild │
            │  start-build + env vars │
            └────────────┬────────────┘
                         ▼
   ┌──────────────────────────────────────────────┐
   │             AWS CodeBuild Project            │
   │                                              │
   │  pre_build  ─ validate, mkdir, clone target  │
   │  build      ─ ./scan.sh  → SCAN_RC           │
   │  post_build ─ python3 report_summary.py      │
   │             ─ s3 cp reports/ → bucket        │
   │             ─ sns publish (summary.txt body) │
   └──────┬────────────────────────┬──────────────┘
          ▼                        ▼
   ┌──────────────┐         ┌─────────────┐
   │  S3 reports  │         │  SNS topic  │
   │   bucket     │         │ → email     │
   └──────────────┘         └─────────────┘
```

Per-scan layout in S3:
```
s3://<reports-bucket>/<client-name>/<scan-id>/
  ├── semgrep.json     (SAST findings)
  ├── trivy.json       (SCA / vuln / secret / misconfig)
  ├── gitleaks.json    (committed secrets)
  ├── zap.json         (web/api DAST, when run)
  ├── summary.json     (structured aggregate)
  ├── summary.txt      (human-readable, same content as the SNS email)
  └── scan_status.txt  (final exit code)
```

---

## What it does

| Scan mode      | Target                  | Scanners used                        |
| -------------- | ----------------------- | ------------------------------------ |
| `repo`         | GitHub repo (any owner) | semgrep + trivy + gitleaks           |
| `web`          | Web URL                 | OWASP ZAP baseline scan              |
| `api`          | OpenAPI spec            | OWASP ZAP API scan                   |

Each run produces five report files in S3 and a single email summary with:

- Total findings, broken down by tool **and** by severity
- Top 5 findings with file/line context
- Recommended next actions (rotate secrets, address criticals, etc.)
- A pointer to the full reports in S3

---

## Stack

- **AWS**: CodeBuild, S3, SNS, Secrets Manager, IAM
- **Terraform** 1.5+ with the AWS provider 5.x
- **Python 3.12**, **Bash**
- Scanners: [semgrep](https://semgrep.dev/), [trivy](https://trivy.dev/), [gitleaks](https://github.com/gitleaks/gitleaks), [OWASP ZAP](https://www.zaproxy.org/)

All four scanners are open source. The interesting work is *not* the scanners themselves — it's the orchestration, IAM, IaC, and report aggregation.

---

## Quick start

Prerequisites: AWS account + Terraform 1.5+ + AWS CLI v2 + a GitHub PAT with `repo` scope.

```bash
# 1. Clone and configure
git clone https://github.com/<your-fork>/aws-managed-security-scan-platform.git
cd aws-managed-security-scan-platform/terraform

# Edit variables.tf or create terraform.tfvars to override defaults:
#   report_bucket_name (must be globally unique)
#   notification_email
#   github_repo_url (after you fork)

# 2. Build the infrastructure
terraform init
terraform plan        # preview ~11 AWS resources
terraform apply       # confirm with "yes"

# 3. Drop the real GitHub PAT into the placeholder secret
aws secretsmanager put-secret-value \
  --secret-id security-scan/github-token \
  --secret-string <your-PAT> \
  --region <your-region>

# 4. Authorize CodeBuild to clone the source repo
aws codebuild import-source-credentials \
  --server-type GITHUB \
  --auth-type PERSONAL_ACCESS_TOKEN \
  --token <your-PAT> \
  --region <your-region>

# 5. Confirm the SNS subscription email (AWS sends one after step 2)

# 6. Run a scan
aws codebuild start-build \
  --project-name managed-security-scan-platform \
  --region <your-region> \
  --environment-variables-override \
      name=TARGET_REPO,value=<owner>/<repo>,type=PLAINTEXT \
      name=CLIENT_NAME,value=<a-client-label>,type=PLAINTEXT
```

Within ~3 minutes you'll have findings in S3 and an email summary.

---

## Repository layout

```
.
├── README.md
├── PROJECT_CONTEXT.md          internal recovery / handoff doc (operating notes)
├── buildspec.yml               CodeBuild orchestration: install → validate → scan.sh → upload → notify
├── scan.sh                     scanner execution: TARGET_TYPE case + semgrep/trivy/gitleaks/ZAP
├── report_summary.py           parses raw scanner JSON into summary.json + summary.txt
├── codebuild-scan-policy.json  legacy template (kept as reference; superseded by Terraform)
└── terraform/
    ├── main.tf                 11 resources: S3, SNS, secrets, IAM, CodeBuild
    ├── variables.tf            11 inputs with sensible defaults
    └── outputs.tf              8 outputs (ARNs + console URL)
```

---

## Design decisions

A few non-obvious choices that shape the architecture:

**1. Target is data, not source.** The CodeBuild project's source is *this* pipeline repo — never the client's code. The client target is cloned (`repo` mode) or referenced by URL (`web` / `api`) at scan time. This keeps scan tooling out of the client's codebase entirely.

**2. `buildspec.yml` does workspace prep; `scan.sh` does scanner execution.** The split keeps credential and token handling in one orchestration layer (the buildspec), and keeps the scan logic portable and independently testable.

**3. Secrets created with placeholders by Terraform; real values set post-apply.** Real PATs and tokens never enter `terraform.tfstate`. The Terraform resources include `lifecycle.ignore_changes = [secret_string]` so future applies don't fight CLI-set values.

**4. `env.shell: bash` is non-optional.** CodeBuild defaults its shell to `/bin/sh` (dash on Ubuntu images). Bash array syntax (`VAR=()`) silently fails with exit 2 in dash, which is how an early build broke. The fix is one line in `env`, but the underlying gotcha is worth knowing.

**5. S3 upload happens *before* SNS publish.** If the upload fails, the build aborts before the notification fires — so no "scan complete" email is ever sent without a corresponding report in S3.

**6. `report_summary.py` is defensive.** If parsing fails for any reason, the script still writes a minimal `summary.txt` so the downstream `sns publish --message file://...` doesn't cascade-fail.

---

## Sample summary

```
Security Scan Summary
=====================
Client:       acme-corp
Target:       acme/api-service (repo)
Scan ID:      20260606T075152Z-551da3ab
Status:       completed WITH findings (rc=1)

Findings by tool:
  semgrep    3
  trivy      6

Findings by severity:
  HIGH       2
  MEDIUM     4
  LOW        3

Top 5 findings:
  1. [HIGH] [trivy] AWS-0095
     Unencrypted SNS topic.
     terraform/main.tf
  2. [HIGH] [trivy] AWS-0132
     S3 encryption should use Customer Managed Keys
     terraform/main.tf
  3. [MEDIUM] [semgrep] terraform.aws.security.aws-codebuild-...
     ...

Recommended next actions:
  - Review 2 HIGH finding(s) for risk acceptance.
  - Full reports in s3://.../acme-corp/20260606T075152Z-551da3ab/
```

---

## Gotchas worth filing (lessons from building this)

The full annotated list (15 entries with fixes) lives in [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md). A few highlights:

- **`detach-role-policy` returning `NoSuchEntity` doesn't mean the policy is gone** — it means the policy isn't currently attached to that role. The standalone policy can still exist. Verify before assuming cleanup.
- **IAM managed policies have versions; `delete-policy` fails until non-default versions are deleted.** Console-edited policies accumulate versions silently.
- **OAuth source credentials don't reliably auto-pickup on freshly Terraform-built CodeBuild projects.** Re-importing as `PERSONAL_ACCESS_TOKEN` works.
- **`git clone` with a token in the URL writes that token into `.git/config`** — which trivy then scans, surfacing your own PAT in the client's report. Scrub the remote after clone.
- **AWS CLI exit code 254 always means "look at the API error message above this line."** It's the service returning an error, not a CLI bug.

---

## Why this exists

I built this end-to-end to ground my cloud engineering and security work in something concrete: real AWS resources, real IAM, real Terraform, real scanners producing real findings. Useful as a portfolio piece and as a starting point if you want a low-cost, AWS-native security scanning baseline for one-off audits or per-client scans.

---

## License

MIT — see [LICENSE](LICENSE).
