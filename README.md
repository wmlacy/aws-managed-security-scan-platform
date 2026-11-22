# Managed Security Scan Platform

A managed, infrastructure-as-code security scanning pipeline. One AWS CodeBuild project runs the right scanners against a **GitHub repo**, a **web URL**, or an **API spec** — uploads structured findings to S3 and emails a human-readable summary.

This project demonstrates an AWS-native approach to security scan orchestration using Terraform, CodeBuild, Secrets Manager, S3, SNS, Bash, Python, and multiple open-source scanners integrated into a single repeatable workflow.

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

Per-scan layout in S3 (six files per run):
```
s3://<reports-bucket>/<client-name>/<scan-id>/
  ├── semgrep.json     (repo: SAST findings)
  ├── trivy.json       (repo: SCA / vuln / secret / misconfig)
  ├── gitleaks.json    (repo: committed secrets)
  ├── zap.json         (web/api: DAST findings, unfiltered)
  ├── zap.html         (web/api: ZAP HTML report)
  ├── zap.yaml         (web/api: ZAP automation plan used for the run)
  ├── summary.json     (structured aggregate, status, suppressed findings)
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

Each run produces six files in S3 (three scanner reports plus `summary.json`, `summary.txt`, and `scan_status.txt`) and a single email summary with:

- A status: **CLEAN**, **FINDINGS**, **INCOMPLETE** (a scanner report is missing or invalid), or **FAILED** (a scanner or the summary step errored)
- Total findings, broken down by tool **and** by severity
- Top 5 findings with file/line context
- For web/api scans, every alert suppressed by `tools/zap-baseline.conf`, with the recorded reason
- Recommended next actions (rotate secrets, address criticals, etc.)
- A pointer to the full reports in S3

---

## Stack

- **AWS**: CodeBuild, S3, SNS, Secrets Manager, IAM, KMS
- **Terraform** 1.5+ with the AWS provider 5.x
- **Python 3.12**, **Bash**
- Scanners: [semgrep](https://semgrep.dev/), [trivy](https://trivy.dev/), [gitleaks](https://github.com/gitleaks/gitleaks), [OWASP ZAP](https://www.zaproxy.org/)

All four scanners are open source. The interesting work is *not* the scanners themselves — it's the orchestration, IAM, IaC, and report aggregation.

---

## Deployment

How the stack is deployed and a scan is run, documented for reference (see [License](#license)).

Prerequisites: AWS account + Terraform 1.5+ + AWS CLI v2 + a GitHub PAT with `repo` scope.

```bash
# 1. Configure
cd terraform

# Real values are supplied in a local, gitignored terraform.tfvars:
#   report_bucket_name (must be globally unique)
#   notification_email
#   github_repo_url (the pipeline repository)

# 2. Build the infrastructure
terraform init
terraform plan        # preview ~22 AWS resources
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
├── tools/
│   └── zap-baseline.conf       ZAP rule policy: FAIL / WARN / IGNORE per rule, with a reason for every IGNORE
├── tests/
│   └── test_report_summary.py  status and suppression tests (python3 -m unittest discover tests)
└── terraform/
    ├── main.tf                 22 resources: KMS, S3 (reports + access logs), SNS, secrets, IAM, CodeBuild
    ├── variables.tf            11 inputs with sensible defaults
    └── outputs.tf              10 outputs (ARNs, bucket names, console URL)
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

**7. One customer-managed KMS key encrypts every data store.** The report bucket (SSE-KMS with a bucket key), the SNS topic, both secrets, and the CodeBuild project share a single rotating CMK. The CodeBuild role's KMS permissions live in the key policy rather than its IAM policy, which avoids a Terraform dependency cycle between the key and the role.

**8. The report bucket is versioned and access-logged; the log bucket is the end of the chain.** Server access logs go to a dedicated bucket with versioning, public access blocked, and 90-day expiry. That bucket uses SSE-S3 because S3 server access logging cannot deliver to an SSE-KMS bucket, and it is not itself logged. Both exceptions are suppressed inline (`#trivy:ignore:AWS-0132`, `#trivy:ignore:AWS-0089`) with the justification next to the resource, so the platform's self-scan reports zero findings without hiding anything undocumented.

**9. Status is fail-closed.** A scan is reported CLEAN only when every report expected for the target type exists and has the expected structure, the scanners exited 0, and no unsuppressed findings remain. A missing, empty, or malformed report yields INCOMPLETE; a non-zero exit with no findings, or a failure of the summary step itself, yields FAILED. The SNS subject is derived from the same status and falls back to "status unknown", never "clean". This closes the false-clean path found during web-mode validation, where ZAP wrote no report yet the build succeeded.

**10. Suppression is traceable.** ZAP alerts are suppressed only by an IGNORE rule in `tools/zap-baseline.conf` that records a reason. Suppressed alerts are excluded from the counts but listed with that reason in the summary, and the raw `zap.json` is uploaded unmodified. HIGH-risk alerts are never suppressed, and an IGNORE rule without a reason has no effect.

---

## Sample summary

```
Security Scan Summary
=====================
Client:       demo
Target:       example-org/api-service (repo)
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
  - Full reports in s3://.../demo/20260606T075152Z-551da3ab/
```

---

## Validation

The platform has been exercised end-to-end against real targets — not merely confirmed to provision:

- **Pipeline validation (repo mode)** — the pipeline was run against its own repository, confirming the complete flow: clone → scan → structured upload to S3 → SNS email summary.
- **Detection depth (repo mode)** — [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Node.js application, was scanned to confirm the SAST/SCA scanners surface *known* vulnerabilities in unfamiliar code. The run reported multiple critical CVEs (e.g. prototype-pollution and deserialization issues) rather than a false-clean result.
- **Web scanning path (web mode)** — [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), an intentionally vulnerable web application, was scanned to verify the ZAP web-scan path, single-page-app crawling, and report generation end to end. This exercise also caught and closed a real defect in which container-side report files were not being captured — the kind of false-clean a security tool must never produce.

Taken together, these confirm the platform detects known security issues under realistic conditions, which is the behavior a reviewer or client actually needs to trust — beyond a successful build.

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

Security scans often produce fragmented outputs across separate tools, formats, and workflows. This project brings those pieces into one AWS-native pipeline so findings can be collected, stored, summarized, and reviewed consistently.

---

## License

Copyright (c) 2026 Will Lacy. All rights reserved. Published for viewing and reference only; see [LICENSE](LICENSE).
