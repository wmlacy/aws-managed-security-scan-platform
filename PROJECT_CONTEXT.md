# Managed Security Scan Platform — Project Context

> Handoff / recovery document. Captures everything not derivable from the code itself: AWS resource identities, design decisions, gotchas hit, and what's pending.
> Last updated: 2026-06-06

---

## What this is

A productized AWS-based security scanning service. A single CodeBuild project takes a target (a GitHub repo, a web URL, or an OpenAPI spec) and runs the appropriate scanners, uploads reports to S3, and sends an SNS notification. Scan logic lives in **this** pipeline repo; the client target is pulled in during `pre_build` as data — never used as the CodeBuild source. That separation is load-bearing for the product: scan tooling never touches the client's codebase.

- **Repo:** https://github.com/wmlacy/aws-managed-security-scan-platform (private)
- **Local working dir:** `/Users/willl/Desktop/Security Scans/`
- **Visibility:** internal tool; not seen externally.

---

## Current status

- **Pipeline is live and works end-to-end on a fully Terraform-managed stack.** All AWS resources (S3, SNS, secrets, IAM role + policy, CodeBuild project) were torn down and recreated from `terraform/{main,variables,outputs}.tf`. End-to-end verified 2026-06-06: a self-test scan against the pipeline repo itself completed all phases, dropped 5 report files in S3, and fired the SNS email.
- **Files built: 7 of 8** from the manifest, plus the IAM policy.
- **Source credentials in place** as PAT (re-imported after destroy — the pre-existing OAuth credential didn't auto-pickup on the new TF-built project).
- Secrets contain real values (set post-apply via `put-secret-value`). Both secrets have `lifecycle.ignore_changes = [secret_string]` in Terraform so future applies don't reset them.

---

## AWS resources in use

All in **region `us-east-1`**, account **`<your-aws-account-id>`**. All managed by Terraform (see `terraform/main.tf`) unless noted.

| Resource | Identifier | Notes |
|---|---|---|
| CodeBuild project | `managed-security-scan-platform` | |
| Service role | `codebuild-managed-security-scan-platform-service-role` | named manually to match prior convention |
| Inline IAM policy on role | `codebuild-scan-policy` | built from `aws_iam_policy_document` — real values via TF refs, no placeholders |
| S3 report bucket | `<your-reports-bucket>` | SSE-S3, public access blocked |
| SNS topic | `arn:aws:sns:us-east-1:<your-aws-account-id>:scan-notifications` | |
| SNS email subscription | `you@example.com` | confirmed |
| Secrets Manager — GitHub PAT | `security-scan/github-token` | real PAT, repo scope. Set via CLI post-apply |
| Secrets Manager — optional ZAP auth header | `security-scan/target-auth-header` | value `none` (sentinel) |
| CodeBuild source credential | account+region level, type `PERSONAL_ACCESS_TOKEN` | **NOT** managed by Terraform — imported via CLI |

---

## Design split

- **`buildspec.yml`** = workspace prep + post-processing. Validates env vars, creates `REPORT_DIR`, clones target-src (repo mode) + token scrub, `chmod +x scan.sh`, then in post_build uploads to S3 and publishes SNS.
- **`scan.sh`** = scanner execution only. Reads env, switches on `TARGET_TYPE`, runs scanners, writes `scan_status.txt`, exits with `SCAN_RC`.
- **Why this split:** keeps credential/token handling in one orchestration layer; keeps scan.sh portable and independently testable; clean separation between "fetch target" and "scan target".

---

## File status (manifest)

| File | Status | Notes |
|---|---|---|
| `README.md` | To do | not started |
| `buildspec.yml` | **Built** | hardened; calls `./scan.sh`; uses `env.shell: bash` |
| `scan.sh` | **Built** | scanner case + ZAP_AUTH array + writes `scan_status.txt`; exits with SCAN_RC |
| `report_summary.py` | **Built** | parses semgrep/trivy/gitleaks/zap output into structured `summary.json` + human-readable `summary.txt`; SNS body now reads `summary.txt` via `file://` |
| `tools/zap-baseline.conf` | To do | only matters once web/api scans run |
| `terraform/main.tf` | **Built** | 11 resources + 3 data blocks; proven by end-to-end run |
| `terraform/variables.tf` | **Built** | 11 inputs with defaults matching live account |
| `terraform/outputs.tf` | **Built** | 8 outputs surfacing ARNs and the console URL |
| `codebuild-scan-policy.json` (footnote) | **Superseded** | template kept as reference; real policy now lives in `main.tf` as `aws_iam_policy_document.codebuild_permissions` |

---

## Required CodeBuild environment overrides (per build)

Project-level env vars are baked into Terraform: `REPORT_BUCKET`, `SNS_TOPIC_ARN`, `TARGET_TYPE=repo`, `CLIENT_NAME=unknown-client`. For each run you override:

| Name | Per-run value | Notes |
|---|---|---|
| `TARGET_REPO` | `owner/repo` (repo mode only) | required for repo scans |
| `TARGET_URL` | URL (web mode only) | required for web scans |
| `OPENAPI_SPEC` | spec URL/path (api mode only) | required for api scans |
| `CLIENT_NAME` | any string | optional; overrides default `unknown-client` |
| `TARGET_TYPE` | `repo` / `web` / `api` | only override when switching mode |

Trigger a scan via CLI:
```
aws codebuild start-build --project-name managed-security-scan-platform --region us-east-1 \
  --environment-variables-override name=TARGET_REPO,value=owner/repo,type=PLAINTEXT name=CLIENT_NAME,value=client-name,type=PLAINTEXT
```

---

## CodeBuild / AWS gotchas hit (and fixes)

Non-obvious things that broke first runs. Worth keeping for future AWS work.

1. **Default shell on Linux is `/bin/sh` (dash on Ubuntu images), not bash.** Bash arrays (`VAR=()`) fail with exit 2. Fix: `env.shell: bash` at top of buildspec.
2. **Secrets Manager rejects empty `SecretString`** (min length 1). Optional-secret pattern: store sentinel `none`, and in script treat empty OR `none` as "not set".
3. **Topic ARN vs Subscription ARN** — `aws sns publish` accepts topic ARN only. Subscription ARN looks the same with `:UUID` appended; passing it returns `NotFound` → CLI exit 254.
4. **Console-auto-created service role only grants CloudWatch Logs.** Must attach scan policy *before* first build, or secrets resolution dies before `install`.
5. **`secrets-manager` entries in buildspec are not optional.** All secrets named there are resolved before `install`; if any is missing in that region, the build fails immediately (which is why `target-auth-header` must exist with value `none` even for repo scans).
6. **Private GitHub source needs credentials.** `aws codebuild import-source-credentials --server-type GITHUB --auth-type PERSONAL_ACCESS_TOKEN --token … --region us-east-1`. PAT needs `repo` scope.
7. **Scanner exit codes vary by tool.** semgrep needs `--error`, trivy needs `--exit-code 1`, gitleaks exits non-zero on findings by default. Without these flags, SCAN_RC reports "clean" even when scans found real issues.
8. **`git clone` with token in URL writes the token into `.git/config`** — which is then scanned by trivy, surfacing your own PAT in the client's report. Fix: `git -C target-src remote set-url origin "https://github.com/${TARGET_REPO}.git"` immediately after clone.
9. **SNS subject must be ASCII and under 100 chars.** Em-dashes break it; long client names + scan IDs blow past 100. Fix: ASCII-only `RESULT`, drop SCAN_ID from subject, `printf '%.99s'` truncation safeguard.
10. **AWS CLI exit codes:** 252 = bad params, 253 = bad config/creds, 254 = service returned an error, 255 = unknown. 254 always means "the real error is on the line above this one."
11. **IAM managed policies have multiple versions; `delete-policy` fails until all non-default versions are deleted.** Use `list-policy-versions` then `delete-policy-version` for each non-default before `delete-policy`. Console-edited policies accumulate versions silently.
12. **`detach-role-policy` returning `NoSuchEntity` does NOT mean the policy is gone.** It means the policy isn't currently attached to that role. The policy itself can still exist standalone. Verify with `get-policy` before assuming cleanup.
13. **OAuth source credentials don't auto-pickup on freshly Terraform-built CodeBuild projects.** Even when `list-source-credentials` shows OAUTH at the account+region level, a new TF-built project may fail DOWNLOAD_SOURCE with "authentication required for primary source". Fix: re-import as `PERSONAL_ACCESS_TOKEN` — PAT credentials are picked up reliably.
14. **PAT pasted into a shell command can pick up stray characters** (trailing whitespace, partial selection). Length check: classic PAT should be ~40 chars (41 with newline from `--output text`). For a clean re-set without history exposure, use `read` with `stty -echo`.
15. **zsh's `read -p` means "coprocess", not "prompt"** — bash idiom `read -s -p "..." VAR` errors with "no coprocess" in zsh. Portable alternative: `echo -n "Prompt: " && stty -echo && read VAR && stty echo && echo`.

---

## Operating commands (quick reference)

```bash
# === Apply / change infrastructure ===
cd "/Users/willl/Desktop/Security Scans/terraform"
terraform plan                  # preview changes
terraform apply                 # apply (asks for "yes")
terraform output                # see all output values
terraform output sns_topic_arn  # see one specific value
terraform destroy               # tear it all down (be careful)

# === Set / rotate the GitHub PAT in the secret (silent input, no shell history) ===
echo -n "Paste PAT then hit Enter: "
stty -echo && read PAT && stty echo && echo
aws secretsmanager put-secret-value \
  --secret-id security-scan/github-token \
  --secret-string "$PAT" \
  --region us-east-1
unset PAT

# === Re-import CodeBuild source credentials ===
echo -n "Paste PAT then hit Enter: "
stty -echo && read PAT && stty echo && echo
aws codebuild import-source-credentials \
  --server-type GITHUB \
  --auth-type PERSONAL_ACCESS_TOKEN \
  --token "$PAT" \
  --region us-east-1
unset PAT

# === Trigger a scan ===
aws codebuild start-build --project-name managed-security-scan-platform --region us-east-1 \
  --environment-variables-override name=TARGET_REPO,value=owner/repo,type=PLAINTEXT name=CLIENT_NAME,value=client-name,type=PLAINTEXT

# === Inspect ===
aws s3 ls s3://<your-reports-bucket>/ --recursive
aws codebuild batch-get-builds --ids <build-id> --region us-east-1 --query 'builds[0].[currentPhase,buildStatus]' --output text
```

---

## Pending / next steps

In order of priority:

1. **`tools/zap-baseline.conf`** — ZAP tuning for web/api scans. Only matters once web/api scans are run in earnest.
2. **`README.md`** — project documentation.
3. **(Optional hardening)** Move the TF stack to KMS CMKs for S3, SNS, and Secrets Manager. The self-scan flagged these as HIGH/MEDIUM — the current "plain setup" choice (decisions A/D) was deliberate but is the obvious next maturity bump.

---

## Relationship to other projects

This is a standalone, productized scanning pipeline. It is **not** linked to the **ASERION Engine** project (also AWS security/compliance scanning, for Thai regulatory pilots) — confirmed separate on 2026-07-07. The two share a domain but no code, infrastructure, or roadmap.
