#!/usr/bin/env python3
"""
report_summary.py - Build human-readable + structured summaries from raw
scanner output, and decide the scan's overall status.

Reads (from REPORT_DIR):
  semgrep.json    (repo scans)
  trivy.json      (repo scans)
  gitleaks.json   (repo scans)
  zap.json        (web/api scans)

Reads (from this repo):
  tools/zap-baseline.conf   ZAP rule policy (override path with ZAP_POLICY)

Reads from environment (set by buildspec/scan.sh):
  REPORT_DIR, SCAN_ID, CLIENT_NAME, TARGET_TYPE, TARGET_DESC, SCAN_RC, REPORT_BUCKET

Writes (into REPORT_DIR, uploaded to S3):
  summary.json    - structured, machine-readable
  summary.txt     - human-readable, used as the SNS message body
Writes (into the working directory, not uploaded; override with SUBJECT_FILE):
  .sns_subject    - SNS subject line derived from the status

Status is fail-closed. CLEAN is reported only when every report expected for
the target type exists and has the expected structure, the scanners exited 0,
and no unsuppressed findings remain. Otherwise the status is FINDINGS,
INCOMPLETE (a report is missing or invalid), or FAILED (a scanner errored, the
exit code is unavailable, or this script itself failed).

Suppression is traceable. A ZAP alert is suppressed only when the policy marks
its rule IGNORE *and* records a reason. Suppressed alerts are excluded from the
counts but listed with their reason in both summaries, and the raw zap.json is
uploaded unmodified. HIGH-risk alerts are never suppressed.

Always exits 0. On internal error, a minimal summary is still written with
status FAILED so the downstream SNS publish never reports a clean result.
"""

import json
import os
import sys
from pathlib import Path


# --------------------------------------------------------------------------
# Env inputs
# --------------------------------------------------------------------------

def env(name, default=""):
    return os.environ.get(name, default)


REPORT_DIR    = env("REPORT_DIR", "reports")
SCAN_ID       = env("SCAN_ID", "unknown-scan-id")
CLIENT_NAME   = env("CLIENT_NAME", "unknown-client")
TARGET_TYPE   = env("TARGET_TYPE", "unknown")
TARGET_DESC   = env("TARGET_DESC", "unknown-target")
SCAN_RC       = env("SCAN_RC", "unknown")
REPORT_BUCKET = env("REPORT_BUCKET", "")

REPORT_PATH = Path(REPORT_DIR)
SUBJECT_PATH = Path(env("SUBJECT_FILE", ".sns_subject"))
ZAP_POLICY_PATH = Path(env(
    "ZAP_POLICY",
    str(Path(__file__).resolve().parent / "tools" / "zap-baseline.conf"),
))

# Reports each target type must produce. A missing or malformed report means
# the scan did not run to completion, so the result can never be CLEAN.
EXPECTED_REPORTS = {
    "repo": ["semgrep.json", "trivy.json", "gitleaks.json"],
    "web": ["zap.json"],
    "api": ["zap.json"],
}
S3_LOCATION = (
    f"s3://{REPORT_BUCKET}/{CLIENT_NAME}/{SCAN_ID}/"
    if REPORT_BUCKET
    else "(REPORT_BUCKET not set)"
)


# --------------------------------------------------------------------------
# Severity normalization (CRITICAL > HIGH > MEDIUM > LOW > INFO)
# --------------------------------------------------------------------------

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def normalize(tool, raw):
    raw = (raw or "").upper()
    if tool == "semgrep":
        return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw, "MEDIUM")
    if tool == "trivy":
        return raw if raw in SEVERITY_RANK else "MEDIUM"
    if tool == "gitleaks":
        # Leaked secrets are inherently serious - normalize to HIGH.
        return "HIGH"
    if tool == "zap":
        # ZAP riskdesc looks like "Medium (Confidence: High)" - the first word is risk.
        first = raw.split()[0] if raw else ""
        return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
                "INFORMATIONAL": "INFO"}.get(first, "MEDIUM")
    return "MEDIUM"


# --------------------------------------------------------------------------
# Tool parsers
# --------------------------------------------------------------------------

def load_json(name):
    p = REPORT_PATH / name
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def parse_semgrep():
    data = load_json("semgrep.json")
    if not data:
        return []
    out = []
    for r in data.get("results", []):
        out.append({
            "tool": "semgrep",
            "severity": normalize("semgrep", r.get("extra", {}).get("severity", "WARNING")),
            "id": r.get("check_id", "unknown"),
            "message": (r.get("extra", {}).get("message") or "")[:200],
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line"),
        })
    return out


def parse_trivy():
    data = load_json("trivy.json")
    if not data:
        return []
    out = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            out.append({
                "tool": "trivy",
                "severity": normalize("trivy", v.get("Severity", "MEDIUM")),
                "id": v.get("VulnerabilityID", "unknown"),
                "message": (v.get("Title") or v.get("Description") or "")[:200],
                "file": target,
                "line": None,
            })
        for s in result.get("Secrets") or []:
            out.append({
                "tool": "trivy",
                "severity": normalize("trivy", s.get("Severity", "HIGH")),
                "id": s.get("RuleID", "secret"),
                "message": (s.get("Title") or "secret found")[:200],
                "file": target,
                "line": s.get("StartLine"),
            })
        for m in result.get("Misconfigurations") or []:
            out.append({
                "tool": "trivy",
                "severity": normalize("trivy", m.get("Severity", "MEDIUM")),
                "id": m.get("ID", "misconfig"),
                "message": (m.get("Title") or "")[:200],
                "file": target,
                "line": None,
            })
    return out


def parse_gitleaks():
    data = load_json("gitleaks.json")
    if not isinstance(data, list):
        return []
    out = []
    for r in data:
        out.append({
            "tool": "gitleaks",
            "severity": "HIGH",
            "id": r.get("RuleID", "leaked-secret"),
            "message": (r.get("Description") or "leaked secret")[:200],
            "file": r.get("File", ""),
            "line": r.get("StartLine"),
        })
    return out


def load_zap_policy():
    """Return ({rule_id: {"action", "reason"}}, policy_found) from the ZAP config.

    Line format (tab separated): <rule id> <ACTION> (<rule name>) <reason>
    """
    policy = {}
    if not ZAP_POLICY_PATH.is_file():
        return policy, False
    for line in ZAP_POLICY_PATH.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.rstrip().split("\t")
        if len(parts) < 3:
            continue
        policy[parts[0].strip()] = {
            "action": parts[1].strip().upper(),
            "reason": parts[3].strip() if len(parts) > 3 else "",
        }
    return policy, True


def parse_zap(policy):
    """Return (active, suppressed) ZAP findings.

    An alert is suppressed only if its rule is IGNORE in the policy, the policy
    records a reason, and the alert is not HIGH risk. Everything else stays
    active, with a note when a policy entry was overridden.
    """
    data = load_json("zap.json")
    active, suppressed = [], []
    if not isinstance(data, dict):
        return active, suppressed
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            rule_id = str(a.get("pluginid") or "")
            try:
                instances = int(a.get("count") or 0)
            except (TypeError, ValueError):
                instances = 0
            f = {
                "tool": "zap",
                "severity": normalize("zap", a.get("riskdesc", "")),
                "id": rule_id or a.get("name", "alert"),
                "message": (a.get("name") or "")[:200],
                "file": site.get("@name", ""),
                "line": None,
                "instances": instances,
            }
            rule = policy.get(rule_id)
            if rule and rule["action"] == "IGNORE":
                if f["severity"] == "HIGH":
                    f["note"] = "policy IGNORE overridden: HIGH-risk alerts are never suppressed"
                    active.append(f)
                elif not rule["reason"]:
                    f["note"] = "policy IGNORE overridden: no reason recorded in the policy"
                    active.append(f)
                else:
                    f["suppression_reason"] = rule["reason"]
                    suppressed.append(f)
            else:
                active.append(f)
    return active, suppressed


# --------------------------------------------------------------------------
# Report completeness + status (fail-closed)
# --------------------------------------------------------------------------

def _has_expected_shape(name, data):
    if name == "semgrep.json":
        return isinstance(data, dict) and isinstance(data.get("results"), list)
    if name == "trivy.json":
        return isinstance(data, dict) and "SchemaVersion" in data
    if name == "gitleaks.json":
        return isinstance(data, list)
    if name == "zap.json":
        return isinstance(data, dict) and isinstance(data.get("site"), list) and len(data["site"]) > 0
    return data is not None


def check_reports():
    """Return a list of problems with the reports expected for TARGET_TYPE."""
    expected = EXPECTED_REPORTS.get(TARGET_TYPE)
    if expected is None:
        return [f"unknown target type '{TARGET_TYPE}'"]
    problems = []
    for name in expected:
        p = REPORT_PATH / name
        if not p.is_file():
            problems.append(f"{name} missing")
            continue
        if p.stat().st_size == 0:
            problems.append(f"{name} is empty")
            continue
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            problems.append(f"{name} is not valid JSON")
            continue
        if not _has_expected_shape(name, data):
            if name == "zap.json" and isinstance(data, dict) and data.get("site") == []:
                problems.append("zap.json lists no sites (target was not reached)")
            else:
                problems.append(f"{name} does not have the expected structure")
    return problems


def decide_status(problems, active_findings):
    """Return (status_code, status_text). CLEAN only if every check passes."""
    try:
        rc = int(SCAN_RC)
    except (TypeError, ValueError):
        rc = None
    if problems:
        return ("INCOMPLETE",
                "INCOMPLETE - not all scanner reports were produced; do not treat as clean")
    if rc is None:
        return "FAILED", f"FAILED - scanner exit code unavailable (rc={SCAN_RC})"
    if active_findings:
        return "FINDINGS", f"completed WITH findings (rc={rc})"
    if rc != 0:
        return ("FAILED",
                f"FAILED - a scanner exited rc={rc} but reported no findings; treat as a scanner error")
    return "CLEAN", "completed cleanly - no unsuppressed findings"


def write_subject(status_code):
    """Write the SNS subject (ASCII, under 100 chars) for buildspec.yml to read."""
    label = {
        "CLEAN": "clean",
        "FINDINGS": f"findings (rc={SCAN_RC})",
        "INCOMPLETE": "INCOMPLETE - reports missing",
        "FAILED": "FAILED",
    }.get(status_code, "status unknown")
    subject = f"Scan {CLIENT_NAME}: {label}"
    subject = " ".join(subject.split()).encode("ascii", "replace").decode("ascii")
    SUBJECT_PATH.write_text(subject[:99])


# --------------------------------------------------------------------------
# Recommended actions
# --------------------------------------------------------------------------

def build_actions(status_code, counts_by_severity, counts_by_tool, findings, suppressed):
    actions = []
    if status_code == "INCOMPLETE":
        actions.append("Re-run the scan. Do not rely on this result until every report is present.")
    if status_code == "FAILED":
        actions.append("Check the CodeBuild logs for the scanner error, then re-run the scan.")
    if counts_by_severity.get("CRITICAL", 0):
        actions.append(f"Address {counts_by_severity['CRITICAL']} CRITICAL finding(s) before deploying.")
    if counts_by_severity.get("HIGH", 0):
        actions.append(f"Review {counts_by_severity['HIGH']} HIGH finding(s) for risk acceptance.")
    if counts_by_tool.get("gitleaks", 0):
        actions.append("Rotate any leaked credentials surfaced by gitleaks immediately.")
    if status_code == "CLEAN":
        actions.append("No unsuppressed findings. Continue normal operations.")
    if suppressed:
        actions.append(f"Review the {len(suppressed)} suppressed alert type(s) listed above; "
                       f"they remain in the raw zap.json.")
    actions.append(f"Full reports in {S3_LOCATION}")
    return actions


# --------------------------------------------------------------------------
# Build summary
# --------------------------------------------------------------------------

def build_summary():
    policy, policy_found = load_zap_policy()
    zap_active, suppressed = parse_zap(policy)
    findings = parse_semgrep() + parse_trivy() + parse_gitleaks() + zap_active
    problems = check_reports()

    counts_by_tool = {}
    counts_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts_by_tool[f["tool"]] = counts_by_tool.get(f["tool"], 0) + 1
        counts_by_severity[f["severity"]] = counts_by_severity.get(f["severity"], 0) + 1

    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["tool"], f["id"]))
    top = findings[:5]

    status_code, status_text = decide_status(problems, findings)
    actions = build_actions(status_code, counts_by_severity, counts_by_tool, findings, suppressed)
    zap_scan = TARGET_TYPE in ("web", "api")
    policy_label = "tools/zap-baseline.conf" if policy_found else "not found - no alerts suppressed"

    summary_data = {
        "scan_id": SCAN_ID,
        "client": CLIENT_NAME,
        "target_type": TARGET_TYPE,
        "target": TARGET_DESC,
        "scan_rc": SCAN_RC,
        "status_code": status_code,
        "status": status_text,
        "report_problems": problems,
        "counts_by_tool": counts_by_tool,
        "counts_by_severity": counts_by_severity,
        "total_findings": len(findings),
        "top_findings": top,
        "suppressed_count": len(suppressed),
        "suppressed_findings": suppressed,
        "suppression_policy": policy_label if zap_scan else None,
        "report_location": S3_LOCATION,
        "recommended_actions": actions,
    }

    # --- summary.txt (used as SNS message body) ---
    lines = [
        "Security Scan Summary",
        "=====================",
        f"Client:       {CLIENT_NAME}",
        f"Target:       {TARGET_DESC} ({TARGET_TYPE})",
        f"Scan ID:      {SCAN_ID}",
        f"Status:       {status_text}",
    ]
    if problems:
        lines.append("Report check: " + "; ".join(problems))
    if zap_scan:
        lines.append(f"ZAP policy:   {policy_label}")
    lines += ["", "Findings by tool:"]
    if counts_by_tool:
        for tool in sorted(counts_by_tool):
            lines.append(f"  {tool:10} {counts_by_tool[tool]}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Findings by severity:")
    any_sev = False
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts_by_severity.get(sev, 0) > 0:
            lines.append(f"  {sev:10} {counts_by_severity[sev]}")
            any_sev = True
    if not any_sev:
        lines.append("  (none)")

    lines.append("")
    if top:
        lines.append(f"Top {len(top)} findings:")
        for i, f in enumerate(top, 1):
            loc = f["file"] or ""
            if f.get("line"):
                loc += f":{f['line']}"
            lines.append(f"  {i}. [{f['severity']}] [{f['tool']}] {f['id']}")
            if f["message"]:
                lines.append(f"     {f['message'][:120]}")
            if loc:
                lines.append(f"     {loc}")
            if f.get("note"):
                lines.append(f"     Note: {f['note']}")
        lines.append("")

    if suppressed:
        lines.append(f"Suppressed by policy ({len(suppressed)} alert type(s), not counted above;")
        lines.append("still present in the raw zap.json):")
        for f in suppressed:
            lines.append(f"  - [{f['severity']}] {f['id']} {f['message']} "
                         f"({f['instances']} instance(s))")
            lines.append(f"    Reason: {f['suppression_reason']}")
        lines.append("")

    lines.append("Recommended next actions:")
    for a in actions:
        lines.append(f"  - {a}")

    return summary_data, "\n".join(lines) + "\n", status_code


# --------------------------------------------------------------------------
# Main (defensive)
# --------------------------------------------------------------------------

def main():
    # Remove any stale subject first: if this run fails before writing a new
    # one, buildspec.yml falls back to "status unknown", never a stale "clean".
    try:
        SUBJECT_PATH.unlink()
    except OSError:
        pass
    try:
        REPORT_PATH.mkdir(parents=True, exist_ok=True)
        summary_data, summary_text, status_code = build_summary()
        (REPORT_PATH / "summary.json").write_text(json.dumps(summary_data, indent=2))
        (REPORT_PATH / "summary.txt").write_text(summary_text)
        write_subject(status_code)
        print(
            f"[report_summary] wrote summary.json and summary.txt "
            f"({summary_data['total_findings']} findings)",
            file=sys.stderr,
        )
    except Exception as e:
        # On any failure, still write a minimal summary.txt so the downstream
        # SNS publish has something to send instead of cascade-failing.
        err = f"{type(e).__name__}: {e}"
        print(f"[report_summary] FAILED: {err}", file=sys.stderr)
        try:
            write_subject("FAILED")
        except Exception:
            pass
        try:
            REPORT_PATH.mkdir(parents=True, exist_ok=True)
            minimal = {
                "scan_id": SCAN_ID,
                "client": CLIENT_NAME,
                "target": TARGET_DESC,
                "scan_rc": SCAN_RC,
                "status_code": "FAILED",
                "status": "FAILED - summary generation failed",
                "error": err,
                "report_location": S3_LOCATION,
            }
            (REPORT_PATH / "summary.json").write_text(json.dumps(minimal, indent=2))
            (REPORT_PATH / "summary.txt").write_text(
                f"Security Scan Summary\n"
                f"=====================\n"
                f"Client:   {CLIENT_NAME}\n"
                f"Target:   {TARGET_DESC} ({TARGET_TYPE})\n"
                f"Scan ID:  {SCAN_ID}\n"
                f"Status:   FAILED - summary generation failed\n"
                f"Error:    {err}\n"
                f"\n"
                f"Raw scan reports are still available in {S3_LOCATION}\n"
            )
        except Exception:
            pass
    # Always exit 0; we don't want to fail post_build over summary generation.
    sys.exit(0)


if __name__ == "__main__":
    main()
