#!/usr/bin/env python3
"""
report_summary.py - Build human-readable + structured summaries from raw
scanner output.

Reads (from REPORT_DIR):
  semgrep.json    (repo scans)
  trivy.json      (repo scans)
  gitleaks.json   (repo scans)
  zap.json        (web/api scans - basic support)

Reads from environment (set by buildspec/scan.sh):
  REPORT_DIR, SCAN_ID, CLIENT_NAME, TARGET_TYPE, TARGET_DESC, SCAN_RC, REPORT_BUCKET

Writes (into REPORT_DIR):
  summary.json    - structured, machine-readable
  summary.txt     - human-readable, used as the SNS message body

Always exits 0. On internal error, a minimal summary.txt is still written
so the downstream SNS publish has something to send.
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


def parse_zap():
    data = load_json("zap.json")
    if not data:
        return []
    out = []
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            out.append({
                "tool": "zap",
                "severity": normalize("zap", a.get("riskdesc", "")),
                "id": a.get("pluginid") or a.get("name", "alert"),
                "message": (a.get("name") or "")[:200],
                "file": site.get("@name", ""),
                "line": None,
            })
    return out


# --------------------------------------------------------------------------
# Recommended actions
# --------------------------------------------------------------------------

def build_actions(counts_by_severity, counts_by_tool, findings):
    actions = []
    if counts_by_severity.get("CRITICAL", 0):
        actions.append(f"Address {counts_by_severity['CRITICAL']} CRITICAL finding(s) before deploying.")
    if counts_by_severity.get("HIGH", 0):
        actions.append(f"Review {counts_by_severity['HIGH']} HIGH finding(s) for risk acceptance.")
    if counts_by_tool.get("gitleaks", 0):
        actions.append("Rotate any leaked credentials surfaced by gitleaks immediately.")
    if not findings:
        actions.append("No findings. Continue normal operations.")
    actions.append(f"Full reports in {S3_LOCATION}")
    return actions


# --------------------------------------------------------------------------
# Build summary
# --------------------------------------------------------------------------

def build_summary():
    findings = parse_semgrep() + parse_trivy() + parse_gitleaks() + parse_zap()

    counts_by_tool = {}
    counts_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts_by_tool[f["tool"]] = counts_by_tool.get(f["tool"], 0) + 1
        counts_by_severity[f["severity"]] = counts_by_severity.get(f["severity"], 0) + 1

    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["tool"], f["id"]))
    top = findings[:5]

    try:
        rc = int(SCAN_RC)
        status_text = "completed cleanly - no blocking findings" if rc == 0 else f"completed WITH findings (rc={rc})"
    except (ValueError, TypeError):
        status_text = f"completed (rc={SCAN_RC})"

    actions = build_actions(counts_by_severity, counts_by_tool, findings)

    summary_data = {
        "scan_id": SCAN_ID,
        "client": CLIENT_NAME,
        "target_type": TARGET_TYPE,
        "target": TARGET_DESC,
        "scan_rc": SCAN_RC,
        "status": status_text,
        "counts_by_tool": counts_by_tool,
        "counts_by_severity": counts_by_severity,
        "total_findings": len(findings),
        "top_findings": top,
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
        "",
        "Findings by tool:",
    ]
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
        lines.append("")

    lines.append("Recommended next actions:")
    for a in actions:
        lines.append(f"  - {a}")

    return summary_data, "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Main (defensive)
# --------------------------------------------------------------------------

def main():
    try:
        REPORT_PATH.mkdir(parents=True, exist_ok=True)
        summary_data, summary_text = build_summary()
        (REPORT_PATH / "summary.json").write_text(json.dumps(summary_data, indent=2))
        (REPORT_PATH / "summary.txt").write_text(summary_text)
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
            REPORT_PATH.mkdir(parents=True, exist_ok=True)
            minimal = {
                "scan_id": SCAN_ID,
                "client": CLIENT_NAME,
                "target": TARGET_DESC,
                "scan_rc": SCAN_RC,
                "status": "summary generation failed",
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
                f"Status:   summary generation failed\n"
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
